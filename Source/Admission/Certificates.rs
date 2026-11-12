// SPDX-License-Identifier: MIT
// Admission TLS renews pinned private certificates and reloads managed public certificates.
use anyhow::{Result, ensure};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use time::OffsetDateTime;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "camelCase", deny_unknown_fields)]
pub enum Configuration {
    Private { directory: PathBuf, host: String },
    Managed { certificate: PathBuf, key: PathBuf },
    ManagedBundle { bundle: PathBuf },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Material {
    pub certificate: String,
    pub key: String,
}
impl Drop for Material {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}
impl Material {
    fn load(&self) -> Result<Arc<CertifiedKey>> {
        ensure!(
            self.certificate.len() <= 196608 && self.key.len() <= 16384,
            "certificate material exceeds bound"
        );
        let certificates = CertificateDer::pem_slice_iter(self.certificate.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(
            !certificates.is_empty()
                && certificates.len() <= 8
                && certificates.iter().all(|c| c.len() <= 16384),
            "invalid admission certificate chain"
        );
        let key = PrivateKeyDer::from_pem_slice(self.key.as_bytes())?;
        Ok(Arc::new(CertifiedKey::from_der(
            certificates,
            key,
            &rustls::crypto::ring::default_provider(),
        )?))
    }
    pub fn validate(&self) -> Result<()> {
        self.load().map(|_| ())
    }
}
fn host_name(host: &str) -> Result<String> {
    let url = reqwest::Url::parse(&format!("https://{host}/"))?;
    ensure!(
        url.host_str() == Some(host)
            && url.port().is_none()
            && url.username().is_empty()
            && url.password().is_none(),
        "certificate host must be an exact IP address or DNS name"
    );
    Ok(host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned())
}
pub fn initialise(directory: &Path, host: &str) -> Result<String> {
    let _ = host_name(host)?;
    super::private::directory(directory)?;
    let key = KeyPair::generate()?;
    crate::files::write_new(
        &directory.join("Authority.pem"),
        key.serialize_pem().as_bytes(),
    )?;
    let (_, pin) = private_certificate(&key, host, OffsetDateTime::now_utc())?;
    Ok(hex::encode(pin))
}
fn private_certificate(
    key: &KeyPair,
    host: &str,
    now: OffsetDateTime,
) -> Result<(Arc<CertifiedKey>, [u8; 32])> {
    let name = host_name(host)?;
    let mut authority = CertificateParams::new(Vec::<String>::new())?;
    authority.not_before = now - time::Duration::minutes(5);
    authority.not_after = now + time::Duration::days(365);
    authority.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    authority.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root = authority.self_signed(key)?;
    let pin = super::transport::authority_pin(root.der())?;
    let issuer = Issuer::new(authority, key);
    let leaf_key = KeyPair::generate()?;
    let mut leaf = CertificateParams::new(vec![name])?;
    leaf.not_before = now - time::Duration::minutes(5);
    leaf.not_after = now + time::Duration::days(7);
    leaf.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let leaf = leaf.signed_by(&leaf_key, &issuer)?;
    let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let certified = CertifiedKey::from_der(
        vec![leaf.der().clone(), root.der().clone()],
        private,
        &rustls::crypto::ring::default_provider(),
    )?;
    Ok((Arc::new(certified), pin))
}
fn load(config: &Configuration) -> Result<(Arc<CertifiedKey>, Option<[u8; 32]>)> {
    match config {
        Configuration::Private { directory, host } => {
            super::private::directory(directory)?;
            let bytes = zeroize::Zeroizing::new(crate::files::read_bounded(
                &directory.join("Authority.pem"),
                true,
            )?);
            let key = KeyPair::from_pem(std::str::from_utf8(&bytes)?)?;
            let (certificate, pin) = private_certificate(&key, host, OffsetDateTime::now_utc())?;
            Ok((certificate, Some(pin)))
        }
        Configuration::Managed { certificate, key } => {
            let pem = crate::files::read_bounded(certificate, false)?;
            let certificates =
                CertificateDer::pem_slice_iter(&pem).collect::<std::result::Result<Vec<_>, _>>()?;
            ensure!(
                !certificates.is_empty()
                    && certificates.len() <= 8
                    && certificates.iter().all(|c| c.len() <= 16384),
                "invalid admission certificate chain"
            );
            let pem = zeroize::Zeroizing::new(crate::files::read_bounded(key, true)?);
            let key = PrivateKeyDer::from_pem_slice(&pem)?;
            Ok((
                Arc::new(CertifiedKey::from_der(
                    certificates,
                    key,
                    &rustls::crypto::ring::default_provider(),
                )?),
                None,
            ))
        }
        Configuration::ManagedBundle { bundle } => {
            let material: Material = super::saved::read(bundle)?;
            Ok((material.load()?, None))
        }
    }
}
struct Current {
    certificate: Arc<CertifiedKey>,
    checked: Instant,
}
struct Reload {
    configuration: Configuration,
    current: Mutex<Current>,
}
impl std::fmt::Debug for Reload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdmissionCertificateResolver")
    }
}
impl ResolvesServerCert for Reload {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let mut current = self.current.lock().ok()?;
        let interval = match self.configuration {
            Configuration::Private { .. } => Duration::from_secs(86400),
            Configuration::Managed { .. } | Configuration::ManagedBundle { .. } => {
                Duration::from_secs(60)
            }
        };
        if current.checked.elapsed() >= interval {
            // Refuse new handshakes if a renewal cannot be loaded. Never skip trust validation.
            current.certificate = load(&self.configuration).ok()?.0;
            current.checked = Instant::now();
        }
        Some(current.certificate.clone())
    }
}
pub fn server(
    configuration: Configuration,
) -> Result<(Arc<rustls::ServerConfig>, Option<[u8; 32]>)> {
    let (certificate, pin) = load(&configuration)?;
    let resolver = Reload {
        configuration,
        current: Mutex::new(Current {
            certificate,
            checked: Instant::now(),
        }),
    };
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(resolver));
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    server.max_early_data_size = 0;
    server.send_tls13_tickets = 0;
    server.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Ok((Arc::new(server), pin))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{
        client::danger::ServerCertVerifier,
        pki_types::{ServerName, UnixTime},
    };
    #[test]
    fn managed_bundle_rejects_partial_or_mismatched_certificate_keys() {
        let key = KeyPair::generate().unwrap();
        let other = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["example.org".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap()
            .pem();
        let mut material = Material {
            certificate,
            key: key.serialize_pem(),
        };
        material.validate().unwrap();
        material.key = other.serialize_pem();
        assert!(material.validate().is_err());
        material.key = key.serialize_pem();
        material
            .certificate
            .truncate(material.certificate.len() / 2);
        assert!(material.validate().is_err());
    }
    #[test]
    fn private_pin_survives_renewal_but_rejects_wrong_names_keys_and_expiry() {
        let key = KeyPair::generate().unwrap();
        let now = OffsetDateTime::now_utc();
        let (first, pin) = private_certificate(&key, "127.0.0.1", now).unwrap();
        let (renewed, renewed_pin) =
            private_certificate(&key, "127.0.0.1", now + time::Duration::days(1)).unwrap();
        assert_eq!(pin, renewed_pin);
        let verifier = super::super::transport::pinned_verifier(pin);
        let check = |certificate: &CertifiedKey, name: &str, at: OffsetDateTime| {
            verifier.verify_server_cert(
                &certificate.cert[0],
                &certificate.cert[1..],
                &ServerName::try_from(name.to_owned()).unwrap(),
                &[],
                UnixTime::since_unix_epoch(Duration::from_secs(at.unix_timestamp() as u64)),
            )
        };
        assert!(check(&first, "127.0.0.1", now).is_ok());
        assert!(check(&renewed, "127.0.0.1", now + time::Duration::days(1)).is_ok());
        assert!(check(&first, "127.0.0.2", now).is_err());
        assert!(check(&first, "127.0.0.1", now + time::Duration::days(8)).is_err());
        let (other, _) =
            private_certificate(&KeyPair::generate().unwrap(), "127.0.0.1", now).unwrap();
        assert!(check(&other, "127.0.0.1", now).is_err());
    }
}
