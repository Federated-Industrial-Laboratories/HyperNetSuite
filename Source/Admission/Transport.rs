// SPDX-License-Identifier: MIT
// Normal HTTPS or a pinned private CA authenticates metadata before any admission secret is sent.
use super::location::Location;
use anyhow::{Result, ensure};
use rustls::{
    RootCertStore,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use std::{io::Read, sync::Arc, time::Duration};

pub const RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub fn authority_pin(certificate: &[u8]) -> Result<[u8; 32]> {
    ensure!(certificate.len() <= 16384, "certificate exceeds its bound");
    let (remaining, cert) = x509_parser::parse_x509_certificate(certificate)
        .map_err(|_| anyhow::anyhow!("invalid certificate"))?;
    ensure!(remaining.is_empty(), "certificate has trailing data");
    Ok(Sha256::digest(cert.public_key().raw).into())
}
#[derive(Debug)]
pub(super) struct PinnedAuthority {
    pin: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}
pub(super) fn pinned_verifier(pin: [u8; 32]) -> PinnedAuthority {
    PinnedAuthority {
        pin,
        provider: Arc::new(rustls::crypto::ring::default_provider()),
    }
}
impl ServerCertVerifier for PinnedAuthority {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if chain.len() > 8 || leaf.len() > 16384 || chain.iter().any(|c| c.len() > 16384) {
            return Err(rustls::Error::General(
                "certificate chain exceeds admission bound".into(),
            ));
        }
        // Private servers send the root along with their chain. Pin its key, not its renewal dates.
        let root = chain
            .iter()
            .chain(std::iter::once(leaf))
            .find(|c| authority_pin(c).is_ok_and(|p| p == self.pin))
            .ok_or_else(|| {
                rustls::Error::General("private authority key differs from invitation".into())
            })?;
        let mut roots = RootCertStore::empty();
        roots.add(root.clone())?;
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), self.provider.clone())
                .build()
                .map_err(|_| rustls::Error::General("private authority is unavailable".into()))?;
        verifier.verify_server_cert(leaf, chain, name, ocsp, now)
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("admission requires TLS 1.3".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
pub fn client(location: &Location) -> Result<reqwest::blocking::Client> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let _ = provider.as_ref().clone().install_default();
    let mut builder = reqwest::blocking::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .user_agent("HyperNetJoin/1");
    if let Some(pin) = location.certificate_authority_pin {
        ensure!(
            location.identity_pin.is_some(),
            "private CA trust requires a native identity pin"
        );
        let config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(pinned_verifier(pin)))
            .with_no_client_auth();
        builder = builder.use_preconfigured_tls(config);
    }
    builder
        .build()
        .map_err(|_| anyhow::anyhow!("admission HTTPS client unavailable"))
}
pub fn response(response: reqwest::blocking::Response) -> Result<Vec<u8>> {
    ensure!(
        response.status().is_success(),
        "admission endpoint refused the request"
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|n| n <= RESPONSE_BYTES as u64),
        "admission response exceeds its bound"
    );
    let mut bytes = Vec::new();
    response
        .take(RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("admission response interrupted"))?;
    ensure!(
        bytes.len() <= RESPONSE_BYTES,
        "admission response exceeds its bound"
    );
    Ok(bytes)
}
pub fn descriptor(location: &Location) -> Result<Vec<u8>> {
    response(
        client(location)?
            .get(location.endpoint("/v1/admission/descriptor")?)
            .send()
            .map_err(|_| anyhow::anyhow!("admission HTTPS verification or connection failed"))?,
    )
}
