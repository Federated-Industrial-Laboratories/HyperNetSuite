// SPDX-License-Identifier: MIT
// Optional public certificates renew through the reviewed local ACME client and enter only the isolated listener.
use super::{
    certificates::Material, helper, host_isolation::Container, location::Location, protocol,
    runtime, saved,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "camelCase", deny_unknown_fields)]
pub enum Configuration {
    #[default]
    Private,
    Acme {
        certbot: PathBuf,
        email: String,
        #[serde(rename = "challengePort")]
        challenge_port: u16,
        #[serde(rename = "termsAccepted")]
        terms_accepted: bool,
    },
    Managed {
        certificate: PathBuf,
        key: PathBuf,
    },
}
impl Configuration {
    pub fn validate(&self, origin: &str, ports: &[u16]) -> Result<()> {
        let _ = Location::parse(origin)?;
        match self {
            Self::Private => (),
            Self::Managed { certificate, key } => {
                ensure!(
                    certificate.is_absolute() && key.is_absolute() && certificate != key,
                    "choose separate absolute certificate and private-key paths"
                );
            }
            Self::Acme {
                certbot,
                email,
                challenge_port,
                terms_accepted,
            } => {
                runtime::executable(certbot)?;
                ensure!(
                    *terms_accepted,
                    "review and accept the certificate authority's terms before requesting a public certificate"
                );
                ensure!(
                    email.len() <= 254
                        && email.split('@').count() == 2
                        && !email.starts_with('@')
                        && !email.ends_with('@')
                        && !email.chars().any(|c| c.is_control() || c.is_whitespace()),
                    "enter a valid certificate contact email"
                );
                ensure!(
                    *challenge_port > 1024 && !ports.contains(challenge_port),
                    "certificate challenge port must be unprivileged and separate from server ports"
                );
            }
        }
        Ok(())
    }
    pub fn review(&self) -> Value {
        match self {
            Self::Private => {
                json!({"mode":"private","connection":"Native link or imported QR pins this server's TLS authority; no public CA is contacted."})
            }
            Self::Managed { .. } => {
                json!({"mode":"managed","connection":"Public HTTPS. The external certificate manager must renew the selected files; changes reload automatically."})
            }
            Self::Acme { challenge_port, .. } => {
                json!({"mode":"acme","connection":"Public HTTPS with automatic Let's Encrypt renewal.","challengePort":challenge_port,"requirement":"Public TCP80 must reach the challenge port on this computer during initial validation and renewals. Configure this forwarding in the router/firewall; the application does not change it.","disclosure":"The certificate authority receives the contact email and server address. Issued certificates are public."})
            }
        }
    }
    fn source(
        &self,
        container: &Container,
        origin: &str,
        stop: &AtomicBool,
    ) -> Result<Option<Material>> {
        match self {
            Self::Private => Ok(None),
            Self::Managed { certificate, key } => Ok(Some(material(certificate, key)?)),
            Self::Acme {
                certbot,
                email,
                challenge_port,
                terms_accepted,
            } => {
                ensure!(*terms_accepted, "certificate terms are not accepted");
                let version = helper::output(
                    certbot,
                    &["--version".into()],
                    &[],
                    stop,
                    Duration::from_secs(15),
                )?;
                let version = std::str::from_utf8(&version)?
                    .trim()
                    .strip_prefix("certbot ")
                    .ok_or_else(|| anyhow::anyhow!("Certbot version unavailable"))?;
                let mut parts = version.split('.');
                let major: u32 = parts.next().unwrap_or("").parse()?;
                let minor: u32 = parts.next().unwrap_or("").parse()?;
                ensure!(
                    (major, minor) >= (5, 10),
                    "install Certbot5.10 or newer for IP-address certificates"
                );
                let root = container.directory.join("Acme");
                saved::create_directory(&root)?;
                for name in ["Config", "Work", "Logs"] {
                    saved::create_directory(&root.join(name))?;
                }
                let webroot = root.join("Webroot");
                for path in [
                    &webroot,
                    &webroot.join(".well-known"),
                    &webroot.join(".well-known/acme-challenge"),
                ] {
                    if !path.exists() {
                        std::fs::DirBuilder::new().mode(0o755).create(path)?;
                    }
                    let meta = std::fs::symlink_metadata(path)?;
                    ensure!(
                        meta.is_dir()
                            && !meta.file_type().is_symlink()
                            && meta.uid() == unsafe { libc::geteuid() }
                            && meta.mode() & 0o777 == 0o755,
                        "certificate challenge directory differs"
                    );
                }
                let config = root.join("Config");
                let live = config.join("live/HyperNetAdmission");
                let mut args: Vec<OsString> = vec![
                    "--non-interactive".into(),
                    "--config-dir".into(),
                    config.as_os_str().into(),
                    "--work-dir".into(),
                    root.join("Work").into_os_string(),
                    "--logs-dir".into(),
                    root.join("Logs").into_os_string(),
                    "--cert-name".into(),
                    "HyperNetAdmission".into(),
                    "--no-directory-hooks".into(),
                ];
                if config.join("renewal/HyperNetAdmission.conf").exists() {
                    args.extend(["renew".into(), "--no-random-sleep-on-renew".into()]);
                } else {
                    args.extend([
                        "certonly".into(),
                        "--webroot".into(),
                        "--webroot-path".into(),
                        webroot.as_os_str().into(),
                        "--preferred-challenges=http".into(),
                        "--agree-tos".into(),
                        "--email".into(),
                        email.into(),
                        "--server".into(),
                        "https://acme-v02.api.letsencrypt.org/directory".into(),
                    ]);
                    let location = Location::parse(origin)?;
                    let host = location
                        .origin
                        .host_str()
                        .ok_or_else(|| anyhow::anyhow!("certificate hostname absent"))?
                        .trim_start_matches('[')
                        .trim_end_matches(']');
                    if host.parse::<std::net::IpAddr>().is_ok() {
                        args.extend([
                            "--ip-address".into(),
                            host.into(),
                            "--required-profile".into(),
                            "shortlived".into(),
                        ]);
                    } else {
                        args.extend(["--domain".into(), host.into()]);
                    }
                }
                // Certbot owns its private account/renewal data. It receives no admission,
                // Home, governance or participant key paths and executes no directory hooks.
                let mut listener = super::host_challenge::Challenge::start(
                    container,
                    &webroot,
                    *challenge_port,
                    stop,
                )?;
                let issued = helper::output(certbot, &args, &[], stop, Duration::from_secs(300));
                let stopped = listener.finish();
                issued.map_err(|_|anyhow::anyhow!("public certificate request or renewal failed; check TCP80 forwarding and the private certificate log"))?;
                stopped?;
                let certificate = live.join("fullchain.pem").canonicalize()?;
                let key = live.join("privkey.pem").canonicalize()?;
                let archive = config.join("archive/HyperNetAdmission").canonicalize()?;
                ensure!(
                    certificate.starts_with(&archive) && key.starts_with(&archive),
                    "certificate renewal paths escape the retained account"
                );
                Ok(Some(material(&certificate, &key)?))
            }
        }
    }
    pub fn prepare(
        &self,
        container: &Container,
        origin: &str,
        stop: &AtomicBool,
    ) -> Result<Option<[u8; 32]>> {
        let location = Location::parse(origin)?;
        if matches!(self, Self::Private) {
            return Ok(Some(
                hex::decode(container.prepare(location.origin.host_str().unwrap(), stop)?)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("private certificate identity differs"))?,
            ));
        }
        container.prepare_state(stop)?;
        self.refresh(container, origin, stop)?;
        Ok(None)
    }
    fn refresh(&self, container: &Container, origin: &str, stop: &AtomicBool) -> Result<()> {
        let Some(material) = self.source(container, origin, stop)? else {
            return Ok(());
        };
        material.validate()?;
        let digest = protocol::digest(material.certificate.as_bytes());
        // Replace the pair even when unchanged: a damaged or missing listener
        // copy must be repairable without changing the retained certificate.
        container.stage("Managed.json", &material, stop)?;
        saved::replace(
            &container.directory.join("TlsHealth.json"),
            &json!({"healthy":true,"checkedAtMs":now_ms(),"certificateDigest":digest}),
        )
    }
    fn interval(&self) -> Duration {
        match self {
            Self::Managed { .. } => Duration::from_secs(60),
            _ => Duration::from_secs(21600),
        }
    }
}
fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
fn material(certificate: &Path, key: &Path) -> Result<Material> {
    let certificate = String::from_utf8(crate::files::read_bounded(certificate, false)?)?;
    let key = zeroize::Zeroizing::new(crate::files::read_bounded(key, true)?);
    let material = Material {
        certificate,
        key: std::str::from_utf8(&key)?.into(),
    };
    material.validate()?;
    Ok(material)
}
pub struct Maintenance {
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Maintenance {
    pub fn start(configuration: Configuration, container: Container, origin: String) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let worker = if matches!(configuration, Configuration::Private) {
            None
        } else {
            Some(std::thread::spawn(move || {
                let mut next = Instant::now();
                while !flag.load(Ordering::Acquire) {
                    if Instant::now() >= next {
                        let success = configuration.refresh(&container, &origin, &flag).is_ok();
                        if !success && !flag.load(Ordering::Acquire) {
                            let _ = saved::replace(
                                &container.directory.join("TlsHealth.json"),
                                &json!({"healthy":false,"checkedAtMs":now_ms(),"code":"CertificateRefreshUnavailable"}),
                            );
                        }
                        next = Instant::now()
                            + if success {
                                configuration.interval()
                            } else {
                                Duration::from_secs(300)
                            };
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
            }))
        };
        Self { stop, worker }
    }
}
impl Drop for Maintenance {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
