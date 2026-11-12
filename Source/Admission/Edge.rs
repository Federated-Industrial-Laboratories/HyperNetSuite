// SPDX-License-Identifier: MIT
// The public TLS listener has bounded work and only a fixed private registrar socket.
use super::{certificates, http};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{BufReader, Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub version: u8,
    pub origin: String,
    pub native_link: String,
    pub listen: SocketAddr,
    pub tls: certificates::Configuration,
    pub registrar: PathBuf,
    pub registrar_uid: u32,
}
impl Configuration {
    pub fn validate(&self) -> Result<reqwest::Url> {
        ensure!(
            self.version == 1 && self.registrar.is_absolute() && self.listen.port() > 0,
            "invalid admission listener configuration"
        );
        let location = super::location::Location::parse(&self.origin)?;
        ensure!(
            location.secret.is_none()
                && location.identity_pin.is_none()
                && location.origin.as_str() == self.origin,
            "listener requires an exact HTTPS origin"
        );
        let native = super::location::Location::parse(&self.native_link)?;
        ensure!(
            native.identity_pin.is_some()
                && native.invitation.is_none()
                && native.origin == location.origin,
            "landing link must pin this server without an invitation secret"
        );
        if let certificates::Configuration::Private { host, .. } = &self.tls {
            ensure!(
                location.origin.host_str() == Some(host),
                "private certificate host differs from origin"
            );
        }
        Ok(location.origin.clone())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase", deny_unknown_fields)]
pub enum Operation {
    Descriptor,
    Challenge { body: serde_json::Value },
    Claim { body: serde_json::Value },
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrarRequest {
    pub format: String,
    pub source: String,
    pub action: Operation,
}
pub fn registrar(config: &Configuration, request: &RegistrarRequest) -> Result<Vec<u8>> {
    let mut socket = super::ipc::Channel::connect(
        &config.registrar,
        config.registrar_uid,
        Duration::from_secs(30),
    )?;
    let body = serde_json::to_vec(request)?;
    ensure!(
        body.len() <= http::BODY_BYTES + 1024,
        "private admission request exceeds bound"
    );
    let body = socket.exchange(&body, super::transport::RESPONSE_BYTES)?;
    serde_json::from_slice::<serde_json::Value>(&body)?;
    Ok(body)
}
struct Budget {
    start: Instant,
    total: usize,
    sources: BTreeMap<IpAddr, usize>,
}
impl Budget {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            total: 0,
            sources: BTreeMap::new(),
        }
    }
    fn admit(&mut self, source: IpAddr) -> bool {
        if self.start.elapsed() >= Duration::from_secs(60) {
            *self = Self::new();
        }
        if self.total >= 120 {
            return false;
        }
        let source = match source {
            IpAddr::V6(v) => IpAddr::V6(std::net::Ipv6Addr::from(u128::from(v) & (!0u128 << 64))),
            other => other,
        };
        if !self.sources.contains_key(&source) && self.sources.len() >= 256 {
            return false;
        }
        let count = self.sources.entry(source).or_default();
        if *count >= 12 {
            return false;
        }
        *count += 1;
        self.total += 1;
        true
    }
}
const LANDING:&[u8]=br#"<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Join HyperNet</title><style>body{max-width:42rem;margin:4rem auto;padding:1rem;font:1.1rem system-ui;line-height:1.6}h1{line-height:1.2}code{overflow-wrap:anywhere}</style><h1>Join this HyperNet server</h1><p><a id="open" hidden>Open HyperNet</a></p><p>Or copy this page's full address, including its invitation fragment. In HyperNet Suite or HyperNet RelayChat, choose <strong>Join a server</strong> and paste it.</p><p>Your application will show the server identity and permissions before you join. Merely viewing this page does not use an invitation.</p><p>The current desktop packages require Linux. On another device, send this address privately to your Linux computer. Keep a private invitation to yourself.</p><p>Install the signed HyperNet Suite or RelayChat package from the publisher's official release page if you do not yet have the application. The invitation never installs software or executes commands.</p><script src="/join.js" defer></script></html>"#;
fn script(config: &Configuration) -> Result<Vec<u8>> {
    let base = super::location::Location::parse(&config.native_link)?.url(true)?;
    Ok(format!("'use strict';const base={};const link=document.getElementById('open');const fragment=location.hash;if(fragment.length<=769&&!location.search){{link.href=fragment?base.split('#')[0]+fragment:base;link.hidden=false;}}",serde_json::to_string(&base)?).into_bytes())
}
struct DeadlineStream {
    stream: TcpStream,
    deadline: Instant,
}
impl DeadlineStream {
    fn remaining(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "admission frame deadline")
            })
    }
}
impl Read for DeadlineStream {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}
impl Write for DeadlineStream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}
fn connection(
    stream: TcpStream,
    source: IpAddr,
    config: &Configuration,
    tls: Arc<rustls::ServerConfig>,
    origin: &reqwest::Url,
) -> Result<()> {
    let socket = DeadlineStream {
        stream,
        deadline: Instant::now() + Duration::from_secs(10),
    };
    let mut stream = rustls::StreamOwned::new(rustls::ServerConnection::new(tls)?, socket);
    let request = http::request(&mut BufReader::new(&mut stream), origin);
    let operation = match request {
        Ok(http::Request::Landing) => {
            return http::response(&mut stream, 200, "text/html; charset=utf-8", LANDING);
        }
        Ok(http::Request::Script) => {
            return http::response(
                &mut stream,
                200,
                "text/javascript; charset=utf-8",
                &script(config)?,
            );
        }
        Ok(http::Request::Descriptor) => Operation::Descriptor,
        Ok(http::Request::Challenge(body)) => Operation::Challenge {
            body: serde_json::from_slice(&body)?,
        },
        Ok(http::Request::Claim(body)) => Operation::Claim {
            body: serde_json::from_slice(&body)?,
        },
        Err(_) => {
            return http::response(
                &mut stream,
                400,
                "application/json",
                br#"{"status":"refused","code":"InvalidRequest"}"#,
            );
        }
    };
    let request = RegistrarRequest {
        format: "HyperNetAdmissionEdge/1".into(),
        source: source.to_string(),
        action: operation,
    };
    let result = registrar(config, &request);
    stream.sock.deadline = Instant::now() + Duration::from_secs(10);
    match result {
        Ok(body) => http::response(&mut stream, 200, "application/json", &body),
        Err(_) => http::response(
            &mut stream,
            503,
            "application/json",
            br#"{"status":"refused","code":"RegistrarUnavailable"}"#,
        ),
    }
}
struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
pub fn serve(config: Configuration, stop: Arc<AtomicBool>) -> Result<()> {
    let origin = config.validate()?;
    let (tls, _) = certificates::server(config.tls.clone())?;
    let listener = TcpListener::bind(config.listen)?;
    listener.set_nonblocking(true)?;
    let active = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::<thread::JoinHandle<()>>::new();
    let mut budget = Budget::new();
    while !stop.load(Ordering::Acquire) {
        workers.retain(|w| !w.is_finished());
        match listener.accept() {
            Ok((stream, peer)) => {
                if active.load(Ordering::Acquire) >= 8 || !budget.admit(peer.ip()) {
                    continue;
                }
                active.fetch_add(1, Ordering::AcqRel);
                let count = active.clone();
                let tls = tls.clone();
                let config = config.clone();
                let origin = origin.clone();
                workers.push(thread::spawn(move || {
                    let _active = Active(count);
                    let _ = connection(stream, peer.ip(), &config, tls, &origin);
                }));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25))
            }
            Err(e) => return Err(e.into()),
        }
    }
    for worker in workers {
        let _ = worker.join();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn real_tls_landing_uses_no_registrar_and_rejects_unpinned_trust() {
        let directory =
            std::env::temp_dir().join(format!("hypernet-admission-{}", crate::random_hex::<12>()));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(directory.clone());
        let pin: [u8; 32] = hex::decode(certificates::initialise(&directory, "127.0.0.1").unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reserve.local_addr().unwrap();
        drop(reserve);
        let origin = format!("https://{address}/");
        let location = super::super::location::Location::parse(&format!(
            "{origin}join#v=1&pin={}&ca={}",
            URL_SAFE_NO_PAD.encode([4; 32]),
            URL_SAFE_NO_PAD.encode(pin)
        ))
        .unwrap();
        let config = Configuration {
            version: 1,
            origin: origin.clone(),
            native_link: location.url(true).unwrap(),
            listen: address,
            tls: certificates::Configuration::Private {
                directory: directory.clone(),
                host: "127.0.0.1".into(),
            },
            registrar: directory.join("Absent.sock"),
            registrar_uid: unsafe { libc::geteuid() },
        };
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = thread::spawn(move || serve(config, stopped));
        struct Running {
            stop: Arc<AtomicBool>,
            worker: Option<thread::JoinHandle<Result<()>>>,
        }
        impl Drop for Running {
            fn drop(&mut self) {
                self.stop.store(true, Ordering::Release);
                if let Some(worker) = self.worker.take() {
                    let _ = worker.join();
                }
            }
        }
        let _running = Running {
            stop,
            worker: Some(worker),
        };
        let until = Instant::now() + Duration::from_secs(3);
        while TcpStream::connect(address).is_err() {
            assert!(Instant::now() < until);
            thread::sleep(Duration::from_millis(10));
        }
        let client = super::super::transport::client(&location).unwrap();
        let landing = super::super::transport::response(
            client
                .get(location.endpoint("/join").unwrap())
                .send()
                .unwrap(),
        )
        .unwrap();
        assert!(
            std::str::from_utf8(&landing)
                .unwrap()
                .contains("Merely viewing this page does not use an invitation")
        );
        assert!(!directory.join("Absent.sock").exists());
        assert!(super::super::transport::descriptor(&location).is_err());
        let unpinned = super::super::location::Location::parse(&origin).unwrap();
        assert!(
            super::super::transport::client(&unpinned)
                .unwrap()
                .get(unpinned.endpoint("/join").unwrap())
                .send()
                .is_err()
        );
        let mut wrong = location.clone();
        wrong.certificate_authority_pin = Some([9; 32]);
        assert!(
            super::super::transport::client(&wrong)
                .unwrap()
                .get(wrong.endpoint("/join").unwrap())
                .send()
                .is_err()
        );
    }
}
