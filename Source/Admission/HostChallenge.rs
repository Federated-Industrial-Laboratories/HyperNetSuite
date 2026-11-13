// SPDX-License-Identifier: MIT
// HTTP certificate validation exposes only bounded ACME tokens from a read-only rootless mount.
use super::{
    host_isolation::{Container, argument},
    protocol, runtime,
};
use anyhow::{Result, ensure};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub struct Challenge {
    container: Container,
    process: Option<runtime::Process>,
}
impl Challenge {
    pub fn start(
        container: &Container,
        directory: &Path,
        port: u16,
        stop: &AtomicBool,
    ) -> Result<Self> {
        let name = format!("{}-acme", container.name());
        container.stop_named(&name, stop)?;
        let args = vec![
            "run".into(),
            "--rm".into(),
            "--pull=never".into(),
            "--read-only".into(),
            "--user=1:1".into(),
            "--cap-drop=ALL".into(),
            "--security-opt=no-new-privileges".into(),
            "--pids-limit=16".into(),
            "--memory=67108864".into(),
            "--cpus=1".into(),
            "--log-driver=none".into(),
            "--network=slirp4netns:allow_host_loopback=false,port_handler=slirp4netns".into(),
            "--publish".into(),
            format!(
                "{}:{port}/tcp",
                SocketAddr::new(container.listen.ip(), port)
            )
            .into(),
            "--volume".into(),
            format!(
                "{}:/HyperNetSuite:ro,nosuid,nodev",
                argument(&container.suite)?
            )
            .into(),
            "--volume".into(),
            format!("{}:/Challenge:ro,nosuid,nodev", argument(directory)?).into(),
            "--name".into(),
            name.into(),
            "--label".into(),
            format!(
                "org.hypernet.admission={}",
                protocol::digest(container.directory.as_os_str().as_encoded_bytes())
            )
            .into(),
            "--entrypoint=/HyperNetSuite".into(),
            container.image.clone().into(),
            "join".into(),
            "certificate-challenge".into(),
            "--directory".into(),
            "/Challenge".into(),
            "--listen".into(),
            format!("0.0.0.0:{port}").into(),
        ];
        let process = runtime::Process::spawn(&container.podman, &args)?;
        let mut result = Self {
            container: container.clone(),
            process: Some(process),
        };
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline && !stop.load(Ordering::Acquire) {
            ensure!(
                result.process.as_mut().unwrap().running()?,
                "certificate challenge listener stopped"
            );
            if TcpStream::connect_timeout(
                &SocketAddr::new(container.listen.ip(), port),
                Duration::from_millis(250),
            )
            .is_ok()
            {
                return Ok(result);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        anyhow::bail!("certificate challenge listener is unavailable")
    }
    pub fn finish(&mut self) -> Result<()> {
        let result = self.container.stop_named(
            &format!("{}-acme", self.container.name()),
            &AtomicBool::new(false),
        );
        self.process.take();
        result
    }
}
impl Drop for Challenge {
    fn drop(&mut self) {
        if self.process.is_some() {
            let _ = self.finish();
        }
    }
}
fn token(header: &[u8]) -> Result<&str> {
    ensure!(
        header.len() <= 8192 && header.ends_with(b"\r\n\r\n"),
        "invalid challenge header"
    );
    let text = std::str::from_utf8(header)?;
    let first = text.split("\r\n").next().unwrap_or("");
    let path = first
        .strip_prefix("GET ")
        .and_then(|s| s.strip_suffix(" HTTP/1.1"))
        .ok_or_else(|| anyhow::anyhow!("unsupported challenge method"))?;
    let token = path
        .strip_prefix("/.well-known/acme-challenge/")
        .ok_or_else(|| anyhow::anyhow!("unknown challenge resource"))?;
    ensure!(
        (1..=128).contains(&token.len())
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')),
        "invalid challenge token"
    );
    Ok(token)
}
fn connection(mut socket: TcpStream, directory: &Path, stop: &AtomicBool) -> Result<()> {
    let end = Instant::now() + Duration::from_secs(5);
    let mut header = Vec::new();
    while header.len() < 8192 && !header.ends_with(b"\r\n\r\n") {
        ensure!(!stop.load(Ordering::Acquire), "challenge stopped");
        socket.set_read_timeout(Some(
            end.checked_duration_since(Instant::now())
                .ok_or_else(|| anyhow::anyhow!("challenge input timed out"))?,
        ))?;
        let mut bytes = [0u8; 512];
        let n = socket.read(&mut bytes)?;
        ensure!(
            n > 0 && header.len() + n <= 8192,
            "challenge input exceeds bound"
        );
        header.extend_from_slice(&bytes[..n]);
    }
    let value = (|| -> Result<Vec<u8>> {
        let token = token(&header)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join(".well-known/acme-challenge").join(token))?;
        ensure!(
            file.metadata()?.is_file() && file.metadata()?.len() <= 4096,
            "invalid challenge file"
        );
        let mut bytes = Vec::new();
        file.take(4097).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 4096
                && bytes
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')),
            "invalid challenge response"
        );
        Ok(bytes)
    })();
    let (status, body) = match value {
        Ok(v) => ("200 OK", v),
        Err(_) => ("404 Not Found", vec![]),
    };
    let mut output=format!("HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",body.len()).into_bytes();
    output.extend(body);
    let mut remaining = output.as_slice();
    while !remaining.is_empty() {
        socket.set_write_timeout(Some(
            end.checked_duration_since(Instant::now())
                .ok_or_else(|| anyhow::anyhow!("challenge output timed out"))?,
        ))?;
        let n = socket.write(remaining)?;
        ensure!(n > 0, "challenge output closed");
        remaining = &remaining[n..];
    }
    Ok(())
}
pub fn serve(directory: &Path, listen: SocketAddr, stop: Arc<AtomicBool>) -> Result<()> {
    ensure!(
        directory.is_absolute() && directory.canonicalize()? == directory && listen.port() > 1024,
        "invalid challenge listener"
    );
    let listener = TcpListener::bind(listen)?;
    listener.set_nonblocking(true)?;
    std::thread::scope(|scope| {
        let listeners = (0..8)
            .map(|_| listener.try_clone())
            .collect::<std::io::Result<Vec<_>>>()?;
        let mut workers = Vec::new();
        for listener in listeners {
            let stop = stop.clone();
            workers.push(scope.spawn(move || -> Result<()> {
                while !stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((socket, _)) => {
                            let _ = connection(socket, directory, &stop);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(25))
                        }
                        Err(e) => {
                            stop.store(true, Ordering::Release);
                            return Err(e.into());
                        }
                    }
                }
                Ok(())
            }));
        }
        for worker in workers {
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("challenge listener failed"))??;
        }
        Ok(())
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn challenge_cannot_read_paths_or_accept_other_methods() {
        assert_eq!(
            token(b"GET /.well-known/acme-challenge/abc_X-1 HTTP/1.1\r\nHost: example.org\r\n\r\n")
                .unwrap(),
            "abc_X-1"
        );
        for path in ["../key", "%2e%2e%2fkey", "abc?key", "abc/key", ""] {
            assert!(
                token(
                    format!("GET /.well-known/acme-challenge/{path} HTTP/1.1\r\n\r\n").as_bytes()
                )
                .is_err()
            );
        }
        assert!(token(b"POST /.well-known/acme-challenge/abc HTTP/1.1\r\n\r\n").is_err());
    }
}
