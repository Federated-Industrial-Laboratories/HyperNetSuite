// SPDX-License-Identifier: MIT
// Private Unix IPC binds one owner and inode before exchanging bounded control frames or raw bytes.
use crate::transfer_files as files;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::{
    fs::{self, File},
    io::{Read, Write},
    net::Shutdown,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
pub const MAXIMUM: usize = 16384;
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub version: u64,
    pub action: String,
    pub service: Option<String>,
    pub protocol: Option<String>,
    pub id: Option<String>,
    pub timeout_ms: Option<u64>,
}
pub fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>> {
    let mut size = [0; 4];
    stream.read_exact(&mut size)?;
    let n = u32::from_be_bytes(size) as usize;
    ensure!(n > 0 && n <= MAXIMUM, "local IPC frame exceeds bound");
    let mut bytes = vec![0; n];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}
pub fn write_frame(stream: &mut impl Write, bytes: &[u8]) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAXIMUM,
        "local IPC frame exceeds bound"
    );
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()?;
    Ok(())
}
pub fn write_json(stream: &mut impl Write, value: &serde_json::Value) -> Result<()> {
    write_frame(stream, &serde_json::to_vec(value)?)
}
pub fn private(path: &Path, create: bool) -> Result<File> {
    ensure!(path.is_absolute(), "agent directory must be absolute");
    if create {
        match fs::create_dir(path) {
            Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o7777 == 0o700,
        "agent directory must be owned and mode0700"
    );
    ensure!(
        path.canonicalize()? == path,
        "agent directory must be canonical without symlinks"
    );
    files::private_directory(path)
}
fn metadata(path: &Path) -> Result<(u64, u64)> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.mode() & libc::S_IFMT == libc::S_IFSOCK
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o7777 == 0o600,
        "agent socket must be owned and mode0600"
    );
    Ok((m.dev(), m.ino()))
}
pub fn peer(stream: &UnixStream) -> Result<()> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut size,
        )
    };
    ensure!(
        r == 0
            && size as usize == std::mem::size_of::<libc::ucred>()
            && credentials.uid == unsafe { libc::geteuid() },
        "local IPC peer has another owner"
    );
    Ok(())
}
pub fn connect(directory: &Path) -> Result<UnixStream> {
    let held = private(directory, false)?;
    let before = held.metadata()?;
    let path = directory.join("Control.sock");
    let socket = metadata(&path)?;
    let stream = UnixStream::connect(&path)?;
    peer(&stream)?;
    let after = fs::symlink_metadata(directory)?;
    ensure!(
        socket == metadata(&path)? && before.dev() == after.dev() && before.ino() == after.ino(),
        "local IPC socket or directory changed during connection"
    );
    stream.set_read_timeout(Some(Duration::from_secs(65)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    Ok(stream)
}
pub struct Listener {
    pub socket: UnixListener,
    path: PathBuf,
    identity: (u64, u64),
}
impl Listener {
    pub fn bind(directory: &Path) -> Result<Self> {
        private(directory, false)?;
        let path = directory.join("Control.sock");
        if fs::symlink_metadata(&path).is_ok() {
            metadata(&path)?;
            let before = metadata(&path)?;
            match UnixStream::connect(&path) {
                Ok(_) => anyhow::bail!("another agent socket is active"),
                Err(e) => ensure!(
                    matches!(
                        e.raw_os_error(),
                        Some(libc::ECONNREFUSED) | Some(libc::ENOENT)
                    ),
                    "cannot establish that the prior socket is stale"
                ),
            };
            ensure!(metadata(&path)? == before, "stale agent socket changed");
            fs::remove_file(&path)?;
        }
        let socket = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let identity = metadata(&path)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket,
            path,
            identity,
        })
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        if metadata(&self.path).ok() == Some(self.identity) {
            let _ = fs::remove_file(&self.path);
        }
    }
}
pub fn call(
    directory: &Path,
    request: serde_json::Value,
) -> Result<(serde_json::Value, UnixStream)> {
    let mut stream = connect(directory)?;
    write_json(&mut stream, &request)?;
    let response: serde_json::Value = serde_json::from_slice(&read_frame(&mut stream)?)?;
    ensure!(
        response["version"] == 1 && response["ok"] == true,
        "application agent refused: {}",
        response["error"]
    );
    Ok((response, stream))
}
pub fn stdio(directory: &Path, request: serde_json::Value) -> Result<()> {
    let (response, mut stream) = call(directory, request)?;
    eprintln!("{}", serde_json::to_string(&response)?);
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    let mut input = stream.try_clone()?;
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut std::io::stdin(), &mut input);
        let _ = input.shutdown(Shutdown::Write);
    });
    let result = std::io::copy(&mut stream, &mut std::io::stdout());
    let _ = stream.shutdown(Shutdown::Both);
    result?;
    Ok(())
}
pub fn disconnected(stream: &UnixStream) -> Result<bool> {
    let mut byte = [0u8; 1];
    let count = unsafe {
        libc::recv(
            stream.as_raw_fd(),
            byte.as_mut_ptr().cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if count >= 0 {
        return Ok(count == 0);
    }
    let error = std::io::Error::last_os_error();
    if matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
    ) {
        Ok(false)
    } else {
        Err(error.into())
    }
}
pub fn failure(stream: &mut UnixStream, code: &str, error: &str) {
    let _ = write_json(
        stream,
        &json!({"version":1,"ok":false,"error":{"code":code,"message":error}}),
    );
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveInfo {
    pub id: String,
    pub direction: String,
    pub service: String,
    pub peer: serde_json::Value,
}
fn direction(
    mut source: UnixStream,
    mut destination: UnixStream,
    remaining: Arc<AtomicU64>,
    last: Arc<AtomicU64>,
    until: Instant,
    idle: Duration,
    cancel: Arc<AtomicBool>,
) -> Result<()> {
    source.set_read_timeout(Some(Duration::from_millis(100)))?;
    destination.set_write_timeout(Some(Duration::from_millis(100)))?;
    let mut buffer = [0u8; 8192];
    loop {
        let now = crate::authority_challenge::boot_time_ms()?;
        ensure!(
            !cancel.load(Ordering::Relaxed)
                && !crate::private_route_client::cancelled()
                && Instant::now() < until
                && now.saturating_sub(last.load(Ordering::Relaxed)) < idle.as_millis() as u64,
            "local stream cancelled, expired or idle"
        );
        let count = match source.read(&mut buffer) {
            Ok(0) => {
                destination.shutdown(Shutdown::Write)?;
                return Ok(());
            }
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                n.checked_sub(count as u64)
            })
            .map_err(|_| anyhow::anyhow!("local stream byte budget exhausted"))?;
        let mut offset = 0;
        while offset < count {
            ensure!(
                !cancel.load(Ordering::Relaxed)
                    && Instant::now() < until
                    && crate::authority_challenge::boot_time_ms()?
                        .saturating_sub(last.load(Ordering::Relaxed))
                        < idle.as_millis() as u64,
                "local stream cancelled or blocked"
            );
            match destination.write(&buffer[offset..count]) {
                Ok(0) => anyhow::bail!("local stream write closed"),
                Ok(n) => {
                    offset += n;
                    last.store(
                        crate::authority_challenge::boot_time_ms()?,
                        Ordering::Relaxed,
                    );
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
}
pub fn pump(
    left: UnixStream,
    right: UnixStream,
    bytes: u64,
    duration: Duration,
    idle: Duration,
    cancel: Arc<AtomicBool>,
) -> Result<()> {
    ensure!(
        bytes > 0 && bytes <= 1073741824 && !duration.is_zero() && !idle.is_zero(),
        "local stream limits are invalid"
    );
    let until = Instant::now() + duration;
    let remaining = Arc::new(AtomicU64::new(bytes));
    let last = Arc::new(AtomicU64::new(crate::authority_challenge::boot_time_ms()?));
    let a = left.try_clone()?;
    let b = right.try_clone()?;
    let other_cancel = cancel.clone();
    let other_remaining = remaining.clone();
    let other_last = last.clone();
    let worker = std::thread::spawn(move || {
        let result = direction(
            a,
            b,
            other_remaining,
            other_last,
            until,
            idle,
            other_cancel.clone(),
        );
        if result.is_err() {
            other_cancel.store(true, Ordering::Relaxed);
        }
        result
    });
    let result = direction(right, left, remaining, last, until, idle, cancel.clone());
    if result.is_err() {
        cancel.store(true, Ordering::Relaxed);
    }
    let other = worker
        .join()
        .map_err(|_| anyhow::anyhow!("local stream worker failed"))?;
    result.and(other)
}

#[cfg(test)]
#[path = "../../Tests/Unit/Networks/LocalStreamIpcUnitTests.rs"]
mod tests;
