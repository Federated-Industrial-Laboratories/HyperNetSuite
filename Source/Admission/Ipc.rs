// SPDX-License-Identifier: MIT
// Local admission calls keep one absolute deadline, including a full socket backlog.
use anyhow::{Result, ensure};
use std::{
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    path::Path,
    time::{Duration, Instant},
};
pub struct Channel {
    socket: UnixStream,
    until: Instant,
}
impl Channel {
    pub fn connect(path: &Path, uid: u32, duration: Duration) -> Result<Self> {
        let until = Instant::now() + duration;
        let name = path.as_os_str().as_bytes();
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        ensure!(
            path.is_absolute() && !name.contains(&0) && name.len() < address.sun_path.len(),
            "invalid local socket path"
        );
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (target, value) in address.sun_path.iter_mut().zip(name) {
            *target = *value as libc::c_char;
        }
        let raw = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        ensure!(raw >= 0, "local socket unavailable");
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let length =
            (std::mem::offset_of!(libc::sockaddr_un, sun_path) + name.len() + 1) as libc::socklen_t;
        loop {
            let rc = unsafe {
                libc::connect(
                    fd.as_raw_fd(),
                    (&address as *const libc::sockaddr_un).cast(),
                    length,
                )
            };
            if rc == 0 {
                break;
            }
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EINTR) => {
                    ensure!(Instant::now() < until, "local connection deadline elapsed");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Some(libc::EISCONN) => break,
                _ => return Err(e.into()),
            }
        }
        let socket = UnixStream::from(fd);
        Self::accepted_until(socket, uid, until)
    }
    #[cfg(any(feature = "gui", test))]
    pub fn accepted(socket: UnixStream, uid: u32, duration: Duration) -> Result<Self> {
        Self::accepted_until(socket, uid, Instant::now() + duration)
    }
    fn accepted_until(socket: UnixStream, uid: u32, until: Instant) -> Result<Self> {
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of_val(&credentials) as libc::socklen_t;
        ensure!(
            unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut credentials as *mut libc::ucred).cast(),
                    &mut size,
                )
            } == 0
                && size as usize == std::mem::size_of_val(&credentials)
                && credentials.uid == uid,
            "local socket owner differs"
        );
        socket.set_nonblocking(false)?;
        Ok(Self { socket, until })
    }
    pub fn exchange(&mut self, bytes: &[u8], maximum: usize) -> Result<Vec<u8>> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= u32::MAX as usize,
            "invalid local request size"
        );
        self.write_all(&(bytes.len() as u32).to_be_bytes())?;
        self.write_all(bytes)?;
        let mut size = [0; 4];
        self.read_exact(&mut size)?;
        let size = u32::from_be_bytes(size) as usize;
        ensure!(size > 0 && size <= maximum, "local response exceeds bound");
        let mut bytes = vec![0; size];
        self.read_exact(&mut bytes)?;
        Ok(bytes)
    }
    fn remaining(&self) -> std::io::Result<Duration> {
        let d = self.until.saturating_duration_since(Instant::now());
        if d.is_zero() {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "local deadline elapsed",
            ))
        } else {
            Ok(d)
        }
    }
}
impl Read for Channel {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        self.socket.set_read_timeout(Some(self.remaining()?))?;
        self.socket.read(out)
    }
}
impl Write for Channel {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.socket.write(input)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    #[test]
    fn dribbled_response_cannot_extend_absolute_deadline() {
        let root = std::env::temp_dir().join(format!("admission-ipc-{}", crate::random_hex::<8>()));
        super::super::saved::create_directory(&root).unwrap();
        let listener = UnixListener::bind(root.join("Bridge.sock")).unwrap();
        let thread = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0u8; 5];
            socket.read_exact(&mut request).unwrap();
            socket.write_all(&4u32.to_be_bytes()).unwrap();
            for byte in b"slow" {
                std::thread::sleep(Duration::from_millis(50));
                if socket.write_all(&[*byte]).is_err() {
                    break;
                }
            }
        });
        let mut channel = Channel::connect(
            &root.join("Bridge.sock"),
            unsafe { libc::geteuid() },
            Duration::from_millis(90),
        )
        .unwrap();
        assert!(channel.exchange(b"x", 8).is_err());
        drop(channel);
        thread.join().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn peer_uid_is_checked_before_request_bytes() {
        let (socket, _peer) = UnixStream::pair().unwrap();
        assert!(
            Channel::accepted(
                socket,
                unsafe { libc::geteuid() }.wrapping_add(1),
                Duration::from_secs(1)
            )
            .is_err()
        );
    }
}
