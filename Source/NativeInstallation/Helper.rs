// SPDX-License-Identifier: MIT
// Execute only the embedded upstream verifier with bounded pipes and cancellation.
use super::{Product, files};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    ffi::OsString,
    io::Read,
    os::{fd::AsRawFd, unix::process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
pub struct Helper {
    directory: PathBuf,
}
impl Drop for Helper {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
struct Child(std::process::Child, bool);
impl Drop for Child {
    fn drop(&mut self) {
        if !self.1 {
            unsafe {
                libc::kill(-(self.0.id() as libc::pid_t), libc::SIGKILL);
            }
            let _ = self.0.wait();
        }
    }
}
fn nonblocking(fd: libc::c_int) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    ensure!(
        flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0,
        "package verifier pipe unavailable"
    );
    Ok(())
}
fn drain(pipe: &mut impl Read, output: &mut Vec<u8>, maximum: usize) -> Result<()> {
    let mut bytes = [0u8; 8192];
    loop {
        match pipe.read(&mut bytes) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                ensure!(
                    output.len() + n <= maximum,
                    "package verifier output exceeds its bound"
                );
                output.extend_from_slice(&bytes[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
            Err(e) => return Err(e.into()),
        }
    }
}
impl Helper {
    pub fn new(root: &Path, product: Product) -> Result<Self> {
        let directory = root.join(format!(".Verifier-{}", files::random()));
        files::directory(&directory)?;
        let result = Self { directory };
        let (bundle, trust) = product.helpers();
        files::exact(&result.directory.join("Bundle.py"), bundle)?;
        files::exact(&result.directory.join("PackageTrust.py"), trust)?;
        Ok(result)
    }
    pub fn run(&self, arguments: &[OsString]) -> Result<Value> {
        crate::private_route_client::check_cancelled()?;
        let mut command = Command::new("/usr/bin/python3");
        command.args(["-I", "-S", "-c", "import sys,runpy; sys.path.insert(0,sys.argv.pop(1)); sys.argv=sys.argv[1:]; runpy.run_path(sys.argv[0],run_name='__main__')"])
            .arg(&self.directory).arg(self.directory.join("Bundle.py")).args(arguments)
            .env_clear().env("PATH", "/usr/bin:/bin").env("LC_ALL", "C")
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).process_group(0);
        for name in ["HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let parent = unsafe { libc::getpid() };
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                    || libc::getppid() != parent
                {
                    return Err(std::io::Error::other("package verifier owner exited"));
                }
                Ok(())
            });
        }
        let mut child = Child(
            command
                .spawn()
                .context("install the distribution Python 3 package")?,
            false,
        );
        let mut stdout = child
            .0
            .stdout
            .take()
            .context("package verifier output missing")?;
        let mut stderr = child
            .0
            .stderr
            .take()
            .context("package verifier diagnostic missing")?;
        nonblocking(stdout.as_raw_fd())?;
        nonblocking(stderr.as_raw_fd())?;
        let end = Instant::now() + Duration::from_secs(180);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        loop {
            crate::private_route_client::check_cancelled()?;
            ensure!(
                Instant::now() < end,
                "package verification timed out; retain state and retry"
            );
            drain(&mut stdout, &mut out, 524288)?;
            drain(&mut stderr, &mut err, 32768)?;
            if let Some(status) = child.0.try_wait()? {
                child.1 = true;
                drain(&mut stdout, &mut out, 524288)?;
                drain(&mut stderr, &mut err, 32768)?;
                ensure!(
                    status.success(),
                    "signed package refused: {}",
                    String::from_utf8_lossy(&err).trim()
                );
                return serde_json::from_slice(&out)
                    .context("package verifier returned invalid JSON");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
