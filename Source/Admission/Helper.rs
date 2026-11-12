// SPDX-License-Identifier: MIT
// Fixed installed helpers exchange bounded JSON; public values never select executable paths.
use anyhow::{Result, ensure};
use serde_json::Value;
use std::{
    ffi::OsString,
    io::{Read, Write},
    os::{fd::AsRawFd, unix::process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
fn nonblocking(fd: libc::c_int) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    ensure!(
        flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0,
        "helper pipe unavailable"
    );
    Ok(())
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
pub fn invoke(
    executable: &Path,
    args: &[OsString],
    input: &Value,
    stop: &AtomicBool,
    timeout: Duration,
) -> Result<Value> {
    ensure!(
        timeout <= Duration::from_secs(60),
        "invalid installed admission helper deadline"
    );
    invoke_owned(executable, args, input, stop, Some(timeout), false)
}
#[cfg(feature = "gui")]
pub fn interactive(
    executable: &Path,
    args: &[OsString],
    input: &Value,
    stop: &AtomicBool,
) -> Result<Value> {
    invoke_owned(executable, args, input, stop, None, true)
}
fn invoke_owned(
    executable: &Path,
    args: &[OsString],
    input: &Value,
    stop: &AtomicBool,
    timeout: Option<Duration>,
    graphical: bool,
) -> Result<Value> {
    let input = zeroize::Zeroizing::new(serde_json::to_vec(input)?);
    Ok(serde_json::from_slice(&run_owned(
        executable, args, &input, stop, timeout, graphical,
    )?)?)
}
/// Run a fixed local setup tool with bounded pipes and its own process group.
pub fn output(
    executable: &Path,
    args: &[OsString],
    input: &[u8],
    stop: &AtomicBool,
    timeout: Duration,
) -> Result<Vec<u8>> {
    ensure!(
        timeout <= Duration::from_secs(1800),
        "invalid local setup deadline"
    );
    run_owned(executable, args, input, stop, Some(timeout), false)
}
fn run_owned(
    executable: &Path,
    args: &[OsString],
    input: &[u8],
    stop: &AtomicBool,
    timeout: Option<Duration>,
    graphical: bool,
) -> Result<Vec<u8>> {
    super::runtime::executable(executable)?;
    ensure!(input.len() <= 4 * 1024 * 1024, "helper input exceeds bound");
    let mut command = Command::new(executable);
    command
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin")
        .current_dir("/")
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in ["HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    if graphical {
        for name in [
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "XAUTHORITY",
            "XDG_SESSION_TYPE",
            "XDG_ACTIVATION_TOKEN",
            "DESKTOP_STARTUP_ID",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
    }
    let parent = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(std::io::Error::other("helper owner exited"));
            }
            Ok(())
        });
    }
    let mut child = Child(command.spawn()?, false);
    let mut stdin = child.0.stdin.take();
    let mut stdout = child
        .0
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("helper output absent"))?;
    let mut stderr = child
        .0
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("helper diagnostic absent"))?;
    nonblocking(stdin.as_ref().unwrap().as_raw_fd())?;
    nonblocking(stdout.as_raw_fd())?;
    nonblocking(stderr.as_raw_fd())?;
    let deadline = timeout.map(|timeout| Instant::now() + timeout);
    let mut written = 0;
    let mut output = Vec::new();
    let mut diagnostics = 0usize;
    let mut ended = false;
    loop {
        ensure!(
            !stop.load(Ordering::Acquire),
            "admission operation cancelled; exact state retained"
        );
        ensure!(
            deadline.is_none_or(|deadline| Instant::now() < deadline),
            "admission helper timed out; exact state retained"
        );
        if let Some(pipe) = &mut stdin {
            match pipe.write(&input[written..]) {
                Ok(n) => {
                    written += n;
                    if written == input.len() {
                        stdin = None;
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e.into()),
            }
        }
        let mut buffer = [0; 8192];
        loop {
            match stdout.read(&mut buffer) {
                Ok(0) => {
                    ended = true;
                    break;
                }
                Ok(n) => {
                    output.extend_from_slice(&buffer[..n]);
                    ensure!(
                        output.len() <= super::transport::RESPONSE_BYTES,
                        "helper output exceeds bound"
                    );
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    break;
                }
                Err(e) => return Err(e.into()),
            }
        }
        loop {
            match stderr.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    diagnostics += n;
                    ensure!(diagnostics <= 65536, "helper diagnostic exceeds bound");
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    break;
                }
                Err(e) => return Err(e.into()),
            }
        }
        // Keep the PID reserved until output closes, including inherited pipe writers.
        if ended && let Some(status) = child.0.try_wait()? {
            child.1 = true;
            ensure!(
                status.success(),
                "native admission helper unavailable; exact state retained"
            );
            return Ok(output);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Native {
    pub configuration: PathBuf,
}
impl Native {
    pub fn call(&self, body: Value, stop: &AtomicBool) -> Result<Value> {
        ensure!(
            self.configuration.is_absolute(),
            "native registrar configuration must be absolute"
        );
        let response = invoke(
            &std::env::current_exe()?,
            &[
                "authority-inspection".into(),
                "admission".into(),
                "registrar".into(),
                "--configuration".into(),
                self.configuration.as_os_str().into(),
                "--json-stdin".into(),
            ],
            &serde_json::json!({"format":"HyperNetNativeAdmission/1","body":body}),
            stop,
            Duration::from_secs(25),
        )?;
        native_response(response)
    }
}
pub fn candidate(directory: &Path, body: Value, stop: &AtomicBool) -> Result<Value> {
    ensure!(
        directory.is_absolute(),
        "candidate directory must be absolute"
    );
    native_response(invoke(
        &std::env::current_exe()?,
        &[
            "authority-inspection".into(),
            "admission".into(),
            "candidate".into(),
            "--directory".into(),
            directory.as_os_str().into(),
            "--json-stdin".into(),
        ],
        &serde_json::json!({"format":"HyperNetNativeAdmission/1","body":body}),
        stop,
        Duration::from_secs(25),
    )?)
}
fn native_response(response: Value) -> Result<Value> {
    ensure!(
        response.get("format").and_then(Value::as_str) == Some("HyperNetNativeAdmission/1"),
        "native admission helper version differs"
    );
    let body = response
        .get("body")
        .filter(|v| v.is_object())
        .ok_or_else(|| anyhow::anyhow!("native helper result absent"))?;
    Ok(body.clone())
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Hrc {
    pub executable: PathBuf,
    pub configuration: PathBuf,
}
impl Hrc {
    pub fn call(&self, action: Value, stop: &AtomicBool) -> Result<Value> {
        ensure!(
            self.configuration.is_absolute(),
            "HRC registrar configuration must be absolute"
        );
        let response = invoke(
            &self.executable,
            &[
                "service".into(),
                "admission-request".into(),
                "--config".into(),
                self.configuration.as_os_str().into(),
            ],
            &serde_json::json!({"format":"HyperNet.HrcAdmission/1","action":action}),
            stop,
            Duration::from_secs(10),
        )?;
        ensure!(
            response.get("format").and_then(Value::as_str) == Some("HyperNet.HrcAdmission/1"),
            "HRC admission helper version differs"
        );
        Ok(response)
    }
}
