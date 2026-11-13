// SPDX-License-Identifier: MIT
// Saved clients own local observers and companions; stopping them preserves identity and authority floors.
use super::{helper, local, protocol, saved};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
#[path = "RuntimeObserverExecutable.rs"]
mod observer_executable;
#[path = "RuntimeProcess.rs"]
mod process;
pub(super) use process::Process;
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub version: u8,
    pub chronyc: PathBuf,
    pub chronyd: Option<PathBuf>,
    pub chrony_socket: Option<PathBuf>,
    pub core: Option<PathBuf>,
    pub time_server: String,
}
impl Default for Configuration {
    fn default() -> Self {
        Self {
            version: 1,
            chronyc: "/usr/bin/chronyc".into(),
            chronyd: Some("/usr/sbin/chronyd".into()),
            chrony_socket: None,
            core: None,
            time_server: "time.cloudflare.com".into(),
        }
    }
}
pub fn executable(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "runtime executable must be canonical"
    );
    let m = std::fs::symlink_metadata(path)?;
    ensure!(
        m.is_file()
            && m.mode() & 0o111 != 0
            && m.mode() & 0o022 == 0
            && (m.uid() == 0 || m.uid() == unsafe { libc::geteuid() }),
        "runtime executable permits replacement"
    );
    for parent in path.parent().unwrap().ancestors() {
        let m = std::fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir()
                && m.mode() & 0o022 == 0
                && (m.uid() == 0 || m.uid() == unsafe { libc::geteuid() }),
            "runtime executable ancestor permits replacement"
        );
    }
    Ok(())
}
fn current_user() -> Result<String> {
    let uid = unsafe { libc::geteuid() };
    let mut record: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let mut bytes = vec![0u8; 65536];
    ensure!(
        unsafe {
            libc::getpwuid_r(
                uid,
                &mut record,
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                &mut result,
            )
        } == 0
            && !result.is_null()
            && !record.pw_name.is_null(),
        "local user name unavailable"
    );
    let name = unsafe { std::ffi::CStr::from_ptr(record.pw_name) }
        .to_str()?
        .to_owned();
    ensure!(
        !name.is_empty() && name.len() <= 256 && !name.chars().any(char::is_control),
        "invalid local user name"
    );
    Ok(name)
}
fn args(parts: &[&str]) -> Vec<OsString> {
    parts.iter().map(OsString::from).collect()
}
fn text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow::anyhow!("runtime path is not UTF-8"))
}
fn run_json(program: &Path, args: &[OsString], stop: &AtomicBool) -> Result<Value> {
    helper::invoke(program, args, &Value::Null, stop, Duration::from_secs(20))
}
pub struct Runtime {
    directory: PathBuf,
    clock: Process,
    chrony: Option<Process>,
    companion: Option<Process>,
    _lock: File,
    pub hrc_clock: Option<Value>,
    pub ipc: PathBuf,
}
impl Runtime {
    pub fn start(directory: &Path, config: &Configuration, stop: &AtomicBool) -> Result<Self> {
        saved::create_directory(directory)?;
        ensure!(
            config.version == 1,
            "unsupported client runtime configuration"
        );
        executable(&config.chronyc)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join("Runtime.lock"))?;
        let m = lock.metadata()?;
        ensure!(
            m.is_file()
                && m.nlink() == 1
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o077 == 0,
            "runtime lock is not private"
        );
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "this saved server already has a runtime"
        );
        saved::replace(
            &directory.join("RuntimeReady.json"),
            &json!({"ready":false}),
        )?;
        let native = directory.join("Native");
        saved::create_directory(&native)?;
        let clock_directory = native.join("Clock");
        saved::create_directory(&clock_directory)?;
        let runtime_root = PathBuf::from(format!("/run/user/{}", unsafe { libc::geteuid() }));
        let parent = std::fs::symlink_metadata(&runtime_root)?;
        ensure!(
            parent.is_dir()
                && parent.uid() == unsafe { libc::geteuid() }
                && parent.mode() & 0o022 == 0
                && runtime_root.canonicalize()? == runtime_root,
            "private user runtime directory unavailable"
        );
        let sockets = runtime_root.join(format!(
            "hypernet-{}",
            &protocol::digest(directory.as_os_str().as_encoded_bytes())[..20]
        ));
        saved::create_directory(&sockets)?;
        let c = sockets.join("C");
        saved::create_directory(&c)?;
        let (socket, chrony) = if let Some(socket) = &config.chrony_socket {
            ensure!(
                config.chronyd.is_none(),
                "choose an existing clock socket or a private observer"
            );
            (socket.clone(), None)
        } else {
            let executable = config.chronyd.as_ref().ok_or_else(|| {
                anyhow::anyhow!("install chrony to prepare the local authenticated observer")
            })?;
            ensure!(
                !config.time_server.is_empty()
                    && config.time_server.len() <= 253
                    && config
                        .time_server
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-')),
                "invalid authenticated time server name"
            );
            let socket = c.join("Chrony.sock");
            let conf = sockets.join("Chrony.conf");
            let content = format!(
                "server {} iburst nts minpoll 4 maxpoll 4\nport 0\ncmdport 0\nbindcmdaddress {}\npidfile {}/Chrony.pid\ndriftfile {}/Drift\nntsdumpdir {}\nmaxclockerror 1000\n",
                config.time_server,
                text(&socket)?,
                text(&sockets)?,
                text(&sockets)?,
                text(&sockets)?
            );
            // The generated runtime path is ASCII and contains no whitespace or remote path input.
            if conf.exists() {
                let retained = crate::files::read_bounded(&conf, true)?;
                ensure!(
                    std::str::from_utf8(&retained)?.trim_end() == content.trim_end(),
                    "private observer configuration changed; stop and review it"
                );
            } else {
                crate::files::write_new(&conf, content.as_bytes())?;
            }
            let executable = observer_executable::prepare(&native, executable, stop)?;
            ensure!(
                !stop.load(Ordering::Acquire),
                "private time observer startup cancelled"
            );
            let process = Process::spawn(
                &executable,
                &args(&["-U", "-x", "-d", "-u", &current_user()?, "-f", text(&conf)?]),
            )?;
            (socket, Some(process))
        };
        let suite = std::env::current_exe()?.canonicalize()?;
        let (clock, hrc_clock) = if let Some(core) = &config.core {
            executable(core)?;
            let configuration = json!({"chronyc":config.chronyc,"socket":socket,"exportDirectory":clock_directory.join("Public")});
            let file = clock_directory.join("ClockConfig.json");
            if file.exists() {
                ensure!(
                    saved::read::<Value>(&file)? == configuration,
                    "saved clock configuration differs"
                );
            } else {
                crate::files::write_new(&file, &serde_json::to_vec(&configuration)?)?;
            }
            if !clock_directory.join("ClockSigner.json").exists() {
                run_json(
                    core,
                    &args(&[
                        "authority-clock",
                        "initialise-export",
                        "--directory",
                        text(&clock_directory)?,
                    ]),
                    stop,
                )?;
            }
            #[derive(Deserialize)]
            struct PublicClock {
                #[serde(rename = "publicKey")]
                public_key: String,
            }
            let identity: PublicClock = saved::read(&clock_directory.join("ClockSigner.json"))?;
            let key = identity.public_key.as_str();
            ensure!(
                protocol::identifier(key),
                "invalid clock monitor public key"
            );
            let hrc_clock = json!({"observation":clock_directory.join("Public/ClockHealth.cbor"),"monitorKey":key});
            (
                Process::spawn(
                    core,
                    &args(&[
                        "authority-clock",
                        "monitor",
                        "--directory",
                        text(&clock_directory)?,
                    ]),
                )?,
                Some(hrc_clock),
            )
        } else {
            (
                Process::spawn(
                    &suite,
                    &args(&[
                        "network",
                        "clock",
                        "monitor",
                        "--directory",
                        text(&clock_directory)?,
                        "--chronyc",
                        text(&config.chronyc)?,
                        "--socket",
                        text(&socket)?,
                    ]),
                )?,
                None,
            )
        };
        let runtime = Self {
            directory: directory.into(),
            clock,
            chrony,
            companion: None,
            _lock: lock,
            hrc_clock,
            ipc: sockets.join("Companion"),
        };
        Ok(runtime)
    }
    pub fn clock_ready(&mut self) -> Result<bool> {
        ensure!(self.clock.running()?, "local clock monitor stopped");
        if let Some(chrony) = &mut self.chrony {
            ensure!(
                chrony.running()?,
                "local authenticated time observer stopped"
            );
        }
        Ok(
            crate::authority_clock::health(&self.directory.join("Native/Clock/ClockHealth.json"))
                .and_then(|c| c.observe())
                .is_ok(),
        )
    }
    pub fn start_chat(&mut self, state: &saved::State) -> Result<()> {
        ensure!(state.desired_online, "saved server is offline");
        if self
            .companion
            .as_mut()
            .is_some_and(|p| p.running().unwrap_or(false))
        {
            return Ok(());
        }
        let profiles = state
            .installed
            .as_ref()
            .and_then(|v| v.get("profiles"))
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("joined native profiles unavailable"))?;
        let Some(chat) = profiles
            .iter()
            .find(|p| p.get("role").and_then(Value::as_u64) == Some(1))
        else {
            return Ok(());
        };
        let options: super::client::HrcOptions =
            saved::read(&self.directory.join("HrcOptions.json"))?;
        ensure!(
            self.hrc_clock.as_ref() == Some(&options.clock),
            "chat requires its retained signed clock observer"
        );
        let descriptor = state
            .metadata
            .permissions
            .hrc
            .as_ref()
            .and_then(|v| v.get("descriptor"))
            .ok_or_else(|| anyhow::anyhow!("HRC descriptor unavailable"))?;
        let service = descriptor
            .pointer("/home/service")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("HRC service identity absent"))?;
        let target = json!([{"service":service,"protocol":descriptor.get("protocol"),"grant":chat.get("connectGrant"),"route":chat.get("destinationRoute"),"renewalMs":60000}]);
        let targets = self.directory.join("Targets.json");
        saved::replace(&targets, &target)?;
        saved::create_directory(&self.ipc)?;
        let profile = chat
            .get("profile")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("chat profile absent"))?;
        ensure!(
            Path::new(profile).starts_with(self.directory.join("Native/Roles/1")),
            "chat profile leaves saved server directory"
        );
        self.companion = Some(Process::spawn(
            &std::env::current_exe()?.canonicalize()?,
            &args(&[
                "network",
                "connect",
                "--profile",
                profile,
                "--",
                "streams",
                "agent",
                "--ipc-directory",
                text(&self.ipc)?,
                "--targets",
                text(&targets)?,
            ]),
        )?);
        Ok(())
    }
    pub fn companion_running(&mut self) -> Result<bool> {
        self.companion
            .as_mut()
            .map(Process::running)
            .transpose()
            .map(|v| v.unwrap_or(false))
    }
    pub fn stop_chat(&mut self) {
        self.companion = None;
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        self.companion = None;
    }
}
pub fn supervise(
    directory: &Path,
    configuration: &Configuration,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let mut runtime = Runtime::start(directory, configuration, &stop)?;
    let mut attempt = 0u32;
    let mut renewed = false;
    while !stop.load(Ordering::Acquire) {
        let state: saved::State = saved::read(&directory.join("Server.json"))?;
        if !state.desired_online {
            runtime.stop_chat();
            return Ok(());
        }
        let chat = state.roles.iter().any(|r| r.role == 1);
        if chat && !runtime.companion_running()? {
            renewed = false;
        }
        if runtime.clock_ready()? && !renewed {
            let command = if chat {
                super::client::Command::RenewChat
            } else {
                super::client::Command::RenewReader
            };
            let renewal = super::client::run(directory, &command, &stop);
            if let Ok(result) = renewal
                && result.get("status").and_then(Value::as_str) == Some("Joined")
            {
                let state: saved::State = saved::read(&directory.join("Server.json"))?;
                runtime.start_chat(&state)?;
                attempt = 0;
                renewed = true;
                saved::replace(&directory.join("RuntimeReady.json"), &json!({"ready":true}))?;
            } else {
                attempt = attempt.saturating_add(1);
            }
        }
        let until = Instant::now() + Duration::from_secs((1u64 << attempt.min(5)).min(30));
        while Instant::now() < until && !stop.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    Ok(())
}

fn utility(executable: &Path, arguments: &[std::ffi::OsString], stop: &AtomicBool) -> Result<()> {
    self::executable(executable)?;
    let mut child = Command::new(executable)
        .args(arguments)
        .env_clear()
        .env(
            "XDG_RUNTIME_DIR",
            format!("/run/user/{}", unsafe { libc::geteuid() }),
        )
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let until = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait()? {
            ensure!(status.success(), "local background service could not start");
            return Ok(());
        }
        if stop.load(Ordering::Acquire) || Instant::now() >= until {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("local service startup cancelled or timed out");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}
pub fn ensure_running(directory: &Path, config: &Path, stop: &AtomicBool) -> Result<()> {
    let _ = local::configuration(directory, config)?;
    let state: saved::State = saved::read(&directory.join("Server.json"))?;
    ensure!(
        state.desired_online,
        "this saved server is offline; reconnect explicitly"
    );
    if !local::owned(directory)? {
        let exe = std::env::current_exe()?.canonicalize()?;
        executable(&exe)?;
        utility(
            Path::new("/usr/bin/systemd-run"),
            &[
                "--user".into(),
                "--collect".into(),
                "--quiet".into(),
                "--property=Restart=no".into(),
                "--property=UMask=0077".into(),
                "--property=NoNewPrivileges=yes".into(),
                format!(
                    "--unit=hypernet-server-{}",
                    protocol::digest(directory.as_os_str().as_encoded_bytes())
                )
                .into(),
                "--".into(),
                exe.into_os_string(),
                "join".into(),
                "session".into(),
                "--directory".into(),
                directory.as_os_str().into(),
                "--config".into(),
                config.as_os_str().into(),
            ],
            stop,
        )?;
    }
    let until = Instant::now() + Duration::from_secs(90);
    while !stop.load(Ordering::Acquire) && Instant::now() < until {
        let state: saved::State = saved::read(&directory.join("Server.json"))?;
        ensure!(state.desired_online, "saved server was disconnected");
        if local::ready(directory, &state) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!("saved connection is not ready; progress and keys are retained")
}
