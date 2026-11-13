// SPDX-License-Identifier: MIT
// User services preserve explicit hosting choices across logout and restart without a lifetime timer.
use super::{helper, protocol, runtime, saved};
use anyhow::{Context, Result, ensure};
use std::{
    fs::{File, OpenOptions},
    io::{ErrorKind, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
fn lock_file(directory: &Path, name: &str) -> Result<File> {
    super::private::directory(directory)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join(name))?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0,
        "host lock is not private"
    );
    Ok(file)
}
fn acquire(file: &File) -> std::io::Result<()> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
pub fn lock(directory: &Path, name: &str) -> Result<File> {
    let file = lock_file(directory, name)?;
    acquire(&file).context("host operation lock unavailable")?;
    Ok(file)
}
fn remaining(cancel: &AtomicBool, end: Instant) -> Result<Duration> {
    ensure!(
        !cancel.load(Ordering::Acquire),
        "host operation lock wait cancelled"
    );
    let remaining = end.saturating_duration_since(Instant::now());
    ensure!(!remaining.is_zero(), "host operation lock wait timed out");
    Ok(remaining)
}
/// Wait for the current owner without reading protected state or extending the request deadline.
pub fn lock_until(directory: &Path, name: &str, cancel: &AtomicBool, end: Instant) -> Result<File> {
    remaining(cancel, end)?;
    let file = lock_file(directory, name)?;
    loop {
        let available = remaining(cancel, end)?;
        match acquire(&file) {
            Ok(()) => {
                remaining(cancel, end)?;
                return Ok(file);
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(available.min(Duration::from_millis(100)));
            }
            Err(error) => return Err(error).context("host operation lock unavailable"),
        }
    }
}
pub fn unit(directory: &Path) -> String {
    format!(
        "hypernet-admission-{}.service",
        protocol::digest(directory.as_os_str().as_encoded_bytes())
    )
}
fn quote(path: &Path) -> Result<String> {
    let s = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("service path is not UTF-8"))?;
    ensure!(!s.chars().any(char::is_control), "invalid service path");
    Ok(format!(
        "\"{}\"",
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    ))
}
fn utility(arguments: &[String], stop: &AtomicBool) -> Result<()> {
    let path = Path::new("/usr/bin/systemctl").canonicalize()?;
    let args = arguments.iter().map(Into::into).collect::<Vec<_>>();
    helper::output(&path, &args, &[], stop, Duration::from_secs(60))?;
    Ok(())
}
pub(crate) fn config_root() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|s| PathBuf::from(s).join(".config")))
        .ok_or_else(|| anyhow::anyhow!("user configuration directory unavailable"))?;
    let target = base.join("systemd/user");
    ensure!(
        target.is_absolute(),
        "configuration directory must be absolute"
    );
    let mut missing = vec![];
    let mut at = target.as_path();
    while !at.exists() {
        missing.push(at.to_owned());
        at = at
            .parent()
            .ok_or_else(|| anyhow::anyhow!("configuration parent unavailable"))?;
    }
    for path in missing.into_iter().rev() {
        saved::create_directory(&path)?;
    }
    for path in target.ancestors() {
        let m = std::fs::symlink_metadata(path)?;
        ensure!(
            m.is_dir()
                && !m.file_type().is_symlink()
                && m.mode() & 0o022 == 0
                && (m.uid() == 0 || m.uid() == unsafe { libc::geteuid() }),
            "service directory permits replacement"
        );
    }
    ensure!(
        std::fs::metadata(&target)?.uid() == unsafe { libc::geteuid() },
        "user service directory is not owned"
    );
    Ok(target)
}
fn content(directory: &Path, executable: &Path) -> Result<String> {
    Ok(format!(
        "[Unit]\nDescription=HyperNet server joining\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart={} join host-session --directory {}\nRestart=on-failure\nRestartSec=5\nUMask=0077\nKillMode=mixed\nTimeoutStopSec=45\n\n[Install]\nWantedBy=default.target\n",
        quote(executable)?,
        quote(directory)?
    ))
}
pub fn start(directory: &Path, executable: &Path, stop: &AtomicBool) -> Result<()> {
    runtime::executable(executable)?;
    let root = config_root()?;
    let target = root.join(unit(directory));
    let content = content(directory, executable)?;
    if target.exists() {
        let m = std::fs::symlink_metadata(&target)?;
        ensure!(
            m.is_file()
                && m.nlink() == 1
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o077 == 0,
            "host unit is not private"
        );
        let old = crate::files::read_bounded(&target, true)?;
        ensure!(
            old == content.as_bytes(),
            "installed host service changed; stop it before installation repair"
        );
    } else {
        let temp = root.join(format!(".hypernet-{}", crate::random_hex::<16>()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(temp, &target)?;
        File::open(&root)?.sync_all()?;
    }
    utility(&["--user".into(), "daemon-reload".into()], stop)?;
    utility(
        &[
            "--user".into(),
            "enable".into(),
            "--now".into(),
            unit(directory),
        ],
        stop,
    )
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Successor {
    previous: PathBuf,
    successor: PathBuf,
    exists: bool,
    previous_sha256: String,
    successor_sha256: String,
}
pub(super) fn require_stopped(directory: &Path, stop: &AtomicBool) -> Result<()> {
    let output = helper::output(
        Path::new("/usr/bin/systemctl"),
        &[
            "--user".into(),
            "show".into(),
            "--property=ActiveState".into(),
            "--property=UnitFileState".into(),
            unit(directory).into(),
        ],
        &[],
        stop,
        Duration::from_secs(10),
    )?;
    let fields: std::collections::BTreeMap<_, _> = std::str::from_utf8(&output)?
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();
    ensure!(
        matches!(fields.get("ActiveState"), Some(&"inactive" | &"failed"))
            && matches!(fields.get("UnitFileState"), Some(&"disabled" | &"")),
        "stop public joining before changing its software"
    );
    Ok(())
}
pub(super) fn review_successor(
    directory: &Path,
    previous: &Path,
    successor: &Path,
    stop: &AtomicBool,
) -> Result<Successor> {
    require_stopped(directory, stop)?;
    runtime::executable(previous)?;
    runtime::executable(successor)?;
    let target = config_root()?.join(unit(directory));
    let old = content(directory, previous)?;
    let new = content(directory, successor)?;
    let exists = target.try_exists()?;
    if exists {
        ensure!(
            crate::native_installation::files::read(&target, 16384, true)? == old.as_bytes(),
            "public joining unit differs from its retained software"
        );
    }
    Ok(Successor {
        previous: previous.into(),
        successor: successor.into(),
        exists,
        previous_sha256: protocol::digest(old.as_bytes()),
        successor_sha256: protocol::digest(new.as_bytes()),
    })
}
impl Successor {
    pub(super) fn validate(
        &self,
        directory: &Path,
        previous: &Path,
        successor: &Path,
    ) -> Result<()> {
        ensure!(
            self.previous == previous
                && self.successor == successor
                && self.previous_sha256
                    == protocol::digest(content(directory, previous)?.as_bytes())
                && self.successor_sha256
                    == protocol::digest(content(directory, successor)?.as_bytes()),
            "public joining software review differs"
        );
        Ok(())
    }
    pub(super) fn apply(&self, directory: &Path, stop: &AtomicBool) -> Result<()> {
        self.validate(directory, &self.previous, &self.successor)?;
        require_stopped(directory, stop)?;
        let root = config_root()?;
        let target = root.join(unit(directory));
        if !self.exists {
            ensure!(
                !target.try_exists()?,
                "unreviewed public joining unit appeared"
            );
            return Ok(());
        }
        let old = content(directory, &self.previous)?;
        let new = content(directory, &self.successor)?;
        let current = crate::native_installation::files::read(&target, 16384, true)?;
        ensure!(
            current == old.as_bytes() || current == new.as_bytes(),
            "public joining unit changed during update"
        );
        if current != new.as_bytes() {
            let temp = root.join(format!(".hypernet-{}", crate::random_hex::<16>()));
            let result = (|| -> Result<()> {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&temp)?;
                file.write_all(new.as_bytes())?;
                file.sync_all()?;
                std::fs::rename(&temp, &target)?;
                File::open(&root)?.sync_all()?;
                Ok(())
            })();
            if result.is_err() {
                let _ = std::fs::remove_file(&temp);
            }
            result?;
        }
        utility(&["--user".into(), "daemon-reload".into()], stop)
    }
}
pub fn stop(directory: &Path, stop: &AtomicBool) -> Result<()> {
    utility(
        &[
            "--user".into(),
            "disable".into(),
            "--now".into(),
            unit(directory),
        ],
        stop,
    )
}
pub fn linger_enabled() -> bool {
    let path = Path::new("/var/lib/systemd/linger");
    unsafe {
        let uid = libc::geteuid();
        let mut record: libc::passwd = std::mem::zeroed();
        let mut result = std::ptr::null_mut();
        let mut bytes = vec![0u8; 65536];
        if libc::getpwuid_r(
            uid,
            &mut record,
            bytes.as_mut_ptr().cast(),
            bytes.len(),
            &mut result,
        ) != 0
            || result.is_null()
            || record.pw_name.is_null()
        {
            return false;
        }
        let Ok(name) = std::ffi::CStr::from_ptr(record.pw_name).to_str() else {
            return false;
        };
        path.join(name).is_file()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt, sync::Arc};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("HostOperationLock{}", crate::random_hex::<8>()));
            saved::create_directory(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn host_status_lock_wait_preserves_owner_deadline_and_cancellation() {
        let fixture = Fixture::new();
        let mut owner = lock(&fixture.0, "Operation.lock").unwrap();
        owner.write_all(b"retained owner").unwrap();
        let identity = owner.metadata().unwrap().ino();
        let cancel = Arc::new(AtomicBool::new(false));
        let (ready, waiting) = std::sync::mpsc::channel();
        let (done, result) = std::sync::mpsc::channel();
        let root = fixture.0.clone();
        let cancelled = cancel.clone();
        let waiter = std::thread::spawn(move || {
            ready.send(()).unwrap();
            let error = lock_until(
                &root,
                "Operation.lock",
                &cancelled,
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap_err();
            done.send(error.to_string()).unwrap();
        });
        waiting.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            result.recv_timeout(Duration::from_millis(30)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        cancel.store(true, Ordering::Release);
        assert!(
            result
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .contains("cancelled")
        );
        waiter.join().unwrap();
        assert!(lock(&fixture.0, "Operation.lock").is_err());
        let error = lock_until(
            &fixture.0,
            "Operation.lock",
            &AtomicBool::new(false),
            Instant::now() + Duration::from_millis(20),
        )
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(lock(&fixture.0, "Operation.lock").is_err());
        assert_eq!(owner.metadata().unwrap().ino(), identity);
        assert_eq!(
            fs::read(fixture.0.join("Operation.lock")).unwrap(),
            b"retained owner"
        );
        drop(owner);
        let acquired = lock_until(
            &fixture.0,
            "Operation.lock",
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(acquired.metadata().unwrap().ino(), identity);
    }

    #[test]
    fn host_status_lock_wait_refuses_non_private_files_and_links() {
        let fixture = Fixture::new();
        let path = fixture.0.join("Shared.lock");
        drop(lock(&fixture.0, "Shared.lock").unwrap());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let cancel = AtomicBool::new(false);
        let end = Instant::now() + Duration::from_secs(5);
        assert!(
            lock_until(&fixture.0, "Shared.lock", &cancel, end)
                .unwrap_err()
                .to_string()
                .contains("not private")
        );
        std::os::unix::fs::symlink(&path, fixture.0.join("Linked.lock")).unwrap();
        assert!(lock_until(&fixture.0, "Linked.lock", &cancel, end).is_err());
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o640);
    }
}
