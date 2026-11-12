// SPDX-License-Identifier: MIT
// User services preserve explicit hosting choices across logout and restart without a lifetime timer.
use super::{helper, protocol, runtime, saved};
use anyhow::{Result, ensure};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::Duration,
};
pub fn lock(directory: &Path, name: &str) -> Result<File> {
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
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "host operation already running"
    );
    Ok(file)
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
fn config_root() -> Result<PathBuf> {
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
pub fn start(directory: &Path, executable: &Path, stop: &AtomicBool) -> Result<()> {
    runtime::executable(executable)?;
    let root = config_root()?;
    let target = root.join(unit(directory));
    let content = format!(
        "[Unit]\nDescription=HyperNet server joining\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart={} join host-session --directory {}\nRestart=on-failure\nRestartSec=5\nUMask=0077\nKillMode=mixed\nTimeoutStopSec=45\n\n[Install]\nWantedBy=default.target\n",
        quote(executable)?,
        quote(directory)?
    );
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
