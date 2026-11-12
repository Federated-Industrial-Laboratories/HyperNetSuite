// SPDX-License-Identifier: MIT
// Private installation state is bounded, locked and atomically replaced.
use anyhow::{Context, Result, ensure};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
};

pub fn directory(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
        "installation directory must be absolute and normalised"
    );
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        if !current.try_exists()? {
            std::fs::DirBuilder::new().mode(0o700).create(&current)?;
        }
        let m = current.symlink_metadata()?;
        ensure!(
            m.is_dir() && !m.file_type().is_symlink(),
            "installation path contains a link or non-directory"
        );
        ensure!(
            m.uid() == 0 || m.uid() == unsafe { libc::geteuid() },
            "installation parent belongs to another user"
        );
        ensure!(
            m.mode() & 0o022 == 0 || (m.uid() == 0 && m.mode() & 0o1000 != 0),
            "installation parent is writable by others"
        );
    }
    let m = path.symlink_metadata()?;
    ensure!(
        m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o777 == 0o700,
        "installation directory must be private and owned by this user"
    );
    Ok(())
}
pub fn read(path: &Path, maximum: u64, private: bool) -> Result<Vec<u8>> {
    let file = open(path, maximum, private)?;
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= maximum,
        "installation input grew beyond its bound"
    );
    Ok(bytes)
}
fn open(path: &Path, maximum: u64, private: bool) -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.len() <= maximum,
        "installation input must be a bounded nonlinked regular file"
    );
    ensure!(
        !private || (m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0),
        "installation state is not private"
    );
    Ok(f)
}
pub fn digest(path: &Path, maximum: u64) -> Result<String> {
    let mut file = open(path, maximum, false)?;
    let mut hash = Sha256::new();
    let mut bytes = [0u8; 65536];
    let mut size = 0;
    loop {
        crate::private_route_client::check_cancelled()?;
        let n = file.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        ensure!(size <= maximum, "installation input grew beyond its bound");
        hash.update(&bytes[..n]);
    }
    Ok(hex::encode(hash.finalize()))
}
pub fn exact(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.try_exists()? {
        ensure!(
            read(path, bytes.len() as u64, true)? == bytes,
            "retained installation evidence differs"
        );
        return Ok(());
    }
    let temporary = path.with_file_name(format!(".Evidence-{}", random()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let from = CString::new(temporary.as_os_str().as_bytes())?;
        let to = CString::new(path.as_os_str().as_bytes())?;
        let renamed = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if renamed != 0 {
            let error = std::io::Error::last_os_error();
            ensure!(
                error.kind() == std::io::ErrorKind::AlreadyExists
                    && read(path, bytes.len() as u64, true)? == bytes,
                "retained installation evidence differs or cannot be published"
            );
        }
        File::open(path.parent().context("installation parent missing")?)?.sync_all()?;
        Ok(())
    })();
    let _ = std::fs::remove_file(temporary);
    result
}
pub fn copy(source: &Path, destination: &Path, maximum: u64) -> Result<()> {
    let mut source = open(source, maximum, false)?;
    let mut target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(destination)?;
    let mut bytes = [0u8; 65536];
    let mut size = 0;
    loop {
        crate::private_route_client::check_cancelled()?;
        let n = source.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        ensure!(size <= maximum, "package input grew beyond its bound");
        target.write_all(&bytes[..n])?;
    }
    target.sync_all()?;
    Ok(())
}
pub fn publish(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_file_name(format!(".Installation-{}", random()));
    exact(&temporary, bytes)?;
    let result = (|| {
        std::fs::rename(&temporary, path)?;
        File::open(path.parent().context("installation parent missing")?)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}
pub fn random() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
pub struct Lock(File);
impl Lock {
    pub fn acquire(root: &Path) -> Result<Self> {
        directory(root)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(root.join("Installation.lock"))?;
        let m = file.metadata()?;
        ensure!(
            m.is_file()
                && m.nlink() == 1
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o077 == 0,
            "installation lock is not private"
        );
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "another installation operation is active"
        );
        Ok(Self(file))
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
