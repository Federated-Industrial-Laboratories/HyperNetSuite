// SPDX-License-Identifier: MIT
// A locked saved runtime executes only a verified private copy of its configured time observer.
use super::{executable, saved};
use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, File, Metadata, OpenOptions, Permissions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

const MAXIMUM_BYTES: u64 = 64 * 1024 * 1024;

fn active(stop: &AtomicBool) -> Result<()> {
    ensure!(
        !stop.load(Ordering::Acquire),
        "private time observer preparation cancelled"
    );
    Ok(())
}

fn same(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.mode() == b.mode()
        && a.nlink() == b.nlink()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

fn private_metadata(metadata: &Metadata, staging: bool) -> Result<()> {
    let mode = metadata.mode() & 0o7777;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == unsafe { libc::geteuid() }
            && (mode == 0o700 || staging && mode == 0o600)
            && metadata.len() <= MAXIMUM_BYTES,
        "private observer executable metadata differs"
    );
    Ok(())
}

fn optional(path: &Path, staging: bool) -> Result<Option<Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            private_metadata(&metadata, staging)?;
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn read(path: &Path, metadata: &Metadata, stop: &AtomicBool) -> Result<Vec<u8>> {
    active(stop)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        same(metadata, &file.metadata()?),
        "observer executable changed before reading"
    );
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAXIMUM_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == metadata.len()
            && bytes.len() as u64 <= MAXIMUM_BYTES
            && same(metadata, &file.metadata()?)
            && same(metadata, &fs::symlink_metadata(path)?),
        "observer executable changed during reading"
    );
    active(stop)?;
    Ok(bytes)
}

fn source_current(source: &Path, metadata: &Metadata) -> Result<()> {
    executable(source)?;
    ensure!(
        same(metadata, &fs::symlink_metadata(source)?),
        "configured observer executable changed during preparation"
    );
    Ok(())
}

/// The caller holds Runtime.lock and has not started the observer.
pub(super) fn prepare(native: &Path, source: &Path, stop: &AtomicBool) -> Result<PathBuf> {
    active(stop)?;
    executable(source)?;
    let original = fs::symlink_metadata(source)?;
    ensure!(
        original.nlink() == 1
            && original.mode() & 0o6000 == 0
            && original.len() > 0
            && original.len() <= MAXIMUM_BYTES,
        "configured observer executable metadata or size differs"
    );
    let bytes = read(source, &original, stop)?;
    source_current(source, &original)?;
    super::super::private::directory(native)?;
    let directory = native.join("RuntimeExecutables");
    saved::create_directory(&directory)?;
    let destination = directory.join("chronyd");
    let temporary = directory.join("chronyd.pending");
    if optional(&temporary, true)?.is_some() {
        active(stop)?;
        fs::remove_file(&temporary)?;
        File::open(&directory)?.sync_all()?;
    }
    let prior = optional(&destination, false)?;
    if let Some(metadata) = &prior
        && read(&destination, metadata, stop)? == bytes
    {
        source_current(source, &original)?;
        executable(&destination)?;
        return Ok(destination);
    }
    active(stop)?;
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        for chunk in bytes.chunks(1024 * 1024) {
            active(stop)?;
            file.write_all(chunk)?;
        }
        file.set_permissions(Permissions::from_mode(0o700))?;
        file.sync_all()?;
        let staged = file.metadata()?;
        private_metadata(&staged, false)?;
        ensure!(
            read(&temporary, &staged, stop)? == bytes,
            "private observer copy differs from configured executable"
        );
        source_current(source, &original)?;
        let current = optional(&destination, false)?;
        ensure!(
            match (&prior, &current) {
                (None, None) => true,
                (Some(old), Some(current)) => same(old, current),
                _ => false,
            },
            "private observer executable changed before publication"
        );
        active(stop)?;
        fs::rename(&temporary, &destination)?;
        File::open(&directory)?.sync_all()?;
        let published = optional(&destination, false)?
            .context("published observer executable is unavailable")?;
        ensure!(
            read(&destination, &published, stop)? == bytes,
            "published observer executable differs"
        );
        source_current(source, &original)?;
        executable(&destination)
    })();
    if result.is_err() && optional(&temporary, true)?.is_some() {
        fs::remove_file(&temporary)?;
        File::open(&directory)?.sync_all()?;
    }
    result?;
    Ok(destination)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;

    struct Fixture {
        root: PathBuf,
        native: PathBuf,
        source: PathBuf,
        stop: AtomicBool,
    }
    impl Fixture {
        fn new() -> Self {
            let base = std::env::var_os("HYPERNET_TEST_DIRECTORY")
                .or_else(|| std::env::var_os("TMPDIR"))
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    std::env::var_os("XDG_STATE_HOME")
                        .map(PathBuf::from)
                        .unwrap_or_else(|| {
                            PathBuf::from(std::env::var_os("HOME").unwrap()).join(".local/state")
                        })
                        .join("HyperNetSuite/Tests")
                });
            assert!(base.is_absolute());
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&base)
                .unwrap();
            crate::admission::private::directory(&base).unwrap();
            let root = base.join(format!("Observer{}", crate::random_hex::<16>()));
            saved::create_directory(&root).unwrap();
            let native = root.join("Native");
            saved::create_directory(&native).unwrap();
            let source = root.join("ConfiguredChronyd");
            fs::write(&source, b"configured observer bytes").unwrap();
            fs::set_permissions(&source, Permissions::from_mode(0o700)).unwrap();
            Self {
                root,
                native,
                source,
                stop: AtomicBool::new(false),
            }
        }
        fn prepare(&self) -> Result<PathBuf> {
            prepare(&self.native, &self.source, &self.stop)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }

    #[test]
    fn observer_copy_reuses_exact_bytes_and_refreshes_only_from_the_configured_source() {
        let f = Fixture::new();
        let path = f.prepare().unwrap();
        assert_eq!(path, f.native.join("RuntimeExecutables/chronyd"));
        assert_eq!(fs::read(&path).unwrap(), fs::read(&f.source).unwrap());
        let initial = fs::metadata(&path).unwrap();
        assert_eq!(initial.mode() & 0o7777, 0o700);
        assert_eq!(initial.uid(), unsafe { libc::geteuid() });
        assert_eq!(f.prepare().unwrap(), path);
        assert!(same(&initial, &fs::metadata(&path).unwrap()));
        let source_before = fs::metadata(&f.source).unwrap();
        fs::write(&f.source, b"updated configured observer").unwrap();
        assert!(source_current(&f.source, &source_before).is_err());
        f.prepare().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"updated configured observer");
        assert_ne!(initial.ino(), fs::metadata(&path).unwrap().ino());
        fs::write(&path, b"corrupt derived cache").unwrap();
        let pending = path.with_extension("pending");
        fs::write(&pending, b"interrupted copy").unwrap();
        fs::set_permissions(&pending, Permissions::from_mode(0o600)).unwrap();
        f.prepare().unwrap();
        assert_eq!(fs::read(&path).unwrap(), fs::read(&f.source).unwrap());
        assert!(!pending.exists());
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    }

    #[test]
    fn observer_copy_refuses_unsafe_source_and_destination_metadata() {
        let f = Fixture::new();
        let path = f.prepare().unwrap();
        let retained = fs::read(&path).unwrap();
        let linked = f.root.join("LinkedSource");
        std::os::unix::fs::symlink(&f.source, &linked).unwrap();
        assert!(prepare(&f.native, &linked, &f.stop).is_err());
        fs::remove_file(&linked).unwrap();
        fs::hard_link(&f.source, &linked).unwrap();
        assert!(f.prepare().is_err());
        fs::remove_file(&linked).unwrap();
        fs::set_permissions(&f.source, Permissions::from_mode(0o722)).unwrap();
        assert!(f.prepare().is_err());
        fs::set_permissions(&f.source, Permissions::from_mode(0o700)).unwrap();
        OpenOptions::new()
            .write(true)
            .open(&f.source)
            .unwrap()
            .set_len(MAXIMUM_BYTES + 1)
            .unwrap();
        assert!(f.prepare().is_err());
        fs::write(&f.source, &retained).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o755)).unwrap();
        assert!(f.prepare().is_err());
        fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&f.source, &path).unwrap();
        assert!(f.prepare().is_err());
        assert!(
            fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        fs::remove_file(&path).unwrap();
        fs::hard_link(&f.source, &path).unwrap();
        assert!(f.prepare().is_err());
        fs::remove_file(&path).unwrap();
        let pending = path.with_extension("pending");
        std::os::unix::fs::symlink(&f.source, &pending).unwrap();
        assert!(f.prepare().is_err());
        assert!(
            fs::symlink_metadata(&pending)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&f.source).unwrap(), retained);
    }

    #[test]
    fn cancelled_observer_copy_preserves_the_selected_source_and_cached_executable() {
        let f = Fixture::new();
        f.stop.store(true, Ordering::Release);
        assert!(f.prepare().is_err());
        assert!(!f.native.join("RuntimeExecutables").exists());
        f.stop.store(false, Ordering::Release);
        let path = f.prepare().unwrap();
        let before = fs::metadata(&path).unwrap();
        fs::write(&f.source, b"new trusted bytes").unwrap();
        f.stop.store(true, Ordering::Release);
        assert!(f.prepare().is_err());
        assert!(same(&before, &fs::metadata(&path).unwrap()));
        assert_eq!(fs::read(&path).unwrap(), b"configured observer bytes");
        assert_eq!(fs::read(&f.source).unwrap(), b"new trusted bytes");
    }
}
