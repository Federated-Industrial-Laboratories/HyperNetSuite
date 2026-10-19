// SPDX-License-Identifier: MIT
// Descriptor-relative file access rejects symlink traversal and publishes without replacement.
use anyhow::{Context, Result, ensure};
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
};

fn name(value: &OsStr) -> Result<CString> {
    Ok(CString::new(value.as_bytes())?)
}
fn open_at(parent: &File, value: &OsStr, flags: i32, mode: u32) -> Result<File> {
    let value = name(value)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            value.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("cannot open path safely");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
pub fn directory(path: &Path) -> Result<File> {
    let mut current = File::open(if path.is_absolute() { "/" } else { "." })?;
    for part in path.components() {
        match part {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(value) => {
                current = open_at(&current, value, libc::O_RDONLY | libc::O_DIRECTORY, 0)?
            }
            _ => anyhow::bail!("parent traversal is not permitted"),
        }
    }
    ensure!(current.metadata()?.is_dir(), "expected a directory");
    Ok(current)
}
pub fn private_directory(path: &Path) -> Result<File> {
    let f = directory(path)?;
    let m = f.metadata()?;
    ensure!(
        m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
        "directory must be owned by the current user and mode 0700"
    );
    Ok(f)
}
fn parent(path: &Path) -> Result<(File, &OsStr)> {
    let value = path.file_name().context("file name required")?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok((directory(parent)?, value))
}
pub fn read(path: &Path, maximum: usize, private: bool) -> Result<Vec<u8>> {
    let (parent, value) = parent(path)?;
    read_at(&parent, value, maximum, private)
}
pub fn read_single(path: &Path, maximum: usize, private: bool) -> Result<Vec<u8>> {
    let (parent, value) = parent(path)?;
    read_file(&parent, value, maximum, private, true)
}
/// Public signed inputs may be readable by others, but must not be writable by them.
pub fn read_public_single(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let (parent, value) = parent(path)?;
    let file = open_at(&parent, value, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
    let metadata = file.metadata()?;
    ensure!(
        (metadata.uid() == 0 || metadata.uid() == unsafe { libc::geteuid() })
            && metadata.mode() & 0o022 == 0,
        "public input must be owned by this user or root and not writable by other users"
    );
    read_opened(file, maximum, false, true)
}
pub fn read_at(parent: &File, value: &OsStr, maximum: usize, private: bool) -> Result<Vec<u8>> {
    read_file(parent, value, maximum, private, private)
}
fn read_file(
    parent: &File,
    value: &OsStr,
    maximum: usize,
    private: bool,
    single: bool,
) -> Result<Vec<u8>> {
    let f = open_at(parent, value, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
    read_opened(f, maximum, private, single)
}
fn read_opened(f: File, maximum: usize, private: bool, single: bool) -> Result<Vec<u8>> {
    let m = f.metadata()?;
    ensure!(!single || m.nlink() == 1, "input must have one hard link");
    ensure!(
        m.is_file() && m.len() <= maximum as u64,
        "input must be a bounded regular file"
    );
    if private {
        ensure!(
            m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0 && m.nlink() == 1,
            "private file must be owned, mode 0600 and have one link"
        );
    }
    let mut bytes = Vec::new();
    f.take((maximum + 1) as u64).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= maximum, "input grew beyond its size limit");
    Ok(bytes)
}
pub fn create_directory(path: &Path) -> Result<File> {
    let (p, n) = parent(path)?;
    let n = name(n)?;
    ensure!(
        unsafe { libc::mkdirat(p.as_raw_fd(), n.as_ptr(), 0o700) } == 0,
        "cannot create private directory: {}",
        std::io::Error::last_os_error()
    );
    p.sync_all()?;
    private_directory(path)
}
pub struct VaultLock {
    file: File,
    owner: libc::pid_t,
}
impl Drop for VaultLock {
    fn drop(&mut self) {
        // A forked child can retain this open file description until exec. Only the
        // acquiring process ends the lock; closing its own descriptor is insufficient.
        if self.owner == unsafe { libc::getpid() } {
            unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}
pub fn lock(parent: &File) -> Result<VaultLock> {
    let f = open_at(
        parent,
        OsStr::new("Vault.lock"),
        libc::O_RDWR | libc::O_CREAT,
        0o600,
    )?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0
            && m.nlink() == 1,
        "unsafe transfer lock"
    );
    ensure!(
        unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another transfer command owns this vault"
    );
    Ok(VaultLock {
        file: f,
        owner: unsafe { libc::getpid() },
    })
}
pub fn atomic_at(parent: &File, destination: &OsStr, bytes: &[u8], replace: bool) -> Result<()> {
    let temporary = format!("Pending{}.bin", crate::random_hex::<16>());
    let temporary = CString::new(temporary)?;
    let destination = name(destination)?;
    let f = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    ensure!(f >= 0, "cannot create private staging file");
    let mut f = unsafe { File::from_raw_fd(f) };
    let result = (|| {
        f.write_all(bytes)?;
        f.sync_all()?;
        let flags = if replace { 0 } else { libc::RENAME_NOREPLACE };
        ensure!(
            unsafe {
                libc::renameat2(
                    parent.as_raw_fd(),
                    temporary.as_ptr(),
                    parent.as_raw_fd(),
                    destination.as_ptr(),
                    flags,
                )
            } == 0,
            "cannot publish file without changing the destination policy: {}",
            std::io::Error::last_os_error()
        );
        parent.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(parent.as_raw_fd(), temporary.as_ptr(), 0);
        }
    }
    result
}
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let (parent, value) = parent(path)?;
    atomic_at(&parent, value, bytes, false)
}
pub fn remove_private_at(parent: &File, value: &OsStr) -> Result<()> {
    let file = open_at(parent, value, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && metadata.nlink() == 1,
        "unsafe private removal target"
    );
    let value = name(value)?;
    ensure!(
        unsafe { libc::unlinkat(parent.as_raw_fd(), value.as_ptr(), 0) } == 0,
        "cannot remove private profile"
    );
    parent.sync_all()?;
    Ok(())
}
pub struct ProfileLock {
    file: File,
    owner_pid: libc::pid_t,
}
impl Drop for ProfileLock {
    fn drop(&mut self) {
        if self.owner_pid == unsafe { libc::getpid() } {
            // Forked helpers can retain the description until exec. Only the
            // process that acquired ownership may release its lock explicitly.
            unsafe {
                libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}
pub fn profile_lock(parent: &File, value: &OsStr) -> Result<ProfileLock> {
    use sha2::{Digest, Sha256};
    let label = format!(
        "Network{}.lock",
        hex::encode(Sha256::digest(value.as_bytes()))
    );
    let file = open_at(
        parent,
        OsStr::new(&label),
        libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
        0o600,
    )?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && metadata.nlink() == 1,
        "unsafe profile lock"
    );
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another command owns this profile"
    );
    let lock = ProfileLock {
        file,
        owner_pid: unsafe { libc::getpid() },
    };
    parent.sync_all()?;
    Ok(lock)
}
pub struct Destination {
    parent: File,
    name: CString,
}
impl Destination {
    pub fn open(path: &Path) -> Result<Self> {
        let p = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = private_directory(p)?;
        let value = path.file_name().context("destination file name required")?;
        let value = name(value)?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                value.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        ensure!(
            result != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT),
            "destination must not already exist"
        );
        Ok(Self {
            parent,
            name: value,
        })
    }
    pub fn publish(self, bytes: &[u8]) -> Result<()> {
        atomic_at(
            &self.parent,
            OsStr::from_bytes(self.name.as_bytes()),
            bytes,
            false,
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    #[test]
    fn profile_lock_owner_releases_inherited_description_without_child_unlock() {
        let root = std::env::temp_dir().join(format!("ProfileLock{}", crate::random_hex::<8>()));
        let directory = create_directory(&root).unwrap();
        let name = OsStr::new("Profile");
        let owner = profile_lock(&directory, name).unwrap();
        let inherited = owner.file.try_clone().unwrap();
        assert!(profile_lock(&directory, name).is_err());
        drop(owner);
        let mut resumed = profile_lock(&directory, name).unwrap();
        drop(inherited);
        assert!(profile_lock(&directory, name).is_err());
        let child_description = resumed.file.try_clone().unwrap();
        resumed.owner_pid = 0;
        drop(resumed);
        assert!(profile_lock(&directory, name).is_err());
        drop(child_description);
        drop(profile_lock(&directory, name).unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn vault_lock_owner_drop_releases_inherited_descriptor_without_child_unlock() {
        let root =
            std::env::temp_dir().join(format!("HyperNetTransferLock{}", crate::random_hex::<16>()));
        let directory = create_directory(&root).unwrap();
        let held = lock(&directory).unwrap();
        assert!(lock(&directory).is_err());
        assert_ne!(
            unsafe { libc::fcntl(held.file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        let mut sockets = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                    sockets.as_mut_ptr(),
                )
            },
            0
        );
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            // After fork, use only descriptor syscalls and this guard's nonallocating drop.
            unsafe { libc::close(sockets[0]) };
            let inherited = unsafe { libc::fcntl(held.file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
            drop(held);
            let ready = u8::from(inherited >= 0);
            let mut finish = 0u8;
            let sent = unsafe { libc::write(sockets[1], std::ptr::from_ref(&ready).cast(), 1) };
            let received =
                unsafe { libc::read(sockets[1], std::ptr::from_mut(&mut finish).cast(), 1) };
            unsafe {
                libc::close(inherited);
                libc::close(sockets[1]);
                libc::_exit(i32::from(ready != 1 || sent != 1 || received != 1));
            }
        }
        unsafe { libc::close(sockets[1]) };
        let mut ready = 0u8;
        let received = unsafe { libc::read(sockets[0], std::ptr::from_mut(&mut ready).cast(), 1) };
        let child_preserved_lock = lock(&directory).is_err();
        drop(held);
        let replacement = lock(&directory);
        let sent = unsafe {
            libc::send(
                sockets[0],
                std::ptr::from_ref(&ready).cast(),
                1,
                libc::MSG_NOSIGNAL,
            )
        };
        unsafe { libc::close(sockets[0]) };
        let mut status = 0;
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        assert_eq!((received, ready, sent, waited), (1, 1, 1, child));
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        assert!(child_preserved_lock, "child drop released the owner's lock");
        assert!(
            replacement.is_ok(),
            "inherited descriptor retained the owner's lock"
        );
        drop(replacement);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn publication_rejects_symlinks_traversal_and_destination_races() {
        let root = std::env::temp_dir().join(format!(
            "HyperNetTransferFiles{}",
            crate::random_hex::<16>()
        ));
        create_directory(&root).unwrap();
        let output = root.join("Output");
        let destination = Destination::open(&output).unwrap();
        write_new(&output, b"existing").unwrap();
        assert!(destination.publish(b"replacement").is_err());
        assert_eq!(read(&output, 64, true).unwrap(), b"existing");
        symlink(&root, root.join("Link")).unwrap();
        assert!(Destination::open(&root.join("Link/Bad")).is_err());
        assert!(read(&root.join("Link/Output"), 64, false).is_err());
        assert!(Destination::open(&root.join("../Escape")).is_err());
        assert!(read(Path::new("/dev/zero"), 64, false).is_err());
        Destination::open(&root.join("Good"))
            .unwrap()
            .publish(b"complete")
            .unwrap();
        assert_eq!(read(&root.join("Good"), 64, true).unwrap(), b"complete");
        std::fs::remove_dir_all(root).unwrap();
    }
}
