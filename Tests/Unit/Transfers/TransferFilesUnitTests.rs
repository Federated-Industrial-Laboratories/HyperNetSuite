// SPDX-License-Identifier: MIT
// Unit tests for TransferFiles.
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
        let received = unsafe { libc::read(sockets[1], std::ptr::from_mut(&mut finish).cast(), 1) };
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
