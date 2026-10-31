// SPDX-License-Identifier: MIT
// Unit tests for Files.
use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};
#[test]
fn secret_files_reject_replacement_symlinks_and_public_modes() {
    let root = std::env::temp_dir().join(format!("HyperNetSuiteFiles{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("Identity.json");
    write_new(&path, b"private").unwrap();
    assert!(write_new(&path, b"replace").is_err());
    assert_eq!(read_bounded(&path, true).unwrap(), b"private\n");
    symlink(&path, root.join("Link")).unwrap();
    assert!(read_bounded(&root.join("Link"), true).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_bounded(&path, true).is_err());
    std::fs::remove_dir_all(root).unwrap();
}
