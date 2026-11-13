// SPDX-License-Identifier: MIT
// Private admission state rejects links and shared filesystem permissions.
use anyhow::{Result, ensure};
use std::{os::unix::fs::MetadataExt, path::Path};
pub fn directory(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "private directory must have a canonical absolute path"
    );
    let m = std::fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir()
            && !m.file_type().is_symlink()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0,
        "admission directory must be private and owned"
    );
    for ancestor in path.ancestors().skip(1) {
        let parent = std::fs::symlink_metadata(ancestor)?;
        let sticky_root = parent.uid() == 0 && parent.mode() & 0o1000 != 0;
        ensure!(
            parent.is_dir()
                && !parent.file_type().is_symlink()
                && (parent.uid() == 0 || parent.uid() == unsafe { libc::geteuid() })
                && (parent.mode() & 0o022 == 0 || sticky_root),
            "private state ancestor permits replacement"
        );
    }
    Ok(())
}
