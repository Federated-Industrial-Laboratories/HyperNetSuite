// SPDX-License-Identifier: MIT
// Bound credential reads and create private files without replacement.
use anyhow::{Context, Result, bail};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

pub fn disable_dumps() -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
    {
        bail!("cannot disable process memory dumps");
    }
    Ok(())
}

pub fn read_bounded(path: &Path, private: bool) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .context("cannot open input file")?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > 131072 {
        bail!("input must be a regular file of at most 128 KiB");
    }
    if private && (meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::geteuid() }) {
        bail!(
            "secret file must be owned by the current user and inaccessible to group and other users"
        );
    }
    let mut bytes = Vec::new();
    file.take(131073).read_to_end(&mut bytes)?;
    if bytes.len() > 131072 {
        bail!("input exceeded its size limit");
    }
    Ok(bytes)
}

pub fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .context("output must be a new file in an existing private directory")?;
    file.write_all(data)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
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
}
