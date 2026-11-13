// SPDX-License-Identifier: Apache-2.0
// Native host inputs remain bounded, private and immutable across interrupted setup.
use anyhow::{Result, ensure};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

fn bounded(path: &Path, private: bool, maximum: usize) -> Result<Vec<u8>> {
    ensure!(maximum <= 8_388_608, "native file bound exceeds limit");
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.len() <= maximum as u64,
        "native input metadata or size differs"
    );
    if private {
        ensure!(
            m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
            "native input is not private"
        );
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= maximum, "native input exceeds bound");
    Ok(bytes)
}
pub fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    bounded(path, true, maximum)
}
pub fn public_file(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    bounded(path, false, maximum)
}
pub fn directory(path: &Path) -> Result<()> {
    crate::admission::saved::create_directory(path)
}
pub fn exact_file(path: &Path, bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= 8_388_608, "native input exceeds bound");
    crate::native_installation::files::exact(path, bytes)
}

pub enum MappedAction {
    Input,
    Directory,
    Remove,
}
pub fn remove(path: &Path) -> Result<()> {
    if path.try_exists()? {
        read(path, 1_048_576)?;
        std::fs::remove_file(path)?;
        File::open(
            path.parent()
                .ok_or_else(|| anyhow::anyhow!("native input parent absent"))?,
        )?
        .sync_all()?;
    }
    Ok(())
}
pub fn mapped(directory: &Path, name: &str, action: MappedAction) -> Result<()> {
    crate::admission::private::directory(directory)?;
    ensure!(
        !name.is_empty()
            && name.len() <= 128
            && name != "."
            && name != ".."
            && name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-')),
        "invalid mapped input name"
    );
    let path = directory.join(name);
    match action {
        MappedAction::Directory => self::directory(&path)?,
        MappedAction::Remove => remove(&path)?,
        MappedAction::Input => {
            let mut input = zeroize::Zeroizing::new(Vec::new());
            std::io::stdin().take(1_048_577).read_to_end(&mut input)?;
            ensure!(input.len() <= 1_048_576, "mapped input exceeds bound");
            exact_file(&path, &input)?;
        }
    }
    crate::print_value(&serde_json::json!({"status":"Ready"}))
}
