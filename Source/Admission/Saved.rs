// SPDX-License-Identifier: MIT
// A private saved-server owner retains identity, trust and offline intent across restarts.
use super::protocol::{self, Intent, Metadata};
use anyhow::{Result, ensure};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Identity {
    pub attempt: String,
    pub control_key: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct State {
    pub version: u8,
    pub location: String,
    pub metadata: Metadata,
    pub desired_online: bool,
    pub roles: Vec<protocol::Role>,
    pub display_name: String,
    pub intent: Option<Intent>,
    pub native_claim: Option<String>,
    pub native_bound: bool,
    pub installed: Option<serde_json::Value>,
    pub hrc: Option<serde_json::Value>,
    #[serde(default)]
    pub removed: bool,
    #[serde(default)]
    pub retirement: Option<String>,
}
pub struct Session {
    pub directory: PathBuf,
    pub key: SigningKey,
    pub identity: Identity,
    _lock: File,
}
pub fn create_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    super::private::directory(path)
}
pub fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0
            && m.len() <= 8 * 1024 * 1024,
        "saved server state must be private and bounded"
    );
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    (&mut file)
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 8 * 1024 * 1024,
        "saved server state exceeds bound"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
pub fn replace(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("saved server parent absent"))?;
    super::private::directory(parent)?;
    if let Ok(m) = std::fs::symlink_metadata(path) {
        ensure!(
            m.is_file()
                && m.nlink() == 1
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o077 == 0,
            "saved server target must be private"
        );
    }
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(value)?);
    ensure!(
        bytes.len() <= 8 * 1024 * 1024,
        "saved server state exceeds bound"
    );
    let temp = parent.join(format!(".join-{}", crate::random_hex::<16>()));
    let result = (|| -> Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        std::fs::rename(&temp, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}
impl Session {
    pub fn open(directory: &Path) -> Result<Self> {
        create_directory(directory)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join("Join.lock"))?;
        let m = lock.metadata()?;
        ensure!(
            m.is_file()
                && m.nlink() == 1
                && m.mode() & 0o077 == 0
                && m.uid() == unsafe { libc::geteuid() },
            "invalid saved server lock"
        );
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "saved server is busy in another window"
        );
        let key_path = directory.join("Control.key");
        let key = if key_path.exists() {
            let bytes = zeroize::Zeroizing::new(crate::files::read_bounded(&key_path, true)?);
            let text = std::str::from_utf8(&bytes)?.trim();
            ensure!(protocol::identifier(text), "invalid saved control key");
            let mut raw = zeroize::Zeroizing::new([0u8; 32]);
            hex::decode_to_slice(text, &mut *raw)?;
            SigningKey::from_bytes(&raw)
        } else {
            ensure!(
                !directory.join("Identity.json").exists()
                    && !directory.join("Server.json").exists(),
                "saved control key missing; keys must not be replaced"
            );
            let key = SigningKey::generate(&mut rand::rngs::OsRng);
            crate::files::write_new(
                &key_path,
                zeroize::Zeroizing::new(hex::encode(key.to_bytes())).as_bytes(),
            )?;
            key
        };
        let identity_path = directory.join("Identity.json");
        let identity: Identity = if identity_path.exists() {
            read(&identity_path)?
        } else {
            ensure!(
                !directory.join("Server.json").exists()
                    && !directory.join("Hrc").exists()
                    && !directory.join("Native/Candidate.json").exists(),
                "saved identity missing"
            );
            let i = Identity {
                attempt: crate::random_hex::<32>(),
                control_key: hex::encode(key.verifying_key().as_bytes()),
            };
            crate::files::write_new(&identity_path, &serde_json::to_vec(&i)?)?;
            i
        };
        ensure!(
            protocol::identifier(&identity.attempt)
                && identity.control_key == hex::encode(key.verifying_key().as_bytes()),
            "saved control key differs from identity"
        );
        Ok(Self {
            directory: directory.into(),
            key,
            identity,
            _lock: lock,
        })
    }
    pub fn native(&self) -> PathBuf {
        self.directory.join("Native")
    }
    pub fn state(&self) -> Result<State> {
        let s: State = read(&self.directory.join("Server.json"))?;
        ensure!(s.version == 1, "unsupported saved server version");
        if let Some(i) = &s.intent {
            i.validate()?;
            ensure!(
                i.attempt == self.identity.attempt && i.control_key == self.identity.control_key,
                "saved join identity changed"
            );
        }
        Ok(s)
    }
    pub fn save(&self, state: &State) -> Result<()> {
        replace(&self.directory.join("Server.json"), state)
    }
}
