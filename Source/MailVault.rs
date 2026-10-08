// SPDX-License-Identifier: MIT
// One authenticated encrypted snapshot commits mail keys, outbox and archive together.
use crate::{
    Identity,
    mail_crypto::{self, Letter, PrivatePackage},
    mail_protocol as wire,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
use zeroize::Zeroize;
pub const MAX_VAULT: usize = 32 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mailbox {
    pub address: String,
    pub owner: Option<Identity>,
    pub request: Identity,
    pub signer: String,
    pub device: wire::Device,
    pub manifest: Option<wire::Signed>,
    pub packages: Vec<PrivatePackage>,
}
impl Drop for Mailbox {
    fn drop(&mut self) {
        self.signer.zeroize();
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Contact {
    pub address: String,
    pub owner_key: String,
    pub generation: u64,
    pub manifest_digest: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Outbox {
    pub mailbox: String,
    pub recipient: String,
    pub claim_id: String,
    pub message_id: String,
    pub expires: u64,
    pub subject: String,
    pub body: String,
    pub claim: Option<wire::Claim>,
    pub recipient_manifest: Option<wire::Signed>,
    pub ciphertext: Option<wire::Ciphertext>,
    pub receipts: BTreeMap<String, wire::Signed>,
    pub state: String,
}
impl Drop for Outbox {
    fn drop(&mut self) {
        self.subject.zeroize();
        self.body.zeroize();
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Archived {
    pub letter: Letter,
    pub admission: Option<wire::Signed>,
    pub receipt: Option<wire::Signed>,
    pub origin: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Data {
    pub version: u32,
    pub network: String,
    pub authority_signer: String,
    pub clock_floor: u64,
    pub mailboxes: BTreeMap<String, Mailbox>,
    pub contacts: BTreeMap<String, Contact>,
    pub hosts: BTreeMap<String, wire::Signed>,
    pub outbox: BTreeMap<String, Outbox>,
    pub archive: BTreeMap<String, Archived>,
}
pub struct Vault {
    pub data: Data,
    directory: PathBuf,
    key: age::x25519::Identity,
    _lock: File,
}
pub fn read_private(path: &Path, max: usize) -> Result<Vec<u8>> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0
            && m.len() <= max as u64,
        "mail private file must be owned, bounded and mode 0600"
    );
    let mut bytes = Vec::new();
    f.take((max + 1) as u64).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= max, "mail private file too large");
    Ok(bytes)
}
pub fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}
fn secure_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
        "mail directory must be owned and mode 0700"
    );
    Ok(())
}
impl Vault {
    pub fn initialise(
        directory: &Path,
        key_path: &Path,
        network: &str,
        authority_signer: &str,
    ) -> Result<Self> {
        crate::protocol::hex_bytes::<32>(network)?;
        crate::protocol::hex_bytes::<32>(authority_signer)?;
        fs::DirBuilder::new().mode(0o700).create(directory)?;
        secure_directory(directory)?;
        let key = age::x25519::Identity::generate();
        use age::secrecy::ExposeSecret;
        let secret = zeroize::Zeroizing::new(key.to_string().expose_secret().as_bytes().to_vec());
        write_new(key_path, &secret)?;
        let lock = Self::lock(directory)?;
        let mut v = Self {
            data: Data {
                version: 1,
                network: network.into(),
                authority_signer: authority_signer.into(),
                clock_floor: crate::now()?,
                mailboxes: BTreeMap::new(),
                contacts: BTreeMap::new(),
                hosts: BTreeMap::new(),
                outbox: BTreeMap::new(),
                archive: BTreeMap::new(),
            },
            directory: directory.into(),
            key,
            _lock: lock,
        };
        v.commit()?;
        Ok(v)
    }
    fn lock(directory: &Path) -> Result<File> {
        secure_directory(directory)?;
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join("Vault.lock"))?;
        let m = f.metadata()?;
        ensure!(
            m.is_file() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
            "invalid vault lock"
        );
        ensure!(
            unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "another mail operation owns this vault"
        );
        Ok(f)
    }
    pub fn open(directory: &Path, key_path: &Path, network: &str) -> Result<Self> {
        let lock = Self::lock(directory)?;
        let bytes = zeroize::Zeroizing::new(read_private(key_path, 4096)?);
        let key = std::str::from_utf8(&bytes)?
            .trim()
            .parse::<age::x25519::Identity>()
            .map_err(|_| anyhow::anyhow!("invalid vault age identity"))?;
        let bytes = read_private(&directory.join("Vault.age"), MAX_VAULT + 65536)?;
        let plain = mail_crypto::decrypt_age(&key, &bytes, MAX_VAULT)?;
        let data: Data = serde_json::from_slice(&plain)?;
        ensure!(
            data.version == 1 && data.network == network,
            "mail vault belongs to another network"
        );
        ensure!(
            crate::now()?.saturating_add(2) >= data.clock_floor,
            "mail clock rollback"
        );
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("Pending")
                && name.ends_with(".age")
                && name.len() == 43
                && name[7..39].bytes().all(|b| b.is_ascii_hexdigit())
            {
                let path = entry.path();
                let _ = read_private(&path, MAX_VAULT + 65536)?;
                fs::remove_file(path)?;
            }
        }
        File::open(directory)?.sync_all()?;
        Ok(Self {
            data,
            directory: directory.into(),
            key,
            _lock: lock,
        })
    }
    pub fn commit(&mut self) -> Result<()> {
        self.data.clock_floor = self.data.clock_floor.max(crate::now()?);
        ensure!(
            self.data.mailboxes.len() <= 64
                && self.data.outbox.len() <= 128
                && self.data.archive.len() <= 1024,
            "mail vault quota exceeded"
        );
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(&self.data)?);
        ensure!(plain.len() <= MAX_VAULT, "mail vault size exceeded");
        let encrypted = mail_crypto::encrypt_age(&self.key.to_public().to_string(), &plain)?;
        let temporary = self
            .directory
            .join(format!("Pending{}.age", crate::random_hex::<16>()));
        write_new(&temporary, &encrypted)?;
        fs::rename(&temporary, self.directory.join("Vault.age"))?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
    pub fn mailbox(&self, label: &str) -> Result<&Mailbox> {
        self.data
            .mailboxes
            .get(label)
            .context("unknown local mailbox")
    }
    pub fn mailbox_mut(&mut self, label: &str) -> Result<&mut Mailbox> {
        self.data
            .mailboxes
            .get_mut(label)
            .context("unknown local mailbox")
    }
    pub fn set_manifest(&mut self, label: &str, signed: wire::Signed) -> Result<wire::Manifest> {
        let m = wire::manifest(&self.data.network, &signed)?;
        let b = self.mailbox(label)?;
        ensure!(
            m.address_id == b.address,
            "address response changed identity"
        );
        if let Some(old) = &b.manifest {
            let previous = wire::manifest(&self.data.network, old)?;
            ensure!(
                m.generation >= previous.generation,
                "mailbox manifest rollback"
            );
            if m.generation == previous.generation {
                ensure!(
                    wire::object_digest(old)? == wire::object_digest(&signed)?,
                    "mailbox manifest fork"
                );
            }
        }
        if let Some(device) = m.devices.iter().find(|d| d.device_id == b.device.device_id) {
            ensure!(
                device.request_key == b.request.public_key
                    && device.mls_signature_key == b.device.mls_signature_key,
                "owner changed local device key binding"
            );
            self.mailbox_mut(label)?.device = device.clone();
        }
        self.mailbox_mut(label)?.manifest = Some(signed);
        self.commit()?;
        Ok(m)
    }
    pub fn age_identity(&self) -> &age::x25519::Identity {
        &self.key
    }
    pub fn age_recipient(&self) -> String {
        self.key.to_public().to_string()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_lock_and_consumption_are_one_persistent_transaction() {
        let root =
            std::env::temp_dir().join(format!("HyperNetMailVault{}", crate::random_hex::<16>()));
        let key = root.with_extension("Identity");
        let network = "12".repeat(32);
        let mut vault = Vault::initialise(&root, &key, &network, &"34".repeat(32)).unwrap();
        assert!(Vault::open(&root, &key, &network).is_err());
        let address = "56".repeat(32);
        let b = crate::mail::local_device(
            &network,
            &address,
            crate::now().unwrap() + 300,
            vec!["Read".into()],
        )
        .unwrap();
        vault.data.mailboxes.insert("Inbox".into(), b);
        vault.commit().unwrap();
        let bytes = std::fs::read(root.join("Vault.age")).unwrap();
        assert!(!bytes.windows(64).any(|w| w == address.as_bytes()));
        drop(vault);
        let reopened = Vault::open(&root, &key, &network).unwrap();
        assert_eq!(reopened.mailbox("Inbox").unwrap().address, address);
        assert!(Vault::open(&root, &key, &"78".repeat(32)).is_err());
        drop(reopened);
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_file(key).unwrap();
    }
}
