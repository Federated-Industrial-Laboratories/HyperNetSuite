// SPDX-License-Identifier: MIT
// One age-encrypted snapshot commits private mail identities, one-use prekeys and received letters together.
use crate::{
    Identity,
    authority_proof::Digest,
    mail_crypto::{self, Letter, PrivatePackage},
    mail_protocol as wire, transfer_files as files,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs::File,
    path::Path,
};
use zeroize::Zeroize;
const LIMIT: usize = 32 * 1024 * 1024;
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
    pub manager: Option<String>,
    pub private: bool,
}
impl Drop for Mailbox {
    fn drop(&mut self) {
        self.signer.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Contact {
    pub owner: String,
    pub generation: u64,
    pub digest: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Outgoing {
    pub mailbox: String,
    pub recipient: String,
    pub id: String,
    pub expires: u64,
    pub subject: String,
    pub body: String,
    pub packages: Vec<String>,
    pub claim: Option<wire::Claim>,
    pub sender_manifest: Option<wire::Signed>,
    pub recipient_manifest: Option<wire::Signed>,
    pub ciphertext: Option<wire::Ciphertext>,
    pub receipts: BTreeMap<String, String>,
    pub form_consent: Option<super::forms::Consent>,
    #[serde(default)]
    pub send_consent: Option<super::application_consent::SendConsent>,
}
impl Drop for Outgoing {
    fn drop(&mut self) {
        self.subject.zeroize();
        self.body.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Archived {
    pub ciphertext_digest: String,
    pub letter: Letter,
    pub receipt: String,
    pub received_by: BTreeMap<String, String>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Data {
    version: u64,
    pub network: Digest,
    pub incarnation: Digest,
    pub bootstrap: Digest,
    clock_floor: u64,
    pub mailboxes: BTreeMap<String, Mailbox>,
    pub contacts: BTreeMap<String, Contact>,
    pub outgoing: BTreeMap<String, Outgoing>,
    pub archive: BTreeMap<String, Archived>,
    #[serde(default)]
    deleted_archive: BTreeSet<String>,
    #[serde(default)]
    pending_fetches: BTreeMap<String, String>,
    pub form_drafts: BTreeMap<String, super::forms::Prepared>,
    pub accepted_forms: BTreeMap<String, super::forms::Accepted>,
    pub form_ledger: BTreeMap<String, super::forms::LedgerEntry>,
}
pub struct Vault {
    pub data: Data,
    directory: File,
    _lock: files::VaultLock,
    key: age::x25519::Identity,
}
impl Vault {
    pub fn initialise(
        path: &Path,
        key_path: &Path,
        n: Digest,
        i: Digest,
        pin: Digest,
    ) -> Result<Self> {
        let directory = files::create_directory(path)?;
        let lock = files::lock(&directory)?;
        let key = age::x25519::Identity::generate();
        use age::secrecy::ExposeSecret;
        let secret = zeroize::Zeroizing::new(key.to_string().expose_secret().as_bytes().to_vec());
        files::write_new(key_path, &secret)?;
        let mut out = Self {
            data: Data {
                version: 1,
                network: n,
                incarnation: i,
                bootstrap: pin,
                clock_floor: crate::now()?,
                mailboxes: BTreeMap::new(),
                contacts: BTreeMap::new(),
                outgoing: BTreeMap::new(),
                archive: BTreeMap::new(),
                deleted_archive: BTreeSet::new(),
                pending_fetches: BTreeMap::new(),
                form_drafts: BTreeMap::new(),
                accepted_forms: BTreeMap::new(),
                form_ledger: BTreeMap::new(),
            },
            directory,
            _lock: lock,
            key,
        };
        out.save()?;
        Ok(out)
    }
    pub fn open(path: &Path, key_path: &Path, n: Digest, i: Digest, pin: Digest) -> Result<Self> {
        let directory = files::private_directory(path)?;
        let lock = files::lock(&directory)?;
        let secret = zeroize::Zeroizing::new(files::read(key_path, 4096, true)?);
        let key: age::x25519::Identity = std::str::from_utf8(&secret)?
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid mail age identity"))?;
        let bytes = files::read_at(&directory, OsStr::new("Vault.age"), LIMIT + 65536, true)?;
        let plain = mail_crypto::decrypt_age(&key, &bytes, LIMIT)?;
        let data: Data = serde_json::from_slice(&plain)?;
        ensure!(
            data.version == 1
                && data.network == n
                && data.incarnation == i
                && data.bootstrap == pin,
            "mail vault differs from independently accepted network"
        );
        ensure!(
            crate::now()?.saturating_add(2) >= data.clock_floor,
            "mail clock rollback"
        );
        Ok(Self {
            data,
            directory,
            _lock: lock,
            key,
        })
    }
    pub fn save(&mut self) -> Result<()> {
        self.data.clock_floor = self.data.clock_floor.max(crate::now()?);
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(&self.data)?);
        ensure!(
            plain.len() <= LIMIT,
            "mail vault reached its 32 MiB admission"
        );
        let bytes = mail_crypto::encrypt_age(&self.key.to_public().to_string(), &plain)?;
        files::atomic_at(&self.directory, OsStr::new("Vault.age"), &bytes, true)
    }
    pub fn mailbox(&self, label: &str) -> Result<&Mailbox> {
        self.data
            .mailboxes
            .get(label)
            .context("local mailbox absent")
    }
    pub fn mailbox_mut(&mut self, label: &str) -> Result<&mut Mailbox> {
        self.data
            .mailboxes
            .get_mut(label)
            .context("local mailbox absent")
    }
    pub fn set_manifest(&mut self, label: &str, signed: wire::Signed) -> Result<wire::Manifest> {
        let n = hex::encode(self.data.network);
        let m = wire::manifest(&n, &signed)?;
        let b = self.mailbox(label)?;
        ensure!(m.address_id == b.address, "mailbox changed identity");
        if let Some(old) = &b.manifest {
            let previous = wire::manifest(&n, old)?;
            ensure!(
                m.generation >= previous.generation
                    && (m.generation != previous.generation
                        || wire::object_digest(old)? == wire::object_digest(&signed)?),
                "mailbox revision rolled back or forked"
            );
        }
        if let Some(d) = m.devices.iter().find(|d| d.device_id == b.device.device_id) {
            ensure!(
                d.request_key == b.request.public_key
                    && d.mls_signature_key == b.device.mls_signature_key,
                "owner substituted local device keys"
            );
            self.mailbox_mut(label)?.device = d.clone();
        }
        self.mailbox_mut(label)?.manifest = Some(signed);
        self.save()?;
        Ok(m)
    }
    pub fn contact(
        &mut self,
        signed: &wire::Signed,
        verified_owner: Option<&str>,
    ) -> Result<wire::Manifest> {
        let m = wire::manifest(&hex::encode(self.data.network), signed)?;
        let digest = wire::object_digest(signed)?;
        ensure!(
            verified_owner.is_none_or(|key| key == m.owner_key),
            "verified contact owner differs from signed mailbox"
        );
        if let Some(old) = self.data.contacts.get(&m.address_id) {
            ensure!(
                old.owner == m.owner_key
                    && m.generation >= old.generation
                    && (m.generation != old.generation || digest == old.digest),
                "contact owner or retained revision changed"
            );
        } else {
            ensure!(
                verified_owner == Some(m.owner_key.as_str()),
                "verify recipient owner independently before first contact"
            );
        }
        self.data.contacts.insert(
            m.address_id.clone(),
            Contact {
                owner: m.owner_key.clone(),
                generation: m.generation,
                digest,
            },
        );
        self.save()?;
        Ok(m)
    }
    pub fn require_fetch(&self, message: &str) -> Result<()> {
        ensure!(
            !self.data.deleted_archive.contains(message),
            "this device's readable copy was permanently deleted"
        );
        Ok(())
    }
    pub fn sync_pending_fetch(&mut self, label: &str, message: Option<&str>) -> Result<()> {
        let requester = self.mailbox(label)?.request.public_key.clone();
        if self
            .data
            .pending_fetches
            .get(&requester)
            .map(String::as_str)
            == message
        {
            return Ok(());
        }
        if let Some(message) = message {
            self.data.pending_fetches.insert(requester, message.into());
        } else {
            self.data.pending_fetches.remove(&requester);
        }
        self.save()
    }
    pub fn fetch<T>(
        &mut self,
        label: &str,
        message: &str,
        package_reference: &str,
        exchange: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        self.require_fetch(message)?;
        let mailbox = self.mailbox(label)?;
        if let Some(archived) = self.data.archive.get(message) {
            ensure!(
                archived.letter.route.recipient_address == mailbox.address,
                "letter belongs to another mailbox"
            );
        } else {
            ensure!(
                mailbox
                    .packages
                    .iter()
                    .any(|p| p.reference == package_reference),
                "one-use private package unavailable; this device cannot read the letter"
            );
        }
        ensure!(
            self.data
                .pending_fetches
                .get(&mailbox.request.public_key)
                .is_none_or(|pending| pending == message),
            "another mail fetch is pending; recover its exact operation first"
        );
        // Keep the archive while an unacknowledged Fetch may need its idempotent callback.
        self.sync_pending_fetch(label, Some(message))?;
        let result = exchange(self)?;
        self.sync_pending_fetch(label, None)?;
        Ok(result)
    }
    pub fn delete_archive(&mut self, message: &str) -> Result<()> {
        ensure!(
            !self
                .data
                .pending_fetches
                .values()
                .any(|pending| pending == message),
            "finish the pending fetch before deleting this readable copy"
        );
        ensure!(
            self.data.archive.remove(message).is_some(),
            "archived message absent"
        );
        self.data.deleted_archive.insert(message.into());
        self.save()
    }
    pub fn archive(
        &mut self,
        label: &str,
        cipher: &wire::Ciphertext,
        package_reference: &str,
        admitted: u64,
        receipt: &[u8],
    ) -> Result<&Letter> {
        let message = cipher.route.message_id.clone();
        self.require_fetch(&message)?;
        let cipher_digest = wire::digest(&serde_json::to_vec(cipher)?);
        let mailbox = self.mailbox(label)?;
        ensure!(
            cipher.route.recipient_address == mailbox.address,
            "letter belongs to another mailbox"
        );
        let device = mailbox.device.device_id.clone();
        if let Some(old) = self.data.archive.get(&message) {
            ensure!(
                old.ciphertext_digest == cipher_digest,
                "message identity has different ciphertext"
            );
        } else {
            let b = self.mailbox(label)?;
            ensure!(
                cipher.route.recipient_address == b.address,
                "letter belongs to another mailbox"
            );
            let package = b
                .packages
                .iter()
                .find(|p| p.reference == package_reference)
                .context("one-use private package unavailable")?;
            let letter = mail_crypto::open(cipher, package, &b.device.device_id, admitted)?;
            self.mailbox_mut(label)?
                .packages
                .retain(|p| p.reference != package_reference);
            self.data.archive.insert(
                message.clone(),
                Archived {
                    ciphertext_digest: cipher_digest,
                    letter,
                    receipt: hex::encode(receipt),
                    received_by: BTreeMap::from([(device.clone(), hex::encode(receipt))]),
                },
            );
            self.save()?;
        }
        if !self
            .data
            .archive
            .get(&message)
            .unwrap()
            .received_by
            .contains_key(&device)
        {
            self.data
                .archive
                .get_mut(&message)
                .unwrap()
                .received_by
                .insert(device, hex::encode(receipt));
            self.save()?;
        }
        Ok(&self
            .data
            .archive
            .get(&message)
            .context("received letter absent")?
            .letter)
    }
}

#[cfg(test)]
#[path = "AuthorityMailVaultTests.rs"]
mod tests;
