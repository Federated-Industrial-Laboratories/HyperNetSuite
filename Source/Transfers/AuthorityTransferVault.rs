// SPDX-License-Identifier: MIT
// Private age-encrypted snapshots retain immutable outgoing ciphertext and idempotent receive progress.
use crate::{
    authority_domains::transfer::Offer,
    authority_proof::{Digest, Key},
    mail_crypto, transfer_files as files, trust_wire as wire,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, ffi::OsStr, fs::File, path::Path};
const LIMIT: usize = 64 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Job {
    pub offer: String,
    pub ciphertext: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Download {
    pub offer: String,
    pub ciphertext: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Data {
    version: u64,
    network: Digest,
    incarnation: Digest,
    bootstrap: Digest,
    member: Key,
    pub outgoing: BTreeMap<String, Job>,
    pub incoming: BTreeMap<String, Download>,
}
pub struct Vault {
    data: Data,
    key: age::x25519::Identity,
    directory: File,
    _lock: files::VaultLock,
}
fn identity(path: &Path) -> Result<age::x25519::Identity> {
    let bytes = zeroize::Zeroizing::new(files::read(path, 4096, true)?);
    std::str::from_utf8(&bytes)?
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid transfer age identity"))
}
impl Vault {
    pub fn initialise(
        path: &Path,
        key_path: &Path,
        n: Digest,
        i: Digest,
        bootstrap: Digest,
        member: Key,
    ) -> Result<Self> {
        let directory = files::create_directory(path)?;
        let lock = files::lock(&directory)?;
        let key = age::x25519::Identity::generate();
        use age::secrecy::ExposeSecret;
        let bytes = zeroize::Zeroizing::new(key.to_string().expose_secret().as_bytes().to_vec());
        files::write_new(key_path, &bytes)?;
        let mut v = Self {
            data: Data {
                version: 1,
                network: n,
                incarnation: i,
                bootstrap,
                member,
                outgoing: BTreeMap::new(),
                incoming: BTreeMap::new(),
            },
            key,
            directory,
            _lock: lock,
        };
        v.save()?;
        Ok(v)
    }
    pub fn open(
        path: &Path,
        key_path: &Path,
        n: Digest,
        i: Digest,
        bootstrap: Digest,
        member: Key,
    ) -> Result<Self> {
        let directory = files::private_directory(path)?;
        let lock = files::lock(&directory)?;
        let key = identity(key_path)?;
        let cipher = files::read_at(&directory, OsStr::new("Vault.age"), LIMIT + 65536, true)?;
        let plain = mail_crypto::decrypt_age(&key, &cipher, LIMIT)?;
        let data: Data = serde_json::from_slice(&plain)?;
        ensure!(
            data.version == 1
                && data.network == n
                && data.incarnation == i
                && data.bootstrap == bootstrap
                && data.member == member,
            "transfer vault differs from accepted network or participant"
        );
        Ok(Self {
            data,
            key,
            directory,
            _lock: lock,
        })
    }
    fn save(&mut self) -> Result<()> {
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(&self.data)?);
        ensure!(
            plain.len() <= LIMIT,
            "encrypted transfer vault reached its 64 MiB admission"
        );
        let bytes = mail_crypto::encrypt_age(&self.recipient(), &plain)?;
        files::atomic_at(&self.directory, OsStr::new("Vault.age"), &bytes, true)
    }
    pub fn recipient(&self) -> String {
        self.key.to_public().to_string()
    }
    pub fn insert(&mut self, offer: &Offer, cipher: &[u8]) -> Result<()> {
        ensure!(
            offer.sender == self.data.member
                && cipher.len() as u64 == offer.payload_bytes
                && wire::digest(cipher) == offer.payload_digest
                && !self.data.outgoing.contains_key(&hex::encode(offer.id)),
            "outgoing transfer differs or identifier already exists"
        );
        self.data.outgoing.insert(
            hex::encode(offer.id),
            Job {
                offer: hex::encode(&offer.envelope),
                ciphertext: STANDARD.encode(cipher),
            },
        );
        self.save()
    }
    pub fn outgoing(&self, id: Digest) -> Result<(Offer, Vec<u8>)> {
        let job = self
            .data
            .outgoing
            .get(&hex::encode(id))
            .context("outgoing transfer absent from encrypted vault")?;
        let o = Offer::parse(
            &hex::decode(&job.offer)?,
            self.data.network,
            self.data.incarnation,
        )?;
        let c = STANDARD.decode(&job.ciphertext)?;
        ensure!(
            o.id == id
                && o.sender == self.data.member
                && c.len() as u64 == o.payload_bytes
                && wire::digest(&c) == o.payload_digest,
            "outgoing ciphertext damaged"
        );
        Ok((o, c))
    }
    pub fn outbox(&self) -> Result<Vec<Offer>> {
        self.data
            .outgoing
            .values()
            .map(|j| {
                Offer::parse(
                    &hex::decode(&j.offer)?,
                    self.data.network,
                    self.data.incarnation,
                )
            })
            .collect()
    }
    pub fn received(&self, offer: &Offer) -> Result<Vec<u8>> {
        let Some(d) = self.data.incoming.get(&hex::encode(offer.id)) else {
            return Ok(vec![]);
        };
        ensure!(
            hex::decode(&d.offer)? == offer.envelope,
            "incoming transfer offer changed"
        );
        let bytes = STANDARD.decode(&d.ciphertext)?;
        ensure!(
            bytes.len() as u64 <= offer.payload_bytes,
            "incoming transfer exceeds its accepted extent"
        );
        Ok(bytes)
    }
    pub fn receive(&mut self, offer: &Offer, offset: u64, bytes: &[u8]) -> Result<()> {
        ensure!(
            offer.recipient == self.data.member && offer.encryption_key == self.recipient(),
            "incoming transfer has another recipient key"
        );
        let mut cipher = self.received(offer)?;
        let offset = usize::try_from(offset)?;
        ensure!(
            offset <= cipher.len()
                && offset
                    .checked_add(bytes.len())
                    .is_some_and(|n| n <= offer.payload_bytes as usize),
            "incoming chunk has a gap or exceeds offer"
        );
        if offset < cipher.len() {
            ensure!(
                offset + bytes.len() <= cipher.len()
                    && cipher[offset..offset + bytes.len()] == *bytes,
                "repeated received chunk differs"
            );
        } else {
            cipher.extend(bytes);
        }
        self.data.incoming.insert(
            hex::encode(offer.id),
            Download {
                offer: hex::encode(&offer.envelope),
                ciphertext: STANDARD.encode(cipher),
            },
        );
        self.save()
    }
    pub fn open_file(
        &self,
        offer: &Offer,
    ) -> Result<(crate::transfer_vault::Header, zeroize::Zeroizing<Vec<u8>>)> {
        let cipher = self.received(offer)?;
        ensure!(
            offer.recipient == self.data.member
                && offer.encryption_key == self.recipient()
                && cipher.len() as u64 == offer.payload_bytes
                && wire::digest(&cipher) == offer.payload_digest,
            "retained ciphertext differs from the accepted offer"
        );
        // The encrypted file format uses SHA256; authority objects use RecordDigest.
        let mut header = ciphertext_header(offer);
        header.payload_digest = crate::mail_protocol::digest(&cipher);
        crate::transfer_vault::unseal(&header, &self.key, &cipher)
    }
    pub fn forget(&mut self, id: Digest) -> Result<()> {
        let name = hex::encode(id);
        self.data.outgoing.remove(&name);
        self.data.incoming.remove(&name);
        self.save()
    }
}
pub fn ciphertext_header(o: &Offer) -> crate::transfer_protocol::Offer {
    crate::transfer_protocol::Offer {
        version: 1,
        network: hex::encode(o.network),
        transfer_id: hex::encode(o.id),
        sender_key: hex::encode(o.sender),
        recipient_key: hex::encode(o.recipient),
        recipient_encryption_key: o.encryption_key.clone(),
        payload_bytes: o.payload_bytes,
        payload_digest: hex::encode(o.payload_digest),
        file_bytes: o.file_bytes,
        label: o.label.clone(),
        expires: o.expires / 1000,
    }
}
pub fn seal(offer: &Offer, name: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    crate::transfer_vault::seal(&ciphertext_header(offer), name, bytes)
}
#[cfg(test)]
#[path = "../../Tests/Unit/Transfers/AuthorityTransferVaultUnitTests.rs"]
mod tests;
