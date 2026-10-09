// SPDX-License-Identifier: MIT
// Encrypted transfer snapshots preserve immutable offers, ciphertext and receive progress.
use crate::{
    mail_crypto, mail_protocol as signed, transfer_files as files, transfer_protocol as wire,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, ffi::OsStr, fs::File, path::Path};
const MAXIMUM: usize = 64 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Job {
    pub offer: wire::Envelope,
    pub ciphertext: String,
    pub receipt: Option<wire::Envelope>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Download {
    pub expires: u64,
    pub offer_digest: String,
    pub host_key: String,
    pub ciphertext: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Data {
    version: u32,
    network: String,
    member_key: String,
    clock_floor: u64,
    pub authority_signer: String,
    pub outgoing: BTreeMap<String, Job>,
    pub incoming: BTreeMap<String, Download>,
}
pub struct Vault {
    pub data: Data,
    pub key: age::x25519::Identity,
    directory: File,
    _lock: File,
}
impl Vault {
    pub fn initialise(
        directory: &Path,
        key_path: &Path,
        config: &crate::Config,
        member: &str,
        authority: &str,
    ) -> Result<Self> {
        crate::protocol::hex_bytes::<32>(authority)?;
        let directory = files::create_directory(directory)?;
        let lock = files::lock(&directory)?;
        let key = age::x25519::Identity::generate();
        use age::secrecy::ExposeSecret;
        let secret = zeroize::Zeroizing::new(key.to_string().expose_secret().as_bytes().to_vec());
        files::write_new(key_path, &secret)?;
        let mut v = Self {
            data: Data {
                version: 1,
                network: config.network.clone(),
                member_key: member.into(),
                clock_floor: crate::now()?,
                authority_signer: authority.into(),
                outgoing: BTreeMap::new(),
                incoming: BTreeMap::new(),
            },
            key,
            directory,
            _lock: lock,
        };
        v.commit()?;
        Ok(v)
    }
    pub fn open(
        directory: &Path,
        key_path: &Path,
        config: &crate::Config,
        member: &str,
    ) -> Result<Self> {
        let directory = files::private_directory(directory)?;
        let lock = files::lock(&directory)?;
        let secret = zeroize::Zeroizing::new(files::read(key_path, 4096, true)?);
        let key: age::x25519::Identity = std::str::from_utf8(&secret)?
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid transfer age identity"))?;
        let bytes = files::read_at(&directory, OsStr::new("Vault.age"), MAXIMUM + 65536, true)?;
        let plain = mail_crypto::decrypt_age(&key, &bytes, MAXIMUM)?;
        let data: Data = serde_json::from_slice(&plain)?;
        ensure!(
            data.version == 1
                && data.network == config.network
                && data.member_key == member
                && crate::now()?.saturating_add(2) >= data.clock_floor,
            "transfer vault identity or clock mismatch"
        );
        Ok(Self {
            data,
            key,
            directory,
            _lock: lock,
        })
    }
    pub fn commit(&mut self) -> Result<()> {
        self.data.clock_floor = self.data.clock_floor.max(crate::now()?);
        ensure!(
            self.data.outgoing.len() <= 64 && self.data.incoming.len() <= 64,
            "transfer vault count limit reached"
        );
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(&self.data)?);
        ensure!(plain.len() <= MAXIMUM, "transfer vault capacity reached");
        let ciphertext = mail_crypto::encrypt_age(&self.key.to_public().to_string(), &plain)?;
        files::atomic_at(&self.directory, OsStr::new("Vault.age"), &ciphertext, true)
    }
    pub fn recipient(&self) -> String {
        self.key.to_public().to_string()
    }
}
const MAGIC: &[u8] = b"HyperNetFile1\0";
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Header {
    version: u32,
    network: String,
    transfer_id: String,
    sender_key: String,
    recipient_key: String,
    pub file_name: String,
    pub file_bytes: u64,
    file_digest: String,
}
pub fn seal(offer: &wire::Offer, file_name: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        !file_name.is_empty()
            && file_name.len() <= 255
            && !matches!(file_name, "." | "..")
            && !file_name.contains(['/', '\\'])
            && !file_name.chars().any(char::is_control),
        "file name is invalid metadata"
    );
    let header = Header {
        version: 1,
        network: offer.network.clone(),
        transfer_id: offer.transfer_id.clone(),
        sender_key: offer.sender_key.clone(),
        recipient_key: offer.recipient_key.clone(),
        file_name: file_name.into(),
        file_bytes: bytes.len() as u64,
        file_digest: signed::digest(bytes),
    };
    let header = serde_json::to_vec(&header)?;
    let mut plain = zeroize::Zeroizing::new(MAGIC.to_vec());
    plain.extend_from_slice(&(header.len() as u32).to_be_bytes());
    plain.extend_from_slice(&header);
    plain.extend_from_slice(bytes);
    let encrypted = mail_crypto::encrypt_age(&offer.recipient_encryption_key, &plain)?;
    ensure!(
        encrypted.len() <= wire::MAX_FILE as usize,
        "encrypted file exceeds the 8 MiB profile; choose a smaller file"
    );
    Ok(encrypted)
}
pub fn unseal(
    offer: &wire::Offer,
    key: &age::x25519::Identity,
    ciphertext: &[u8],
) -> Result<(Header, zeroize::Zeroizing<Vec<u8>>)> {
    ensure!(
        key.to_public().to_string() == offer.recipient_encryption_key
            && ciphertext.len() as u64 == offer.payload_bytes
            && signed::digest(ciphertext) == offer.payload_digest,
        "transfer ciphertext or recipient binding mismatch"
    );
    let plain = mail_crypto::decrypt_age(key, ciphertext, wire::MAX_FILE as usize)?;
    ensure!(
        plain.starts_with(MAGIC) && plain.len() >= MAGIC.len() + 4,
        "invalid encrypted file profile"
    );
    let header_bytes = u32::from_be_bytes(plain[MAGIC.len()..MAGIC.len() + 4].try_into()?) as usize;
    let start = MAGIC.len() + 4;
    ensure!(
        header_bytes <= 4096 && start + header_bytes <= plain.len(),
        "invalid encrypted file header"
    );
    let header: Header = serde_json::from_slice(&plain[start..start + header_bytes])?;
    let bytes = zeroize::Zeroizing::new(plain[start + header_bytes..].to_vec());
    ensure!(
        header.version == 1
            && header.network == offer.network
            && header.transfer_id == offer.transfer_id
            && header.sender_key == offer.sender_key
            && header.recipient_key == offer.recipient_key
            && header.file_bytes == offer.file_bytes
            && bytes.len() as u64 == offer.file_bytes
            && signed::digest(&bytes) == header.file_digest,
        "encrypted file integrity or context mismatch"
    );
    Ok((header, bytes))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_file_binds_recipient_offer_and_all_plain_bytes() {
        let key = age::x25519::Identity::generate();
        let mut offer = wire::Offer {
            version: 1,
            network: "11".repeat(32),
            transfer_id: "22".repeat(16),
            sender_key: "33".repeat(32),
            recipient_key: "44".repeat(32),
            recipient_encryption_key: key.to_public().to_string(),
            payload_bytes: 0,
            payload_digest: String::new(),
            file_bytes: 5,
            label: "Opaque".into(),
            expires: 1,
        };
        let mut cipher = seal(&offer, "Private.txt", b"hello").unwrap();
        offer.payload_bytes = cipher.len() as u64;
        offer.payload_digest = signed::digest(&cipher);
        assert!(!cipher.windows(11).any(|s| s == b"Private.txt"));
        assert_eq!(&*unseal(&offer, &key, &cipher).unwrap().1, b"hello");
        offer.transfer_id = "55".repeat(16);
        assert!(unseal(&offer, &key, &cipher).is_err());
        offer.transfer_id = "22".repeat(16);
        assert!(unseal(&offer, &age::x25519::Identity::generate(), &cipher).is_err());
        cipher[80] ^= 1;
        offer.payload_digest = signed::digest(&cipher);
        assert!(unseal(&offer, &key, &cipher).is_err());
    }
}
