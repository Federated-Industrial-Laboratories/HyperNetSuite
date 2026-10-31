// SPDX-License-Identifier: MIT
// Encrypt files with exact offer, recipient and content binding.
use crate::{mail_crypto, mail_protocol as signed, transfer_protocol as wire};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

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
#[path = "../../Tests/Unit/Transfers/TransferVaultUnitTests.rs"]
mod tests;
