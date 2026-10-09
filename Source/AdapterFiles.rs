// SPDX-License-Identifier: MIT
// Strict bounded data files and private disclosure records; no executable adapter surface.
use crate::{Config, Identity, mail_protocol as wire, transfer_files};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::path::Path;
pub const RECEIPT_DOMAIN: &[u8] = b"HyperNet/AdapterDisclosure/1\0";
pub const MAX_FILE: usize = 131072;

pub fn read<T: DeserializeOwned>(path: &Path, maximum: usize) -> Result<T> {
    let raw = zeroize::Zeroizing::new(transfer_files::read(path, maximum, true)?);
    Ok(serde_json::from_slice(&raw)?)
}
pub fn write<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec_pretty(value)?);
    ensure!(
        bytes.len() <= MAX_FILE,
        "adapter file exceeds its size bound"
    );
    transfer_files::Destination::open(path)?.publish(&bytes)
}
pub fn label(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')),
        "recipient label must contain 1..64 letters, digits, underscore or hyphen"
    );
    Ok(())
}
pub fn purpose(value: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.len() <= 256 && !value.chars().any(char::is_control),
        "purpose must contain 1..256 bytes without control characters"
    );
    Ok(())
}
pub fn lifetime(issued_at: u64, expires: u64, now: u64) -> Result<()> {
    ensure!(
        issued_at > 0
            && issued_at <= now
            && expires > now
            && expires > issued_at
            && expires <= issued_at.saturating_add(300),
        "disclosure is expired or exceeds the 300-second lifetime"
    );
    Ok(())
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisclosureReceipt<T> {
    pub version: u32,
    pub network: String,
    pub signer: String,
    pub job_digest: String,
    pub disclosure: T,
}
pub fn sign<T: Serialize>(c: &Config, key: &Identity, job: &T) -> Result<wire::Signed> {
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(job)?);
    wire::sign(
        RECEIPT_DOMAIN,
        &c.network,
        key,
        &DisclosureReceipt {
            version: 1,
            network: c.network.clone(),
            signer: key.public_key.clone(),
            job_digest: wire::digest(&bytes),
            disclosure: job,
        },
    )
}
pub fn verify<T: DeserializeOwned + Serialize>(
    c: &Config,
    key: &Identity,
    proof: &wire::Signed,
) -> Result<DisclosureReceipt<T>> {
    let value: DisclosureReceipt<T> =
        wire::verify(RECEIPT_DOMAIN, &c.network, &key.public_key, proof)?;
    ensure!(
        value.version == 1 && value.network == c.network && value.signer == key.public_key,
        "disclosure receipt identity differs from this profile"
    );
    ensure!(
        value.job_digest == wire::digest(&serde_json::to_vec(&value.disclosure)?),
        "disclosure digest mismatch"
    );
    Ok(value)
}
