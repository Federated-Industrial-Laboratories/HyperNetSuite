// SPDX-License-Identifier: MIT
// Independent mail wire types, purpose-bound signatures and pinned transport.
use crate::{Config, Identity, files, protocol};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path};
pub const MANIFEST: &[u8] = b"HyperNet/MailManifest/1\0";
pub const HOST: &[u8] = b"HyperNet/MailHost/1\0";
pub const OPERATION: &[u8] = b"HyperNet/MailOperation/1\0";
pub const PERMISSION: &[u8] = b"HyperNet/MailPermission/1\0";
pub const RECEIPT: &[u8] = b"HyperNet/MailReceipt/1\0";
pub const PROFILE: &str = "HyperNetMailMls1";
pub const MAX_OBJECT: usize = 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Signed {
    pub network: String,
    pub public_key: String,
    pub payload: String,
    pub signature: String,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Device {
    pub device_id: String,
    pub request_key: String,
    pub mls_signature_key: String,
    pub permissions: Vec<String>,
    pub expires: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub network: String,
    pub address_id: String,
    pub owner_key: String,
    pub generation: u64,
    pub previous_digest: Option<String>,
    pub expires: u64,
    pub devices: Vec<Device>,
    pub storage_hosts: Vec<String>,
    pub required_copies: u16,
    pub retention_seconds: u64,
    pub deleted: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Package {
    pub device_id: String,
    pub reference: String,
    pub expires: u64,
    pub package: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Claim {
    pub version: u32,
    pub network: String,
    pub sender_address: String,
    pub sender_device: String,
    pub claim_id: String,
    pub recipient_address: String,
    pub recipient_generation: u64,
    pub recipient_manifest_digest: String,
    pub expires: u64,
    pub packages: Vec<Package>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Route {
    pub version: u32,
    pub profile: String,
    pub network: String,
    pub message_id: String,
    pub replacement: u64,
    pub sender_address: String,
    pub sender_device: String,
    pub recipient_address: String,
    pub recipient_generation: u64,
    pub recipient_manifest_digest: String,
    pub claim_id: String,
    pub expires: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ciphertext {
    pub route: Route,
    pub sender_manifest: Signed,
    pub recipient_manifest: Signed,
    pub welcome: String,
    pub message: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Operation {
    pub version: u32,
    pub network: String,
    pub operation_id: String,
    pub issued_at: u64,
    pub host_key: String,
    pub action: String,
    pub address_id: String,
    pub device_id: String,
    pub message_id: Option<String>,
    pub manifest_generation: u64,
    pub manifest_digest: String,
    pub payload_digest: Option<String>,
    pub payload_bytes: u64,
    pub after: Option<String>,
    pub route: Option<Route>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Permission {
    pub version: u32,
    pub network: String,
    pub authority_epoch: u64,
    pub authority_revision: i64,
    pub host_key: String,
    pub host_generation: u64,
    pub operation_digest: String,
    pub address_id: String,
    pub manifest_generation: u64,
    pub manifest_digest: String,
    pub issued_at: u64,
    pub expires: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub version: u32,
    pub network: String,
    pub host_key: String,
    pub host_generation: u64,
    pub message_id: String,
    pub replacement: u64,
    pub payload_digest: String,
    pub recipient_address: String,
    pub recipient_generation: u64,
    pub status: String,
    pub recorded_at: u64,
    pub expires: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Host {
    pub version: u32,
    pub network: String,
    pub host_key: String,
    pub generation: u64,
    pub services: Vec<String>,
    pub endpoint: String,
    pub address: String,
    pub ca_digest: String,
    pub certificate_digest: String,
    pub authority_endpoint: String,
    pub authority_address: String,
    pub authority_signer: String,
    pub memory_bytes: u64,
    pub pids: u64,
    pub cpu_quota: u64,
    pub cpu_period: u64,
    pub state_bytes: u64,
    pub expires: u64,
}
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}
pub fn decode(value: &str, maximum: usize) -> Result<Vec<u8>> {
    ensure!(
        value.len() <= maximum.saturating_mul(4) / 3 + 4,
        "mail encoding exceeds limit"
    );
    let bytes = B64.decode(value)?;
    ensure!(bytes.len() <= maximum, "mail object exceeds limit");
    Ok(bytes)
}
pub fn signed_digest(domain: &[u8], signed: &Signed) -> Result<String> {
    let mut bytes = domain.to_vec();
    bytes.extend(protocol::hex_bytes::<32>(&signed.network)?);
    bytes.extend(protocol::hex_bytes::<32>(&signed.public_key)?);
    bytes.extend(decode(&signed.payload, MAX_OBJECT)?);
    Ok(digest(&bytes))
}
pub fn object_digest(signed: &Signed) -> Result<String> {
    signed_digest(MANIFEST, signed)
}
pub fn fresh_directory(value: &Value) -> Result<()> {
    let now = crate::now()?;
    let until = value["validUntil"]
        .as_u64()
        .context("missing directory expiry")?;
    ensure!(
        until >= now
            && until <= now.saturating_add(5)
            && value["authorityRevision"].as_i64().is_some_and(|r| r > 0),
        "stale mail authority directory"
    );
    Ok(())
}
pub fn address_id(network: &str, key: &str) -> Result<String> {
    let mut b = b"HyperNet/MailAddress/1\0".to_vec();
    b.extend(protocol::hex_bytes::<32>(network)?);
    b.extend(protocol::hex_bytes::<32>(key)?);
    Ok(digest(&b))
}
pub fn device_id(address: &str, key: &str) -> Result<String> {
    let mut b = b"HyperNet/MailDevice/1\0".to_vec();
    b.extend(protocol::hex_bytes::<32>(address)?);
    b.extend(protocol::hex_bytes::<32>(key)?);
    Ok(digest(&b))
}
pub fn new_identity() -> Identity {
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    Identity {
        secret_key: hex::encode(key.to_bytes()),
        public_key: hex::encode(key.verifying_key().to_bytes()),
    }
}
pub fn sign<T: Serialize>(
    domain: &[u8],
    network: &str,
    key: &Identity,
    value: &T,
) -> Result<Signed> {
    let payload = serde_json::to_vec(value)?;
    ensure!(payload.len() <= MAX_OBJECT, "signed mail object too large");
    let mut bytes = domain.to_vec();
    bytes.extend(protocol::hex_bytes::<32>(network)?);
    bytes.extend(protocol::hex_bytes::<32>(&key.public_key)?);
    bytes.extend(&payload);
    let secret = zeroize::Zeroizing::new(protocol::hex_bytes::<32>(&key.secret_key)?);
    let keypair = SigningKey::from_bytes(&secret);
    ensure!(
        hex::encode(keypair.verifying_key().to_bytes()) == key.public_key,
        "mail signing identity mismatch"
    );
    Ok(Signed {
        network: network.into(),
        public_key: key.public_key.clone(),
        payload: encode(&payload),
        signature: hex::encode(keypair.sign(&bytes).to_bytes()),
    })
}
pub fn verify<T: DeserializeOwned>(
    domain: &[u8],
    network: &str,
    key: &str,
    signed: &Signed,
) -> Result<T> {
    ensure!(
        signed.network == network && signed.public_key == key,
        "mail signature scope mismatch"
    );
    let payload = decode(&signed.payload, MAX_OBJECT)?;
    let mut bytes = domain.to_vec();
    bytes.extend(protocol::hex_bytes::<32>(network)?);
    bytes.extend(protocol::hex_bytes::<32>(key)?);
    bytes.extend(&payload);
    VerifyingKey::from_bytes(&protocol::hex_bytes::<32>(key)?)?.verify_strict(
        &bytes,
        &Signature::from_bytes(&protocol::hex_bytes::<64>(&signed.signature)?),
    )?;
    Ok(serde_json::from_slice(&payload)?)
}
pub fn manifest(network: &str, signed: &Signed) -> Result<Manifest> {
    let m: Manifest = verify(MANIFEST, network, &signed.public_key, signed)?;
    ensure!(
        m.version == 1
            && m.network == network
            && m.owner_key == signed.public_key
            && m.address_id == address_id(network, &m.owner_key)?
            && m.generation > 0,
        "invalid address manifest"
    );
    ensure!(
        m.devices.len() <= 8
            && m.storage_hosts.len() <= 4
            && (60..=604800).contains(&m.retention_seconds)
            && m.required_copies as usize <= m.storage_hosts.len()
            && ((m.deleted
                && m.devices.is_empty()
                && m.storage_hosts.is_empty()
                && m.required_copies == 0)
                || (!m.deleted && !m.devices.is_empty() && m.required_copies > 0)),
        "invalid mailbox policy"
    );
    if let Some(previous) = &m.previous_digest {
        protocol::hex_bytes::<32>(previous)?;
    }
    let mut hosts = std::collections::BTreeSet::new();
    for host in &m.storage_hosts {
        protocol::hex_bytes::<32>(host)?;
        ensure!(hosts.insert(host), "duplicate storage host");
    }
    let mut keys = std::collections::BTreeSet::new();
    let mut public = std::collections::BTreeSet::from([m.owner_key.as_str()]);
    for d in &m.devices {
        ensure!(
            d.device_id == device_id(&m.address_id, &d.request_key)? && keys.insert(&d.device_id),
            "invalid or duplicate mail device"
        );
        for key in [&d.request_key, &d.mls_signature_key] {
            VerifyingKey::from_bytes(&protocol::hex_bytes::<32>(key)?)?;
            ensure!(public.insert(key), "mail device keys must be distinct");
        }
        ensure!(
            d.expires <= m.expires
                && d.permissions.len() <= 3
                && d.permissions
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == d.permissions.len(),
            "invalid device lifetime or scopes"
        );
        ensure!(
            !d.permissions.is_empty()
                && d.permissions
                    .iter()
                    .all(|p| matches!(p.as_str(), "Read" | "Send" | "Delete")),
            "invalid mail scope"
        );
    }
    Ok(m)
}
pub fn authority(config: &Config, key: &Identity, command: Value) -> Result<Value> {
    let reply = protocol::send(
        config,
        key,
        &crate::random_hex::<16>(),
        crate::now()?,
        command,
    )?;
    Ok(reply["result"].clone())
}
pub fn address_get(config: &Config, key: &Identity, address: &str) -> Result<Signed> {
    let result = authority(
        config,
        key,
        json!({"type":"MailAddressGet","addressId":address}),
    )?;
    fresh_directory(&result)?;
    let signed: Signed = serde_json::from_value(result["manifest"].clone())?;
    let m = manifest(&config.network, &signed)?;
    ensure!(m.address_id == address, "wrong mailbox returned");
    Ok(signed)
}
pub fn host(config: &Config, signed: &Signed, authority_key: &str) -> Result<Host> {
    let h: Host = verify(HOST, &config.network, &signed.public_key, signed)?;
    ensure!(
        h.version == 1
            && h.network == config.network
            && h.host_key == signed.public_key
            && h.services == ["Mail"]
            && h.authority_signer == authority_key
            && h.expires > crate::now()?,
        "invalid mail host consent"
    );
    protocol::endpoint(&h.endpoint)?;
    let address: std::net::SocketAddr = h.address.parse()?;
    ensure!(
        address.port() != 0 && !address.ip().is_unspecified() && !address.ip().is_multicast(),
        "invalid mail host endpoint"
    );
    ensure!(
        digest(&files::read_bounded(&config.ca_certificate, false)?) == h.ca_digest,
        "mail store CA differs from configured trust"
    );
    Ok(h)
}
pub fn store(config: &Config, h: &Host, op: &Signed, payload: Option<&[u8]>) -> Result<Value> {
    let url = protocol::endpoint(&h.endpoint)?.join("V1/Mail")?;
    let tls = crate::mail_tls::config(
        &files::read_bounded(&config.ca_certificate, false)?,
        &h.certificate_digest,
    )?;
    let addr: std::net::SocketAddr = h.address.parse()?;
    let response = reqwest::blocking::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .use_preconfigured_tls(tls)
        .resolve(url.host_str().context("mail store host missing")?, addr)
        .timeout(std::time::Duration::from_secs(15))
        .build()?
        .post(url)
        .json(&json!({"operation":op,"payload":payload.map(encode)}))
        .send()
        .map_err(|_| anyhow::anyhow!("mail store transport unavailable"))?;
    let status = response.status();
    let mut bytes = Vec::new();
    response
        .take((MAX_OBJECT * 2 + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_OBJECT * 2, "mail response too large");
    let value: Value = serde_json::from_slice(&bytes)?;
    if !status.is_success() || value["ok"] != true {
        let code = value["code"].as_str().unwrap_or("MailStoreUnavailable");
        if code.len() < 80 && code.bytes().all(|b| b.is_ascii_alphanumeric()) {
            bail!("mail store refused operation: {code}");
        }
        bail!("mail store refused operation");
    }
    Ok(value["result"].clone())
}
pub fn read_signed(path: &Path) -> Result<Signed> {
    Ok(serde_json::from_slice(&files::read_bounded(path, false)?)?)
}
