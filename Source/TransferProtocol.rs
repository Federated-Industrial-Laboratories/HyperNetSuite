// SPDX-License-Identifier: MIT
// Immutable encrypted transfer offers and current selected-store permissions.
pub use crate::mail_protocol::Signed as Envelope;
use serde::{Deserialize, Serialize};

pub const HOST: &[u8] = b"HyperNet/TransferHost/1\0";
pub const OFFER: &[u8] = b"HyperNet/TransferOffer/1\0";
pub const ACCEPTANCE: &[u8] = b"HyperNet/TransferAcceptance/1\0";
pub const OPERATION: &[u8] = b"HyperNet/TransferOperation/1\0";
pub const RECEIPT: &[u8] = b"HyperNet/TransferReceipt/1\0";
pub const MAX_FILE: u64 = 8 * 1024 * 1024;
pub const CHUNK: u64 = 64 * 1024;
pub const MAX_LIFETIME: u64 = 604800;
pub type HostConsent = crate::mail_protocol::Host;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Offer {
    pub version: u32,
    pub network: String,
    pub transfer_id: String,
    pub sender_key: String,
    pub recipient_key: String,
    pub recipient_encryption_key: String,
    pub payload_bytes: u64,
    pub payload_digest: String,
    pub file_bytes: u64,
    pub label: String,
    pub expires: u64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Acceptance {
    pub version: u32,
    pub network: String,
    pub transfer_id: String,
    pub offer_digest: String,
    pub host_key: String,
    pub destination: String,
    pub expires: u64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransferRecord {
    pub offer: Envelope,
    pub body: Offer,
    pub offer_digest: String,
    pub acceptance: Option<Envelope>,
    pub accepted: Option<Acceptance>,
    pub cancelled: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Operation {
    pub version: u32,
    pub network: String,
    pub operation_id: String,
    pub issued_at: u64,
    pub host_key: String,
    pub transfer_id: String,
    pub offer_digest: String,
    pub action: String,
    pub offset: u64,
    pub chunk_bytes: u64,
    pub chunk_digest: Option<String>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StoreReceipt {
    pub version: u32,
    pub network: String,
    pub host_key: String,
    pub transfer_id: String,
    pub offer_digest: String,
    pub payload_digest: String,
    pub payload_bytes: u64,
    pub stored_bytes: u64,
    pub status: String,
    pub recorded_at: u64,
}
use crate::{Config, Identity, mail_protocol as signed, protocol};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::io::Read;
pub fn record(config: &Config, value: &Value) -> Result<TransferRecord> {
    let r: TransferRecord = serde_json::from_value(value.clone())?;
    let offer: Offer = signed::verify(OFFER, &config.network, &r.offer.public_key, &r.offer)?;
    ensure!(
        serde_json::to_value(&offer)? == serde_json::to_value(&r.body)?
            && r.offer_digest == signed::signed_digest(OFFER, &r.offer)?,
        "transfer directory changed signed offer"
    );
    protocol::hex_bytes::<16>(&offer.transfer_id)?;
    protocol::hex_bytes::<32>(&offer.payload_digest)?;
    protocol::hex_bytes::<32>(&offer.sender_key)?;
    protocol::hex_bytes::<32>(&offer.recipient_key)?;
    let recipient: age::x25519::Recipient = offer
        .recipient_encryption_key
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid transfer encryption key"))?;
    ensure!(
        offer.version == 1
            && offer.network == config.network
            && offer.sender_key == r.offer.public_key
            && offer.payload_bytes > 0
            && offer.payload_bytes <= MAX_FILE
            && offer.file_bytes < offer.payload_bytes
            && recipient.to_string() == offer.recipient_encryption_key,
        "invalid transfer offer"
    );
    match (&r.acceptance, &r.accepted) {
        (Some(envelope), Some(body)) => {
            let a: Acceptance =
                signed::verify(ACCEPTANCE, &config.network, &offer.recipient_key, envelope)?;
            ensure!(
                serde_json::to_value(&a)? == serde_json::to_value(body)?
                    && a.version == 1
                    && a.network == config.network
                    && a.transfer_id == offer.transfer_id
                    && a.offer_digest == r.offer_digest
                    && a.expires <= offer.expires,
                "transfer acceptance binding mismatch"
            );
            protocol::hex_bytes::<32>(&a.host_key)?;
        }
        (None, None) => {}
        _ => anyhow::bail!("incomplete transfer acceptance"),
    }
    Ok(r)
}
pub fn get(config: &Config, identity: &Identity, id: &str) -> Result<TransferRecord> {
    protocol::hex_bytes::<16>(id)?;
    let value = signed::authority(
        config,
        identity,
        json!({"type":"TransferOfferGet","transferId":id}),
    )?;
    let r = record(config, &value["transfer"])?;
    ensure!(r.body.transfer_id == id, "wrong transfer returned");
    Ok(r)
}
pub fn active(r: &TransferRecord) -> Result<()> {
    ensure!(
        !r.cancelled && r.body.expires > crate::now()?,
        "transfer cancelled or expired"
    );
    if let Some(a) = &r.accepted {
        ensure!(a.expires > crate::now()?, "transfer acceptance expired");
    }
    Ok(())
}
pub fn host(config: &Config, envelope: &Envelope, authority_key: &str) -> Result<HostConsent> {
    let h: HostConsent = signed::verify(HOST, &config.network, &envelope.public_key, envelope)?;
    ensure!(
        h.version == 1
            && h.network == config.network
            && h.host_key == envelope.public_key
            && h.services == ["Transfer"]
            && h.authority_signer == authority_key
            && h.generation > 0
            && h.expires > crate::now()?,
        "invalid transfer host consent"
    );
    let endpoint = protocol::endpoint(&h.endpoint)?;
    let address: std::net::SocketAddr = h.address.parse()?;
    ensure!(
        address.port() > 0
            && !address.ip().is_unspecified()
            && !address.ip().is_multicast()
            && endpoint.port_or_known_default() == Some(address.port()),
        "invalid transfer host endpoint"
    );
    ensure!(
        signed::digest(&crate::files::read_bounded(&config.ca_certificate, false)?) == h.ca_digest,
        "transfer host CA differs from configured trust"
    );
    protocol::hex_bytes::<32>(&h.certificate_digest)?;
    Ok(h)
}
pub fn hosts(config: &Config, identity: &Identity) -> Result<Vec<Envelope>> {
    let result = signed::authority(config, identity, json!({"type":"TransferHosts"}))?;
    Ok(serde_json::from_value(result["hosts"].clone())?)
}
pub fn selected_host(
    config: &Config,
    identity: &Identity,
    r: &TransferRecord,
    authority: &str,
) -> Result<HostConsent> {
    active(r)?;
    let selected = &r
        .accepted
        .as_ref()
        .context("recipient must accept before transfer")?
        .host_key;
    for envelope in hosts(config, identity)? {
        if &envelope.public_key == selected {
            return host(config, &envelope, authority);
        }
    }
    anyhow::bail!("selected transfer store unavailable; no fallback is permitted")
}
#[allow(clippy::too_many_arguments)]
pub fn operation(
    config: &Config,
    identity: &Identity,
    host: &HostConsent,
    record: &TransferRecord,
    action: &str,
    offset: u64,
    chunk_bytes: u64,
    payload: Option<&[u8]>,
) -> Result<Envelope> {
    signed::sign(
        OPERATION,
        &config.network,
        identity,
        &Operation {
            version: 1,
            network: config.network.clone(),
            operation_id: crate::random_hex::<16>(),
            issued_at: crate::now()?,
            host_key: host.host_key.clone(),
            transfer_id: record.body.transfer_id.clone(),
            offer_digest: record.offer_digest.clone(),
            action: action.into(),
            offset,
            chunk_bytes,
            chunk_digest: payload.map(signed::digest),
        },
    )
}
pub fn store(
    config: &Config,
    host: &HostConsent,
    operation: &Envelope,
    payload: Option<&[u8]>,
) -> Result<Value> {
    let url = protocol::endpoint(&host.endpoint)?.join("V1/Transfer")?;
    let tls = crate::mail_tls::config(
        &crate::files::read_bounded(&config.ca_certificate, false)?,
        &host.certificate_digest,
    )?;
    let address: std::net::SocketAddr = host.address.parse()?;
    let response = reqwest::blocking::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .use_preconfigured_tls(tls)
        .resolve(
            url.host_str().context("transfer host name missing")?,
            address,
        )
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(15))
        .build()?
        .post(url)
        .json(&json!({"operation":operation,"payload":payload.map(signed::encode)}))
        .send()
        .map_err(|_| {
            anyhow::anyhow!(
                "transfer store transport unavailable; exact ciphertext remains resumable"
            )
        })?;
    let status = response.status();
    let mut bytes = Vec::new();
    response.take(262145).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 262144, "transfer response exceeds limit");
    let value: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        status.is_success() && value["ok"] == true,
        "transfer store refused operation: {}",
        crate::terminal_text(value["code"].as_str().unwrap_or("Unavailable"), false)
    );
    Ok(value["result"].clone())
}
pub fn receipt(
    config: &Config,
    host: &HostConsent,
    r: &TransferRecord,
    result: &Value,
) -> Result<(Envelope, StoreReceipt)> {
    let envelope: Envelope = serde_json::from_value(result["receipt"].clone())?;
    let receipt: StoreReceipt =
        signed::verify(RECEIPT, &config.network, &host.host_key, &envelope)?;
    ensure!(
        receipt.version == 1
            && receipt.network == config.network
            && receipt.host_key == host.host_key
            && receipt.transfer_id == r.body.transfer_id
            && receipt.offer_digest == r.offer_digest
            && receipt.payload_digest == r.body.payload_digest
            && receipt.payload_bytes == r.body.payload_bytes
            && receipt.stored_bytes <= receipt.payload_bytes
            && matches!(receipt.status.as_str(), "Staging" | "Complete" | "Deleted")
            && (receipt.status != "Complete" || receipt.stored_bytes == receipt.payload_bytes)
            && receipt.recorded_at <= crate::now()?.saturating_add(5),
        "invalid transfer receipt binding"
    );
    Ok((envelope, receipt))
}
