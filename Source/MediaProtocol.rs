// SPDX-License-Identifier: MIT
// Independent reference-bound page-media wire types and pinned store transport.
pub use crate::mail_protocol::Signed as Envelope;
use crate::{Config, Identity, mail_protocol as signed, markup::media::Asset, protocol};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::Read;
pub const HOST: &[u8] = b"HyperNet/PageMediaHost/1\0";
pub const OPERATION: &[u8] = b"HyperNet/PageMediaOperation/1\0";
pub const RECEIPT: &[u8] = b"HyperNet/PageMediaReceipt/1\0";
pub const CHUNK: u64 = 32768;
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostConsent {
    pub version: u32,
    pub network: String,
    pub host_key: String,
    pub generation: u64,
    pub services: Vec<String>,
    pub endpoint: String,
    pub address: std::net::SocketAddr,
    pub ca_digest: String,
    pub certificate_digest: String,
    pub authority_endpoint: String,
    pub authority_address: std::net::SocketAddr,
    pub authority_signer: String,
    pub memory_bytes: u64,
    pub pids: u64,
    pub cpu_quota: u64,
    pub cpu_period: u64,
    pub state_bytes: u64,
    pub expires: u64,
    pub namespaces: Vec<String>,
    pub retention_seconds: u64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Operation {
    pub agreement_id: Option<String>,
    pub admission: Option<crate::federation_proof::Evidence>,
    pub version: u32,
    pub network: String,
    pub operation_id: String,
    pub issued_at: u64,
    pub host_key: String,
    pub page_id: String,
    pub revision: u64,
    pub asset_id: String,
    pub source_digest: String,
    pub action: String,
    pub offset: u64,
    pub chunk_bytes: u64,
    pub chunk_digest: Option<String>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StoreReceipt {
    pub agreement_id: Option<String>,
    pub version: u32,
    pub network: String,
    pub host_key: String,
    pub host_generation: u64,
    pub page_id: String,
    pub revision: u64,
    pub asset_id: String,
    pub source_digest: String,
    pub digest: String,
    pub bytes: u64,
    pub stored_bytes: u64,
    pub status: String,
    pub requester_key: String,
    pub action: String,
    pub recorded_at: u64,
}

#[derive(Clone)]
pub struct Reference {
    pub agreement_id: Option<String>,
    pub storage_hosts: Vec<String>,
    pub page_id: String,
    pub revision: u64,
    pub source_digest: String,
    pub namespace: String,
    pub asset: Asset,
}

pub fn host(config: &Config, envelope: &Envelope, authority: &str) -> Result<HostConsent> {
    let h: HostConsent = signed::verify(HOST, &config.network, &envelope.public_key, envelope)?;
    protocol::hex_bytes::<32>(&h.host_key)?;
    protocol::hex_bytes::<32>(authority)?;
    protocol::hex_bytes::<32>(&h.certificate_digest)?;
    ensure!(
        h.version == 1
            && h.network == config.network
            && h.host_key == envelope.public_key
            && h.services == ["PageMedia"]
            && h.authority_signer == authority
            && h.generation > 0
            && h.expires > crate::now()?
            && !h.namespaces.is_empty()
            && h.namespaces.len() <= 16
            && h.namespaces.iter().all(|n| crate::markup::namespace(n))
            && h.namespaces.windows(2).all(|p| p[0] < p[1])
            && (1..=604800).contains(&h.retention_seconds),
        "invalid page media host consent"
    );
    let url = protocol::endpoint(&h.endpoint)?;
    ensure!(
        h.address.port() > 0
            && !h.address.ip().is_unspecified()
            && !h.address.ip().is_multicast()
            && url.port_or_known_default() == Some(h.address.port()),
        "invalid page media host address"
    );
    ensure!(
        signed::digest(&crate::files::read_bounded(&config.ca_certificate, false)?) == h.ca_digest,
        "page media host CA differs from configured trust"
    );
    Ok(h)
}
pub fn hosts(config: &Config, identity: &Identity) -> Result<Vec<HostConsent>> {
    let result = signed::authority(config, identity, json!({"type":"PageMediaHosts"}))?;
    signed::fresh_directory(&result)?;
    let authority = result["authoritySigner"]
        .as_str()
        .context("missing media authority signer")?;
    let entries: Vec<Envelope> = serde_json::from_value(result["hosts"].clone())?;
    ensure!(entries.len() <= 16, "too many media hosts");
    let mut keys = std::collections::BTreeSet::new();
    entries
        .iter()
        .map(|entry| {
            ensure!(keys.insert(&entry.public_key), "duplicate media host");
            host(config, entry, authority)
        })
        .collect()
}
pub fn selected_host(
    config: &Config,
    identity: &Identity,
    reference: &Reference,
    key: Option<&str>,
) -> Result<HostConsent> {
    crate::markup::media::validate_asset(&reference.asset).map_err(anyhow::Error::msg)?;
    if let Some(key) = key {
        ensure!(
            reference.storage_hosts.iter().any(|h| h == key),
            "host is outside the signed asset manifest"
        );
    }
    let hosts = hosts(config, identity)?;
    for expected in reference
        .storage_hosts
        .iter()
        .filter(|h| key.is_none_or(|key| h.as_str() == key))
    {
        if let Some(host) = hosts
            .iter()
            .find(|h| &h.host_key == expected && h.namespaces.contains(&reference.namespace))
        {
            return Ok(host.clone());
        }
    }
    anyhow::bail!("no currently consented host in the exact asset manifest")
}
#[allow(clippy::too_many_arguments)]
pub fn operation(
    config: &Config,
    identity: &Identity,
    host: &HostConsent,
    r: &Reference,
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
            agreement_id: r.agreement_id.clone(),
            admission: None,
            version: 1,
            network: config.network.clone(),
            operation_id: crate::random_hex::<16>(),
            issued_at: crate::now()?,
            host_key: host.host_key.clone(),
            page_id: r.page_id.clone(),
            revision: r.revision,
            asset_id: r.asset.id.clone(),
            source_digest: r.source_digest.clone(),
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
    let url = protocol::endpoint(&host.endpoint)?.join("V1/PageMedia")?;
    let tls = crate::mail_tls::config(
        &crate::files::read_bounded(&config.ca_certificate, false)?,
        &host.certificate_digest,
    )?;
    let response = reqwest::blocking::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .use_preconfigured_tls(tls)
        .resolve(
            url.host_str().context("media host name missing")?,
            host.address,
        )
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(15))
        .build()?
        .post(url)
        .json(&json!({"operation":operation,"payload":payload.map(signed::encode)}))
        .send()
        .map_err(|_| anyhow::anyhow!("page media store unavailable; upload remains resumable"))?;
    let status = response.status();
    let mut bytes = Vec::new();
    response.take(65537).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 65536, "media response exceeds its bound");
    let value: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        status.is_success() && value["ok"] == true,
        "media store refused operation: {}",
        crate::terminal_text(value["code"].as_str().unwrap_or("Unavailable"), false)
    );
    Ok(value["result"].clone())
}
pub fn receipt(
    config: &Config,
    identity: &Identity,
    host: &HostConsent,
    r: &Reference,
    action: &str,
    result: &Value,
) -> Result<(Envelope, StoreReceipt)> {
    let envelope: Envelope = serde_json::from_value(result["receipt"].clone())?;
    let value: StoreReceipt = signed::verify(RECEIPT, &config.network, &host.host_key, &envelope)?;
    ensure!(
        value.agreement_id == r.agreement_id
            && value.version == 1
            && value.network == config.network
            && value.host_key == host.host_key
            && value.host_generation == host.generation
            && value.page_id == r.page_id
            && value.revision == r.revision
            && value.asset_id == r.asset.id
            && value.source_digest == r.source_digest
            && value.digest == r.asset.digest
            && value.bytes == r.asset.bytes
            && value.stored_bytes <= value.bytes
            && value.requester_key == identity.public_key
            && value.action == action
            && matches!(value.status.as_str(), "Missing" | "Staging" | "Complete")
            && (value.status != "Complete" || value.stored_bytes == value.bytes)
            && value.recorded_at <= crate::now()?.saturating_add(5)
            && crate::now()?.saturating_sub(value.recorded_at) <= 30,
        "media receipt does not bind the exact current operation and manifest"
    );
    Ok((envelope, value))
}
