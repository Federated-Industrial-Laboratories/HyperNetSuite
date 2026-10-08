// SPDX-License-Identifier: MIT
// Sign and inspect explicit, dual-identity consent without contacting either network.
use crate::{federation_proof::Treaty, files, protocol};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
};

const DOMAIN: &[u8] = b"HyperNet/BridgeConsent/1\0";
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Endpoint {
    pub network: String,
    pub device_key: String,
    pub authority_key: String,
    pub authority_endpoint: String,
    pub authority_address: SocketAddr,
    pub ca_certificate_digest: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Consent {
    pub version: u32,
    pub service: String,
    pub agreement_id: String,
    pub treaty_digest: String,
    pub source_namespace: String,
    pub destination_namespace: String,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub expires: u64,
    pub memory_bytes: u64,
    pub pids: u64,
    pub cpu_quota: u64,
    pub cpu_period: u64,
    pub state_bytes: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Signed {
    payload: String,
    source_signature: String,
    destination_signature: String,
}

impl Endpoint {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.authority_endpoint.len() <= 512,
            "endpoint exceeds its bound"
        );
        for value in [
            &self.network,
            &self.device_key,
            &self.authority_key,
            &self.ca_certificate_digest,
        ] {
            protocol::hex_bytes::<32>(value)?;
        }
        let endpoint = protocol::endpoint(&self.authority_endpoint)?;
        let hostname = endpoint
            .host_str()
            .context("endpoint requires a DNS name")?;
        ensure!(
            hostname.parse::<IpAddr>().is_err()
                && hostname.is_ascii()
                && hostname
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
            "endpoint requires an explicit DNS server name"
        );
        ensure!(
            self.authority_address.port() > 0
                && !self.authority_address.ip().is_unspecified()
                && !self.authority_address.ip().is_multicast()
                && endpoint.port_or_known_default() == Some(self.authority_address.port()),
            "invalid pinned authority address or port"
        );
        Ok(())
    }
}
impl Consent {
    pub fn validate(&self) -> Result<()> {
        let now = crate::now()?;
        ensure!(
            self.version == 1 && self.service == "FederationPages",
            "unsupported bridge consent"
        );
        protocol::hex_bytes::<16>(&self.agreement_id)?;
        protocol::hex_bytes::<32>(&self.treaty_digest)?;
        self.source.validate()?;
        self.destination.validate()?;
        let keys = [
            &self.source.device_key,
            &self.destination.device_key,
            &self.source.authority_key,
            &self.destination.authority_key,
        ];
        ensure!(
            keys.into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == 4,
            "bridge and authority keys must have distinct purposes and identities"
        );
        ensure!(
            self.source.network != self.destination.network
                && self.source.device_key != self.destination.device_key
                && crate::markup::namespace(&self.source_namespace)
                && crate::markup::namespace(&self.destination_namespace),
            "invalid bridge identity or namespace separation"
        );
        ensure!(
            self.expires > now && self.expires <= now.saturating_add(604800),
            "bridge consent is expired or exceeds seven days"
        );
        ensure!(
            (67108864..=8589934592).contains(&self.memory_bytes)
                && (16..=512).contains(&self.pids)
                && self.cpu_period == 100000
                && (1000..=800000).contains(&self.cpu_quota)
                && (1048576..=268435456).contains(&self.state_bytes),
            "invalid bridge resource limits"
        );
        Ok(())
    }
    fn matches(&self, treaty: &Treaty) -> Result<()> {
        ensure!(
            self.treaty_digest == treaty.digest()?
                && self.agreement_id == treaty.agreement_id
                && self.source.network == treaty.source_network
                && self.destination.network == treaty.destination_network
                && self.source.device_key == treaty.source_bridge_key
                && self.destination.device_key == treaty.destination_bridge_key
                && self.source.authority_key == treaty.source_authority_key
                && self.destination.authority_key == treaty.destination_authority_key
                && self.source_namespace == treaty.source_namespace
                && self.destination_namespace == treaty.destination_namespace
                && self.expires <= treaty.expires,
            "bridge consent does not match the exact treaty"
        );
        Ok(())
    }
}

pub fn sign(
    spec: &Path,
    treaty_path: &Path,
    source_identity: &Path,
    destination_identity: &Path,
    output: &Path,
) -> Result<()> {
    let consent: Consent = serde_json::from_slice(&files::read_bounded(spec, false)?)?;
    consent.validate()?;
    let treaty: Treaty = serde_json::from_slice(&files::read_bounded(treaty_path, false)?)?;
    consent.matches(&treaty)?;
    let source = crate::load_identity(source_identity)?;
    let destination = crate::load_identity(destination_identity)?;
    ensure!(
        source.public_key == consent.source.device_key
            && destination.public_key == consent.destination.device_key,
        "bridge identities do not match consent"
    );
    let payload = serde_json::to_vec(&consent)?;
    ensure!(
        payload.len() <= 8192,
        "bridge consent payload exceeds its bound"
    );
    let mut message = DOMAIN.to_vec();
    message.extend(&payload);
    let source_secret = zeroize::Zeroizing::new(protocol::hex_bytes::<32>(&source.secret_key)?);
    let destination_secret =
        zeroize::Zeroizing::new(protocol::hex_bytes::<32>(&destination.secret_key)?);
    let signed = Signed {
        payload: URL_SAFE_NO_PAD.encode(payload),
        source_signature: hex::encode(
            SigningKey::from_bytes(&source_secret)
                .sign(&message)
                .to_bytes(),
        ),
        destination_signature: hex::encode(
            SigningKey::from_bytes(&destination_secret)
                .sign(&message)
                .to_bytes(),
        ),
    };
    let mut bytes = serde_json::to_vec_pretty(&signed)?;
    bytes.push(b'\n');
    ensure!(bytes.len() <= 16384, "bridge consent exceeds its bound");
    files::write_new(output, &bytes[..bytes.len() - 1])?;
    crate::print_value(
        &json!({"profile":hex::encode(Sha256::digest(&bytes)),"agreementId":consent.agreement_id,"sourceNamespace":consent.source_namespace,"destinationNamespace":consent.destination_namespace,"expires":consent.expires,"bridgeMemoryBytes":consent.memory_bytes,"totalMemoryBytesIncludingRelays":consent.memory_bytes+268435456}),
    )
}

pub fn registration(path: &Path, network: &str, device: &str, certificate: &str) -> Result<Value> {
    protocol::hex_bytes::<32>(certificate)?;
    let bytes = files::read_bounded(path, true)?;
    ensure!(bytes.len() <= 16384, "bridge consent exceeds its bound");
    let signed: Signed = serde_json::from_slice(&bytes)?;
    let payload = URL_SAFE_NO_PAD.decode(&signed.payload)?;
    ensure!(
        payload.len() <= 8192,
        "bridge consent payload exceeds its bound"
    );
    let consent: Consent = serde_json::from_slice(&payload)?;
    consent.validate()?;
    let mut message = DOMAIN.to_vec();
    message.extend(payload);
    for (key, signature) in [
        (&consent.source.device_key, &signed.source_signature),
        (
            &consent.destination.device_key,
            &signed.destination_signature,
        ),
    ] {
        VerifyingKey::from_bytes(&protocol::hex_bytes::<32>(key)?)?.verify_strict(
            &message,
            &Signature::from_bytes(&protocol::hex_bytes::<64>(signature)?),
        )?;
    }
    ensure!(
        (network == consent.source.network && device == consent.source.device_key)
            || (network == consent.destination.network && device == consent.destination.device_key),
        "configuration is not a consented bridge endpoint"
    );
    Ok(
        json!({"type":"BridgeConsent","agreementId":consent.agreement_id,"profile":hex::encode(Sha256::digest(&bytes)),"expires":consent.expires,"certificate":certificate,"document":URL_SAFE_NO_PAD.encode(bytes)}),
    )
}
