// SPDX-License-Identifier: MIT
// Independently verify bilateral terms, author sharing and fresh cross-network evidence.
use crate::{
    markup,
    page_proof::{self, Bundle, Descriptor, Envelope},
    protocol,
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Treaty {
    pub version: u32,
    pub agreement_id: String,
    pub source_network: String,
    pub destination_network: String,
    pub source_authority_key: String,
    pub destination_authority_key: String,
    pub source_bridge_key: String,
    pub destination_bridge_key: String,
    pub source_namespace: String,
    pub destination_namespace: String,
    pub service: String,
    pub profile: String,
    pub expires: u64,
}

impl Treaty {
    pub fn validate(&self) -> Result<()> {
        protocol::hex_bytes::<16>(&self.agreement_id)?;
        protocol::hex_bytes::<32>(&self.source_network)?;
        protocol::hex_bytes::<32>(&self.destination_network)?;
        let mut keys = std::collections::BTreeSet::new();
        for key in [
            &self.source_authority_key,
            &self.destination_authority_key,
            &self.source_bridge_key,
            &self.destination_bridge_key,
        ] {
            protocol::hex_bytes::<32>(key)?;
            ensure!(
                keys.insert(key),
                "federation keys must have distinct purposes and identities"
            );
        }
        ensure!(
            self.version == 1
                && self.source_network != self.destination_network
                && self.service == "Pages"
                && self.profile == markup::PROFILE
                && self.expires > 0
                && markup::namespace(&self.source_namespace)
                && markup::namespace(&self.destination_namespace),
            "invalid federation treaty"
        );
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest(b"HyperNet/FederationTreaty/1\0", self)
    }
}

pub fn digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String> {
    let mut message = domain.to_vec();
    message.extend(serde_json::to_vec(value)?);
    Ok(hex::encode(Sha256::digest(message)))
}
pub fn descriptor_digest(value: &Descriptor) -> Result<String> {
    digest(b"HyperNet/FederationPage/1\0", value)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Evidence {
    pub public_key: String,
    pub payload: String,
    pub signature: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Admission {
    pub version: u32,
    pub agreement_digest: String,
    pub source_network: String,
    pub destination_network: String,
    pub source_bridge_key: String,
    pub destination_bridge_key: String,
    pub destination_profile: String,
    pub request_id: String,
    pub authority_revision: u64,
    pub issued_at: u64,
    pub valid_until: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Export {
    pub version: u32,
    pub agreement_digest: String,
    pub admission_digest: String,
    pub descriptor: Descriptor,
    pub author_share_digest: String,
    pub source_profile: String,
    pub authority_revision: u64,
    pub issued_at: u64,
    pub valid_until: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Share {
    #[serde(rename = "type")]
    kind: String,
    agreement_id: String,
    agreement_digest: String,
    page_id: String,
    publication_version: u64,
    descriptor_digest: String,
    allow: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Review {
    #[serde(rename = "type")]
    kind: String,
    agreement_id: String,
    page_id: String,
    expected_version: u64,
    descriptor_digest: String,
    decision: String,
}

pub fn evidence<T: DeserializeOwned>(
    value: &Evidence,
    key: &str,
    domain: &[u8],
) -> Result<(T, String)> {
    ensure!(
        value.public_key == key,
        "federation evidence signer mismatch"
    );
    ensure!(
        value.payload.len() <= 8192,
        "federation evidence exceeds its bound"
    );
    let bytes = URL_SAFE_NO_PAD.decode(&value.payload)?;
    ensure!(bytes.len() <= 4096, "federation evidence exceeds its bound");
    let mut message = domain.to_vec();
    message.extend(&bytes);
    VerifyingKey::from_bytes(&protocol::hex_bytes::<32>(key)?)?.verify_strict(
        &message,
        &Signature::from_bytes(&protocol::hex_bytes::<64>(&value.signature)?),
    )?;
    Ok((
        serde_json::from_slice(&bytes)?,
        hex::encode(Sha256::digest(message)),
    ))
}

fn lease(issued: u64, until: u64, revision: u64, now: u64) -> Result<()> {
    ensure!(
        issued <= now && until > now && until <= issued.saturating_add(5) && revision > 0,
        "federation authority evidence is stale or invalid"
    );
    Ok(())
}

pub fn artifact(
    treaty: &Treaty,
    descriptor: &Descriptor,
    bundle: &Bundle,
    author_share: &Envelope,
) -> Result<(String, String)> {
    let treaty_digest = treaty.digest()?;
    ensure!(
        descriptor.namespace == treaty.source_namespace && descriptor.profile == treaty.profile,
        "foreign publication is outside treaty scope"
    );
    let body = page_proof::verify(&treaty.source_network, descriptor, bundle)?;
    let (share, share_digest) =
        page_proof::envelope::<Share>(&treaty.source_network, author_share)?;
    let share = share.command;
    ensure!(
        author_share.public_key == descriptor.author
            && share.kind == "FederationShare"
            && share.allow
            && share.agreement_id == treaty.agreement_id
            && share.agreement_digest == treaty_digest
            && share.page_id == descriptor.page_id
            && share.publication_version == descriptor.publication_version
            && share.descriptor_digest == descriptor_digest(descriptor)?,
        "author did not share this exact page with this agreement"
    );
    Ok((body, share_digest))
}

pub fn freshness(
    treaty: &Treaty,
    descriptor: &Descriptor,
    share_digest: &str,
    admission: &Evidence,
    export: &Evidence,
    now: u64,
) -> Result<u64> {
    let treaty_digest = treaty.digest()?;
    ensure!(treaty.expires > now, "federation agreement has expired");
    let (permit, permit_digest) = evidence::<Admission>(
        admission,
        &treaty.destination_authority_key,
        b"HyperNet/FederationAdmission/1\0",
    )?;
    lease(
        permit.issued_at,
        permit.valid_until,
        permit.authority_revision,
        now,
    )?;
    protocol::hex_bytes::<32>(&permit.destination_profile)?;
    protocol::hex_bytes::<16>(&permit.request_id)?;
    ensure!(
        permit.version == 1
            && permit.agreement_digest == treaty_digest
            && permit.source_network == treaty.source_network
            && permit.destination_network == treaty.destination_network
            && permit.source_bridge_key == treaty.source_bridge_key
            && permit.destination_bridge_key == treaty.destination_bridge_key
            && permit.valid_until <= treaty.expires,
        "destination admission is outside treaty scope"
    );
    let (permission, _) = evidence::<Export>(
        export,
        &treaty.source_authority_key,
        b"HyperNet/FederationExport/1\0",
    )?;
    lease(
        permission.issued_at,
        permission.valid_until,
        permission.authority_revision,
        now,
    )?;
    protocol::hex_bytes::<32>(&permission.source_profile)?;
    ensure!(
        permission.version == 1
            && permission.agreement_digest == treaty_digest
            && permission.admission_digest == permit_digest
            && descriptor_digest(&permission.descriptor)? == descriptor_digest(descriptor)?
            && permission.author_share_digest == share_digest
            && permission.source_profile == permit.destination_profile
            && permission.valid_until <= permit.valid_until,
        "source export does not bind this admission and exact shared publication"
    );
    Ok(permission.valid_until)
}

pub struct Publication {
    pub treaty: Treaty,
    pub descriptor: Descriptor,
    pub body: String,
    pub reviewer: String,
    pub authority_revision: u64,
}

pub fn read(network: &str, agreement: &str, page_id: &str, result: &Value) -> Result<Publication> {
    let treaty: Treaty = serde_json::from_value(result["treaty"].clone())?;
    ensure!(
        treaty.destination_network == network
            && treaty.agreement_id == agreement
            && result["agreementDigest"].as_str() == Some(&treaty.digest()?),
        "foreign page belongs to another agreement or destination"
    );
    let descriptor: Descriptor = serde_json::from_value(result["descriptor"].clone())?;
    ensure!(
        descriptor.page_id == page_id,
        "authority returned another foreign page"
    );
    let bundle: Bundle = serde_json::from_value(result["bundle"].clone())?;
    let share: Envelope = serde_json::from_value(result["authorShare"].clone())?;
    let (body, share_digest) = artifact(&treaty, &descriptor, &bundle, &share)?;
    let approval: Envelope = serde_json::from_value(result["approval"].clone())?;
    let (review, _) = page_proof::envelope::<Review>(network, &approval)?;
    let review = review.command;
    ensure!(
        review.kind == "FederationReview"
            && review.decision == "Approve"
            && review.agreement_id == agreement
            && review.page_id == page_id
            && review.descriptor_digest == descriptor_digest(&descriptor)?
            && review.expected_version > 0
            && review.expected_version.checked_add(1).is_some(),
        "foreign page lacks exact local approval"
    );
    let admission: Evidence = serde_json::from_value(result["admission"].clone())?;
    let export: Evidence = serde_json::from_value(result["export"].clone())?;
    let until = freshness(
        &treaty,
        &descriptor,
        &share_digest,
        &admission,
        &export,
        crate::now()?,
    )?;
    let revision = page_proof::fresh(result)?;
    ensure!(
        result["validUntil"]
            .as_u64()
            .is_some_and(|value| value <= until),
        "local freshness exceeds bilateral permission"
    );
    Ok(Publication {
        treaty,
        descriptor,
        body,
        reviewer: approval.public_key,
        authority_revision: revision,
    })
}

#[cfg(test)]
#[path = "FederationProofTests.rs"]
mod tests;
