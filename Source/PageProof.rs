// SPDX-License-Identifier: MIT
// Verify immutable page evidence independently of the authority implementation.
use crate::{markup, protocol};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Envelope {
    pub network: String,
    pub public_key: String,
    pub payload: String,
    pub signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request<T> {
    pub version: u32,
    pub request_id: String,
    pub issued_at: u64,
    pub command: T,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Submission {
    #[serde(rename = "type")]
    pub kind: String,
    pub page_id: String,
    pub expected_version: u64,
    pub namespace: String,
    pub audience: String,
    pub profile: String,
    pub digest: String,
    pub body: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Review {
    #[serde(rename = "type")]
    kind: String,
    page_id: String,
    expected_version: u64,
    revision: u64,
    digest: String,
    profile: String,
    author: String,
    namespace: String,
    audience: String,
    submission_digest: String,
    decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    application_policy_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    application_review_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    review_expires: Option<u64>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Descriptor {
    pub page_id: String,
    pub publication_version: u64,
    pub revision: u64,
    pub author: String,
    pub reviewer: String,
    pub namespace: String,
    pub audience: String,
    pub profile: String,
    pub digest: String,
    pub submission_digest: String,
    pub approval_digest: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub submission: Envelope,
    pub approval: Envelope,
}

pub fn envelope<T: DeserializeOwned>(
    network: &str,
    proof: &Envelope,
) -> Result<(Request<T>, String)> {
    ensure!(
        proof.network == network,
        "page proof belongs to another network"
    );
    let bytes = URL_SAFE_NO_PAD.decode(&proof.payload)?;
    ensure!(bytes.len() <= 65536, "page proof exceeds its bound");
    let public = protocol::hex_bytes::<32>(&proof.public_key)?;
    let mut message = b"HyperNet/Request/1\0".to_vec();
    message.extend_from_slice(&protocol::hex_bytes::<32>(network)?);
    message.extend_from_slice(&public);
    message.extend_from_slice(&bytes);
    VerifyingKey::from_bytes(&public)?.verify_strict(
        &message,
        &Signature::from_bytes(&protocol::hex_bytes::<64>(&proof.signature)?),
    )?;
    let request: Request<T> = serde_json::from_slice(&bytes)?;
    ensure!(request.version == 1, "unsupported page proof version");
    protocol::hex_bytes::<16>(&request.request_id)?;
    // Archive timestamps establish provenance only. Fresh publication authority is separate.
    ensure!(request.issued_at > 0, "invalid page proof timestamp");
    Ok((request, hex::encode(Sha256::digest(message))))
}

pub fn submission(network: &str, proof: &Envelope) -> Result<(Submission, String)> {
    let (request, digest) = envelope::<Submission>(network, proof)?;
    let value = request.command;
    ensure!(
        value.kind == "PageSubmit"
            && value.profile == markup::PROFILE
            && value.audience == "Members"
            && markup::namespace(&value.namespace),
        "invalid page submission scope"
    );
    protocol::hex_bytes::<16>(&value.page_id)?;
    protocol::hex_bytes::<32>(&value.digest)?;
    ensure!(
        value.expected_version.checked_add(1).is_some(),
        "page version overflow"
    );
    markup::validate_profile(&value.profile, &value.body).map_err(anyhow::Error::msg)?;
    ensure!(
        hex::encode(Sha256::digest(value.body.as_bytes())) == value.digest,
        "page source digest mismatch"
    );
    Ok((value, digest))
}

pub fn verify(network: &str, descriptor: &Descriptor, bundle: &Bundle) -> Result<String> {
    ensure!(
        serde_json::to_vec(bundle)?.len() <= 56 * 1024,
        "page bundle exceeds its bound"
    );
    let (source, source_digest) = submission(network, &bundle.submission)?;
    let (approval, approval_digest) = envelope::<Review>(network, &bundle.approval)?;
    let approval = approval.command;
    ensure!(
        approval.review_expires.is_none_or(|value| value > 0),
        "invalid review deadline"
    );
    match (
        &approval.application_policy_digest,
        &approval.application_review_mode,
    ) {
        (None, None) => {}
        (Some(digest), Some(mode)) => {
            ensure!(
                approval.review_expires.is_some(),
                "application approval lacks review deadline"
            );
            protocol::hex_bytes::<32>(digest)?;
            ensure!(
                mode == "Manual" || mode == "Automatic",
                "invalid application review mode"
            );
        }
        _ => anyhow::bail!("incomplete application review policy"),
    }
    ensure!(
        approval.kind == "PageReview" && approval.decision == "Approve",
        "page lacks approval evidence"
    );
    ensure!(
        source.page_id == descriptor.page_id
            && approval.page_id == descriptor.page_id
            && bundle.submission.public_key == descriptor.author
            && approval.author == descriptor.author
            && bundle.approval.public_key == descriptor.reviewer
            && source.namespace == descriptor.namespace
            && approval.namespace == descriptor.namespace
            && source.audience == descriptor.audience
            && approval.audience == descriptor.audience
            && source.profile == descriptor.profile
            && approval.profile == descriptor.profile
            && source.digest == descriptor.digest
            && approval.digest == descriptor.digest
            && source_digest == descriptor.submission_digest
            && approval.submission_digest == source_digest
            && approval_digest == descriptor.approval_digest
            && source.expected_version.checked_add(1) == Some(descriptor.revision)
            && approval.revision == descriptor.revision
            && approval.expected_version >= approval.revision
            && approval.expected_version.checked_add(1) == Some(descriptor.publication_version),
        "page approval does not bind this publication"
    );
    let document = markup::parse(&source.body).map_err(anyhow::Error::msg)?;
    ensure!(
        document.forms.is_empty()
            || serde_json::to_vec(bundle)?.len() <= markup::forms::MAX_BUNDLE_BYTES,
        "form page bundle exceeds 20 KiB"
    );
    Ok(source.body)
}

pub fn fresh(result: &serde_json::Value) -> Result<u64> {
    let now = crate::now()?;
    let until = result["validUntil"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("missing publication freshness"))?;
    let revision = result["authorityRevision"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("missing authority revision"))?;
    ensure!(
        until >= now && until <= now.saturating_add(5) && revision > 0,
        "publication status is stale or invalid"
    );
    Ok(revision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{Value, json};

    fn proof(seed: u8, command: Value) -> Envelope {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let payload = serde_json::to_vec(
            &json!({"version":1,"requestId":"02".repeat(16),"issuedAt":1,"command":command}),
        )
        .unwrap();
        let public = key.verifying_key().to_bytes();
        let mut message = b"HyperNet/Request/1\0".to_vec();
        message.extend([1; 32]);
        message.extend(public);
        message.extend(&payload);
        Envelope {
            network: "01".repeat(32),
            public_key: hex::encode(public),
            payload: URL_SAFE_NO_PAD.encode(payload),
            signature: hex::encode(key.sign(&message).to_bytes()),
        }
    }

    #[test]
    fn archived_proofs_bind_exact_content_reviewer_and_scope() {
        let network = "01".repeat(32);
        let body = "HyperNetPage/2\n# Example\n: Exact reviewed content.\n";
        let source = proof(
            3,
            json!({"type":"PageSubmit","pageId":"04".repeat(16),"expectedVersion":0,"namespace":"News","audience":"Members","profile":markup::PROFILE,"digest":hex::encode(Sha256::digest(body)),"body":body}),
        );
        let (submission, source_digest) = submission(&network, &source).unwrap();
        let review_command = json!({"type":"PageReview","pageId":submission.page_id,"expectedVersion":1,"revision":1,"digest":submission.digest,"profile":markup::PROFILE,"author":source.public_key,"namespace":"News","audience":"Members","submissionDigest":source_digest,"decision":"Approve"});
        let approval = proof(5, review_command.clone());
        let (_, approval_digest) = envelope::<Review>(&network, &approval).unwrap();
        let descriptor = Descriptor {
            page_id: submission.page_id,
            publication_version: 2,
            revision: 1,
            author: source.public_key.clone(),
            reviewer: approval.public_key.clone(),
            namespace: "News".into(),
            audience: "Members".into(),
            profile: markup::PROFILE.into(),
            digest: submission.digest,
            submission_digest: source_digest,
            approval_digest,
        };
        let bundle = Bundle {
            submission: source,
            approval,
        };
        assert_eq!(verify(&network, &descriptor, &bundle).unwrap(), body);
        assert!(verify(&"06".repeat(32), &descriptor, &bundle).is_err());
        for field in [
            "pageId",
            "publicationVersion",
            "revision",
            "author",
            "reviewer",
            "namespace",
            "audience",
            "profile",
            "digest",
            "submissionDigest",
            "approvalDigest",
        ] {
            let mut changed = serde_json::to_value(&descriptor).unwrap();
            changed[field] = if changed[field].is_number() {
                json!(9)
            } else {
                json!("wrong")
            };
            assert!(
                verify(&network, &serde_json::from_value(changed).unwrap(), &bundle).is_err(),
                "{field}"
            );
        }
        let mut tampered = bundle.clone();
        tampered.submission.signature = "00".repeat(64);
        assert!(verify(&network, &descriptor, &tampered).is_err());
        let mut rejected = review_command.clone();
        rejected["decision"] = json!("Reject");
        tampered.approval = proof(5, rejected);
        tampered.submission = bundle.submission.clone();
        assert!(verify(&network, &descriptor, &tampered).is_err());
        let mut application_review = review_command.clone();
        application_review["applicationPolicyDigest"] = json!("07".repeat(32));
        application_review["applicationReviewMode"] = json!("Automatic");
        let mut application_bundle = bundle.clone();
        let mut application_descriptor = descriptor.clone();
        application_bundle.approval = proof(5, application_review.clone());
        application_descriptor.approval_digest =
            envelope::<Review>(&network, &application_bundle.approval)
                .unwrap()
                .1;
        assert!(verify(&network, &application_descriptor, &application_bundle).is_err());
        // Historical expiry does not invalidate a signature; live authority controls present reads.
        application_review["reviewExpires"] = json!(50);
        application_bundle.approval = proof(5, application_review);
        application_descriptor.approval_digest =
            envelope::<Review>(&network, &application_bundle.approval)
                .unwrap()
                .1;
        assert_eq!(
            verify(&network, &application_descriptor, &application_bundle).unwrap(),
            body
        );
        let mut unknown = review_command;
        unknown["execute"] = json!("never");
        assert!(envelope::<Review>(&network, &proof(5, unknown)).is_err());
        let mut extra = serde_json::to_value(&bundle).unwrap();
        extra["body"] = json!(body);
        assert!(serde_json::from_value::<Bundle>(extra).is_err());
    }

    #[test]
    fn archive_proof_is_not_fresh_publication_authority() {
        let now = crate::now().unwrap();
        assert!(fresh(&json!({"validUntil":now+5,"authorityRevision":1})).is_ok());
        for value in [
            json!({}),
            json!({"validUntil":now-1,"authorityRevision":1}),
            json!({"validUntil":now+6,"authorityRevision":1}),
            json!({"validUntil":now,"authorityRevision":0}),
        ] {
            assert!(fresh(&value).is_err());
        }
    }
}
