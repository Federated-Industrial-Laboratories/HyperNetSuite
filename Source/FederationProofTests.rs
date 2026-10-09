// SPDX-License-Identifier: MIT
// Reject forged scope, substituted author approval and stale bilateral permission.
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

fn key(seed: u8) -> String {
    hex::encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}
fn signed(seed: u8, domain: &[u8], payload: Value) -> Evidence {
    let payload = serde_json::to_vec(&payload).unwrap();
    let mut message = domain.to_vec();
    message.extend(&payload);
    Evidence {
        public_key: key(seed),
        payload: URL_SAFE_NO_PAD.encode(payload),
        signature: hex::encode(
            SigningKey::from_bytes(&[seed; 32])
                .sign(&message)
                .to_bytes(),
        ),
    }
}
fn request(network: &str, seed: u8, command: Value) -> Envelope {
    let mut domain = b"HyperNet/Request/1\0".to_vec();
    domain.extend(protocol::hex_bytes::<32>(network).unwrap());
    domain.extend(protocol::hex_bytes::<32>(&key(seed)).unwrap());
    let proof = signed(
        seed,
        &domain,
        json!({"version":1,"requestId":"01".repeat(16),"issuedAt":1,"command":command}),
    );
    Envelope {
        network: network.into(),
        public_key: proof.public_key,
        payload: proof.payload,
        signature: proof.signature,
    }
}
fn fixture(now: u64) -> (Treaty, Value) {
    let treaty = Treaty {
        version: 2,
        media_profiles: Vec::new(),
        media_source_hosts: Vec::new(),
        media_destination_hosts: Vec::new(),
        media_max_bytes: 0,
        media_required_copies: 0,
        agreement_id: "03".repeat(16),
        source_network: "01".repeat(32),
        destination_network: "02".repeat(32),
        source_authority_key: key(10),
        destination_authority_key: key(11),
        source_bridge_key: key(12),
        destination_bridge_key: key(13),
        source_namespace: "News".into(),
        destination_namespace: "Partner".into(),
        service: "Pages".into(),
        profile: markup::PROFILE.into(),
        expires: now + 3600,
    };
    let page = "04".repeat(16);
    let body = "HyperNetPage/2\n# Shared\n: Exact authorised bytes.\n";
    let body_digest = hex::encode(Sha256::digest(body));
    let submission = request(
        &treaty.source_network,
        3,
        json!({"type":"PageSubmit","pageId":page,"expectedVersion":0,"namespace":"News","audience":"Members","profile":markup::PROFILE,"digest":body_digest,"body":body}),
    );
    let (_, submission_digest) =
        page_proof::envelope::<Value>(&treaty.source_network, &submission).unwrap();
    let approval = request(
        &treaty.source_network,
        5,
        json!({"type":"PageReview","pageId":page,"expectedVersion":1,"revision":1,"digest":body_digest,"profile":markup::PROFILE,"author":key(3),"namespace":"News","audience":"Members","submissionDigest":submission_digest,"decision":"Approve"}),
    );
    let (_, approval_digest) =
        page_proof::envelope::<Value>(&treaty.source_network, &approval).unwrap();
    let descriptor = Descriptor {
        page_id: page.clone(),
        publication_version: 2,
        revision: 1,
        author: key(3),
        reviewer: key(5),
        namespace: "News".into(),
        audience: "Members".into(),
        profile: markup::PROFILE.into(),
        digest: body_digest,
        submission_digest,
        approval_digest,
    };
    let share = request(
        &treaty.source_network,
        3,
        json!({"type":"FederationShare","agreementId":treaty.agreement_id,"agreementDigest":treaty.digest().unwrap(),"pageId":page,"publicationVersion":2,"descriptorDigest":descriptor_digest(&descriptor).unwrap(),"allow":true}),
    );
    let (_, share_digest) = page_proof::envelope::<Value>(&treaty.source_network, &share).unwrap();
    let local_approval = request(
        &treaty.destination_network,
        6,
        json!({"type":"FederationReview","agreementId":treaty.agreement_id,"pageId":page,"expectedVersion":1,"descriptorDigest":descriptor_digest(&descriptor).unwrap(),"decision":"Approve"}),
    );
    let admission = signed(
        11,
        b"HyperNet/FederationAdmission/1\0",
        json!({"version":1,"agreementDigest":treaty.digest().unwrap(),"sourceNetwork":treaty.source_network,"destinationNetwork":treaty.destination_network,"sourceBridgeKey":key(12),"destinationBridgeKey":key(13),"destinationProfile":"05".repeat(32),"requestId":"06".repeat(16),"authorityRevision":7,"issuedAt":now,"validUntil":now+5}),
    );
    let (_, admission_digest) =
        evidence::<Admission>(&admission, &key(11), b"HyperNet/FederationAdmission/1\0").unwrap();
    let export = signed(
        10,
        b"HyperNet/FederationExport/1\0",
        json!({"version":1,"agreementDigest":treaty.digest().unwrap(),"admissionDigest":admission_digest,"descriptor":descriptor,"authorShareDigest":share_digest,"sourceProfile":"05".repeat(32),"authorityRevision":8,"issuedAt":now,"validUntil":now+5}),
    );
    let result = json!({"treaty":treaty,"agreementDigest":treaty.digest().unwrap(),"descriptor":descriptor,"bundle":Bundle{submission,approval},"authorShare":share,"approval":local_approval,"admission":admission,"export":export,"authorityRevision":9,"validUntil":now+5});
    (treaty, result)
}

#[test]
fn foreign_read_requires_all_three_content_permissions() {
    let (treaty, result) = fixture(crate::now().unwrap());
    let page = "04".repeat(16);
    let verify = |v: &Value| read(&treaty.destination_network, &treaty.agreement_id, &page, v);
    assert!(
        verify(&result)
            .unwrap()
            .body
            .contains("Exact authorised bytes.")
    );
    for field in ["authorShare", "approval", "admission", "export"] {
        let mut changed = result.clone();
        changed[field]["signature"] = json!("00".repeat(64));
        assert!(verify(&changed).is_err(), "{field}");
    }
    let share_command = serde_json::from_slice::<Value>(
        &URL_SAFE_NO_PAD
            .decode(result["authorShare"]["payload"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap()["command"]
        .clone();
    let mut changed = result.clone();
    changed["authorShare"] = json!(request(&treaty.source_network, 5, share_command));
    assert!(
        verify(&changed).is_err(),
        "source reviewer cannot replace author opt-in"
    );
    let mut changed = result.clone();
    changed["treaty"]["destinationNamespace"] = json!("Other");
    assert!(
        verify(&changed).is_err(),
        "namespace is part of exact bilateral terms"
    );
    assert!(read(&treaty.source_network, &treaty.agreement_id, &page, &result).is_err());
    assert!(
        read(
            &treaty.destination_network,
            &"08".repeat(16),
            &page,
            &result
        )
        .is_err()
    );
}

#[test]
fn signed_leases_cannot_cross_time_domain_or_admission() {
    let now = 1000;
    let (treaty, result) = fixture(now);
    let descriptor = serde_json::from_value(result["descriptor"].clone()).unwrap();
    let admission: Evidence = serde_json::from_value(result["admission"].clone()).unwrap();
    let export: Evidence = serde_json::from_value(result["export"].clone()).unwrap();
    let share = serde_json::from_value(result["authorShare"].clone()).unwrap();
    let (_, share_digest) = page_proof::envelope::<Value>(&treaty.source_network, &share).unwrap();
    let check =
        |a: &Evidence, e: &Evidence, at| freshness(&treaty, &descriptor, &share_digest, a, e, at);
    assert_eq!(check(&admission, &export, now).unwrap(), now + 5);
    assert!(check(&admission, &export, now - 1).is_err());
    assert!(check(&admission, &export, now + 5).is_err());
    let mut payload: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&admission.payload).unwrap()).unwrap();
    payload["requestId"] = json!("09".repeat(16));
    let substituted = signed(11, b"HyperNet/FederationAdmission/1\0", payload.clone());
    assert!(
        check(&substituted, &export, now).is_err(),
        "export binds one exact permit"
    );
    let wrong_domain = signed(11, b"HyperNet/FederationExport/1\0", payload);
    assert!(check(&wrong_domain, &export, now).is_err());
    let mut payload: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&export.payload).unwrap()).unwrap();
    payload["validUntil"] = json!(now + 6);
    assert!(
        check(
            &admission,
            &signed(10, b"HyperNet/FederationExport/1\0", payload),
            now
        )
        .is_err()
    );
}
