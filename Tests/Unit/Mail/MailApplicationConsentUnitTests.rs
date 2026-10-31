// SPDX-License-Identifier: MIT
// Unit tests for MailApplicationConsent.
use super::*;
fn outgoing() -> Outgoing {
    Outgoing {
        mailbox: "Inbox".into(),
        recipient: "Recipient".into(),
        id: "Message".into(),
        expires: 1000,
        subject: "Subject".into(),
        body: "Exact private body".into(),
        packages: vec![],
        claim: None,
        sender_manifest: None,
        recipient_manifest: None,
        ciphertext: None,
        receipts: BTreeMap::new(),
        form_consent: None,
        send_consent: None,
    }
}
fn consent(job: &Outgoing) -> SendConsent {
    SendConsent {
        content_digest: content(job).unwrap(),
        sender_record: "SenderRecord".into(),
        recipient_record: "RecipientRecord".into(),
        sender_manifest: "SenderManifest".into(),
        recipient_manifest: "RecipientManifest".into(),
        recipient_owner: "Owner".into(),
        recipient_generation: 1,
        store: "Store".into(),
        required_copies: 1,
    }
}
#[test]
fn native_mail_consent_rejects_content_recipient_expiry_and_store_changes() {
    let original = outgoing();
    let accepted = consent(&original);
    accepted.validate(&original, "Store").unwrap();
    for change in 0..7 {
        let mut changed = outgoing();
        match change {
            0 => changed.body.push('!'),
            1 => changed.subject.push('!'),
            2 => changed.recipient.push('!'),
            3 => changed.mailbox.push('!'),
            4 => changed.id.push('!'),
            5 => changed.expires += 1,
            _ => {}
        }
        assert!(
            accepted
                .validate(&changed, if change == 6 { "OtherStore" } else { "Store" })
                .is_err()
        );
    }
    let mut resumed = outgoing();
    resumed.receipts.insert("Store".into(), "Receipt".into());
    accepted.validate(&resumed, "Store").unwrap();
    let mut old = serde_json::to_value(&original).unwrap();
    old.as_object_mut().unwrap().remove("sendConsent");
    assert!(
        serde_json::from_value::<Outgoing>(old)
            .unwrap()
            .send_consent
            .is_none()
    );
}
#[test]
fn native_mail_consent_rejects_mailbox_change_between_review_and_claim() {
    let sender = VersionRef {
        kind: 137,
        id: [1; 32],
        generation: 2,
        digest: [2; 32],
    };
    let recipient = VersionRef {
        kind: 137,
        id: [3; 32],
        generation: 4,
        digest: [4; 32],
    };
    let mut accepted = consent(&outgoing());
    accepted.sender_record = reference(&sender).unwrap();
    accepted.recipient_record = reference(&recipient).unwrap();
    let claim = mail::Claim {
        sender,
        recipient,
        device: [5; 32],
        packages: vec![],
        expires: 1000,
        creation: [6; 32],
        payload_digest: None,
        payload_bytes: 0,
        binding: None,
        placement: vec![],
        created_ms: 100,
    };
    accepted.claim(&claim).unwrap();
    let mut changed = claim.clone();
    changed.recipient.generation += 1;
    assert!(accepted.claim(&changed).is_err());
    let mut forked = claim.clone();
    forked.recipient.digest = [9; 32];
    assert!(accepted.claim(&forked).is_err());
    let mut sender_changed = claim;
    sender_changed.sender.generation += 1;
    assert!(accepted.claim(&sender_changed).is_err());
}
