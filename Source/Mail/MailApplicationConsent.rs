// SPDX-License-Identifier: MIT
// Ordinary Mail confirmation binds one immutable letter and exact mailbox revisions.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SendConsent {
    pub content_digest: String,
    pub sender_record: String,
    pub recipient_record: String,
    pub sender_manifest: String,
    pub recipient_manifest: String,
    pub recipient_owner: String,
    pub recipient_generation: u64,
    pub store: String,
    pub required_copies: u16,
}

pub(super) fn reference(value: &VersionRef) -> Result<String> {
    Ok(hex::encode(wire::encode(
        &crate::authority_membership::reference(value),
    )?))
}
pub(super) fn content(job: &Outgoing) -> Result<String> {
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&(
        &job.id,
        &job.mailbox,
        &job.recipient,
        job.expires,
        &job.subject,
        &job.body,
    ))?);
    Ok(hex::encode(wire::digest(&bytes)))
}
impl SendConsent {
    pub(super) fn validate(&self, job: &Outgoing, store: &str) -> Result<()> {
        ensure!(
            self.content_digest == content(job)? && self.store == store,
            "confirmed letter or destination changed; review the exact message again"
        );
        Ok(())
    }
    pub(super) fn mailboxes(
        &self,
        sender: &mail::Mailbox,
        sender_ref: &VersionRef,
        recipient: &mail::Mailbox,
        recipient_ref: &VersionRef,
    ) -> Result<()> {
        ensure!(
            self.sender_record == reference(sender_ref)?
                && self.recipient_record == reference(recipient_ref)?
                && self.sender_manifest == hex::encode(sender.publication.digest)
                && self.recipient_manifest == hex::encode(recipient.publication.digest)
                && self.recipient_owner == recipient.publication.manifest.owner_key
                && self.recipient_generation == recipient.publication.manifest.generation,
            "confirmed mailbox revision or contact changed; review the exact message again"
        );
        Ok(())
    }
    pub(super) fn claim(&self, claim: &mail::Claim) -> Result<()> {
        ensure!(
            self.sender_record == reference(&claim.sender)?
                && self.recipient_record == reference(&claim.recipient)?,
            "mail claim differs from the confirmed mailbox revisions"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
}
