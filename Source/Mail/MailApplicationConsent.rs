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
#[path = "../../Tests/Unit/Mail/MailApplicationConsentUnitTests.rs"]
mod tests;
