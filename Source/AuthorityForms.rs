// SPDX-License-Identifier: MIT
// Explicitly reviewed forms use current publications and the separately scoped encrypted Mail workflow.
use super::*;
use crate::{
    authority_pages::{
        Client as PageClient,
        publication::{self, Identity as PublicationIdentity},
    },
    markup,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[path = "AuthorityFormsModel.rs"]
mod model;
use model::*;
pub use model::{Accepted, Consent, LedgerEntry, Prepared, Review};
#[path = "AuthorityFormsWorkflow.rs"]
mod operations;
pub(crate) use operations::{accept, confirm, prepare, receive, send};
#[path = "AuthorityFormsCli.rs"]
mod cli;
pub use cli::{Arguments, run};

#[derive(Clone, Args)]
pub struct Access {
    /// Separate requester floor for the selected Mail device.
    #[arg(id = "mail_directory", long = "mail-directory")]
    pub directory: PathBuf,
    #[arg(long)]
    pub vault: PathBuf,
    #[arg(long)]
    pub age_key: PathBuf,
    #[arg(long)]
    pub mailbox: String,
}
impl Access {
    pub(crate) fn device(&self, location: &Location, socket: &Path) -> DeviceOnline {
        DeviceOnline {
            location: location.with_directory(self.directory.clone()),
            vault: VaultLocation {
                vault: self.vault.clone(),
                age_key: self.age_key.clone(),
            },
            mailbox: self.mailbox.clone(),
            socket: socket.into(),
        }
    }
}
pub(super) fn validate_outgoing(job: &Outgoing) -> Result<()> {
    if let Some(consent) = &job.form_consent {
        consent.validate(job)?;
    }
    Ok(())
}
pub(super) fn guard_mailboxes(
    job: &Outgoing,
    sender: &mail::Mailbox,
    sender_ref: &VersionRef,
    recipient: &mail::Mailbox,
    recipient_ref: &VersionRef,
) -> Result<()> {
    if let Some(consent) = &job.form_consent {
        consent.validate(job)?;
        ensure!(
            publication::reference(sender_ref)? == consent.review.sender_record
                && publication::reference(recipient_ref)? == consent.review.recipient_record
                && hex::encode(sender.publication.digest) == consent.review.sender_manifest_digest
                && hex::encode(recipient.publication.digest)
                    == consent.review.recipient_manifest_digest,
            "confirmed form mailbox or placement changed; prepare and confirm a new submission"
        );
    }
    Ok(())
}
pub(super) fn guard_claim(job: &Outgoing, claim: &mail::Claim) -> Result<()> {
    if let Some(consent) = &job.form_consent {
        consent.validate(job)?;
        ensure!(
            publication::reference(&claim.sender)? == consent.review.sender_record
                && publication::reference(&claim.recipient)? == consent.review.recipient_record
                && hex::encode(claim.device) == consent.review.sender_request_key
                && claim.expires
                    == consent
                        .review
                        .expires
                        .checked_mul(1000)
                        .context("form expiry overflow")?,
            "mail claim differs from the exact confirmed form consent"
        );
    }
    Ok(())
}
#[cfg(test)]
#[path = "AuthorityFormsTests.rs"]
mod tests;
