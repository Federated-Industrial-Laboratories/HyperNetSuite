// SPDX-License-Identifier: MIT
// Form payloads bind exact native publication bytes, every reviewed value and the authenticated Mail route.
use super::*;
pub(super) const PROFILE: &str = "HyperNetFormSubmission/1";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Review {
    pub review_id: String,
    pub submission_id: String,
    pub publication: PublicationIdentity,
    pub sender_address: String,
    pub sender_device: String,
    pub sender_request_key: String,
    pub sender_record: String,
    pub sender_manifest_digest: String,
    pub recipient_address: String,
    pub recipient_owner: String,
    pub recipient_record: String,
    pub recipient_manifest_digest: String,
    pub recipient_generation: u64,
    pub form_id: String,
    pub form_label: String,
    pub schema_digest: String,
    pub values: BTreeMap<String, Value>,
    pub expires: u64,
    pub storage_hosts: Vec<String>,
    pub required_copies: u16,
    pub retention_seconds: u64,
    pub private: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Prepared {
    pub review: Review,
    pub mailbox: String,
    pub bundle: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Consent {
    pub review: Review,
    pub payload_digest: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Accepted {
    pub publication: PublicationIdentity,
    pub form_id: String,
    pub schema_digest: String,
    pub recipient_address: String,
    pub recipient_owner: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LedgerEntry {
    pub payload_digest: String,
    pub accepted_record: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Submission {
    pub profile: String,
    pub submission_id: String,
    pub publication: PublicationIdentity,
    pub sender_address: String,
    pub sender_device: String,
    pub recipient_address: String,
    pub recipient_manifest_digest: String,
    pub expires: u64,
    pub bundle: String,
    pub form_id: String,
    pub schema_digest: String,
    pub values: BTreeMap<String, Value>,
}
pub(super) fn form(
    bundle: &crate::authority_domains::page::objects::Bundle,
    id: &str,
) -> Result<markup::forms::Form> {
    markup::parse(std::str::from_utf8(&bundle.source)?)
        .map_err(anyhow::Error::msg)?
        .forms
        .into_iter()
        .find(|f| f.id == id)
        .context("form is absent from the approved Page")
}
pub(super) fn bundle(s: &Submission) -> Result<crate::authority_domains::page::objects::Bundle> {
    ensure!(
        s.profile == PROFILE && s.bundle.len() <= markup::forms::MAX_BUNDLE_BYTES * 4 / 3 + 4,
        "unsupported or oversized form submission"
    );
    let bytes = B64.decode(&s.bundle)?;
    ensure!(
        bytes.len() <= markup::forms::MAX_BUNDLE_BYTES && B64.encode(&bytes) == s.bundle,
        "noncanonical or oversized form bundle"
    );
    let bundle = crate::authority_domains::page::objects::Bundle::parse(
        &bytes,
        id(&s.publication.network)?,
        id(&s.publication.incarnation)?,
    )?;
    s.publication.validate(&bundle)?;
    let f = form(&bundle, &s.form_id)?;
    ensure!(
        f.recipient == s.recipient_address && f.schema_digest == s.schema_digest,
        "form recipient or schema differs"
    );
    markup::forms::validate_values(&f, &s.values).map_err(anyhow::Error::msg)?;
    id(&s.submission_id)?;
    id(&s.sender_address)?;
    id(&s.sender_device)?;
    id(&s.recipient_address)?;
    id(&s.recipient_manifest_digest)?;
    Ok(bundle)
}
pub(super) fn body(s: &Submission) -> Result<String> {
    bundle(s)?;
    let body = serde_json::to_string(s)?;
    ensure!(
        body.len() <= 32768,
        "encoded form submission exceeds the Mail body bound"
    );
    Ok(body)
}
impl Prepared {
    pub(super) fn submission(&self) -> Submission {
        let r = &self.review;
        Submission {
            profile: PROFILE.into(),
            submission_id: r.submission_id.clone(),
            publication: r.publication.clone(),
            sender_address: r.sender_address.clone(),
            sender_device: r.sender_device.clone(),
            recipient_address: r.recipient_address.clone(),
            recipient_manifest_digest: r.recipient_manifest_digest.clone(),
            expires: r.expires,
            bundle: self.bundle.clone(),
            form_id: r.form_id.clone(),
            schema_digest: r.schema_digest.clone(),
            values: r.values.clone(),
        }
    }
    pub(super) fn outgoing(&self) -> Result<Outgoing> {
        let body = body(&self.submission())?;
        Ok(Outgoing {
            mailbox: self.mailbox.clone(),
            recipient: self.review.recipient_address.clone(),
            id: self.review.submission_id.clone(),
            expires: self.review.expires,
            subject: format!("Form: {}", self.review.form_label),
            body: body.clone(),
            packages: vec![],
            claim: None,
            sender_manifest: None,
            recipient_manifest: None,
            ciphertext: None,
            receipts: BTreeMap::new(),
            form_consent: Some(Consent {
                review: self.review.clone(),
                payload_digest: protocol::digest(body.as_bytes()),
            }),
        })
    }
}
impl Consent {
    pub(super) fn validate(&self, job: &Outgoing) -> Result<()> {
        ensure!(
            job.body.len() <= 32768 && protocol::digest(job.body.as_bytes()) == self.payload_digest,
            "confirmed form body changed"
        );
        let s: Submission = serde_json::from_str(&job.body)?;
        let r = &self.review;
        ensure!(
            s.profile == PROFILE
                && s.submission_id == r.submission_id
                && job.id == r.submission_id
                && s.publication == r.publication
                && s.sender_address == r.sender_address
                && s.sender_device == r.sender_device
                && s.recipient_address == r.recipient_address
                && job.recipient == r.recipient_address
                && s.recipient_manifest_digest == r.recipient_manifest_digest
                && s.expires == r.expires
                && job.expires == r.expires
                && s.form_id == r.form_id
                && s.schema_digest == r.schema_digest
                && s.values == r.values,
            "outgoing form differs from explicit consent"
        );
        bundle(&s)?;
        Ok(())
    }
}
pub(super) fn accepted_key(p: &PublicationIdentity, form: &str, address: &str) -> Result<String> {
    Ok(protocol::digest(&serde_json::to_vec(&(
        &p.network,
        &p.incarnation,
        &p.page,
        &p.revision,
        &p.approval,
        &p.bundle,
        form,
        address,
    ))?))
}
