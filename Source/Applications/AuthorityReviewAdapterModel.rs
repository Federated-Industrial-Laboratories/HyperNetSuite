// SPDX-License-Identifier: MIT
// Exact native provenance and signed local receipts bind every disclosure and apply attempt.
use super::*;
pub(super) const MAX_RESULT: usize = 8192;
pub(super) const JOB_RECEIPT: &str = "NativePageReviewDisclosure";
pub(super) const APPLY_RECEIPT: &str = "NativePageReviewApply";
pub(super) const MEDIA_RECEIPT: &str = "NativePageMediaDisclosure";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Job {
    pub version: u64,
    pub kind: String,
    pub network: String,
    pub incarnation: String,
    pub job_id: String,
    pub requester: String,
    pub grant: String,
    pub application: Option<String>,
    pub application_registration: Option<String>,
    pub review_mode: Option<u64>,
    pub recipient: String,
    pub purpose: String,
    pub policy_digest: String,
    pub issued_at: u64,
    pub expires: u64,
    pub consent_disclosure: bool,
    pub page_id: String,
    pub ledger: String,
    pub revision: String,
    pub source: String,
    pub author: String,
    pub author_statement: String,
    pub namespace: String,
    pub body: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Saved {
    pub job: Job,
    pub revision_record: String,
    pub application_record: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Recommendation {
    pub version: u64,
    pub job_id: String,
    pub network: String,
    pub incarnation: String,
    pub page_id: String,
    pub source: String,
    pub policy_digest: String,
    pub job_digest: String,
    pub decision: Decision,
    pub rationale: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ApplyReceipt {
    pub job_digest: String,
    pub recommendation_digest: String,
    pub automatic: bool,
    pub decision: Decision,
    pub native_decision: String,
}
pub(super) fn digest<T: Serialize>(value: &T) -> Result<String> {
    use sha2::{Digest as _, Sha256};
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}
pub(super) fn reference(text: &str, kind: u64) -> Result<VersionRef> {
    let r = domain::version(&wire::decode(&hex::decode(text)?)?)?;
    ensure!(
        r.kind == kind && publication::reference(&r)? == text,
        "adapter reference differs"
    );
    Ok(r)
}
pub(super) fn seal<T: Serialize>(
    label: &str,
    value: &T,
    n: Digest,
    i: Digest,
    key: &SigningKey,
) -> Result<Vec<u8>> {
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(value)?);
    ensure!(
        bytes.len() <= wire::MAXIMUM - 1024,
        "adapter receipt exceeds its wire bound"
    );
    wire::sign_envelope(
        &wire::encode(&V::Array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text(label.into()),
            V::Bytes(n.to_vec()),
            V::Bytes(i.to_vec()),
            V::Bytes(key.verifying_key().to_bytes().to_vec()),
            V::Bytes(bytes.to_vec()),
        ]))?,
        key,
    )
}
pub(super) fn open<T: DeserializeOwned>(
    label: &str,
    bytes: &[u8],
    n: Digest,
    i: Digest,
    key: Digest,
) -> Result<T> {
    let (payload, signatures) = wire::envelope(bytes, 1)?;
    let v = wire::decode(&payload)?;
    let f = v.array(7)?;
    ensure!(
        f[0].uint()? == 200
            && f[1].uint()? == 1
            && f[2].text()? == label
            && f[3].fixed::<32>()? == n
            && f[4].fixed::<32>()? == i
            && f[5].fixed::<32>()? == key
            && signatures.len() == 1
            && signatures[0].0 == key,
        "adapter receipt differs from the selected network, requester or purpose"
    );
    Ok(serde_json::from_slice(f[6].bytes()?)?)
}
impl Saved {
    pub fn inspection(
        &self,
        n: Digest,
        i: Digest,
        requester: Digest,
    ) -> Result<statements::Inspection> {
        let j = &self.job;
        ensure!(
            j.version == 1
                && j.kind == "NativePageReview"
                && j.network == hex::encode(n)
                && j.incarnation == hex::encode(i)
                && j.requester == hex::encode(requester)
                && j.consent_disclosure,
            "review disclosure identity differs"
        );
        raw(&j.job_id)?;
        id(&j.policy_digest)?;
        disclosure::label(&j.recipient)?;
        disclosure::purpose(&j.purpose)?;
        let grant = reference(&j.grant, 102)?;
        let record = domain::Record::parse(&hex::decode(&self.revision_record)?, n, i)?;
        let revision = page::Revision::parse(&record.payload, n, i)?;
        let author = &revision.author;
        let ledger = reference(&j.ledger, 140)?;
        ensure!(
            record.reference == reference(&j.revision, 141)?
                && ledger.id == author.intent.resource
                && raw(&j.page_id)? == author.raw_page
                && j.namespace == author.namespace
                && j.author == hex::encode(author.intent.requester)
                && j.author_statement == hex::encode(author.intent.digest)
                && j.source == hex::encode(author.source.canonical()),
            "review job differs from native author provenance"
        );
        revision.verify_source(j.body.as_bytes())?;
        match (&j.application, &self.application_record) {
            (None, None) => ensure!(
                j.review_mode.is_none() && j.application_registration.is_none(),
                "ordinary reviewer supplied application policy"
            ),
            (Some(expected), Some(bytes)) => {
                let r = domain::Record::parse(&hex::decode(bytes)?, n, i)?;
                ensure!(
                    r.reference == reference(expected, 148)? && r.reference.id == requester,
                    "review application record differs"
                );
                let policy = page::ApplicationPolicy::parse(r.payload.bytes()?, n, i)?;
                let (mode, policy_digest) = policy
                    .review
                    .context("application lacks review decision consent")?;
                ensure!(
                    policy.application == requester
                        && policy.grant == grant
                        && j.application_registration.as_deref()
                            == Some(&publication::reference(&policy.registration)?)
                        && j.review_mode == Some(mode)
                        && j.policy_digest == hex::encode(policy_digest)
                        && j.expires
                            .checked_mul(1000)
                            .is_some_and(|e| e <= policy.expires_ms)
                        && policy.allows("ReviewInspect", &j.namespace, Some(author.raw_page))
                        && policy.allows("ReviewDecide", &j.namespace, Some(author.raw_page)),
                    "review job exceeds native application policy"
                );
            }
            _ => anyhow::bail!("review application provenance is incomplete"),
        }
        Ok(statements::Inspection {
            record,
            revision,
            source: j.body.as_bytes().to_vec(),
        })
    }
    pub fn live(&self) -> Result<()> {
        disclosure::lifetime(self.job.issued_at, self.job.expires, crate::now()?)
    }
    pub fn mode(&self, automatic: bool) -> Result<(u64, Option<Digest>)> {
        if automatic {
            ensure!(
                self.job.application.is_some() && self.job.review_mode == Some(1),
                "--automatic requires explicit current Automatic application consent"
            );
        }
        Ok((
            self.job.review_mode.unwrap_or(0),
            self.job
                .application
                .as_ref()
                .map(|_| id(&self.job.policy_digest))
                .transpose()?,
        ))
    }
    pub fn recommendation(&self, r: &Recommendation) -> Result<()> {
        let j = &self.job;
        ensure!(
            r.version == 1
                && r.job_id == j.job_id
                && r.network == j.network
                && r.incarnation == j.incarnation
                && r.page_id == j.page_id
                && r.source == j.source
                && r.policy_digest == j.policy_digest
                && r.job_digest == digest(j)?,
            "recommendation does not bind this exact disclosure"
        );
        ensure!(
            r.rationale.len() <= 2048,
            "recommendation rationale exceeds 2048 bytes"
        );
        Ok(())
    }
    pub fn validate_apply(
        &self,
        r: &Recommendation,
        a: &ApplyReceipt,
        n: Digest,
        i: Digest,
        key: Digest,
    ) -> Result<Vec<u8>> {
        self.recommendation(r)?;
        ensure!(
            a.job_digest == digest(&self.job)?
                && a.recommendation_digest == digest(r)?
                && a.decision != Decision::Abstain
                && (!a.automatic || a.decision == r.decision),
            "retained apply receipt differs from the exact recommendation or decision"
        );
        let (mode, policy) = self.mode(a.automatic)?;
        let bytes = B64.decode(&a.native_decision)?;
        let (review, _, _) = statements::parse_decision(&bytes, n, i, key)?;
        ensure!(
            review.grant == reference(&self.job.grant, 102)?
                && review.application
                    == self
                        .job
                        .application
                        .as_deref()
                        .map(|s| reference(s, 148))
                        .transpose()?
                && review.mode == mode
                && review.policy == policy
                && review.expires_ms
                    == self
                        .job
                        .expires
                        .checked_mul(1000)
                        .context("review expiry overflow")?
                && review.approve == (a.decision == Decision::Approve),
            "retained decision differs from explicit consent"
        );
        ensure!(
            statements::encode_decision(&self.inspection(n, i, key)?, &review)? == bytes,
            "retained decision differs from exact disclosed source"
        );
        Ok(bytes)
    }
}
