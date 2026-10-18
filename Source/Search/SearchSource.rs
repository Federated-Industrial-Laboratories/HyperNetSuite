// SPDX-License-Identifier: MIT
// Retained text is reconstructed from exact signed publications; sealed source requires its recipient key.
use super::*;
use crate::{
    authority_domains::{
        self as domain, federation as fed, page, sealed_identity as identity,
        sealed_publication as sealed,
    },
    sealed_crypto as crypto, sealed_page_data as data,
    sealed_vault::Vault,
};
use zeroize::Zeroizing;

pub struct SourceView {
    pub bytes: Zeroizing<Vec<u8>>,
    pub uri: Option<String>,
    pub provenance: serde_json::Value,
}
pub fn open(
    entry: &library::Entry,
    bootstrap: &Verified,
    requester: Digest,
    vault: Option<&Vault>,
    at: u64,
) -> Result<SourceView> {
    let scope = bootstrap.descriptor().scope();
    let (network, incarnation) = (scope.network, scope.incarnation);
    match &entry.source {
        library::Source::Native { bundle, approval } => {
            let bundle = page::objects::Bundle::parse(bundle, network, incarnation)?;
            let record = domain::Record::parse(approval, network, incarnation)?;
            ensure!(
                record.reference == entry.publication && record.reference.kind == 142,
                "retained native approval differs"
            );
            let review = page::Review::parse(&record.payload, network, incarnation)?;
            ensure!(
                review.statement.approve
                    && review.statement.bytes == bundle.review.bytes
                    && bundle.author.namespace == entry.namespace
                    && page::page_id(&bundle.author.raw_page)? == entry.id,
                "retained native publication identity differs"
            );
            review
                .bundle
                .context("retained native bundle absent")?
                .verify(&bundle.bytes)?;
            Ok(SourceView {
                bytes: Zeroizing::new(bundle.source.clone()),
                uri: Some(format!(
                    "hypernet://{}/{}/{}/{}",
                    hex::encode(network),
                    hex::encode(bundle.author.intent.requester),
                    entry.namespace,
                    hex::encode(bundle.author.raw_page)
                )),
                provenance: json!({"kind":"Native","author":hex::encode(bundle.author.intent.requester),"reviewer":hex::encode(bundle.review.intent.requester),"revision":bundle.author.intent.revision}),
            })
        }
        library::Source::Imported {
            bundle,
            revision,
            review,
        } => {
            let revision_record = domain::Record::parse(revision, network, incarnation)?;
            ensure!(
                revision_record.reference.kind == 155,
                "retained imported revision kind differs"
            );
            let revision = fed::ForeignRevision::parse(&revision_record.payload)?;
            let review_record = domain::Record::parse(review, network, incarnation)?;
            let review = fed::ForeignReview::parse(&review_record.payload, network, incarnation)?;
            let bundle = page::objects::Bundle::parse(
                bundle,
                revision.source.network,
                revision.source.incarnation,
            )?;
            revision.bundle.verify(&bundle.bytes)?;
            ensure!(
                review_record.reference == entry.publication
                    && review_record.reference.kind == 156
                    && review.approve
                    && review.revision == revision_record.reference
                    && revision.page == entry.id
                    && revision.metadata.author.bytes == bundle.author.bytes
                    && revision.native == bundle.review.revision,
                "retained imported publication identity differs"
            );
            Ok(SourceView {
                bytes: Zeroizing::new(bundle.source.clone()),
                uri: None,
                provenance: json!({"kind":"Imported","agreement":hex::encode(revision.agreement),"sourceNetwork":hex::encode(revision.source.network),"sourcePage":hex::encode(bundle.author.raw_page),"sourceAuthor":hex::encode(bundle.author.intent.requester),"localReviewer":hex::encode(review.reviewer),"revision":bundle.author.intent.revision}),
            })
        }
        library::Source::Sealed {
            ciphertext,
            outer,
            policy,
            binding,
            device,
        } => {
            let vault =
                vault.context("sealed retained content is locked; supply its recipient vault")?;
            let outer = sealed::Outer::parse(outer, network, incarnation)?;
            let record = sealed::signed_record(policy, network, incarnation)?;
            let policy =
                sealed::ObjectPolicy::parse(&sealed::payload(&record)?, network, incarnation)?;
            let record = identity::signed_record(binding, network, incarnation)?;
            let binding =
                identity::Binding::parse(&identity::payload(&record)?, network, incarnation)?;
            let key = vault.device_identity(*device)?;
            ensure!(
                outer.reference == entry.publication
                    && outer.object == entry.id
                    && policy.object == entry.id
                    && policy.namespace == page::namespace_id(&entry.namespace)?
                    && binding.device == *device
                    && binding.signing_key == requester
                    && vault.device_signer(*device)?.verifying_key().to_bytes() == requester
                    && crypto::recipient_key(&key.to_public())? == binding.encryption_key,
                "retained sealed publication or recipient identity differs"
            );
            let content = crypto::open(
                &key,
                ciphertext,
                outer.ciphertext,
                &data::context(&outer, network, incarnation),
                |content| {
                    data::verify_container(content, &outer, &policy, at)?;
                    Ok(())
                },
            )?;
            Ok(SourceView {
                bytes: content.source.clone(),
                uri: None,
                provenance: json!({"kind":"Sealed","object":hex::encode(outer.object),"revision":outer.revision,"reviewer":hex::encode(outer.reviewer),"recipientDevice":hex::encode(device)}),
            })
        }
    }
}
