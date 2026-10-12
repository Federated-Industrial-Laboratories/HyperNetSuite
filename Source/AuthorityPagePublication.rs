// SPDX-License-Identifier: MIT
// A publication binds current certified metadata to the exact inert source and signed approval.
use super::*;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Identity {
    pub network: String,
    pub incarnation: String,
    pub page: String,
    pub ledger: String,
    pub revision: String,
    pub approval: String,
    pub bundle: String,
}
pub(crate) fn reference(r: &VersionRef) -> Result<String> {
    Ok(hex::encode(wire::encode(
        &crate::authority_membership::reference(r),
    )?))
}
impl Identity {
    pub fn page_id(&self) -> Result<[u8; 16]> {
        raw(&self.page)
    }
    pub fn validate(&self, bundle: &Bundle) -> Result<()> {
        ensure!(
            self.network == hex::encode(bundle.author.intent.network)
                && self.incarnation == hex::encode(bundle.author.intent.incarnation)
                && self.page_id()? == bundle.author.raw_page,
            "form publication belongs to another network or Page"
        );
        let decode = |text: &str, kind| -> Result<VersionRef> {
            let r = domain::version(&wire::decode(&hex::decode(text)?)?)?;
            ensure!(r.kind == kind, "publication reference kind differs");
            Ok(r)
        };
        let ledger = decode(&self.ledger, 140)?;
        let revision = decode(&self.revision, 141)?;
        let approval = decode(&self.approval, 142)?;
        ensure!(
            ledger.id == bundle.author.intent.resource
                && revision == bundle.review.revision
                && approval.id == revision.id,
            "publication identity differs from exact signed revision"
        );
        let object = Reference::parse(&wire::decode(&hex::decode(&self.bundle)?)?)?;
        ensure!(
            object.class() == Class::PageBundle,
            "publication is not a Page bundle"
        );
        object.verify(&bundle.bytes)?;
        Ok(())
    }
}
pub(crate) struct Publication {
    pub identity: Identity,
    pub bundle: Bundle,
    pub assets: Vec<VersionRef>,
    pub height: u64,
}
pub(crate) fn fetch(c: &mut Client, grant: &VersionRef, page_id: [u8; 16]) -> Result<Publication> {
    let (result, objects) = c.action(
        Action::Read { page: page_id },
        Some(grant.clone()),
        Resolved::default(),
    )?;
    let scope = result.prefix.scope();
    let head = result.cache.state.record(140, page::page_id(&page_id)?)?;
    let ledger = page::Ledger::parse(&head.payload)?;
    let reference = ledger
        .published
        .context("Page has no approved publication")?;
    let record = result.cache.state.record(142, reference.id)?;
    ensure!(
        record.reference == reference,
        "Page publication differs from current head"
    );
    let review = page::Review::parse(&record.payload, scope.network, scope.incarnation)?;
    let object = review
        .bundle
        .as_ref()
        .context("approved Page bundle is absent")?;
    let bundle = Bundle::parse(objects.get(object)?, scope.network, scope.incarnation)?;
    let revision = result
        .cache
        .state
        .record(141, review.statement.revision.id)?;
    let source = page::Revision::parse(&revision.payload, scope.network, scope.incarnation)?;
    ensure!(
        revision.reference == review.statement.revision
            && bundle.author.raw_page == page_id
            && bundle.author.bytes == source.author.bytes
            && bundle.review.bytes == review.statement.bytes,
        "Page bundle differs from certified publication"
    );
    let identity = Identity {
        network: hex::encode(scope.network),
        incarnation: hex::encode(scope.incarnation),
        page: hex::encode(page_id),
        ledger: self::reference(&head.reference)?,
        revision: self::reference(&revision.reference)?,
        approval: self::reference(&reference)?,
        bundle: hex::encode(object.canonical()),
    };
    identity.validate(&bundle)?;
    let assets = result
        .cache
        .state
        .records
        .values()
        .filter(|r| r.reference.kind == 144)
        .filter_map(|r| {
            page::Asset::parse(&r.payload)
                .ok()
                .filter(|a| a.revision == revision.reference)
                .map(|_| r.reference.clone())
        })
        .collect();
    Ok(Publication {
        identity,
        bundle,
        assets,
        height: result.prefix.height(),
    })
}
