// SPDX-License-Identifier: MIT
// Detached author and review statements bind exact inspected source and current capabilities.
use super::*;
pub(super) fn application(
    cache: &Cache,
    c: &Client,
) -> Result<Option<(VersionRef, page::ApplicationPolicy)>> {
    let scope = c.bootstrap.descriptor().scope();
    cache
        .state
        .records
        .get(&(148, c.key.verifying_key().to_bytes()))
        .map(|r| {
            Ok((
                r.reference.clone(),
                page::ApplicationPolicy::parse(
                    r.payload.bytes()?,
                    scope.network,
                    scope.incarnation,
                )?,
            ))
        })
        .transpose()
}
#[allow(clippy::too_many_arguments)]
pub(super) fn author(
    online: Online,
    capability: Capability,
    file: PathBuf,
    namespace: String,
    page_text: String,
    revision: u64,
    expires_ms: u64,
    output: PathBuf,
) -> Result<()> {
    let bytes = source(&file)?;
    let page_id = raw(&page_text)?;
    let mut c = Client::new(&online)?;
    let grant = c.grant(capability)?;
    let current = c.context(2, page_id, Some(namespace.clone()), &grant)?;
    if let Some(record) = current
        .cache
        .state
        .records
        .get(&(140, page::page_id(&page_id)?))
    {
        let head = page::Ledger::parse(&record.payload)?;
        ensure!(
            head.author == c.key.verifying_key().to_bytes() && head.namespace == namespace,
            "Page identity has another author or namespace"
        );
        ensure!(
            head.last_revision.checked_add(1) == Some(revision),
            "Page revision must follow its retained floor"
        );
    } else {
        ensure!(revision == 1, "a new Page starts at revision one");
    }
    let app = application(&current.cache, &c)?;
    let reference = Reference::for_bytes(Class::PageSource, &bytes)?;
    let parameters = Author::parameters(
        page_id,
        &namespace,
        &bytes,
        &grant,
        app.as_ref().map(|a| &a.0),
        expires_ms,
    )?;
    let statement = c.statement(
        "PageAuthorStatement",
        page::page_id(&page_id)?,
        revision,
        parameters,
    )?;
    let scope = c.bootstrap.descriptor().scope();
    Author::parse(&statement, scope.network, scope.incarnation)?;
    files::write_new(&output, &statement)?;
    crate::print_value(
        &json!({"status":"PageAuthorStatementSaved","pageId":page_text,"revision":revision,"sourceSha256":hex::encode(reference.content_sha256())}),
    )
}
pub(super) struct Inspection {
    pub record: domain::Record,
    pub revision: page::Revision,
    pub source: Vec<u8>,
}
impl Inspection {
    pub fn fetch(
        c: &mut Client,
        grant: &VersionRef,
        page_id: [u8; 16],
    ) -> Result<(ResultState, Self)> {
        content_cli::resume_source(c, grant, page::content::Effect::Inspect)?;
        let (result, _) = c.action(
            Action::Inspect { page: page_id },
            Some(grant.clone()),
            Resolved::default(),
        )?;
        let scope = result.prefix.scope();
        let head = page::Ledger::parse(
            &result
                .cache
                .state
                .record(140, page::page_id(&page_id)?)?
                .payload,
        )?;
        let pending = head.pending.context("Page has no pending revision")?;
        let revision = page::Revision::parse(
            &result.cache.state.record(141, pending.id)?.payload,
            scope.network,
            scope.incarnation,
        )?;
        let placement = content_cli::selected_placement(&result.cache.state, &revision)?;
        let bytes =
            content_cli::fetch_source(c, grant, &placement, page::content::Effect::Inspect)?;
        let inspected = Self::from_result(&result, &bytes, page_id)?;
        Ok((result, inspected))
    }
    pub fn from_result(result: &ResultState, bytes: &[u8], page_id: [u8; 16]) -> Result<Self> {
        let head = page::Ledger::parse(
            &result
                .cache
                .state
                .record(140, page::page_id(&page_id)?)?
                .payload,
        )?;
        let reference = head.pending.context("Page has no pending revision")?;
        let record = result.cache.state.record(141, reference.id)?.clone();
        ensure!(
            record.reference == reference,
            "pending Page revision differs"
        );
        let scope = result.prefix.scope();
        let revision = page::Revision::parse(&record.payload, scope.network, scope.incarnation)?;
        let source = bytes.to_vec();
        revision.verify_source(&source)?;
        Ok(Self {
            record,
            revision,
            source,
        })
    }
    pub fn encode(&self, n: Digest, i: Digest) -> Result<Vec<u8>> {
        wire::encode(&V::Array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("PageReviewInput".into()),
            V::Bytes(n.to_vec()),
            V::Bytes(i.to_vec()),
            V::Bytes(self.record.bytes.clone()),
            V::Bytes(self.source.clone()),
        ]))
    }
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        let value = wire::decode(bytes)?;
        let f = value.array(7)?;
        ensure!(
            f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == "PageReviewInput"
                && f[3].fixed::<32>()? == n
                && f[4].fixed::<32>()? == i,
            "Page review input context differs"
        );
        let record = domain::Record::parse(f[5].bytes()?, n, i)?;
        ensure!(
            record.reference.kind == 141,
            "Page review input is not a revision"
        );
        let revision = page::Revision::parse(&record.payload, n, i)?;
        let source = f[6].bytes()?.to_vec();
        revision.verify_source(&source)?;
        Ok(Self {
            record,
            revision,
            source,
        })
    }
}
#[allow(clippy::too_many_arguments)]
pub(super) fn review(
    online: Online,
    capability: Capability,
    input: PathBuf,
    decision: Decision,
    expires_ms: u64,
    output: PathBuf,
) -> Result<()> {
    let approve = matches!(decision, Decision::Approve);
    let mut c = Client::new(&online)?;
    let scope = c.bootstrap.descriptor().scope();
    let (network, incarnation) = (scope.network, scope.incarnation);
    let old = Inspection::parse(
        &files::read_single(&input, crate::authority_objects::PAGE_BUNDLE_BYTES, true)?,
        network,
        incarnation,
    )?;
    let grant = c.grant(capability)?;
    let (current, inspected) = Inspection::fetch(&mut c, &grant, old.revision.author.raw_page)?;
    ensure!(
        inspected.record.bytes == old.record.bytes && inspected.source == old.source,
        "pending Page differs from the retained review input; inspect it again"
    );
    let app = application(&current.cache, &c)?;
    let (mode, policy) = if let Some((_, application)) = &app {
        let (mode, policy) = application
            .review
            .context("application has no review policy")?;
        (mode, Some(policy))
    } else {
        (0, None)
    };
    let decision = decision_bytes(
        &c,
        &old,
        &grant,
        app.as_ref().map(|a| &a.0),
        approve,
        mode,
        policy,
        expires_ms,
    )?;
    files::write_new(&output, &decision)?;
    crate::print_value(
        &json!({"status":"PageReviewStatementSaved","pageId":hex::encode(old.revision.author.raw_page),"revision":old.revision.author.intent.revision,"approved":approve}),
    )
}

pub(super) const DECISION_BYTES: usize = crate::authority_objects::PAGE_BUNDLE_BYTES
    + crate::authority_objects::PAGE_SOURCE_BYTES
    + page::MAXIMUM_PROVENANCE
    + 256;

#[allow(clippy::too_many_arguments)]
pub(super) fn decision_bytes(
    c: &Client,
    inspected: &Inspection,
    grant: &VersionRef,
    application: Option<&VersionRef>,
    approve: bool,
    mode: u64,
    policy: Option<Digest>,
    expires_ms: u64,
) -> Result<Vec<u8>> {
    let scope = c.store.descriptor().scope();
    let author = &inspected.revision.author;
    let parameters = Reviewer::parameters(
        &inspected.record.reference,
        &author.source,
        author.intent.requester,
        author.intent.digest,
        grant,
        application,
        approve,
        mode,
        policy,
        expires_ms,
    )?;
    let bytes = c.statement(
        "PageReviewStatement",
        author.intent.resource,
        author.intent.revision,
        parameters,
    )?;
    let review = Reviewer::parse(&bytes, scope.network, scope.incarnation)?;
    encode_decision(inspected, &review)
}

pub(super) fn encode_decision(inspected: &Inspection, review: &Reviewer) -> Result<Vec<u8>> {
    let author = &inspected.revision.author;
    ensure!(
        review.revision == inspected.record.reference
            && review.source == author.source
            && review.author == author.intent.requester
            && review.author_statement == author.intent.digest
            && review.intent.resource == author.intent.resource
            && review.intent.revision == author.intent.revision,
        "review decision differs from inspected native source"
    );
    inspected.revision.verify_source(&inspected.source)?;
    let bundle = if review.approve {
        Some(Bundle::encode(
            &inspected.source,
            &author.bytes,
            &review.bytes,
        )?)
    } else {
        None
    };
    if let Some(bundle) = &bundle {
        Bundle::parse(bundle, author.intent.network, author.intent.incarnation)?;
    }
    wire::encode(&V::Array(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("PageReviewDecision".into()),
        V::Bytes(review.bytes.clone()),
        bundle.map_or(V::Null, V::Bytes),
        V::Bytes(inspected.source.clone()),
    ]))
}

pub(super) fn parse_decision(
    bytes: &[u8],
    n: Digest,
    i: Digest,
    requester: Digest,
) -> Result<(Reviewer, Option<Reference>, Resolved)> {
    ensure!(
        bytes.len() <= DECISION_BYTES,
        "Page decision exceeds its bound"
    );
    let value = wire::decode(bytes)?;
    let f = value.array(6)?;
    ensure!(
        f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "PageReviewDecision",
        "invalid retained Page decision"
    );
    let review = Reviewer::parse(f[3].bytes()?, n, i)?;
    ensure!(
        review.intent.requester == requester && review.approve == (f[4] != V::Null),
        "Page reviewer or bundle differs"
    );
    let source = Object::verify(review.source.clone(), f[5].bytes()?.to_vec())?;
    let mut references = vec![review.source.clone()];
    let mut objects = vec![source];
    let bundle = if review.approve {
        let bytes = f[4].bytes()?.to_vec();
        let bundle = Bundle::parse(&bytes, n, i)?;
        ensure!(
            bundle.review.bytes == review.bytes && bundle.source == f[5].bytes()?,
            "approved bundle differs from exact decision"
        );
        let reference = Reference::for_bytes(Class::PageBundle, &bytes)?;
        references.push(reference.clone());
        objects.push(Object::verify(reference.clone(), bytes)?);
        Some(reference)
    } else {
        None
    };
    references.sort();
    Ok((review, bundle, Resolved::exact(&references, objects)?))
}

pub(super) fn apply_decision(c: &mut Client, bytes: &[u8]) -> Result<ResultState> {
    let scope = c.store.descriptor().scope();
    let (review, bundle, _) = parse_decision(
        bytes,
        scope.network,
        scope.incarnation,
        c.key.verifying_key().to_bytes(),
    )?;
    let grant = review.grant.clone();
    Ok(c.action(
        Action::Review { review, bundle },
        Some(grant),
        Resolved::default(),
    )?
    .0)
}
