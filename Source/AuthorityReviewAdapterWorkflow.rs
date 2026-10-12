// SPDX-License-Identifier: MIT
// Current certified context precedes disclosure; immutable signed decisions precede submission.
use super::*;

fn context(c: &Client) -> (Digest, Digest, Digest) {
    let s = c.store.descriptor().scope();
    (s.network, s.incarnation, c.key.verifying_key().to_bytes())
}
fn load(path: &Path, context: (Digest, Digest, Digest)) -> Result<Saved> {
    let s: Saved = open(
        JOB_RECEIPT,
        &files::read_single(path, wire::MAXIMUM, true)?,
        context.0,
        context.1,
        context.2,
    )?;
    s.inspection(context.0, context.1, context.2)?;
    s.live()?;
    Ok(s)
}
fn recommendation(saved: &Saved, path: &Path) -> Result<Recommendation> {
    let value = disclosure::read(path, MAX_RESULT)?;
    saved.recommendation(&value)?;
    Ok(value)
}
fn inspect(
    c: &mut Client,
    grant: &VersionRef,
    page: [u8; 16],
) -> Result<(ResultState, statements::Inspection)> {
    let (result, objects) = c.action(
        Action::Inspect { page },
        Some(grant.clone()),
        Resolved::default(),
    )?;
    let inspected = statements::Inspection::from_result(&result, &objects, page)?;
    Ok((result, inspected))
}
fn current(
    c: &mut Client,
    grant: &VersionRef,
    saved: &Saved,
) -> Result<(ResultState, statements::Inspection)> {
    let (n, i, key) = context(c);
    let old = saved.inspection(n, i, key)?;
    ensure!(
        *grant == reference(&saved.job.grant, 102)?,
        "review grant differs from disclosure"
    );
    let (result, inspected) = inspect(c, grant, old.revision.author.raw_page)?;
    let head = result
        .cache
        .state
        .record(140, old.revision.author.intent.resource)?;
    ensure!(
        head.reference == reference(&saved.job.ledger, 140)?
            && inspected.record.bytes == old.record.bytes
            && inspected.source == old.source,
        "pending Page changed since disclosure; export a fresh job"
    );
    let app = statements::application(&result.cache, c)?;
    ensure!(
        app.as_ref().map(|a| &a.0)
            == saved
                .job
                .application
                .as_deref()
                .map(|s| reference(s, 148))
                .transpose()?
                .as_ref(),
        "native application policy changed since disclosure"
    );
    // The exact 148 record includes the admitted 127 reference, grant, mode and policy digest.
    if let Some((reference, _)) = app {
        ensure!(
            saved.application_record.as_deref()
                == Some(&hex::encode(
                    &result.cache.state.record(148, reference.id)?.bytes
                )),
            "native application consent differs from disclosure"
        );
    }
    saved.live()?;
    Ok((result, inspected))
}

pub(super) fn run(command: Command) -> Result<()> {
    match command {
        Command::Export {
            online,
            capability,
            page_id,
            recipient,
            purpose,
            policy_digest,
            expires,
            consent_disclosure,
            output,
            receipt,
        } => {
            ensure!(
                consent_disclosure,
                "--consent-disclosure is required to release pending plaintext"
            );
            ensure!(
                output != receipt,
                "plaintext and receipt require distinct destinations"
            );
            disclosure::label(&recipient)?;
            disclosure::purpose(&purpose)?;
            id(&policy_digest)?;
            let now = crate::now()?;
            disclosure::lifetime(now, expires, now)?;
            let output_destination = files::Destination::open(&output)?;
            let receipt_destination = files::Destination::open(&receipt)?;
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let (result, inspection) = inspect(&mut c, &grant, raw(&page_id)?)?;
            let (n, i, key) = context(&c);
            let author = &inspection.revision.author;
            let head = result.cache.state.record(140, author.intent.resource)?;
            let app = statements::application(&result.cache, &c)?;
            let saved = Saved {
                job: Job {
                    version: 1,
                    kind: "NativePageReview".into(),
                    network: hex::encode(n),
                    incarnation: hex::encode(i),
                    job_id: crate::random_hex::<16>(),
                    requester: hex::encode(key),
                    grant: publication::reference(&grant)?,
                    application: app
                        .as_ref()
                        .map(|a| publication::reference(&a.0))
                        .transpose()?,
                    application_registration: app
                        .as_ref()
                        .map(|a| publication::reference(&a.1.registration))
                        .transpose()?,
                    review_mode: app.as_ref().and_then(|a| a.1.review.map(|r| r.0)),
                    recipient,
                    purpose,
                    policy_digest,
                    issued_at: now,
                    expires,
                    consent_disclosure: true,
                    page_id,
                    ledger: publication::reference(&head.reference)?,
                    revision: publication::reference(&inspection.record.reference)?,
                    source: hex::encode(author.source.canonical()),
                    author: hex::encode(author.intent.requester),
                    author_statement: hex::encode(author.intent.digest),
                    namespace: author.namespace.clone(),
                    body: String::from_utf8(inspection.source)?,
                },
                revision_record: hex::encode(&inspection.record.bytes),
                application_record: app
                    .as_ref()
                    .map(|a| {
                        result
                            .cache
                            .state
                            .record(148, a.0.id)
                            .map(|r| hex::encode(&r.bytes))
                    })
                    .transpose()?,
            };
            saved.inspection(n, i, key)?;
            let body = zeroize::Zeroizing::new(serde_json::to_vec_pretty(
                &json!({"job":saved.job,"jobDigest":digest(&saved.job)?}),
            )?);
            ensure!(
                body.len() <= disclosure::MAX_FILE,
                "review export exceeds its encoded file bound"
            );
            let proof = seal(JOB_RECEIPT, &saved, n, i, &c.key)?;
            receipt_destination.publish(&proof)?;
            saved.live()?;
            output_destination.publish(&body)?;
            crate::print_value(
                &json!({"status":"ReviewDisclosed","jobId":saved.job.job_id,"jobDigest":digest(&saved.job)?,
                "recipient":saved.job.recipient,"expires":expires,"output":output,"receipt":receipt,
                "credentialsExported":false,"executionAllowed":false}),
            )
        }
        Command::Import {
            location,
            key,
            receipt,
            result,
        } => {
            let bootstrap = control::bootstrap(&location)?;
            let key = domain_cli::signer(&key)?;
            let s = bootstrap.descriptor().scope();
            let saved = load(
                &receipt,
                (s.network, s.incarnation, key.verifying_key().to_bytes()),
            )?;
            let value = recommendation(&saved, &result)?;
            crate::print_value(
                &json!({"jobId":saved.job.job_id,"recommendation":value.decision,
                "rationale":value.rationale,"applied":false,"authorityChecked":false}),
            )
        }
        Command::Apply {
            online,
            capability,
            receipt,
            result,
            decision,
            automatic,
            decision_output,
        } => {
            ensure!(
                decision_output != receipt && decision_output != result,
                "apply receipt requires its own destination"
            );
            let mut c = Client::new(&online)?;
            let (n, i, key) = context(&c);
            let saved = load(&receipt, (n, i, key))?;
            let value = recommendation(&saved, &result)?;
            let choice = if automatic {
                value.decision.clone()
            } else {
                decision.context("an explicit human decision is required")?
            };
            ensure!(
                choice != Decision::Abstain,
                "Abstain cannot change publication"
            );
            let grant = c.grant(capability)?;
            ensure!(
                grant == reference(&saved.job.grant, 102)?,
                "apply grant differs from disclosure"
            );
            let (mode, policy) = saved.mode(automatic)?;
            let retained = if decision_output.exists() {
                let applied: ApplyReceipt = open(
                    APPLY_RECEIPT,
                    &files::read_single(&decision_output, wire::MAXIMUM, true)?,
                    n,
                    i,
                    key,
                )?;
                ensure!(
                    applied.automatic == automatic && applied.decision == choice,
                    "retry must retain the original decision and automatic selection"
                );
                applied
            } else {
                let (_, inspected) = current(&mut c, &grant, &saved)?;
                let app = saved
                    .job
                    .application
                    .as_deref()
                    .map(|s| reference(s, 148))
                    .transpose()?;
                let bytes = statements::decision_bytes(
                    &c,
                    &inspected,
                    &grant,
                    app.as_ref(),
                    choice == Decision::Approve,
                    mode,
                    policy,
                    saved
                        .job
                        .expires
                        .checked_mul(1000)
                        .context("review expiry overflow")?,
                )?;
                let applied = ApplyReceipt {
                    job_digest: digest(&saved.job)?,
                    recommendation_digest: digest(&value)?,
                    automatic,
                    decision: choice,
                    native_decision: B64.encode(bytes),
                };
                persist_apply(&decision_output, &saved, &value, &applied, n, i, &c.key)?;
                applied
            };
            let bytes = saved.validate_apply(&value, &retained, n, i, key)?;
            saved.live()?;
            // Exact signed input is durable before the first network mutation and is reused on retry.
            let result = statements::apply_decision(&mut c, &bytes)?;
            crate::print_value(&json!({"status":"ReviewApplied","jobId":saved.job.job_id,
                "decision":retained.decision,"automatic":automatic,"decisionReceipt":decision_output,
                "height":result.prefix.height()}))
        }
        Command::MediaExport {
            online,
            capability,
            receipt,
            asset,
            transport,
            progress_directory,
            consent_media_disclosure,
            output,
            media_receipt,
        } => {
            ensure!(
                consent_media_disclosure,
                "--consent-media-disclosure is required to release selected asset bytes"
            );
            ensure!(
                output != receipt && media_receipt != receipt && output != media_receipt,
                "media plaintext and receipts require distinct destinations"
            );
            let output_destination = files::Destination::open(&output)?;
            let receipt_destination = files::Destination::open(&media_receipt)?;
            let mut c = Client::new(&online)?;
            let (n, i, key) = context(&c);
            let saved = load(&receipt, (n, i, key))?;
            let grant = c.grant(capability)?;
            ensure!(
                grant == reference(&saved.job.grant, 102)?,
                "media grant differs from disclosure"
            );
            let pending = c.store.resume_ordinary()?;
            let pending_media = pending
                .as_ref()
                .map(|pending| -> Result<bool> {
                    let operation = domain::Operation::parse(
                        &crate::authority_proof::Intent::from_signed(pending.signed())?,
                    )?;
                    Ok(matches!(
                        operation.command,
                        domain::Command::Page(
                            Action::MediaGet { .. }
                                | Action::MediaInspect { .. }
                                | Action::MediaAuthorise {
                                    effect: page::MediaEffect::Inspect,
                                    ..
                                }
                        )
                    ))
                })
                .transpose()?
                .unwrap_or(false);
            let (asset_ref, metadata) = if pending_media {
                // The exact pending effect is reconciled before any new context request.
                // Its signed scope and durable media job must still match the requested asset.
                select_asset(&c.cache()?, &reference(&saved.job.revision, 141)?, &asset)?
            } else {
                let (result, inspected) = current(&mut c, &grant, &saved)?;
                select_asset(&result.cache, &inspected.record.reference, &asset)?
            };
            let expiry = saved
                .job
                .expires
                .checked_mul(1000)
                .context("media inspection expiry overflow")?;
            let bytes = media::inspect_asset(
                &mut c,
                &grant,
                asset_ref.clone(),
                &transport,
                &progress_directory,
                expiry,
            )?;
            let (result, _) = current(&mut c, &grant, &saved)?;
            let evidence_record = result.cache.state.record(145, asset_ref.id)?;
            let evidence = page::Evidence::parse(&evidence_record.payload, n, i)?;
            let app = saved
                .job
                .application
                .as_deref()
                .map(|s| reference(s, 148))
                .transpose()?;
            ensure!(
                evidence.asset == asset_ref
                    && evidence.inspections.iter().any(|v| v.reviewer == key
                        && v.grant == grant
                        && v.application == app
                        && v.expires_ms == expiry),
                "current media inspection does not bind this review job"
            );
            let metadata = json!({"version":1,"kind":"NativePageMediaReview","network":saved.job.network,
                "incarnation":saved.job.incarnation,"reviewJobId":saved.job.job_id,"reviewJobDigest":digest(&saved.job)?,
                "requester":saved.job.requester,"recipient":saved.job.recipient,"purpose":saved.job.purpose,
                "policyDigest":saved.job.policy_digest,"issuedAt":crate::now()?,"expires":saved.job.expires,
                "consentMediaDisclosure":true,"pageId":saved.job.page_id,"revision":saved.job.revision,
                "source":saved.job.source,"assetReference":publication::reference(&asset_ref)?,"asset":metadata.manifest,
                "inspection":publication::reference(&evidence_record.reference)?});
            let body = zeroize::Zeroizing::new(serde_json::to_vec(
                &json!({"disclosure":metadata,"payload":B64.encode(&bytes)}),
            )?);
            let maximum = (crate::markup::media::MAX_PAGE_BYTES as usize).div_ceil(3) * 4
                + disclosure::MAX_FILE;
            ensure!(
                body.len() <= maximum,
                "media export exceeds the canonical asset and metadata bounds"
            );
            let proof = seal(MEDIA_RECEIPT, &metadata, n, i, &c.key)?;
            receipt_destination.publish(&proof)?;
            saved.live()?;
            output_destination.publish(&body)?;
            crate::print_value(
                &json!({"status":"ReviewMediaDisclosed","jobId":saved.job.job_id,"asset":asset,
                "bytes":bytes.len(),"output":output,"receipt":media_receipt,"credentialsExported":false,"executionAllowed":false}),
            )
        }
    }
}
#[allow(clippy::too_many_arguments)]
pub(super) fn persist_apply(
    path: &Path,
    saved: &Saved,
    recommendation: &Recommendation,
    applied: &ApplyReceipt,
    n: Digest,
    i: Digest,
    key: &SigningKey,
) -> Result<()> {
    saved.validate_apply(
        recommendation,
        applied,
        n,
        i,
        key.verifying_key().to_bytes(),
    )?;
    files::Destination::open(path)?.publish(&seal(APPLY_RECEIPT, applied, n, i, key)?)
}
fn select_asset(
    cache: &Cache,
    revision: &VersionRef,
    asset: &str,
) -> Result<(VersionRef, page::Asset)> {
    for record in cache
        .state
        .records
        .values()
        .filter(|r| r.reference.kind == 144)
    {
        let metadata = page::Asset::parse(&record.payload)?;
        if metadata.revision == *revision && metadata.manifest.id == asset {
            return Ok((record.reference.clone(), metadata));
        }
    }
    anyhow::bail!("selected asset is absent from the exact pending native revision")
}
