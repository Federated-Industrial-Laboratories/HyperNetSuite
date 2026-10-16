// SPDX-License-Identifier: MIT
// Policy discovery carries no content identifiers and precedes private ordinary operations.
use super::*;
const ACTION: &str = "AuthorityPolicyContext";

/// Finish a retained discovery before a workflow classifies its pending domain operation.
/// An absent discovery or a different exact operation never creates another request.
pub fn resume_pending_discovery(
    bootstrap: &Verified,
    path: &Path,
    signer: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    clock: impl FnMut() -> Result<ClockHealth>,
) -> Result<()> {
    if store
        .resume_ordinary()?
        .map(|p| Intent::from_signed(p.signed()))
        .transpose()?
        .is_some_and(|i| i.action == ACTION)
    {
        discover(bootstrap, path, signer, store, session, clock)?;
    }
    Ok(())
}

pub(super) fn pair_from_value(
    value: &V,
    network: [u8; 32],
    incarnation: [u8; 32],
) -> Result<(Vec<u8>, Vec<u8>, Vec<VersionRef>)> {
    let f = record(value, 201, 5)?;
    ensure!(f[2].text()? == ACTION, "policy discovery action differs");
    let refs = parse_versions(&f[3])?;
    let bytes = f[4].array(2)?;
    let p = bytes[0].bytes()?.to_vec();
    let r = bytes[1].bytes()?.to_vec();
    let expected = vec![
        policies::record_reference(&p, network, incarnation, 100)?,
        policies::record_reference(&r, network, incarnation, 114)?,
    ];
    ensure!(
        refs == expected,
        "policy discovery references differ from exact pair"
    );
    validate_pair(&p, &r, network, incarnation)?;
    Ok((p, r, refs))
}

#[allow(clippy::too_many_arguments)]
pub fn discover(
    bootstrap: &Verified,
    path: &Path,
    signer: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    mut clock: impl FnMut() -> Result<ClockHealth>,
) -> Result<()> {
    ensure!(
        bootstrap.fully_accepted()
            && bootstrap.descriptor().canonical() == store.initial_descriptor().canonical(),
        "policy discovery bootstrap differs"
    );
    store.require_requester(signer.verifying_key().to_bytes())?;
    if let Some(pending) = store.resume_ordinary()? {
        let intent = Intent::from_signed(pending.signed())?;
        if intent.action != ACTION {
            // The exact original request must be reconciled before another can use this stream.
            return Ok(());
        }
    }
    let descriptor = store.descriptor().clone();
    stream_client::ensure_stream(&descriptor, path, signer, store, session, &mut clock)?;
    let scope = descriptor.scope();
    let parameters = wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text(ACTION.into()),
        b(&scope.network),
    ]))?;
    let mut initial_control = None;
    let intent = if let Some(pending) = store.resume_ordinary()? {
        let i = Intent::from_signed(pending.signed())?;
        ensure!(
            i.action == ACTION
                && i.resource == scope.network
                && i.revision == 0
                && i.expected.is_empty()
                && i.parameters == parameters,
            "another exact request is pending"
        );
        pending.signed().to_vec()
    } else {
        // Content-free transport preparation leaves the floor unchanged and precedes a new intent.
        initial_control =
            Some(crate::authority_local_transport::LocalControl::prepare_authority(path, store)?);
        prepare_ordinary(
            &descriptor,
            signer,
            store,
            ACTION,
            scope.network,
            0,
            &[],
            &parameters,
        )?
    };
    let (reply, evidence, challenge, ordered, deadline, control) =
        crate::authority_local_transport::retry_expired_exchange(|| {
            ensure!(
                store
                    .resume_ordinary()?
                    .is_some_and(|p| p.signed() == intent),
                "policy exchange lost its exact pending intent"
            );
            let control = if let Some(control) = initial_control.take() {
                control
            } else {
                crate::authority_local_transport::LocalControl::prepare_authority(path, store)?
            };
            let health = clock()?;
            let issued = health.observe()?;
            let challenge = session.issue(&intent, signer, random_id()?, DURATION, health)?;
            let parsed = Challenge::from_signed(&challenge)?;
            let ordered = wire::encode(&a(vec![
                V::Uint(22),
                V::Uint(1),
                scope.value(),
                b(&intent),
                b(&challenge),
                V::Uint(parsed.expires_at_ms),
            ]))?;
            let deadline = issued
                .boot_ms
                .checked_add(DURATION)
                .context("policy discovery deadline overflow")?;
            let exchange = crate::authority_local_transport::exchange(
                &descriptor,
                &ordered,
                deadline,
                &control,
                store.prefix(),
                store.tree_head(),
                &mut clock,
            );
            if exchange.is_err() {
                session.discard(&challenge)?;
            }
            Ok((
                deadline,
                exchange.map(|(reply, evidence)| {
                    (reply, evidence, challenge, ordered, deadline, control)
                }),
            ))
        })?;
    let result = (|| {
        let evidence = AncestryEvidence::from_shared(evidence);
        let mut pair = None;
        let verified = proof::verify_response(
            &descriptor,
            proof::ProofContext {
                intent: &intent,
                challenge: &challenge,
                restrictions: Restrictions::default(),
                minimum_height: store.prefix().height(),
                maximum_effect: 1,
                expected_stream: None,
            },
            proof::Response {
                ordered_request: &ordered,
                operation_result: &reply.result,
                certificate: &reply.certificate,
                ancestry: &evidence.nodes,
            },
            |_, result, executed| {
                ensure!(
                    result.disposition == Disposition::Permit && executed.maximum_effect == 1,
                    "policy discovery refused"
                );
                let (p, r, refs) = pair_from_value(
                    &wire::decode(&result.value)?,
                    scope.network,
                    scope.incarnation,
                )?;
                crate::authority_domains::result::minimum(&refs, store.generations())?;
                pair = Some((p, r));
                ActionValidation::governance_context(refs)
            },
        )?;
        let verified = evidence.attach(store, verified)?;
        let (p, r) = pair.context("certified policy pair absent")?;
        // Retain candidate bytes before the floor so a power loss cannot hide a learned contract.
        files::atomic_at(
            store.profile_directory(),
            OsStr::new(PENDING),
            &super::pair(&p, &r)?,
            true,
        )?;
        let permit = store.accept(verified, session, clock()?, 0)?;
        permit.perform(
            store,
            session,
            clock()?,
            1,
            |r| {
                ensure!(
                    *r == Restrictions::default(),
                    "policy discovery restrictions changed"
                );
                Ok(())
            },
            |_, store| retain_pair(store, &p, &r),
        )?;
        remaining(deadline)?;
        Ok(())
    })();
    if result.is_err() {
        session.discard(&challenge)?;
    } else {
        control.retain(store);
    }
    result
}

#[allow(clippy::too_many_arguments)]
pub fn refresh_before_request(
    bootstrap: &Verified,
    path: &Path,
    signer: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    clock: impl FnMut() -> Result<ClockHealth>,
) -> Result<()> {
    discover(bootstrap, path, signer, store, session, clock)?;
    require_accepted(bootstrap, store)
}
