// SPDX-License-Identifier: MIT
//! An administrator proposes one exact pre-state and four admitted successor deployments.
use super::*;
use crate::{
    authority_deployment_records::Index,
    authority_epoch::{Declaration, Nomination},
    authority_membership::{Reservations, Snapshot},
};
use std::collections::BTreeSet;

pub fn draft(
    bootstrap: &Verified,
    context: &ContextState,
    store: &Store,
    grant: [u8; 32],
    deployments: &[[u8; 32]],
    health: ClockHealth,
) -> Result<Declaration> {
    context.current(store)?;
    ensure!(
        store.initial_descriptor().canonical() == bootstrap.descriptor().canonical()
            && deployments.len() == 4
            && deployments.iter().copied().collect::<BTreeSet<_>>().len() == 4
            && store.resume_ordinary()?.is_none()
            && store.resume_fence()?.is_none(),
        "Draft requires the accepted bootstrap, four distinct deployments and a resolved stream"
    );
    store.ordinary_slot()?;
    let at = health.observe()?.wall_ms;
    let scope = store.descriptor().scope();
    let decision = context.governance.current_capability(
        grant,
        &Requirement {
            subject: store.requester(),
            actions: &[9],
            scope: (0, scope.network),
            namespace: None,
            usage: [0, 1, 0, 1],
            evaluated_at_ms: at,
            expected: &[],
        },
    )?;
    let records = context.current_records(store)?;
    let index = Index::parse(
        &records,
        &Reservations(bootstrap.reservations().to_vec()),
        scope.network,
        scope.incarnation,
    )?;
    let mut references = decision.dependencies;
    for kind in [100, 114] {
        references.push(
            context
                .governance
                .versions()
                .into_iter()
                .find(|v| v.kind == kind && v.id == scope.network)
                .context("Current network policy missing")?,
        );
    }
    let mut nominations = Vec::new();
    for deployment in deployments {
        let registered = index
            .deployments
            .get(deployment)
            .context("Successor deployment is not admitted")?;
        ensure!(
            !index.withdrawals.contains_key(deployment),
            "Successor deployment was withdrawn"
        );
        let voter = *registered
            .services
            .get(&0)
            .context("Successor deployment has no authority role")?;
        ensure!(
            !store.descriptor().voters().contains(&voter),
            "Successor requires fresh authority identities"
        );
        let registrar = context.governance.current_capability(
            registered.grant.id,
            &Requirement {
                subject: registered.registrar,
                actions: &[13],
                scope: (5, *deployment),
                namespace: None,
                usage: [0, 1, 0, 1],
                evaluated_at_ms: at,
                expected: &[],
            },
        )?;
        references.extend(registrar.dependencies);
        references.extend([
            registered.reference.clone(),
            registered.profile.clone(),
            registered.consent.clone(),
        ]);
        nominations.push(Nomination {
            voter,
            profile: registered.profile.clone(),
            consent: registered.consent.clone(),
        });
    }
    nominations.sort_by_key(|n| n.voter);
    references.sort_by_key(VersionRef::index);
    references.dedup();
    proof::validate_versions(&references, 64)?;
    let snapshot = Snapshot::parse(&a(vec![
        a(vec![
            V::Uint(scope.epoch),
            V::Uint(store.prefix().height()),
            b(store.prefix().policy_state()),
        ]),
        a(references.iter().map(version_value).collect()),
    ]))?;
    Declaration::create(
        scope.clone(),
        store.requester(),
        grant,
        snapshot,
        nominations,
    )
}

pub fn propose_local(
    declaration: &Declaration,
    path: &Path,
    signer: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    mut clock: impl FnMut() -> Result<ClockHealth>,
) -> Result<Prefix> {
    let descriptor = store.descriptor().clone();
    ensure!(
        declaration.old_scope == *descriptor.scope() && declaration.requester == store.requester(),
        "Declaration belongs to another authority or requester"
    );
    store.require_requester(signer.verifying_key().to_bytes())?;
    let intent = if let Some(pending) = store.resume_ordinary()? {
        ensure!(
            Declaration::from_intent(&Intent::from_signed(pending.signed())?)?.bytes
                == declaration.bytes,
            "Pending request differs from the exact declaration"
        );
        pending.signed().to_vec()
    } else {
        ensure!(
            declaration.snapshot.height == store.prefix().height()
                && declaration.snapshot.state == *store.prefix().policy_state(),
            "Declaration pre-state changed; draft again after resolving the prior request"
        );
        prepare_ordinary(
            &descriptor,
            signer,
            store,
            "Reconfigure",
            descriptor.scope().network,
            declaration.snapshot.height,
            &declaration.snapshot.references,
            &declaration.parameters()?,
        )?
    };
    Declaration::from_intent(&Intent::from_signed(&intent)?)?;
    let control = crate::authority_local_transport::LocalControl::prepare_authority(path, store)?;
    let health = clock()?;
    let now = health.observe()?;
    let challenge = session.issue(&intent, signer, random_id()?, DURATION, health)?;
    let parsed = Challenge::from_signed(&challenge)?;
    let ordered = wire::encode(&a(vec![
        V::Uint(22),
        V::Uint(1),
        descriptor.scope().value(),
        b(&intent),
        b(&challenge),
        V::Uint(parsed.expires_at_ms),
    ]))?;
    let deadline = now
        .boot_ms
        .checked_add(DURATION)
        .context("Epoch proposal deadline overflow")?;
    let result = (|| {
        let (reply, history) = crate::authority_local_transport::exchange(
            &descriptor,
            &ordered,
            deadline,
            &control,
            store.prefix(),
            store.tree_head(),
            &mut clock,
        )?;
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
                ancestry: &history.nodes,
            },
            |i, result, executed| {
                ensure!(
                    Declaration::from_intent(i)?.bytes == declaration.bytes,
                    "Certified declaration differs"
                );
                let value = wire::decode(&result.value)?;
                if result.disposition == Disposition::Refuse {
                    let fields = record(&value, 201, 4)?;
                    ensure!(
                        fields[2].text()? == "Reconfigure"
                            && fields[3].array(0)?.is_empty()
                            && executed.maximum_effect == 0,
                        "Invalid reconfiguration refusal"
                    );
                    return ActionValidation::new(vec![]);
                }
                let fields = record(&value, 201, 6)?;
                ensure!(
                    result.disposition == Disposition::Permit
                        && fields[2].text()? == "Reconfigure"
                        && fields[4].fixed::<32>()? == declaration.digest()
                        && fields[5].uint()? == declaration.next_epoch
                        && parse_versions(&fields[3])? == declaration.snapshot.references,
                    "Certified reconfiguration result differs from the exact proposal"
                );
                ActionValidation::new(declaration.snapshot.references.clone())
            },
        )?;
        let verified = history.attach(store, verified)?;
        if verified.disposition() != Disposition::Permit {
            let code = verified.code();
            store.observe(verified)?;
            bail!("Reconfiguration refused with code {code}");
        }
        let prefix = verified.point().prefix().clone();
        let permit = store.accept(verified, session, clock()?, 0)?;
        remaining(deadline)?;
        permit.perform(
            store,
            session,
            clock()?,
            1,
            |r| {
                ensure!(
                    *r == Restrictions::default(),
                    "Reconfiguration restrictions changed"
                );
                Ok(())
            },
            |_, _| Ok(prefix),
        )
    })();
    if result.is_err() {
        session.discard(&challenge)?;
    }
    result
}
