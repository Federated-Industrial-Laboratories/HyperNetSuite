// SPDX-License-Identifier: MIT
// Managers prepare one tracked activation request; the dedicated service supplies its own challenge.
use super::*;
use crate::authority_membership::Snapshot;
use crate::authority_runtime_activation::{self as activation, Operation as Activation};
pub fn prepare(
    bootstrap: &Verified,
    cache: &Cache,
    signer: &SigningKey,
    store: &mut Store,
    role: u64,
    generation: u64,
    health: ClockHealth,
) -> Result<activation::Request> {
    ensure!(
        bootstrap.fully_accepted()
            && bootstrap.descriptor().canonical() == store.initial_descriptor().canonical(),
        "activation bootstrap and requester floor differ"
    );
    store.require_requester(signer.verifying_key().to_bytes())?;
    cache.current(store)?;
    let records = merged(bootstrap, &cache.entries)?;
    let registration = records::Index::parse(
        &records,
        &Reservations(bootstrap.reservations().to_vec()),
        store.prefix().scope().network,
        store.prefix().scope().incarnation,
    )?
    .deployments
    .get(&cache.deployment)
    .context("deployment is not registered")?
    .clone();
    let recipient = *registration
        .services
        .get(&role)
        .context("deployment has no selected service role")?;
    let grant = cache.version(
        102,
        cache
            .grant
            .context("activation requires a scoped manager grant")?,
    )?;
    if let Some(pending) = store.resume_ordinary()? {
        let request = activation::Request::new(pending.signed().to_vec(), records)?;
        let op = request.operation();
        ensure!(
            request.intent().resource == cache.deployment
                && op.grant == grant
                && op.admission == registration.reference
                && op.role == role
                && op.recipient == recipient
                && op.local_generation == generation,
            "another immutable request is pending; inspect its outcome before replacing it"
        );
        return Ok(request);
    }
    let slot = store.ordinary_slot()?;
    let mut snapshot = Snapshot::parse(&a(vec![
        a(vec![
            V::Uint(slot.minimum_policy_epoch()),
            V::Uint(slot.minimum_policy_height()),
            b(store.prefix().policy_state()),
        ]),
        a(vec![]),
    ]))?;
    let mut op = Activation {
        grant,
        admission: registration.reference,
        role,
        recipient,
        local_generation: generation,
        snapshot: snapshot.clone(),
    };
    let mut probe = Intent {
        network: store.prefix().scope().network,
        incarnation: store.prefix().scope().incarnation,
        generation: slot.generation(),
        generation_id: slot.generation_id(),
        sequence: slot.sequence(),
        acknowledged_through: slot.acknowledged_through(),
        requester: store.requester(),
        action: activation::ACTION.into(),
        resource: cache.deployment,
        revision: generation,
        profile_generation: registration.profile.generation,
        minimum_policy_epoch: slot.minimum_policy_epoch(),
        minimum_policy_height: slot.minimum_policy_height(),
        expected: vec![],
        parameters: vec![],
        digest: [1; 32],
    };
    let decision = op.prepare(
        &records,
        &Reservations(bootstrap.reservations().to_vec()),
        &probe,
        recipient,
        health.observe()?.wall_ms,
        false,
    )?;
    ensure!(
        decision.code == 0,
        "activation preflight refused with code {}",
        decision.code
    );
    snapshot.references = decision.versions.clone();
    snapshot.value = a(vec![
        snapshot.value.array(2)?[0].clone(),
        a(decision
            .versions
            .iter()
            .map(membership::reference)
            .collect()),
    ]);
    op.snapshot = snapshot;
    probe.expected = decision.versions;
    probe.parameters = wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text(activation::ACTION.into()),
        membership::reference(&op.grant),
        membership::reference(&op.admission),
        V::Uint(role),
        b(&recipient),
        V::Uint(generation),
        op.snapshot.value.clone(),
    ]))?;
    let payload = wire::encode(&a(vec![
        V::Uint(20),
        V::Uint(1),
        b(&probe.network),
        b(&probe.incarnation),
        V::Uint(probe.generation),
        b(&probe.generation_id),
        V::Uint(probe.sequence),
        V::Uint(probe.acknowledged_through),
        b(&probe.requester),
        V::Text(probe.action),
        b(&probe.resource),
        V::Uint(probe.revision),
        V::Uint(probe.profile_generation),
        V::Uint(probe.minimum_policy_epoch),
        V::Uint(probe.minimum_policy_height),
        a(probe.expected.iter().map(membership::reference).collect()),
        b(&probe.parameters),
    ]))?;
    let signed = wire::sign_envelope(&payload, signer)?;
    let request = activation::Request::new(signed.clone(), records)?;
    store.prepare_ordinary(slot, &signed)?;
    Ok(request)
}
