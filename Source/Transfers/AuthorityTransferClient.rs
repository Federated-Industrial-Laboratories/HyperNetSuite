// SPDX-License-Identifier: MIT
// Participant streams prepare immutable effects and acknowledge only independently verified store reports.
use super::*;
use crate::authority_domains::{
    self as domain,
    transfer::{self, Command, Receipt, Request},
};
use crate::authority_inspection::domain_client::{self, Cache};
use crate::authority_membership::Reservations;
pub fn ensure(
    bootstrap: &Verified,
    store: &mut Store,
    authority: &Path,
    signer: &SigningKey,
    session: &mut Session,
    mut clock: impl FnMut() -> Result<ClockHealth>,
) -> Result<()> {
    let descriptor = store.descriptor().clone();
    stream_client::ensure_stream(&descriptor, authority, signer, store, session, &mut clock)?;
    crate::authority_inspection::policy::refresh_before_request(
        bootstrap, authority, signer, store, session, &mut clock,
    )
}
pub fn prepare(
    bootstrap: &Verified,
    signer: &SigningKey,
    store: &mut Store,
    command: Command,
    health: ClockHealth,
) -> Result<Request> {
    ensure!(
        matches!(command, Command::Execute { .. }),
        "only a finite serving command can leave the participant"
    );
    crate::authority_inspection::policy::require_accepted(bootstrap, store)?;
    store.require_requester(signer.verifying_key().to_bytes())?;
    if let Some(pending) = store.resume_ordinary()? {
        let request = Request::parse(pending.signed())?;
        ensure!(
            request.command().value() == command.value(),
            "another transfer effect is pending; recover its exact operation first"
        );
        crate::authority_inspection::policy::require_pending_policy(
            bootstrap,
            store,
            request.intent(),
        )?;
        return Ok(request);
    }
    let cache = Cache::load(bootstrap, store)?;
    let records = domain_client::merge(bootstrap, &cache.records)?;
    let expected = vec![crate::authority_inspection::policy::current_reference(
        bootstrap, store,
    )?];
    let op = domain::Operation {
        grant: None,
        command: command.into(),
        snapshot: domain::snapshot(&a(vec![
            a(vec![
                V::Uint(store.prefix().scope().epoch),
                V::Uint(store.prefix().height()),
                b(store.prefix().policy_state()),
            ]),
            a(expected.iter().map(version_value).collect()),
        ]))?,
    };
    let descriptor = store.descriptor().clone();
    let slot = store.ordinary_slot()?;
    let probe = Intent {
        network: descriptor.scope().network,
        incarnation: descriptor.scope().incarnation,
        generation: slot.generation(),
        generation_id: slot.generation_id(),
        sequence: slot.sequence(),
        acknowledged_through: slot.acknowledged_through(),
        requester: store.requester(),
        action: "AuthorityDomain".into(),
        resource: op.command.resource(),
        revision: 0,
        profile_generation: 0,
        minimum_policy_epoch: slot.minimum_policy_epoch(),
        minimum_policy_height: slot.minimum_policy_height(),
        expected: expected.clone(),
        parameters: op.parameters()?,
        digest: [1; 32],
    };
    let d = op.prepare(
        &cache.state,
        &records,
        &Reservations(bootstrap.reservations().to_vec()),
        &probe,
        health.observe()?.wall_ms,
        false,
        true,
    )?;
    ensure!(
        d.code == 0,
        "transfer effect preflight refused with code {}; refresh its exact current agreement",
        d.code
    );
    Request::parse(&prepare_ordinary(
        &descriptor,
        signer,
        store,
        "AuthorityDomain",
        probe.resource,
        0,
        &expected,
        &probe.parameters,
    )?)
}
pub fn pending(store: &Store) -> Result<Option<Request>> {
    store
        .resume_ordinary()?
        .map(|p| Request::parse(p.signed()))
        .transpose()
}
pub fn packet(request: &Request, payload: &[u8], reconcile: bool) -> Result<Vec<u8>> {
    ensure!(
        payload.len() <= transfer::CHUNK as usize,
        "transfer chunk exceeds bound"
    );
    wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("TransferExchange".into()),
        b(request.signed()),
        b(payload),
        V::Bool(reconcile),
    ]))
}
/// The idempotent local callback retains received data before the outgoing request is acknowledged.
#[allow(
    clippy::too_many_arguments,
    reason = "Keep protocol inputs, state and validation callbacks explicit."
)]
pub fn complete<T>(
    bootstrap: &Verified,
    bytes: &[u8],
    authority: &Path,
    signer: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    mut clock: impl FnMut() -> Result<ClockHealth>,
    apply: impl FnOnce(&Request, &[u8]) -> Result<T>,
) -> Result<T> {
    let receipt = Receipt::parse(bytes)?;
    let descriptor = store.descriptor_for_scope(&receipt.scope()?)?;
    let report = receipt.verify(bootstrap, &descriptor)?;
    let pending = store
        .resume_ordinary()?
        .context("transfer receipt has no pending participant request")?;
    ensure!(
        report.request().requester == store.requester()
            && pending.digest() == report.request().digest,
        "transfer receipt differs from exact pending participant request"
    );
    let request = Request::parse(pending.signed())?;
    let direct = report.result().disposition() == Disposition::Permit
        && matches!(
            request.command(),
            Command::Execute {
                effect: transfer::Effect::Fetch,
                ..
            }
        )
        && store.transfer_completion_connected(&report)?;
    if !direct {
        let current = store.descriptor().clone();
        stream_client::status_local(&current, authority, signer, store, session, &mut clock)?;
    }
    if report.result().disposition() != Disposition::Permit {
        anyhow::bail!(
            "transfer effect refused with code {}; current stream status is retained",
            report.result().code()
        );
    }
    let result_value = wire::decode(&report.result().result.value)?;
    let records = result_value.array(5)?[4].array(4)?[2]
        .list(64)?
        .iter()
        .map(|v| Ok(v.bytes()?.to_vec()))
        .collect::<Result<Vec<_>>>()?;
    crate::authority_inspection::policy::require_records_accepted(bootstrap, store, &records)?;
    let result = apply(&request, report.response())?;
    store.record_transfer(report)?;
    crate::authority_inspection::policy::retain_records(bootstrap, store, &records)?;
    Ok(result)
}
