// SPDX-License-Identifier: MIT
// Media participants retain exact requests and validate selected-store receipts before acknowledgement.
use super::*;
use crate::{
    authority_domains::{
        self as domain,
        page::{self, Command, MediaRequest as Request},
    },
    authority_inspection::domain_client::{self, Cache},
    authority_membership::Reservations,
};
pub fn ensure(
    store: &mut Store,
    authority: &Path,
    signer: &SigningKey,
    session: &mut Session,
    mut clock: impl FnMut() -> Result<ClockHealth>,
) -> Result<()> {
    let descriptor = store.descriptor().clone();
    stream_client::ensure_stream(&descriptor, authority, signer, store, session, &mut clock)
}
pub fn prepare(
    bootstrap: &Verified,
    signer: &SigningKey,
    store: &mut Store,
    command: Command,
    grant: VersionRef,
    health: ClockHealth,
) -> Result<Request> {
    prepare_domain(
        bootstrap,
        signer,
        store,
        command.into(),
        Some(grant),
        health,
    )
}
pub fn prepare_domain(
    bootstrap: &Verified,
    signer: &SigningKey,
    store: &mut Store,
    command: domain::Command,
    grant: Option<VersionRef>,
    health: ClockHealth,
) -> Result<Request> {
    ensure!(
        matches!(
            &command,
            domain::Command::Page(Command::MediaAuthorise { .. })
                | domain::Command::Federation(domain::federation::Command::MediaAuthorise { .. })
        ),
        "only a finite media effect can leave the participant"
    );
    store.require_requester(signer.verifying_key().to_bytes())?;
    if let Some(pending) = store.resume_ordinary()? {
        let request = Request::parse(pending.signed())?;
        let old = domain::Operation::parse(request.intent())?;
        ensure!(
            request.domain_command().value() == command.value() && old.grant == grant,
            "another media effect is pending; recover its exact operation first"
        );
        return Ok(request);
    }
    let cache = Cache::load(bootstrap, store)?;
    let records = domain_client::merge(bootstrap, &cache.records)?;
    let mut op = domain::Operation {
        grant,
        command,
        snapshot: domain::snapshot(&a(vec![
            a(vec![
                V::Uint(store.prefix().scope().epoch),
                V::Uint(store.prefix().height()),
                b(store.prefix().policy_state()),
            ]),
            a(vec![]),
        ]))?,
    };
    let mut probe = request_probe(store, &op)?;
    let d = op.prepare(
        &cache.state,
        &records,
        &Reservations(bootstrap.reservations().to_vec()),
        &probe,
        health.observe()?.wall_ms,
        false,
        false,
    )?;
    ensure!(
        d.code == 0,
        "media effect preflight refused with code {}; refresh its exact publication and hosting consent",
        d.code
    );
    if op.mutation() {
        probe.expected = d.dependencies;
        op.snapshot = domain::snapshot(&a(vec![
            a(vec![
                V::Uint(store.prefix().scope().epoch),
                V::Uint(store.prefix().height()),
                b(store.prefix().policy_state()),
            ]),
            a(probe.expected.iter().map(version_value).collect()),
        ]))?;
        probe.parameters = op.parameters()?;
    }
    retain_request(store, signer, &probe)
}
fn request_probe(store: &Store, operation: &domain::Operation) -> Result<Intent> {
    let scope = store.descriptor().scope();
    let slot = store.ordinary_slot()?;
    Ok(Intent {
        network: scope.network,
        incarnation: scope.incarnation,
        generation: slot.generation(),
        generation_id: slot.generation_id(),
        sequence: slot.sequence(),
        acknowledged_through: slot.acknowledged_through(),
        requester: store.requester(),
        action: "AuthorityDomain".into(),
        resource: operation.command.resource(),
        revision: u64::from(operation.mutation()),
        profile_generation: 0,
        minimum_policy_epoch: slot.minimum_policy_epoch(),
        minimum_policy_height: slot.minimum_policy_height(),
        expected: vec![],
        parameters: operation.parameters()?,
        digest: [1; 32],
    })
}
fn retain_request(store: &mut Store, signer: &SigningKey, probe: &Intent) -> Result<Request> {
    // Refuse an inconsistent marker or snapshot before it can become a durable pending request.
    domain::Operation::parse(probe)?;
    Request::parse(&prepare_ordinary(
        &store.descriptor().clone(),
        signer,
        store,
        "AuthorityDomain",
        probe.resource,
        probe.revision,
        &probe.expected,
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
    ensure!(payload.len() <= 32768, "media chunk exceeds its wire bound");
    wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("MediaExchange".into()),
        b(request.signed()),
        b(payload),
        V::Bool(reconcile),
    ]))
}
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
    let receipt = page::MediaReceipt::parse(bytes)?;
    let descriptor = store.descriptor_for_scope(&receipt.scope()?)?;
    let report = receipt.verify(bootstrap, &descriptor)?;
    let pending = store
        .resume_ordinary()?
        .context("media receipt has no pending participant request")?;
    ensure!(
        report.request().requester == store.requester()
            && pending.digest() == report.request().digest,
        "media receipt differs from exact pending participant request"
    );
    let request = Request::parse(pending.signed())?;
    let current = store.descriptor().clone();
    stream_client::status_local(&current, authority, signer, store, session, &mut clock)?;
    ensure!(
        report.result().disposition() == Disposition::Permit,
        "media effect refused with code {}; current stream status is retained",
        report.result().code()
    );
    domain_client::retain_media(bootstrap, store, &report)?;
    // The callback must durably retain a received range or receipt before acknowledging it.
    let result = apply(&request, report.response())?;
    store.record_media(report)?;
    Ok(result)
}

#[cfg(test)]
#[path = "AuthorityPageMediaClientTests.rs"]
mod tests;
