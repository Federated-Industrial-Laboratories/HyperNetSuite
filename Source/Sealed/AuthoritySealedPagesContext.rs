// SPDX-License-Identifier: MIT
// Local dependency discovery never weakens the signed final snapshot or contact pins.
use super::*;
pub(super) fn snapshot(c: &Client, refs: &[VersionRef]) -> Result<V> {
    Ok(a(vec![
        a(vec![
            V::Uint(c.store.prefix().scope().epoch),
            V::Uint(c.store.prefix().height()),
            b(c.store.prefix().policy_state()),
        ]),
        a(refs.iter().map(reference).collect()),
    ]))
}
pub(super) fn probe(
    c: &Client,
    command: domain::Command,
    grant: &VersionRef,
    snapshot: &V,
) -> Result<Vec<VersionRef>> {
    let operation = domain::Operation {
        command,
        grant: Some(grant.clone()),
        snapshot: domain::snapshot(snapshot)?,
    };
    let scope = c.bootstrap.descriptor().scope();
    let intent = Intent {
        network: scope.network,
        incarnation: scope.incarnation,
        generation: 1,
        generation_id: [1; 32],
        sequence: 1,
        acknowledged_through: 0,
        requester: c.key.verifying_key().to_bytes(),
        action: "AuthorityDomain".into(),
        resource: operation.command.resource(),
        revision: 1,
        profile_generation: 0,
        minimum_policy_epoch: scope.epoch,
        minimum_policy_height: c.store.prefix().height(),
        expected: vec![],
        parameters: operation.parameters()?,
        digest: [1; 32],
    };
    let cache = c.cache()?;
    let governance = domain::result::merge(&c.bootstrap, &cache.records)?;
    let decision = operation.prepare(
        &cache.state,
        &governance,
        &Reservations(c.bootstrap.reservations().to_vec()),
        &intent,
        now(c)?,
        false,
        false,
    )?;
    ensure!(
        decision.code == 0,
        "sealed preparation refused with code {}; refresh the exact object and recipient context",
        decision.code
    );
    Ok(decision.dependencies)
}
pub(super) fn prepare(
    c: &Client,
    name: &str,
    resource: Digest,
    grant: &VersionRef,
    build: impl Fn(&V) -> Result<domain::Command>,
) -> Result<domain::Command> {
    if let Some(pending) = c.store.resume_ordinary()? {
        let intent = Intent::from_signed(pending.signed())?;
        let operation = domain::Operation::parse(&intent)?;
        ensure!(
            operation.command.name() == name
                && operation.command.resource() == resource
                && operation.grant.as_ref() == Some(grant),
            "another exact authority request is pending"
        );
        return Ok(operation.command);
    }
    let first = snapshot(c, &[])?;
    let refs = probe(c, build(&first)?, grant, &first)?;
    build(&snapshot(c, &refs)?)
}
pub(super) fn read_grant(
    c: &Client,
    selected: Option<&str>,
    fallback: &VersionRef,
) -> Result<VersionRef> {
    selected
        .map(|v| c.cache()?.grant(&c.bootstrap, id(v)?))
        .transpose()
        .map(|v| v.unwrap_or_else(|| fallback.clone()))
}
pub(super) fn identity_context(
    c: &mut Client,
    grant: &VersionRef,
    kind: u64,
    lookup: Digest,
) -> Result<domain::Record> {
    let result = c.domain_action(
        identity::Command::Context { kind, lookup }.into(),
        Some(grant.clone()),
    )?;
    Ok(result.cache.state.record(kind, lookup)?.clone())
}
pub(super) fn pinned_audience(vault: &Vault, audience: &identity::Audience) -> Result<()> {
    for root in &audience.allowed_roots {
        ensure!(
            vault.contact_root(root.id)?.reference == *root,
            "audience root differs from independently accepted contact"
        );
    }
    Ok(())
}
pub(super) fn current_policy(
    c: &mut Client,
    grant: &VersionRef,
    expected: &publication::ObjectPolicy,
) -> Result<()> {
    let result = c.domain_action(
        publication::Command::Context {
            object: expected.object,
        }
        .into(),
        Some(grant.clone()),
    )?;
    ensure!(
        result.cache.state.record(104, expected.object)?.reference == expected.reference,
        "sealed object policy changed"
    );
    Ok(())
}
pub(super) fn own_device(
    vault: &Vault,
    device: &identity::Binding,
) -> Result<age::x25519::Identity> {
    let identity = vault.device_identity(device.device)?;
    ensure!(
        vault
            .device_signer(device.device)?
            .verifying_key()
            .to_bytes()
            == device.signing_key
            && crypto::recipient_key(&identity.to_public())? == device.encryption_key,
        "selected binding differs from locally held recipient keys"
    );
    Ok(identity)
}

pub(super) fn reviewer(
    vault: &mut Vault,
    state: &domain::State,
    governance: &crate::authority_governance::Governance,
    object: Digest,
    at: u64,
    envelope: &[u8],
) -> Result<identity::Binding> {
    let device = identity::Binding::parse(
        &wire::envelope(envelope, 1)?.0,
        state.network,
        state.incarnation,
    )?;
    vault.observe_binding(device.member, envelope, |root, device| {
        identity::current_member(governance, state.network, root.member, at)?;
        identity::admitted_device(state, root, device, at, (2, object))?
            .context("reviewer device admission is not current for this object")?;
        Ok(())
    })
}

#[cfg(test)]
#[path = "AuthoritySealedPagesContextTests.rs"]
mod tests;
