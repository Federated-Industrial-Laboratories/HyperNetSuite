// SPDX-License-Identifier: MIT
// Policy discovery carries no content identifiers and precedes private ordinary operations.
use super::*;
const ACTION: &str = "AuthorityPolicyContext";

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
fn discover_once(
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
    if store.resume_ordinary()?.is_some() {
        // Reconcile the original operation under its retained policy before another query.
        return Ok(());
    }
    let descriptor = store.descriptor().clone();
    let scope = descriptor.scope();
    let exchange = crate::authority_inspection::read_client::exchange(
        crate::authority_read::Query::PolicyContext,
        path,
        signer,
        store,
        session,
        &mut clock,
    )?;
    let result = (|| {
        let mut pair = None;
        let verified = crate::authority_read::verify_response(
            &descriptor,
            &exchange.request,
            &exchange.challenge,
            crate::authority_read::Response {
                node: &exchange.reply.node,
                certificate: &exchange.reply.certificate,
                result: &exchange.reply.result,
                ancestry: &exchange.evidence.nodes,
            },
            |_, result, _| {
                if result.disposition != Disposition::Permit {
                    return Ok(vec![]);
                }
                let (p, r, refs) = pair_from_value(
                    &wire::decode(&result.value)?,
                    scope.network,
                    scope.incarnation,
                )?;
                crate::authority_domains::result::minimum(&refs, store.generations())?;
                pair = Some((p, r));
                Ok(refs)
            },
        )?;
        let verified = exchange.evidence.attach_read(store, verified)?;
        if verified.result.disposition != Disposition::Permit {
            store.observe_read(verified, session, &mut clock, 0)?;
            bail!("policy discovery refused");
        }
        let (p, r) = pair.context("certified policy pair absent")?;
        // Candidate bytes precede the floor so interruption cannot hide a learned contract.
        retain_cached_pair(store, PENDING, &p, &r)?;
        store.accept_read(verified, session, &mut clock, 0, |_, store| {
            retain_pair(store, &p, &r)
        })?;
        remaining(exchange.deadline)?;
        Ok(())
    })();
    if result.is_err() {
        session.discard(&exchange.challenge)?;
    } else {
        exchange.control.retain(store);
    }
    result
}

#[allow(clippy::too_many_arguments)]
pub fn discover(
    bootstrap: &Verified,
    path: &Path,
    signer: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    clock: impl FnMut() -> Result<ClockHealth>,
) -> Result<()> {
    discover_once(bootstrap, path, signer, store, session, clock)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn refresh_before_request_with_budget(
    bootstrap: &Verified,
    path: &Path,
    signer: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    mut clock: impl FnMut() -> Result<ClockHealth>,
    budget: &mut crate::authority_inspection::read_client::RetryBudget,
) -> Result<()> {
    budget.run(|budget| {
        discover_once(bootstrap, path, signer, store, session, || {
            budget.clock(&mut clock)
        })
    })?;
    require_accepted(bootstrap, store)
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
