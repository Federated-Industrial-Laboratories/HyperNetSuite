// SPDX-License-Identifier: MIT
// The closed fresh-read set retains authenticated context without completing an ordinary effect.
use super::*;
use crate::authority_read::{self as read, Query};

pub(super) fn handles(command: &Command) -> bool {
    matches!(
        command,
        Command::Page(domains::page::Command::View { .. })
            | Command::Route(
                domains::routes::Command::Lookup { .. }
                    | domains::routes::Command::VoucherContext { .. }
            )
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn local(
    bootstrap: &Verified,
    request: Request,
    path: &Path,
    signer: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    clock: &mut impl FnMut() -> Result<ClockHealth>,
) -> Result<ResultState> {
    ensure!(
        bootstrap.fully_accepted()
            && bootstrap.descriptor().canonical() == store.initial_descriptor().canonical(),
        "fresh domain bootstrap differs from retained floor"
    );
    ensure!(
        store.resume_ordinary()?.is_none() && store.resume_fence()?.is_none(),
        "reconcile the exact pending operation before a fresh domain read"
    );
    // This content-free read enforces the accepted privacy contract before resource disclosure.
    policy::refresh_before_request(bootstrap, path, signer, store, session, &mut *clock)?;
    let prior = Cache::load(bootstrap, store)?;
    let expected = vec![policy::current_reference(bootstrap, store)?];
    let operation = request.operation(store, &expected)?;
    let descriptor = store.descriptor().clone();
    let exchange = crate::authority_inspection::read_client::exchange(
        Query::Domain(operation),
        path,
        signer,
        store,
        session,
        clock,
    )?;
    let result = (|| {
        let mut candidate = None;
        let verified = read::verify_response(
            &descriptor,
            &exchange.request,
            &exchange.challenge,
            read::Response {
                node: &exchange.reply.node,
                certificate: &exchange.reply.certificate,
                result: &exchange.reply.result,
                ancestry: &exchange.evidence.nodes,
            },
            |request, result, statement| {
                let checked = read::verify_domain(
                    bootstrap,
                    &prior.state,
                    &prior.records,
                    request,
                    result,
                    statement,
                    &[],
                )?;
                ensure!(
                    checked.updates.is_empty(),
                    "fresh read returned a state mutation"
                );
                minimum(&checked.versions, store.generations())?;
                policy::require_records_accepted(bootstrap, store, &checked.records)?;
                let versions = checked.versions.clone();
                candidate = Some(checked);
                Ok(versions)
            },
        )?;
        let verified = exchange.evidence.attach_read(store, verified)?;
        if verified.result.disposition != Disposition::Permit {
            let code = verified.result.code;
            store.observe_read(verified, session, clock, 0)?;
            return Err(Refusal { code }.into());
        }
        let candidate = candidate.context("permitted fresh read lacks validated context")?;
        let prefix = verified.point().prefix().clone();
        let evaluated_at_ms = verified.statement.evaluated_at_ms;
        let expires_at_ms = verified.statement.expires_at_ms;
        let receipt = wire::encode(&a(vec![
            V::Uint(201),
            V::Uint(1),
            V::Text("AuthorityReadReceipt".into()),
            b(&exchange.request),
            b(&exchange.challenge),
            b(&exchange.reply.result),
            b(&exchange.reply.certificate),
            b(&exchange.reply.node),
        ]))?;
        remaining(exchange.deadline)?;
        store.accept_read(verified, session, clock, 0, |_, store| {
            let cache = Cache {
                state: candidate.state,
                records: candidate.records,
            };
            cache.save(store)?;
            policy::retain_records(bootstrap, store, &cache.records)?;
            remaining(exchange.deadline)?;
            Ok(ResultState {
                value: candidate.value,
                prefix,
                cache,
                evaluated_at_ms,
                expires_at_ms,
                deadline_boot_ms: exchange.deadline,
                receipt,
            })
        })
    })();
    if result.is_err() {
        session.discard(&exchange.challenge)?;
    } else {
        exchange.control.retain(store);
    }
    result
}
