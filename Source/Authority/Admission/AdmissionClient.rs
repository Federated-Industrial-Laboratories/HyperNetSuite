// SPDX-License-Identifier: MIT
// Native admission retains its own exact request journal and certified context before external handoff.
use super::*;
use crate::{
    authority_admission as native,
    authority_read::{self as read, Query},
};
use serde::{Deserialize, Serialize};

#[path = "AdmissionHelperTypes.rs"]
pub(crate) mod types;
const CURRENT: &str = "AdmissionRecords.cbor";
const STAGED: &str = "AdmissionRecordsPending.cbor";
const SOURCE: &str = "AdmissionRequestSource.cbor";
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Certificate {
    schema: String,
    bootstrap: String,
    epochs: Vec<crate::authority_epoch::archive::Activated>,
    request: String,
    challenge: String,
    node: String,
    certificate: String,
    result: String,
    ancestry: Vec<String>,
}
impl Certificate {
    pub fn verify(bootstrap: &Verified, bytes: &[u8], now: u64) -> Result<native::Disclosure> {
        Self::verify_inner(bootstrap, bytes, Some(now))
    }
    pub(crate) fn authenticate(bootstrap: &Verified, bytes: &[u8]) -> Result<native::Disclosure> {
        Self::verify_inner(bootstrap, bytes, None)
    }
    fn verify_inner(
        bootstrap: &Verified,
        bytes: &[u8],
        now: Option<u64>,
    ) -> Result<native::Disclosure> {
        ensure!(
            bytes.len() <= types::MAX_INPUT_BYTES && bootstrap.fully_accepted(),
            "admission proof bounds differ"
        );
        let c: Self = serde_json::from_slice(bytes)?;
        ensure!(
            c.schema == "HyperNetNativeAdmissionProof/1"
                && c.bootstrap == hex::encode(bootstrap.file_digest())
                && c.ancestry.len() <= 128,
            "admission proof bootstrap differs"
        );
        let descriptor =
            crate::authority_epoch::archive::resolve(bootstrap.descriptor(), &c.epochs)?.descriptor;
        let mut disclosure = None;
        let request = hex::decode(&c.request)?;
        let challenge = hex::decode(&c.challenge)?;
        let node = hex::decode(&c.node)?;
        let quorum = hex::decode(&c.certificate)?;
        let result = hex::decode(&c.result)?;
        let ancestry = c
            .ancestry
            .iter()
            .map(hex::decode)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let verified = read::verify_response(
            &descriptor,
            &request,
            &challenge,
            read::Response {
                node: &node,
                certificate: &quorum,
                result: &result,
                ancestry: &ancestry,
            },
            |request, result, statement| {
                let Query::Admission { policy, claim } = request.query else {
                    bail!("admission proof has another query")
                };
                let d = native::Disclosure::parse(
                    &wire::decode(&result.value)?,
                    descriptor.scope().network,
                    descriptor.scope().incarnation,
                    request.requester,
                    policy,
                    claim,
                    statement.evaluated_at_ms,
                )?;
                let versions = d.versions.clone();
                disclosure = Some(d);
                Ok(versions)
            },
        )?;
        ensure!(
            verified.result.disposition == Disposition::Permit
                && now.is_none_or(|now| verified.statement.evaluated_at_ms
                    <= now.saturating_add(1250)
                    && now.saturating_add(1250) < verified.statement.expires_at_ms
                    && now >= bootstrap.summary.bootstrap_time_ms),
            "admission proof is refused, expired or future"
        );
        disclosure.context("admission proof contains no current context")
    }
    fn encode(bootstrap: &Verified, store: &Store, x: &read_client::Exchange) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&Self {
            schema: "HyperNetNativeAdmissionProof/1".into(),
            bootstrap: hex::encode(bootstrap.file_digest()),
            epochs: store.epoch_archive()?,
            request: hex::encode(&x.request),
            challenge: hex::encode(&x.challenge),
            node: hex::encode(&x.reply.node),
            certificate: hex::encode(&x.reply.certificate),
            result: hex::encode(&x.reply.result),
            ancestry: x.evidence.nodes.iter().map(hex::encode).collect(),
        })?)
    }
}
fn encode_records(records: &[Vec<u8>]) -> Result<Vec<u8>> {
    wire::encode_state(&a(records.iter().map(|x| b(x)).collect()))
}
fn read_records(store: &Store, name: &str) -> Result<Option<Vec<Vec<u8>>>> {
    let bytes = match files::read_at(
        store.profile_directory(),
        OsStr::new(name),
        crate::authority_capacity::MAX_STATE_BYTES,
        true,
    ) {
        Ok(bytes) => bytes,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    wire::decode_state(&bytes)?
        .list(crate::authority_capacity::MAX_RECORDS)?
        .iter()
        .map(|x| Ok(x.bytes()?.to_vec()))
        .collect::<Result<Vec<_>>>()
        .map(Some)
}
pub(crate) fn retained(bootstrap: &Verified, store: &Store) -> Result<Vec<Vec<u8>>> {
    for name in [STAGED, CURRENT] {
        if let Some(records) = read_records(store, name)?
            && ContextState::retained(bootstrap, store, &records).is_ok()
        {
            return Ok(records);
        }
    }
    let mut records = read_records(store, "Governance.cbor")?
        .unwrap_or_else(|| bootstrap.governance_records().to_vec());
    tier::refresh_cached_tiers(bootstrap, store, &mut records)?;
    policy::refresh_cached_policies(bootstrap, store, &mut records)?;
    ContextState::retained(bootstrap, store, &records)?;
    Ok(records)
}
fn merge(bootstrap: &Verified, store: &Store, records: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    let prior = retained(bootstrap, store)?;
    let n = store.descriptor().scope().network;
    let i = store.descriptor().scope().incarnation;
    let mut map = prior
        .into_iter()
        .map(|b| {
            Ok((
                Governance::record_versions(n, i, std::slice::from_ref(&b))?
                    .remove(0)
                    .index(),
                b,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    for bytes in records {
        let r = Governance::record_versions(n, i, std::slice::from_ref(bytes))?.remove(0);
        map.insert(r.index(), bytes.clone());
    }
    Ok(map.into_values().collect())
}
fn stage(store: &Store, name: &str, records: &[Vec<u8>]) -> Result<()> {
    files::atomic_at(
        store.profile_directory(),
        OsStr::new(name),
        &encode_records(records)?,
        true,
    )
}
fn publish(bootstrap: &Verified, store: &Store, records: &[Vec<u8>]) -> Result<()> {
    let context = ContextState::retained(bootstrap, store, records)?;
    stage(store, CURRENT, records)?;
    context.save(store)?;
    policy::retain_records(bootstrap, store, records)?;
    domain_client::Cache::retain_context(bootstrap, store, &context)
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn query(
    bootstrap: &Verified,
    socket: &Path,
    key: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    clock: &mut impl FnMut() -> Result<ClockHealth>,
    policy_id: [u8; 32],
    claim: Option<[u8; 32]>,
) -> Result<(native::Disclosure, Vec<u8>)> {
    stream_client::ensure_stream(
        &store.descriptor().clone(),
        socket,
        key,
        store,
        session,
        clock,
    )?;
    let descriptor = store.descriptor().clone();
    let exchange = read_client::exchange_with_budget(
        Query::Admission {
            policy: policy_id,
            claim,
        },
        socket,
        key,
        store,
        session,
        clock,
        None,
    )?;
    let result = (|| {
        let mut disclosure = None;
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
                let d = native::Disclosure::parse(
                    &wire::decode(&result.value)?,
                    descriptor.scope().network,
                    descriptor.scope().incarnation,
                    request.requester,
                    policy_id,
                    claim,
                    statement.evaluated_at_ms,
                )?;
                crate::authority_domains::result::minimum(&d.versions, store.generations())?;
                let refs = d.versions.clone();
                disclosure = Some(d);
                Ok(refs)
            },
        )?;
        let verified = exchange.evidence.attach_read(store, verified)?;
        if verified.result.disposition != Disposition::Permit {
            let code = verified.result.code;
            store.observe_read(verified, session, clock, 0)?;
            bail!("admission context refused with code {code}");
        }
        let disclosure = disclosure.context("admission context absent")?;
        let records = merge(bootstrap, store, &disclosure.records)?;
        stage(store, STAGED, &records)?;
        let proof = Certificate::encode(bootstrap, store, &exchange)?;
        let ((), consumed) =
            store.accept_read_consumed(verified, session, clock, 0, |_, store| {
                publish(bootstrap, store, &records)
            })?;
        exchange
            .control
            .acknowledge_read(&consumed, key, exchange.deadline);
        Ok((disclosure, proof))
    })();
    if result.is_err() {
        session.discard(&exchange.challenge)?;
    } else {
        exchange.control.retain(store);
    }
    result
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn mutate(
    bootstrap: &Verified,
    socket: &Path,
    key: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    clock: &mut impl FnMut() -> Result<ClockHealth>,
    requested: Option<native::Operation>,
) -> Result<()> {
    let descriptor = store.descriptor().clone();
    let (operation, intent, source) = if let Some(pending) = store.resume_ordinary()? {
        let intent = Intent::from_signed(pending.signed())?;
        let operation = native::Operation::parse(&intent)?;
        if let Some(requested) = requested {
            ensure!(
                requested.parameters()? == operation.parameters()?,
                "another exact admission operation is pending"
            );
        }
        let source = read_records(store, SOURCE)?
            .context("pending admission source is missing; preserve the requester journal")?;
        (operation, pending.signed().to_vec(), source)
    } else {
        let operation = requested.context("there is no admission operation to resume")?;
        let source = retained(bootstrap, store)?;
        let reference = native::record_reference(
            &operation.next,
            descriptor.scope().network,
            descriptor.scope().incarnation,
        )?;
        let intent = sign_ordinary(
            &descriptor,
            key,
            store,
            "AuthorityAdmission",
            reference.id,
            reference.generation,
            &operation.snapshot.references,
            &operation.parameters()?,
        )?;
        let parsed = Intent::from_signed(&intent)?;
        let operation = native::Operation::parse(&parsed)?;
        operation.authorise(
            &source,
            &crate::authority_membership::Reservations(bootstrap.reservations().to_vec()),
            &parsed,
            clock()?.observe()?.wall_ms,
            false,
        )?;
        // Invalid public input never occupies the registrar's durable ordinary slot.
        stage(store, SOURCE, &source)?;
        store.prepare_ordinary(store.ordinary_slot()?, &intent)?;
        (operation, intent, source)
    };
    let control = LocalControl::prepare_authority(socket, store)?;
    let health = clock()?;
    let now = health.observe()?;
    let challenge = session.issue(&intent, key, random_id()?, DURATION, health)?;
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
        .context("admission deadline overflow")?;
    let (reply, evidence) = crate::authority_local_transport::exchange(
        &descriptor,
        &ordered,
        deadline,
        &control,
        store.prefix(),
        store.tree_head(),
        clock,
    )?;
    let mut prospective = None;
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
        |intent, result, executed| {
            if result.disposition != Disposition::Permit {
                return ActionValidation::new(vec![]);
            }
            let selected = operation.authorise(
                &source,
                &crate::authority_membership::Reservations(bootstrap.reservations().to_vec()),
                intent,
                executed.evaluated_at_ms,
                false,
            )?;
            let refs = operation.result_references(
                &selected.dependencies,
                intent.network,
                intent.incarnation,
            )?;
            let expected = a(vec![
                V::Uint(201),
                V::Uint(1),
                V::Text("AuthorityAdmission".into()),
                a(refs.iter().map(version_value).collect()),
                b(&operation.next),
            ]);
            ensure!(
                wire::decode(&result.value)? == expected,
                "admission result differs from independently checked transition"
            );
            prospective = Some(selected.records);
            ActionValidation::mutation(refs, operation.updates(intent.network, intent.incarnation)?)
        },
    )?;
    let verified = evidence.attach(store, verified)?;
    if verified.disposition() != Disposition::Permit {
        let code = verified.code();
        store.observe(verified)?;
        session.discard(&challenge)?;
        bail!("admission mutation refused with code {code}");
    }
    let records = prospective.context("admission result has no validated records")?;
    stage(store, STAGED, &records)?;
    let permit = store.accept_with_clock(verified, session, clock, 0)?;
    permit.perform_with_clock(
        store,
        session,
        clock,
        1,
        |restrictions| {
            ensure!(
                *restrictions == Restrictions::default(),
                "admission restriction differs"
            );
            Ok(())
        },
        |_, store| publish(bootstrap, store, &records),
    )?;
    control.retain(store);
    Ok(())
}
