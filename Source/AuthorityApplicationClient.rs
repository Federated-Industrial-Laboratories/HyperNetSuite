// SPDX-License-Identifier: MIT
// Scoped application workflows retain quorum floors without exposing complete governance.
use super::*;
use crate::authority_applications::{self as applications, Operation};
use crate::authority_membership::{self as membership, Mutation, Reservations};
use std::collections::BTreeSet;

const CONTEXT: &str = "AuthorityDelegationContext";
const LIMIT: usize = 98304;
pub enum Request {
    Context(Selection),
    Delegate {
        parent: VersionRef,
        child: V,
    },
    Register {
        parent: VersionRef,
        accepted: Vec<u8>,
    },
    Get([u8; 32]),
    List,
    Withdraw(VersionRef),
}
impl Request {
    fn action(&self) -> &'static str {
        match self {
            Self::Context(_) => CONTEXT,
            Self::Delegate { .. } => "AuthorityDelegateGrant",
            Self::Register { .. } => "AuthorityApplicationRegister",
            Self::Get(_) => "AuthorityApplicationGet",
            Self::List => "AuthorityApplicationList",
            Self::Withdraw(_) => "AuthorityApplicationWithdraw",
        }
    }
    fn resource(&self, scope: &proof::Scope, requester: [u8; 32]) -> Result<([u8; 32], u64)> {
        Ok(match self {
            Self::Context(selection) => (selection.parent, 0),
            Self::Delegate { child, .. } => {
                (membership::ChildSpec::parse(child, scope.network)?.id, 1)
            }
            Self::Register { accepted, .. } => (
                applications::Acceptance::parse(accepted, scope.network, scope.incarnation, true)?
                    .application,
                1,
            ),
            Self::Get(key) => (*key, 0),
            Self::List => (requester, 0),
            Self::Withdraw(reference) => (reference.id, 1),
        })
    }
    fn parameters(&self, store: &Store, expected: &[VersionRef]) -> Result<Vec<u8>> {
        let mut p = vec![V::Uint(200), V::Uint(1), V::Text(self.action().into())];
        let snapshot = || {
            a(vec![
                point(store.prefix()),
                a(expected.iter().map(version_value).collect()),
            ])
        };
        match self {
            Self::Context(s) => {
                p.extend([
                    b(&s.parent),
                    b(&s.tier),
                    s.child.map_or(V::Null, |v| b(&v)),
                    point(store.prefix()),
                    a(store.generations().iter().map(version_value).collect()),
                ]);
            }
            Self::Delegate { parent, child } => {
                p.extend([version_value(parent), child.clone(), snapshot()])
            }
            Self::Register { parent, accepted } => {
                p.extend([version_value(parent), b(accepted), snapshot()])
            }
            Self::Get(application) => p.extend([
                b(application),
                a(store.generations().iter().map(version_value).collect()),
            ]),
            Self::List => p.extend([
                b(&store.requester()),
                a(store.generations().iter().map(version_value).collect()),
            ]),
            Self::Withdraw(reference) => p.extend([version_value(reference), snapshot()]),
        }
        wire::encode(&a(p))
    }
    fn matches_pending(
        &self,
        intent: &Intent,
        scope: &proof::Scope,
        requester: [u8; 32],
    ) -> Result<()> {
        let (resource, revision) = self.resource(scope, requester)?;
        ensure!(
            intent.action == self.action()
                && intent.resource == resource
                && intent.revision == revision
                && intent.profile_generation == 0,
            "another exact request is pending; resume it or explicitly fence its generation"
        );
        let decoded = wire::decode(&intent.parameters)?;
        let f = decoded.list(8)?;
        let equal = match self {
            Self::Context(s) => {
                f.len() == 8
                    && f[3] == b(&s.parent)
                    && f[4] == b(&s.tier)
                    && f[5] == s.child.map_or(V::Null, |v| b(&v))
            }
            Self::Delegate { parent, child } => {
                f.len() == 6 && f[3] == version_value(parent) && f[4] == *child
            }
            Self::Register { parent, accepted } => {
                f.len() == 6 && f[3] == version_value(parent) && f[4] == b(accepted)
            }
            Self::Get(key) => f.len() == 5 && f[3] == b(key),
            Self::List => f.len() == 5 && f[3] == b(&requester),
            Self::Withdraw(reference) => f.len() == 5 && f[3] == version_value(reference),
        };
        ensure!(
            equal,
            "request differs from exact durable application intent"
        );
        Ok(())
    }
}
pub struct ResultState {
    pub value: V,
    pub prefix: Prefix,
    pub context: Option<DelegationContext>,
}
struct Candidate {
    value: V,
    versions: Vec<VersionRef>,
    context: Option<DelegationContext>,
}
struct Prepared<'a> {
    bootstrap: &'a Verified,
    descriptor: TrustDescriptor,
    request: Request,
    source: Vec<Vec<u8>>,
    selected_entries: Vec<Vec<u8>>,
    selection: Option<Selection>,
    receipt: Option<&'a Path>,
    intent: Vec<u8>,
    challenge: Vec<u8>,
    ordered: Vec<u8>,
    deadline: u64,
}
impl<'a> Prepared<'a> {
    #[allow(
        clippy::too_many_arguments,
        reason = "Keep protocol inputs, state and validation callbacks explicit."
    )]
    fn new(
        bootstrap: &'a Verified,
        request: Request,
        context: Option<&DelegationContext>,
        receipt: Option<&'a Path>,
        signer: &SigningKey,
        store: &mut Store,
        session: &mut Session,
        health: ClockHealth,
    ) -> Result<Self> {
        ensure!(
            bootstrap.fully_accepted()
                && bootstrap.descriptor().canonical() == store.initial_descriptor().canonical(),
            "application bootstrap differs from current floor"
        );
        store.require_requester(signer.verifying_key().to_bytes())?;
        let source = if let Some(context) = context {
            context.current(store)?;
            merged(bootstrap, &context.entries)?
        } else if let Request::Withdraw(reference) = &request {
            load_state(store, reference.id)?
        } else {
            Vec::new()
        };
        let selection = context.map(|c| c.selection.clone());
        let now = health.observe()?;
        let descriptor = store.descriptor().clone();
        let scope = descriptor.scope();
        let intent = if let Some(pending) = store.resume_ordinary()? {
            request.matches_pending(
                &Intent::from_signed(pending.signed())?,
                scope,
                store.requester(),
            )?;
            pending.signed().to_vec()
        } else {
            let (resource, revision) = request.resource(scope, store.requester())?;
            if matches!(request, Request::Delegate { .. } | Request::Register { .. }) {
                ensure!(
                    context.is_some_and(|c| c.entries.len() < 64),
                    "selected mutation cache cannot fit its created record"
                );
            }
            let mut probe = Intent {
                network: scope.network,
                incarnation: scope.incarnation,
                generation: 1,
                generation_id: [1; 32],
                sequence: 1,
                acknowledged_through: 0,
                requester: store.requester(),
                action: request.action().into(),
                resource,
                revision,
                profile_generation: 0,
                minimum_policy_epoch: scope.epoch,
                minimum_policy_height: store.prefix().height(),
                expected: Vec::new(),
                parameters: request.parameters(store, &[])?,
                digest: [1; 32],
            };
            let dependencies = match &request {
                Request::Delegate { .. } => {
                    let decision = Mutation::parse(&probe)?.prepare(
                        &source,
                        &Reservations(bootstrap.reservations().to_vec()),
                        &probe,
                        now.wall_ms,
                        false,
                    )?;
                    ensure!(
                        decision.code == 0,
                        "application delegation preflight refused with code {}",
                        decision.code
                    );
                    decision.dependencies
                }
                Request::Register { .. } | Request::Withdraw(_) => {
                    let decision = Operation::parse(&probe)?.prepare(
                        &source,
                        &Reservations(bootstrap.reservations().to_vec()),
                        &probe,
                        now.wall_ms,
                        false,
                    )?;
                    ensure!(
                        decision.code == 0,
                        "application mutation preflight refused with code {}",
                        decision.code
                    );
                    decision
                        .dependencies
                        .into_iter()
                        .filter(|v| decision.created.as_ref() != Some(v))
                        .collect()
                }
                _ => Vec::new(),
            };
            probe.parameters = request.parameters(store, &dependencies)?;
            probe.expected = dependencies;
            if matches!(request, Request::Register { .. }) {
                let created = Operation::parse(&probe)?
                    .derive(&probe)?
                    .context("application registration lacks derived record")?;
                member_offer::preflight_receipt(
                    &probe,
                    &created,
                    &VersionRef {
                        kind: 127,
                        id: resource,
                        generation: 1,
                        digest: wire::digest(&created),
                    },
                )?;
            }
            prepare_ordinary(
                &descriptor,
                signer,
                store,
                request.action(),
                resource,
                revision,
                &probe.expected,
                &probe.parameters,
            )?
        };
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
        Ok(Self {
            bootstrap,
            descriptor,
            request,
            source,
            selected_entries: context.map_or_else(Vec::new, |c| c.entries.clone()),
            selection,
            receipt,
            intent,
            challenge,
            ordered,
            deadline: now
                .boot_ms
                .checked_add(DURATION)
                .context("application deadline overflow")?,
        })
    }
    fn candidate(
        &self,
        intent: &Intent,
        result: &OperationResult,
        executed: &ExecutedResult,
    ) -> Result<Candidate> {
        let immutable = Intent::from_signed(&self.intent)?;
        let challenge = Challenge::from_signed(&self.challenge)?;
        ensure!(
            intent.digest == immutable.digest
                && result.disposition == Disposition::Permit
                && executed.maximum_effect == 1
                && executed.recipient == intent.requester,
            "application result differs from immutable request"
        );
        ensure!(
            executed.expires_at_ms
                <= challenge.evaluation_expiry(executed.evaluated_at_ms, executed.expires_at_ms)?,
            "application evaluation lies outside conservative challenge interval"
        );
        let value = wire::decode(&result.value)?;
        let f = value.list(7)?;
        ensure!(
            f.len() >= 5
                && f[0].uint()? == 201
                && f[1].uint()? == 1
                && f[2].text()? == self.request.action(),
            "unexpected application result schema"
        );
        let reservations = Reservations(self.bootstrap.reservations().to_vec());
        let mut context = None;
        let refs = match &self.request {
            Request::Get(_) | Request::List => {
                applications::validate_lifecycle_result(intent, &value)?
            }
            Request::Delegate { .. } => {
                let mutation = Mutation::parse(intent)?;
                let created = mutation.derive(intent)?;
                let reference = VersionRef {
                    kind: 102,
                    id: intent.resource,
                    generation: 1,
                    digest: wire::digest(&created),
                };
                let mut entries = self.source.clone();
                let cached = versions(&entries)?.contains(&reference);
                let creation_height = record(&value, 201, 6)?[5].uint()?;
                ensure!(
                    creation_height > mutation.snapshot().height
                        && creation_height <= executed.height,
                    "delegation creation height differs from its causal floor or execution"
                );
                let replay = executed.height > creation_height;
                if replay && !cached {
                    entries.push(created.clone());
                    membership::sort_records(&mut entries)?;
                }
                let decision = mutation.authorise(
                    &entries,
                    &reservations,
                    intent,
                    executed.evaluated_at_ms,
                    replay,
                )?;
                ensure!(
                    decision.code == 0
                        && decision.record == created
                        && decision.dependencies == intent.expected
                        && executed.expires_at_ms <= decision.expires_ms,
                    "delegation lacks its exact current dependencies"
                );
                let mut refs = decision.dependencies;
                refs.push(reference);
                refs.sort_by_key(VersionRef::index);
                ensure!(
                    f[4].bytes()? == created && parse_versions(&f[3])? == refs,
                    "delegation result differs from exact created grant"
                );
                if !cached && !replay {
                    entries.push(created);
                    membership::sort_records(&mut entries)?;
                }
                let selected = self
                    .selection
                    .clone()
                    .context("delegation requires scoped context")?;
                // Keep only the previously selected closure and its newly certified child.
                let keep = refs.iter().map(VersionRef::index).collect::<BTreeSet<_>>();
                let entries = entries
                    .into_iter()
                    .filter(|v| {
                        versions(std::slice::from_ref(v))
                            .is_ok_and(|r| keep.contains(&r[0].index()))
                    })
                    .collect();
                context = Some(DelegationContext {
                    selection: selected,
                    descriptor: self.descriptor.clone(),
                    entries,
                });
                refs
            }
            _ => {
                let operation = Operation::parse(intent)?;
                let mut entries = self.source.clone();
                let mut replay = false;
                if matches!(self.request, Request::Context(_)) {
                    ensure!(
                        result.value.len() <= LIMIT,
                        "delegation context exceeds bound"
                    );
                    let selected = record(&value, 201, 5)?[4]
                        .list(64)?
                        .iter()
                        .map(|v| Ok(v.bytes()?.to_vec()))
                        .collect::<Result<Vec<_>>>()?;
                    let refs = versions(&selected)?;
                    ensure!(
                        parse_versions(&f[3])? == refs,
                        "selected records differ from certified references"
                    );
                    entries = merged(self.bootstrap, &selected)?;
                    let Request::Context(selection) = &self.request else {
                        unreachable!()
                    };
                    context = Some(DelegationContext {
                        selection: selection.clone(),
                        descriptor: self.descriptor.clone(),
                        entries: selected,
                    });
                } else if let Some(created) = operation.derive(intent)? {
                    let reference = versions(std::slice::from_ref(&created))?.remove(0);
                    let cached = versions(&entries)?.contains(&reference);
                    let snapshot_height = operation
                        .snapshot()
                        .context("mutation requires snapshot")?
                        .height;
                    let creation_height = record(&value, 201, 6)?[5].uint()?;
                    ensure!(
                        creation_height > snapshot_height && creation_height <= executed.height,
                        "application creation height differs from its causal floor or execution"
                    );
                    replay = executed.height > creation_height;
                    if replay && !cached {
                        entries.push(created.clone());
                        membership::sort_records(&mut entries)?;
                    }
                    if let Some(selection) = &self.selection {
                        if !cached && !replay {
                            entries.push(created);
                            membership::sort_records(&mut entries)?;
                        }
                        context = Some(DelegationContext {
                            selection: selection.clone(),
                            descriptor: self.descriptor.clone(),
                            entries: {
                                let mut selected = self.selected_entries.clone();
                                if !selected.iter().any(|v| wire::digest(v) == reference.digest) {
                                    selected.push(
                                        entries
                                            .iter()
                                            .find(|v| wire::digest(v) == reference.digest)
                                            .context("derived application record is absent")?
                                            .clone(),
                                    );
                                    membership::sort_records(&mut selected)?;
                                }
                                selected
                            },
                        });
                        // Fresh authorization must still inspect the pre-insertion state.
                        if !cached && !replay {
                            entries.retain(|v| wire::digest(v) != reference.digest);
                        }
                    }
                }
                let decision = operation.authorise(
                    &entries,
                    &reservations,
                    intent,
                    executed.evaluated_at_ms,
                    replay,
                )?;
                let evaluated_value = if operation.snapshot().is_some() {
                    a(f[..5].to_vec())
                } else {
                    value.clone()
                };
                ensure!(
                    decision.code == 0
                        && decision.value == evaluated_value
                        && executed.expires_at_ms <= decision.expires_ms,
                    "application result differs from exact authorized lifecycle"
                );
                parse_versions(&f[3])?
            }
        };
        Ok(Candidate {
            value,
            versions: refs,
            context,
        })
    }
    fn validate(
        &self,
        intent: &Intent,
        result: &OperationResult,
        executed: &ExecutedResult,
    ) -> Result<ActionValidation> {
        if result.disposition == Disposition::Refuse {
            let value = wire::decode(&result.value)?;
            let f = record(&value, 201, 4)?;
            ensure!(
                f[2].text()? == self.request.action()
                    && f[3].array(0)?.is_empty()
                    && executed.maximum_effect == 0,
                "invalid application refusal"
            );
            return ActionValidation::new(Vec::new());
        }
        ensure!(
            result.disposition == Disposition::Permit,
            "application operations have no pending result"
        );
        let candidate = self.candidate(intent, result, executed)?;
        if matches!(self.request, Request::List) {
            ActionValidation::application_list(candidate.versions)
        } else {
            ActionValidation::new(candidate.versions)
        }
    }
    fn finish(
        self,
        reply: CertifiedReply,
        evidence: AncestryEvidence,
        store: &mut Store,
        session: &mut Session,
        clock: &mut impl FnMut() -> Result<ClockHealth>,
    ) -> Result<ResultState> {
        ensure!(
            evidence.nodes.last().is_some_and(|v| *v == reply.node),
            "application ancestry differs from control node"
        );
        let verified = proof::verify_response(
            &self.descriptor,
            proof::ProofContext {
                intent: &self.intent,
                challenge: &self.challenge,
                restrictions: Restrictions::default(),
                minimum_height: store.prefix().height(),
                maximum_effect: 1,
                expected_stream: None,
            },
            proof::Response {
                ordered_request: &self.ordered,
                operation_result: &reply.result,
                certificate: &reply.certificate,
                ancestry: &evidence.nodes,
            },
            |i, r, e| self.validate(i, r, e),
        )?;
        let verified = evidence.attach(store, verified)?;
        if verified.disposition() != Disposition::Permit {
            let code = verified.code();
            store.observe(verified)?;
            session.discard(&self.challenge)?;
            bail!("authority application refused with code {code}");
        }
        remaining(self.deadline)?;
        let candidate = self.candidate(
            verified.request().ordinary()?,
            &verified.result,
            &verified.executed,
        )?;
        if matches!(
            self.request,
            Request::Get(_) | Request::List | Request::Withdraw(_)
        ) {
            metadata_minima(&candidate.versions, store.generations())?;
        } else {
            relevant_minima(&candidate.versions, store.generations())?;
        }
        if matches!(self.request, Request::List) {
            check_list_cache(store, &candidate.value)?;
        }
        let prefix = verified.point().prefix().clone();
        let receipt = if self.receipt.is_some() {
            application_offer::receipt(&self.intent, &self.challenge, &self.ordered, &reply)?
        } else {
            Vec::new()
        };
        let permit = store.accept(verified, session, clock()?, 0)?;
        remaining(self.deadline)?;
        permit.perform(
            store,
            session,
            clock()?,
            1,
            |r| {
                ensure!(
                    *r == Restrictions::default(),
                    "application restrictions changed"
                );
                Ok(())
            },
            |_, accepted_store| {
                if let Some(context) = &candidate.context {
                    context.save(accepted_store)?;
                }
                match &self.request {
                    Request::Get(application) => {
                        save_get(accepted_store, *application, &candidate.value)?
                    }
                    Request::Withdraw(reference) => {
                        let mut entries = self.source.clone();
                        let created = record(&candidate.value, 201, 6)?[4].bytes()?.to_vec();
                        if !entries.contains(&created) {
                            entries.push(created);
                            membership::sort_records(&mut entries)?;
                        }
                        save_state(accepted_store, reference.id, &entries)?;
                    }
                    Request::List => save_list(accepted_store, &candidate.value)?,
                    _ => {}
                }
                if let Some(path) = self.receipt {
                    application_offer::save_receipt(path, &receipt, &self.intent)?;
                }
                Ok(ResultState {
                    value: candidate.value,
                    prefix,
                    context: candidate.context,
                })
            },
        )
    }
    fn local(
        self,
        control: &crate::authority_local_transport::LocalControl,
        store: &mut Store,
        session: &mut Session,
        clock: &mut impl FnMut() -> Result<ClockHealth>,
    ) -> Result<ResultState> {
        let challenge = self.challenge.clone();
        let result = (|| {
            let (reply, evidence) = exchange(
                &self.descriptor,
                &self.ordered,
                self.deadline,
                control,
                store,
                clock,
            )?;
            self.finish(reply, evidence, store, session, clock)
        })();
        if result.is_err() {
            session.discard(&challenge)?;
        }
        result
    }
}
#[allow(
    clippy::too_many_arguments,
    reason = "Keep protocol inputs, state and validation callbacks explicit."
)]
pub fn local(
    bootstrap: &Verified,
    request: Request,
    context: Option<&DelegationContext>,
    receipt: Option<&Path>,
    path: &Path,
    signer: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    mut clock: impl FnMut() -> Result<ClockHealth>,
) -> Result<ResultState> {
    // Context discovery already owns the stream; do not order a status between snapshot and mutation.
    if context.is_none() {
        stream_client::ensure_stream(
            &store.descriptor().clone(),
            path,
            signer,
            store,
            session,
            &mut clock,
        )?;
    }
    let control = crate::authority_local_transport::LocalControl::prepare_authority(path, store)?;
    let pending = Prepared::new(
        bootstrap,
        request,
        context,
        receipt,
        signer,
        store,
        session,
        clock()?,
    )?;
    pending.local(&control, store, session, &mut clock)
}
#[cfg(test)]
#[path = "AuthorityApplicationClientTests.rs"]
mod tests;

#[path = "AuthorityApplicationContext.rs"]
mod context;
pub use context::{DelegationContext, Selection, withdrawal_target};
use context::{
    check_list_cache, load_state, merged, metadata_minima, point, relevant_minima, save_get,
    save_list, save_state, versions,
};

pub(super) fn exchange(
    descriptor: &TrustDescriptor,
    ordered: &[u8],
    deadline: u64,
    control: &crate::authority_local_transport::LocalControl,
    store: &Store,
    clock: &mut impl FnMut() -> Result<ClockHealth>,
) -> Result<(CertifiedReply, AncestryEvidence)> {
    let (reply, evidence) = crate::authority_local_transport::exchange(
        descriptor,
        ordered,
        deadline,
        control,
        store.prefix(),
        store.tree_head(),
        clock,
    )?;
    Ok((reply, AncestryEvidence::from_shared(evidence)))
}
