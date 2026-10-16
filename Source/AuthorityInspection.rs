// SPDX-License-Identifier: MIT
// Private operator inspection reveals one exact record only after a durable quorum floor.
#[cfg(test)]
use crate::authority_challenge::boot_time_ms;
use crate::{
    authority_challenge::{ClockHealth, Session},
    authority_floor::Store,
    authority_governance::{Governance, Requirement},
    authority_proof::{
        self as proof, ActionValidation, Challenge, Disposition, ExecutedResult, Intent,
        OperationResult, Prefix, Restrictions, TrustDescriptor, VersionRef,
    },
    transfer_files as files,
    trust_bootstrap::Verified,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, bail, ensure};
use ed25519_dalek::SigningKey;
use rand::{RngCore, rngs::OsRng};
use std::{
    collections::BTreeMap,
    ffi::{CString, OsStr},
    os::{fd::AsRawFd, unix::ffi::OsStrExt},
    path::Path,
    time::Duration,
};

const ACTION: &str = "AuthorityInspect";
const DURATION: u64 = 5000;
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn random_id() -> Result<[u8; 32]> {
    let mut value = [0; 32];
    OsRng.try_fill_bytes(&mut value)?;
    ensure!(value != [0; 32], "random inspection identifier failed");
    Ok(value)
}
fn version_value(v: &VersionRef) -> V {
    a(vec![
        V::Uint(v.kind),
        b(&v.id),
        V::Uint(v.generation),
        b(&v.digest),
    ])
}
fn parse_versions(value: &V) -> Result<Vec<VersionRef>> {
    let values = value
        .list(64)?
        .iter()
        .map(|v| {
            let f = v.array(4)?;
            Ok(VersionRef {
                kind: f[0].uint()?,
                id: f[1].fixed()?,
                generation: f[2].uint()?,
                digest: f[3].fixed()?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    proof::validate_versions(&values, 64)?;
    Ok(values)
}
fn record(value: &V, kind: u64, arity: usize) -> Result<&[V]> {
    let f = value.array(arity)?;
    ensure!(
        f[0].uint()? == kind && f[1].uint()? == 1,
        "unexpected inspection record kind or version"
    );
    Ok(f)
}

/// Records are accepted only from complete bootstrap verification or exact retained certified hashes.
pub struct ContextState {
    descriptor: TrustDescriptor,
    governance: Governance,
}
impl ContextState {
    /// Return only records authenticated by this requester's complete retained context.
    pub fn current_records(&self, store: &Store) -> Result<Vec<Vec<u8>>> {
        self.current(store)?;
        self.governance
            .versions()
            .iter()
            .map(|r| Ok(self.governance.record_bytes(r.kind, r.id)?.to_vec()))
            .collect()
    }
    pub fn bootstrap(bootstrap: &Verified, store: &Store) -> Result<Self> {
        Self::retained(bootstrap, store, bootstrap.governance_records())
    }
    pub fn retained(bootstrap: &Verified, store: &Store, records: &[Vec<u8>]) -> Result<Self> {
        ensure!(
            bootstrap.fully_accepted(),
            "inspection requires fully accepted bootstrap custody"
        );
        ensure!(
            store.initial_descriptor().canonical() == bootstrap.descriptor().canonical(),
            "inspection floor has another independently accepted bootstrap"
        );
        let descriptor = store.descriptor().clone();
        let scope = descriptor.scope();
        let genesis = Governance::parse(
            scope.network,
            scope.incarnation,
            bootstrap.governance_records(),
        )?;
        let governance = Governance::parse(scope.network, scope.incarnation, records)?;
        let mut expected = genesis
            .versions()
            .into_iter()
            .map(|v| (v.index(), v))
            .collect::<BTreeMap<_, _>>();
        for version in store.generations().iter().filter(|v| {
            matches!(
                v.kind,
                100 | 101 | 102 | 105 | 114 | 117 | 125 | 126 | 127 | 128 | 129 | 130 | 131
            )
        }) {
            if let Some(old) = expected.get(&version.index()) {
                ensure!(
                    version.generation >= old.generation
                        && (version.generation != old.generation || version.digest == old.digest),
                    "certified governance conflicts with bootstrap"
                );
            }
            expected.insert(version.index(), version.clone());
        }
        ensure!(
            governance.versions() == expected.into_values().collect::<Vec<_>>(),
            "retained governance is incomplete, stale or uncertified"
        );
        Ok(Self {
            descriptor,
            governance,
        })
    }
    fn current(&self, store: &Store) -> Result<()> {
        ensure!(
            store.prefix().scope() == self.descriptor.scope(),
            "authority configuration changed"
        );
        let versions = self.governance.versions();
        for v in store.generations().iter().filter(|v| {
            matches!(
                v.kind,
                100 | 101 | 102 | 105 | 114 | 117 | 125 | 126 | 127 | 128 | 129 | 130 | 131
            )
        }) {
            ensure!(
                versions.contains(v),
                "retained governance needs a certified refresh"
            );
        }
        Ok(())
    }
    fn candidates(&self, grant: [u8; 32], target: &VersionRef) -> Result<Vec<VersionRef>> {
        let available = self
            .governance
            .versions()
            .into_iter()
            .map(|v| (v.index(), v))
            .collect::<BTreeMap<_, _>>();
        let network = self.descriptor.scope().network;
        let policy = wire::decode(self.governance.record_bytes(100, network)?)?;
        let policy = policy.array(17)?;
        let mut root_subjects = Vec::new();
        for root in policy[15].list(16)? {
            let record = wire::decode(self.governance.record_bytes(102, root.fixed()?)?)?;
            root_subjects.push(record.array(17)?[8].fixed::<32>()?);
        }
        let mut needed =
            std::collections::BTreeSet::from([(100, network), (114, network), target.index()]);
        let mut seen = std::collections::BTreeSet::new();
        let mut cursor = grant;
        loop {
            ensure!(
                seen.len() <= 8 && seen.insert(cursor),
                "inspection grant chain is cyclic or too deep"
            );
            let record = wire::decode(self.governance.record_bytes(102, cursor)?)?;
            let fields = record.array(17)?;
            needed.insert((102, cursor));
            let tier = fields[9].array(4)?;
            needed.insert((tier[0].uint()?, tier[1].fixed()?));
            let subject = fields[8].fixed::<32>()?;
            if !root_subjects.contains(&subject) {
                let mut admission = None;
                for reference in available.values().filter(|v| v.kind == 125) {
                    let record = wire::decode(self.governance.record_bytes(125, reference.id)?)?;
                    let f = record.array(12)?;
                    if f[7].fixed::<32>()? == subject {
                        admission = Some((reference.index(), f[10].array(4)?.to_vec()));
                        break;
                    }
                }
                let (index, reader) =
                    admission.context("inspection subject has no retained admission")?;
                needed.insert(index);
                needed.insert((reader[0].uint()?, reader[1].fixed()?));
            }
            if fields[13] == V::Null {
                break;
            }
            cursor = fields[13].array(4)?[1].fixed()?;
        }
        let values = needed
            .iter()
            .map(|k| {
                available
                    .get(k)
                    .cloned()
                    .context("inspection dependency has no certified version")
            })
            .collect::<Result<Vec<_>>>()?;
        proof::validate_versions(&values, 64)?;
        Ok(values)
    }
    pub fn prepare<'a>(
        &'a self,
        request: Request,
        signer: &SigningKey,
        store: &mut Store,
        session: &mut Session,
        health: ClockHealth,
    ) -> Result<Prepared<'a>> {
        store.require_requester(signer.verifying_key().to_bytes())?;
        if let Some(pending) = store.resume_ordinary()? {
            let intent = Intent::from_signed(pending.signed())?;
            let parameters = wire::decode(&intent.parameters)?;
            let fields = record(&parameters, 200, 6)?;
            ensure!(
                intent.action == ACTION
                    && intent.resource == request.lookup
                    && intent.profile_generation == 0
                    && fields[2].text()? == ACTION
                    && fields[3].fixed::<32>()? == request.grant
                    && fields[4].uint()? == request.kind
                    && fields[5].fixed::<32>()? == request.lookup,
                "another exact request is pending; resume it or explicitly fence its generation"
            );
            let target = intent
                .expected
                .iter()
                .find(|v| {
                    v.kind == request.kind
                        && v.id == request.lookup
                        && v.generation == intent.revision
                })
                .context("pending inspection omitted its target version")?
                .clone();
            return self.prepared(
                request,
                target,
                intent.expected.clone(),
                pending.signed().to_vec(),
                signer,
                session,
                health,
            );
        }
        self.current(store)?;
        ensure!(
            request.grant != [0; 32]
                && request.lookup != [0; 32]
                && matches!(request.kind, 100 | 101 | 102 | 114 | 125 | 126 | 127 | 128),
            "invalid inspection resource"
        );
        let target = self
            .governance
            .versions()
            .into_iter()
            .find(|v| v.kind == request.kind && v.id == request.lookup)
            .context("inspection target has no retained certified version")?;
        let now = health.observe()?;
        let subject = signer.verifying_key().to_bytes();
        let all = self.candidates(request.grant, &target)?;
        let decision = self.governance.capability(
            request.grant,
            &Requirement {
                subject,
                actions: &[25],
                scope: (0, self.descriptor.scope().network),
                namespace: None,
                usage: [0, 1, 0, 1],
                evaluated_at_ms: now.wall_ms,
                expected: &all,
            },
        )?;
        let mut expected = decision.dependencies;
        expected.push(target.clone());
        expected.sort_by_key(VersionRef::index);
        expected.dedup();
        proof::validate_versions(&expected, 64)?;
        let parameters = wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text(ACTION.into()),
            b(&request.grant),
            V::Uint(request.kind),
            b(&request.lookup),
        ]))?;
        let intent = prepare_ordinary(
            &self.descriptor,
            signer,
            store,
            ACTION,
            request.lookup,
            target.generation,
            &expected,
            &parameters,
        )?;
        self.prepared(request, target, expected, intent, signer, session, health)
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Keep protocol inputs, state and validation callbacks explicit."
    )]
    fn prepared<'a>(
        &'a self,
        request: Request,
        target: VersionRef,
        expected: Vec<VersionRef>,
        intent: Vec<u8>,
        signer: &SigningKey,
        session: &mut Session,
        health: ClockHealth,
    ) -> Result<Prepared<'a>> {
        let now = health.observe()?;
        let deadline = now
            .boot_ms
            .checked_add(DURATION)
            .context("inspection deadline overflow")?;
        let challenge = session.issue(&intent, signer, random_id()?, DURATION, health)?;
        let parsed = Challenge::from_signed(&challenge)?;
        let ordered = wire::encode(&a(vec![
            V::Uint(22),
            V::Uint(1),
            self.descriptor.scope().value(),
            b(&intent),
            b(&challenge),
            V::Uint(parsed.expires_at_ms),
        ]))?;
        Ok(Prepared {
            context: self,
            request,
            target,
            expected,
            intent,
            challenge,
            ordered,
            deadline,
        })
    }
    /// The clock provider must return current measured health; there is no healthy default.
    pub fn inspect_local(
        &self,
        path: &Path,
        request: Request,
        signer: &SigningKey,
        store: &mut Store,
        session: &mut Session,
        mut clock: impl FnMut() -> Result<ClockHealth>,
    ) -> Result<Inspection> {
        stream_client::ensure_stream(&self.descriptor, path, signer, store, session, &mut clock)?;
        let control = LocalControl::prepare_authority(path, store)?;
        self.inspect_prepared(&control, request, signer, store, session, clock)
    }
    fn inspect_prepared(
        &self,
        control: &LocalControl,
        request: Request,
        signer: &SigningKey,
        store: &mut Store,
        session: &mut Session,
        mut clock: impl FnMut() -> Result<ClockHealth>,
    ) -> Result<Inspection> {
        let pending = self.prepare(request, signer, store, session, clock()?)?;
        let challenge = pending.challenge.clone();
        let result = (|| {
            let digest = wire::digest(&pending.ordered);
            let mut response =
                control.exchange(&pending.control(0, &pending.ordered)?, pending.deadline)?;
            let certified = loop {
                match pending.local_reply(&response)? {
                    Some(reply) => break reply,
                    None => {
                        clock()?.observe()?;
                        pending.remaining()?;
                        std::thread::sleep(Duration::from_millis(pending.remaining()?.min(25)));
                        response =
                            control.exchange(&pending.control(1, &digest)?, pending.deadline)?;
                    }
                }
            };
            let evidence =
                AncestryEvidence::fetch(control, store, &certified.node, pending.deadline)?;
            pending.finish_evidence(certified, evidence, store, session, &mut clock)
        })();
        if result.is_err() {
            session.discard(&challenge)?;
        }
        result
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Request {
    pub grant: [u8; 32],
    pub kind: u64,
    pub lookup: [u8; 32],
}
pub struct Prepared<'a> {
    context: &'a ContextState,
    request: Request,
    target: VersionRef,
    expected: Vec<VersionRef>,
    intent: Vec<u8>,
    challenge: Vec<u8>,
    ordered: Vec<u8>,
    deadline: u64,
}
/// This value cannot be constructed until persistence and the final one-use deadline check succeed.
pub struct Inspection {
    reference: VersionRef,
    canonical: Vec<u8>,
    prefix: Prefix,
}
impl Inspection {
    pub fn reference(&self) -> &VersionRef {
        &self.reference
    }
    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }
    pub fn prefix(&self) -> &Prefix {
        &self.prefix
    }
}
use crate::authority_local_transport::CertifiedReply;
impl Prepared<'_> {
    #[cfg(test)]
    pub fn ordered_request(&self) -> &[u8] {
        &self.ordered
    }
    #[cfg(test)]
    pub fn cancel(self, session: &mut Session) -> Result<()> {
        session.discard(&self.challenge)
    }
    fn remaining(&self) -> Result<u64> {
        remaining(self.deadline)
    }
    fn control(&self, operation: u64, payload: &[u8]) -> Result<Vec<u8>> {
        let payload = if operation == 0 {
            wire::encode(&a(vec![b(payload), a(vec![])]))?
        } else {
            payload.to_vec()
        };
        wire::encode(&a(vec![
            V::Uint(41),
            V::Uint(1),
            self.context.descriptor.scope().value(),
            V::Uint(operation),
            b(&payload),
        ]))
    }
    fn local_reply(&self, bytes: &[u8]) -> Result<Option<CertifiedReply>> {
        let value = wire::decode(bytes)?;
        let f = record(&value, 42, 10)?;
        f[9].array(0)?;
        ensure!(
            proof::Scope::parse(&f[2])? == *self.context.descriptor.scope(),
            "local control scope differs"
        );
        ensure!(
            f[4].uint()? == 0 && f[5].fixed::<32>()? == wire::digest(&self.ordered),
            "local control refused or returned another request"
        );
        match f[3].uint()? {
            0 => {
                f[6].null()?;
                f[7].null()?;
                f[8].null()?;
                Ok(None)
            }
            1 => Ok(Some(CertifiedReply {
                node: f[6].bytes()?.to_vec(),
                certificate: f[7].bytes()?.to_vec(),
                result: f[8].bytes()?.to_vec(),
            })),
            _ => bail!("local control response is not an inspection result"),
        }
    }
    #[cfg(test)]
    fn ancestry_reply(&self, bytes: &[u8], tip: &[u8]) -> Result<Vec<Vec<u8>>> {
        let value = wire::decode(bytes)?;
        let f = record(&value, 43, 4)?;
        ensure!(
            proof::Scope::parse(&f[2])? == *self.context.descriptor.scope(),
            "ancestry response scope differs"
        );
        let nodes = f[3]
            .list(128)?
            .iter()
            .map(|v| Ok(v.bytes()?.to_vec()))
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            nodes.last().is_some_and(|node| node == tip),
            "ancestry does not end at requested certified node"
        );
        Ok(nodes)
    }
    fn validate(
        &self,
        intent: &Intent,
        result: &OperationResult,
        executed: &ExecutedResult,
    ) -> Result<ActionValidation> {
        let immutable = Intent::from_signed(&self.intent)?;
        ensure!(
            intent.digest == immutable.digest
                && intent.parameters == immutable.parameters
                && intent.expected == self.expected
                && intent.revision == self.target.generation
                && intent.profile_generation == 0
                && executed.recipient == intent.requester,
            "inspection request context differs"
        );
        let value = wire::decode(&result.value)?;
        match result.disposition {
            Disposition::Refuse => {
                let f = record(&value, 201, 4)?;
                ensure!(
                    f[2].text()? == ACTION
                        && f[3].array(0)?.is_empty()
                        && executed.maximum_effect == 0,
                    "invalid inspection refusal"
                );
                ActionValidation::new(Vec::new())
            }
            Disposition::Pending => bail!("inspection has no pending authority result"),
            Disposition::Permit => {
                let f = record(&value, 201, 5)?;
                ensure!(
                    f[2].text()? == ACTION && executed.maximum_effect == 1,
                    "invalid inspection effect or result action"
                );
                let challenge = Challenge::from_signed(&self.challenge)?;
                ensure!(
                    executed.expires_at_ms
                        <= challenge
                            .evaluation_expiry(executed.evaluated_at_ms, executed.expires_at_ms)?,
                    "inspection evaluation is outside its conservative request interval"
                );
                let versions = parse_versions(&f[3])?;
                let decision = self.context.governance.capability(
                    self.request.grant,
                    &Requirement {
                        subject: intent.requester,
                        actions: &[25],
                        scope: (0, intent.network),
                        namespace: None,
                        usage: [0, 1, 0, 1],
                        evaluated_at_ms: executed.evaluated_at_ms,
                        expected: &intent.expected,
                    },
                )?;
                let mut used = decision.dependencies;
                used.push(self.target.clone());
                used.sort_by_key(VersionRef::index);
                used.dedup();
                ensure!(
                    versions == used
                        && versions == self.expected
                        && executed.expires_at_ms <= decision.expires_ms,
                    "inspection omitted or changed a certified dependency"
                );
                let exact = self
                    .context
                    .governance
                    .record_bytes(self.target.kind, self.target.id)?;
                ensure!(
                    f[4].bytes()? == exact && wire::digest(exact) == self.target.digest,
                    "inspection target record differs from its requested certified version"
                );
                ActionValidation::new(versions)
            }
        }
    }
    /// External transport may supply bytes, but all acceptance and effect checks remain fixed here.
    #[cfg(test)]
    pub fn accept(
        self,
        local_reply: &[u8],
        ancestry: Vec<Vec<u8>>,
        store: &mut Store,
        session: &mut Session,
        mut clock: impl FnMut() -> Result<ClockHealth>,
    ) -> Result<Inspection> {
        let challenge = self.challenge.clone();
        let result = (|| {
            let certified = self
                .local_reply(local_reply)?
                .context("inspection is not certified")?;
            self.finish(certified, ancestry, store, session, &mut clock)
        })();
        if result.is_err() {
            session.discard(&challenge)?;
        }
        result
    }
    #[cfg(test)]
    fn finish(
        self,
        reply: CertifiedReply,
        ancestry: Vec<Vec<u8>>,
        store: &mut Store,
        session: &mut Session,
        clock: &mut impl FnMut() -> Result<ClockHealth>,
    ) -> Result<Inspection> {
        self.finish_evidence(
            reply,
            AncestryEvidence::direct(ancestry),
            store,
            session,
            clock,
        )
    }
    fn finish_evidence(
        self,
        reply: CertifiedReply,
        evidence: AncestryEvidence,
        store: &mut Store,
        session: &mut Session,
        clock: &mut impl FnMut() -> Result<ClockHealth>,
    ) -> Result<Inspection> {
        let ancestry = &evidence.nodes;
        ensure!(
            ancestry.last().is_some_and(|v| *v == reply.node),
            "inspection ancestry differs from control node"
        );
        let verified = proof::verify_response(
            &self.context.descriptor,
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
                ancestry,
            },
            |i, r, e| self.validate(i, r, e),
        )?;
        let verified = evidence.attach(store, verified)?;
        if verified.disposition() != Disposition::Permit {
            let code = verified.code();
            store.observe(verified)?;
            session.discard(&self.challenge)?;
            bail!("authority inspection refused with code {code}");
        }
        self.remaining()?;
        self.context.current(store)?;
        let decision = self.context.governance.capability(
            self.request.grant,
            &Requirement {
                subject: verified.request().requester(),
                actions: &[25],
                scope: (0, verified.request().network()),
                namespace: None,
                usage: [0, 1, 0, 1],
                evaluated_at_ms: verified.executed.evaluated_at_ms,
                expected: &self.expected,
            },
        )?;
        let prefix = verified.point().prefix().clone();
        let permit = store.accept(verified, session, clock()?, decision.not_before_ms)?;
        self.remaining()?;
        self.context.current(store)?;
        let health = clock()?;
        permit.perform(
            store,
            session,
            health,
            1,
            |restrictions| {
                ensure!(
                    *restrictions == Restrictions::default(),
                    "inspection restrictions changed"
                );
                Ok(())
            },
            |result, _| {
                let value = wire::decode(&result.value)?;
                let fields = record(&value, 201, 5)?;
                Ok(Inspection {
                    reference: self.target,
                    canonical: fields[4].bytes()?.to_vec(),
                    prefix,
                })
            },
        )
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "Keep protocol inputs, state and validation callbacks explicit."
)]
fn prepare_ordinary(
    descriptor: &TrustDescriptor,
    signer: &SigningKey,
    store: &mut Store,
    action: &str,
    resource: [u8; 32],
    revision: u64,
    expected: &[VersionRef],
    parameters: &[u8],
) -> Result<Vec<u8>> {
    store.require_requester(signer.verifying_key().to_bytes())?;
    let slot = store.ordinary_slot()?;
    let payload = wire::encode(&a(vec![
        V::Uint(20),
        V::Uint(1),
        b(&descriptor.scope().network),
        b(&descriptor.scope().incarnation),
        V::Uint(slot.generation()),
        b(&slot.generation_id()),
        V::Uint(slot.sequence()),
        V::Uint(slot.acknowledged_through()),
        b(&store.requester()),
        V::Text(action.into()),
        b(&resource),
        V::Uint(revision),
        V::Uint(0),
        V::Uint(slot.minimum_policy_epoch()),
        V::Uint(slot.minimum_policy_height()),
        a(expected.iter().map(version_value).collect()),
        b(parameters),
    ]))?;
    let signed = wire::sign_envelope(&payload, signer)?;
    Ok(store.prepare_ordinary(slot, &signed)?.signed().to_vec())
}

use crate::authority_local_transport::{LocalControl, remaining};

#[cfg(test)]
#[path = "AuthorityInspectionTests.rs"]
mod tests;

#[path = "AuthorityGovernanceClient.rs"]
mod governance_client;
pub use governance_client::{MemberMutation, MemberRequest, RevokeRequest};
pub(crate) use governance_client::{grant, policy, tier};

#[path = "AuthorityMemberOffer.rs"]
pub(crate) mod member_offer;

#[path = "AuthorityHistoryControl.rs"]
mod history_control;
use history_control::AncestryEvidence;

#[path = "AuthorityStreamClient.rs"]
pub(crate) mod stream_client;

#[path = "AuthorityApplicationClient.rs"]
pub(crate) mod application_client;

#[path = "AuthorityApplicationOffer.rs"]
pub(crate) mod application_offer;

#[path = "AuthorityDeploymentClient.rs"]
pub(crate) mod deployment_client;

#[path = "AuthorityDomainClient.rs"]
pub(crate) mod domain_client;

#[path = "AuthorityEpochClient.rs"]
pub(crate) mod epoch_client;

#[path = "AuthorityMailClient.rs"]
pub(crate) mod mail_client;
#[path = "AuthorityPageMediaClient.rs"]
pub(crate) mod page_media_client;
#[path = "AuthorityTransferClient.rs"]
pub(crate) mod transfer_client;
