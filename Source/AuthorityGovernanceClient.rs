// SPDX-License-Identifier: MIT
// Explicit discovery authenticates a complete context; mutations bind one retained pre-state.
use super::*;

const CONTEXT: &str = "AuthorityContext";
const REVOKE: &str = "AuthorityRevokeGrant";
const CACHE: &str = "Governance.cbor";
const CONTEXT_LIMIT: usize = crate::authority_capacity::MAX_STATE_BYTES;
use crate::authority_capacity::MAX_RECORDS;
#[path = "AuthorityGrantClient.rs"]
pub(crate) mod grant;
#[path = "AuthorityContextPaging.rs"]
mod paging;
#[path = "AuthorityPolicyClient.rs"]
pub(crate) mod policy;
#[path = "AuthorityTierClient.rs"]
pub(crate) mod tier;
fn governance_kind(kind: u64) -> bool {
    matches!(
        kind,
        100 | 101 | 102 | 105 | 114 | 117 | 125 | 126 | 127 | 128 | 129 | 130 | 131
    )
}
fn point(prefix: &Prefix) -> V {
    a(vec![
        V::Uint(prefix.scope().epoch),
        V::Uint(prefix.height()),
        b(prefix.policy_state()),
    ])
}
fn records(governance: &Governance) -> Result<Vec<Vec<u8>>> {
    governance
        .versions()
        .iter()
        .map(|v| Ok(governance.record_bytes(v.kind, v.id)?.to_vec()))
        .collect()
}
fn minima(bootstrap: &Verified, store: &Store) -> Result<Vec<VersionRef>> {
    let context = bootstrap.descriptor().scope();
    ensure!(
        bootstrap.fully_accepted()
            && bootstrap.descriptor().canonical() == store.initial_descriptor().canonical(),
        "context bootstrap differs from retained authority"
    );
    let initial = Governance::parse(
        context.network,
        context.incarnation,
        bootstrap.governance_records(),
    )?;
    let mut known = initial
        .versions()
        .into_iter()
        .map(|v| (v.index(), v))
        .collect::<BTreeMap<_, _>>();
    for current in store
        .generations()
        .iter()
        .filter(|v| governance_kind(v.kind))
    {
        if let Some(old) = known.get(&current.index()) {
            ensure!(
                current.generation >= old.generation
                    && (current.generation != old.generation || current.digest == old.digest),
                "floor conflicts with bootstrap governance"
            );
        }
        known.insert(current.index(), current.clone());
    }
    let values = known.into_values().collect::<Vec<_>>();
    proof::validate_versions(&values, MAX_RECORDS)?;
    Ok(values)
}
fn complete_minima(current: &[VersionRef], known: &[VersionRef]) -> Result<()> {
    for prior in known {
        let value = current
            .iter()
            .find(|v| v.index() == prior.index())
            .context("context omitted a retained governance record")?;
        ensure!(
            value.generation >= prior.generation
                && (value.generation != prior.generation || value.digest == prior.digest),
            "context is below or conflicts with a retained generation"
        );
    }
    Ok(())
}

impl ContextState {
    pub fn load(bootstrap: &Verified, store: &Store, directory: &Path) -> Result<Self> {
        let directory = files::private_directory(directory)?;
        let bytes = files::read_at(&directory, OsStr::new(CACHE), CONTEXT_LIMIT, true)?;
        let decoded = wire::decode_state(&bytes)?;
        let mut values = decoded
            .list(MAX_RECORDS)?
            .iter()
            .map(|v| Ok(v.bytes()?.to_vec()))
            .collect::<Result<Vec<_>>>()?;
        tier::refresh_cached_tiers(bootstrap, store, &mut values)?;
        policy::refresh_cached_policies(bootstrap, store, &mut values)?;
        Self::retained(bootstrap, store, &values)
    }
    /// The floor already authenticates every cached digest; the cache never confers authority itself.
    pub fn save(&self, store: &Store) -> Result<()> {
        self.current(store)?;
        policy::retain_context(store, &self.governance)?;
        let bytes = wire::encode_state(&a(records(&self.governance)?
            .iter()
            .map(|v| b(v))
            .collect()))?;
        ensure!(
            bytes.len() <= CONTEXT_LIMIT,
            "governance cache exceeds its bound"
        );
        files::atomic_at(store.profile_directory(), OsStr::new(CACHE), &bytes, true)
    }
    pub fn refresh_local(
        bootstrap: &Verified,
        path: &Path,
        grant: [u8; 32],
        signer: &SigningKey,
        store: &mut Store,
        session: &mut Session,
        mut clock: impl FnMut() -> Result<ClockHealth>,
    ) -> Result<Self> {
        stream_client::ensure_stream(
            &store.descriptor().clone(),
            path,
            signer,
            store,
            session,
            &mut clock,
        )?;
        loop {
            let control = LocalControl::prepare_authority(path, store)?;
            let pending =
                GovernancePrepared::refresh(bootstrap, grant, signer, store, session, clock()?)?;
            match pending.local(&control, store, session, &mut clock)? {
                Outcome::Context(value) => {
                    paging::clear(store)?;
                    return Ok(*value);
                }
                Outcome::Page => (),
                _ => bail!("unexpected governance result"),
            }
        }
    }
    /// Discard only incomplete cached pages after the previous exact request is resolved.
    pub fn restart_discovery(store: &Store) -> Result<()> {
        paging::clear(store)
    }
    pub fn revoke_grant_local(
        &self,
        path: &Path,
        request: RevokeRequest,
        signer: &SigningKey,
        store: &mut Store,
        session: &mut Session,
        mut clock: impl FnMut() -> Result<ClockHealth>,
    ) -> Result<CreatedRecord> {
        stream_client::ensure_stream(&self.descriptor, path, signer, store, session, &mut clock)?;
        let control = LocalControl::prepare_authority(path, store)?;
        let pending = GovernancePrepared::revoke(
            self,
            request.grant,
            request.target,
            signer,
            store,
            session,
            clock()?,
        )?;
        match pending.local(&control, store, session, &mut clock)? {
            Outcome::Revoked(value) => Ok(*value),
            _ => bail!("unexpected governance result"),
        }
    }
}
pub struct RevokeRequest {
    pub grant: [u8; 32],
    pub target: VersionRef,
}
pub struct CreatedRecord {
    reference: VersionRef,
    canonical: Vec<u8>,
    prefix: Prefix,
    #[cfg(test)]
    context: ContextState,
}
impl CreatedRecord {
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
#[allow(
    clippy::large_enum_variant,
    reason = "Bounded records are processed individually without an additional allocation."
)]
enum Mode<'a> {
    Grant(grant::Prepared),
    Tier(tier::Prepared),
    Policy(policy::Prepared),
    Refresh {
        minimum: Vec<VersionRef>,
        pages: Option<paging::Pages>,
    },
    Revoke {
        context: &'a ContextState,
        target: VersionRef,
        tombstone: Vec<u8>,
    },
    Member(MemberPrepared<'a>),
}
struct GovernancePrepared<'a> {
    descriptor: TrustDescriptor,
    grant: [u8; 32],
    mode: Mode<'a>,
    expected: Vec<VersionRef>,
    intent: Vec<u8>,
    challenge: Vec<u8>,
    ordered: Vec<u8>,
    deadline: u64,
}
enum Outcome {
    Grant(grant::ResultState),
    Tier(tier::ResultState),
    Policy(policy::ResultState),
    Context(Box<ContextState>),
    Page,
    Revoked(Box<CreatedRecord>),
    Created(Box<CreatedRecord>),
}
struct Parameters<'a> {
    descriptor: TrustDescriptor,
    grant: [u8; 32],
    mode: Mode<'a>,
    expected: Vec<VersionRef>,
    canonical: Vec<u8>,
}
struct Candidate {
    governance: Option<Governance>,
    pages: Option<paging::Pages>,
    not_before: u64,
    versions: Vec<VersionRef>,
}
impl<'a> GovernancePrepared<'a> {
    fn refresh(
        bootstrap: &Verified,
        grant: [u8; 32],
        signer: &SigningKey,
        store: &mut Store,
        session: &mut Session,
        health: ClockHealth,
    ) -> Result<Self> {
        store.require_requester(signer.verifying_key().to_bytes())?;
        if let Some(pending) = store.resume_ordinary()? {
            let intent = Intent::from_signed(pending.signed())?;
            let decoded = wire::decode(&intent.parameters)?;
            let fields = record(&decoded, 200, 6)?;
            ensure!(
                intent.action == CONTEXT
                    && intent.resource == bootstrap.descriptor().scope().network
                    && intent.revision == 0
                    && intent.expected.is_empty()
                    && fields[2].text()? == CONTEXT
                    && fields[3].fixed::<32>()? == grant,
                "another exact request is pending; resume it or explicitly fence its generation"
            );
            let minimum = minima(bootstrap, store)?;
            let pages = paging::resume(store.descriptor(), grant, store, &fields[5])?;
            return Self::new(
                Parameters {
                    descriptor: store.descriptor().clone(),
                    grant,
                    mode: Mode::Refresh { minimum, pages },
                    expected: Vec::new(),
                    canonical: intent.parameters,
                },
                signer,
                store,
                session,
                health,
            );
        }
        let minimum = minima(bootstrap, store)?;
        let pages =
            paging::Pages::load(store.descriptor(), grant, store)?.filter(|p| !p.complete());
        let parameters = wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text(CONTEXT.into()),
            b(&grant),
            point(store.prefix()),
            pages.as_ref().map_or(V::Null, paging::Pages::cursor),
        ]))?;
        Self::new(
            Parameters {
                descriptor: store.descriptor().clone(),
                grant,
                mode: Mode::Refresh { minimum, pages },
                expected: Vec::new(),
                canonical: parameters,
            },
            signer,
            store,
            session,
            health,
        )
    }
    fn revoke(
        context: &'a ContextState,
        grant: [u8; 32],
        target: VersionRef,
        signer: &SigningKey,
        store: &mut Store,
        session: &mut Session,
        health: ClockHealth,
    ) -> Result<Self> {
        store.require_requester(signer.verifying_key().to_bytes())?;
        if let Some(pending) = store.resume_ordinary()? {
            let intent = Intent::from_signed(pending.signed())?;
            let decoded = wire::decode(&intent.parameters)?;
            let fields = record(&decoded, 200, 6)?;
            ensure!(
                intent.action == REVOKE
                    && intent.resource == target.id
                    && intent.revision == target.generation
                    && fields[2].text()? == REVOKE
                    && fields[3].fixed::<32>()? == grant
                    && fields[4] == version_value(&target),
                "another exact request is pending; resume it or explicitly fence its generation"
            );
            let tombstone = wire::encode(&a(vec![
                V::Uint(126),
                V::Uint(1),
                b(&intent.network),
                b(&intent.incarnation),
                V::Uint(1),
                V::Null,
                version_value(&target),
                b(&intent.requester),
                fields[5].clone(),
            ]))?;
            return Self::new(
                Parameters {
                    descriptor: context.descriptor.clone(),
                    grant,
                    mode: Mode::Revoke {
                        context,
                        target,
                        tombstone,
                    },
                    expected: intent.expected,
                    canonical: intent.parameters,
                },
                signer,
                store,
                session,
                health,
            );
        }
        context.current(store)?;
        ensure!(
            target.kind == 102 && context.governance.versions().contains(&target),
            "revocation requires the exact retained grant reference"
        );
        ensure!(
            !context
                .governance
                .versions()
                .iter()
                .any(|v| v.kind == 126 && v.id == target.id),
            "grant is already permanently revoked"
        );
        let now = health.observe()?;
        let decision = context.governance.current_capability(
            grant,
            &Requirement {
                subject: signer.verifying_key().to_bytes(),
                actions: &[12],
                scope: (0, context.descriptor.scope().network),
                namespace: None,
                usage: [0, 1, 0, 1],
                evaluated_at_ms: now.wall_ms,
                expected: &[],
            },
        )?;
        let mut expected = decision.dependencies;
        expected.push(target.clone());
        expected.sort_by_key(VersionRef::index);
        expected.dedup();
        proof::validate_versions(&expected, 64)?;
        let snapshot = a(vec![
            point(store.prefix()),
            a(expected.iter().map(version_value).collect()),
        ]);
        let tombstone = wire::encode(&a(vec![
            V::Uint(126),
            V::Uint(1),
            b(&context.descriptor.scope().network),
            b(&context.descriptor.scope().incarnation),
            V::Uint(1),
            V::Null,
            version_value(&target),
            b(&signer.verifying_key().to_bytes()),
            snapshot.clone(),
        ]))?;
        let parameters = wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text(REVOKE.into()),
            b(&grant),
            version_value(&target),
            snapshot,
        ]))?;
        Self::new(
            Parameters {
                descriptor: context.descriptor.clone(),
                grant,
                mode: Mode::Revoke {
                    context,
                    target,
                    tombstone,
                },
                expected,
                canonical: parameters,
            },
            signer,
            store,
            session,
            health,
        )
    }
    fn new(
        parameters: Parameters<'a>,
        signer: &SigningKey,
        store: &mut Store,
        session: &mut Session,
        health: ClockHealth,
    ) -> Result<Self> {
        let Parameters {
            descriptor,
            grant,
            mode,
            expected,
            canonical,
        } = parameters;
        let (action, resource, revision) = match &mode {
            Mode::Grant(grant) => (
                grant.action(),
                grant.proposal.resource,
                grant.proposal.revision,
            ),
            Mode::Tier(tier) => (tier.action(), tier.resource(), tier.revision()?),
            Mode::Policy(policy) => ("AuthorityPolicyApply", policy.network(), policy.revision()?),
            Mode::Refresh { .. } => (CONTEXT, descriptor.scope().network, 0),
            Mode::Revoke { target, .. } => (REVOKE, target.id, target.generation),
            Mode::Member(member) => (member.action, member.reference.id, 1),
        };
        ensure!(grant != [0; 32], "governance grant identifier is empty");
        let now = health.observe()?;
        store.require_requester(signer.verifying_key().to_bytes())?;
        let intent = if let Some(pending) = store.resume_ordinary()? {
            let immutable = Intent::from_signed(pending.signed())?;
            ensure!(
                immutable.action == action
                    && immutable.resource == resource
                    && immutable.revision == revision
                    && immutable.profile_generation == 0
                    && immutable.expected == expected
                    && immutable.parameters == canonical,
                "prepared workflow differs from the exact pending request"
            );
            pending.signed().to_vec()
        } else {
            prepare_ordinary(
                &descriptor,
                signer,
                store,
                action,
                resource,
                revision,
                &expected,
                &canonical,
            )?
        };
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
        Ok(Self {
            descriptor,
            grant,
            mode,
            expected,
            intent,
            challenge,
            ordered,
            deadline: now
                .boot_ms
                .checked_add(DURATION)
                .context("governance deadline overflow")?,
        })
    }
    fn action(&self) -> &'static str {
        match self.mode {
            Mode::Grant(ref grant) => grant.action(),
            Mode::Tier(ref tier) => tier.action(),
            Mode::Policy(_) => "AuthorityPolicyApply",
            Mode::Refresh { .. } => CONTEXT,
            Mode::Revoke { .. } => REVOKE,
            Mode::Member(ref member) => member.action,
        }
    }
    fn candidate(
        &self,
        intent: &Intent,
        result: &OperationResult,
        executed: &ExecutedResult,
    ) -> Result<Candidate> {
        let immutable = Intent::from_signed(&self.intent)?;
        ensure!(
            intent.digest == immutable.digest
                && intent.expected == self.expected
                && intent.profile_generation == 0
                && executed.recipient == intent.requester
                && result.disposition == Disposition::Permit
                && executed.maximum_effect == 1,
            "governance result differs from its immutable request"
        );
        let challenge = Challenge::from_signed(&self.challenge)?;
        ensure!(
            executed.expires_at_ms
                <= challenge.evaluation_expiry(executed.evaluated_at_ms, executed.expires_at_ms)?,
            "governance evaluation lies outside its conservative interval"
        );
        let value = wire::decode(&result.value)?;
        if let Mode::Grant(grant) = &self.mode {
            return grant.candidate(intent, &value, executed);
        }
        if let Mode::Tier(tier) = &self.mode {
            return tier.candidate(intent, &value, executed);
        }
        if let Mode::Policy(policy) = &self.mode {
            return policy.candidate(intent, &value, executed);
        }
        let arity = match self.mode {
            Mode::Tier(_) | Mode::Grant(_) | Mode::Policy(_) => unreachable!(),
            Mode::Member(_) | Mode::Revoke { .. } => 6,
            Mode::Refresh { .. } => 5,
        };
        let f = record(&value, 201, arity)?;
        ensure!(
            f[2].text()? == self.action(),
            "governance result action differs"
        );
        let versions = f[3]
            .list(MAX_RECORDS)?
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
        proof::validate_versions(&versions, MAX_RECORDS)?;
        let scope = self.descriptor.scope();
        let (governance, decision) = match &self.mode {
            Mode::Tier(_) | Mode::Grant(_) | Mode::Policy(_) => unreachable!(),
            Mode::Member(member) => member.candidate(intent, result, executed, &versions)?,
            Mode::Refresh { minimum, pages } => {
                let encoded = wire::encode(&a(vec![
                    V::Uint(24),
                    V::Uint(1),
                    V::Text(CONTEXT.into()),
                    V::Uint(0),
                    V::Uint(0),
                    b(&result.value),
                ]))?;
                ensure!(
                    encoded.len() <= paging::PAGE_BYTES
                        && versions.len() <= 64
                        && intent.revision == 0
                        && intent.resource == scope.network
                        && intent.expected.is_empty(),
                    "invalid context page bounds"
                );
                let next = paging::append(&self.descriptor, pages.as_ref(), &f[4], &versions)?;
                let (governance, not_before) = if next.complete() {
                    let governance =
                        Governance::parse(scope.network, scope.incarnation, &next.entries)?;
                    complete_minima(&governance.versions(), minimum)?;
                    let decision = governance.current_capability(
                        self.grant,
                        &Requirement {
                            subject: intent.requester,
                            actions: &[25],
                            scope: (0, scope.network),
                            namespace: None,
                            usage: [0, 1, 0, 1],
                            evaluated_at_ms: executed.evaluated_at_ms,
                            expected: &[],
                        },
                    )?;
                    ensure!(
                        executed.expires_at_ms <= decision.expires_ms,
                        "context permission exceeds current capability validity"
                    );
                    (Some(governance), decision.not_before_ms)
                } else {
                    (None, 0)
                };
                return Ok(Candidate {
                    governance,
                    pages: Some(next),
                    not_before,
                    versions,
                });
            }
            Mode::Revoke {
                context,
                target,
                tombstone,
            } => {
                let creation_height = f[5].uint()?;
                ensure!(
                    creation_height > intent.minimum_policy_height
                        && creation_height <= executed.height,
                    "revocation creation height differs from its causal floor or execution"
                );
                ensure!(
                    intent.resource == target.id
                        && intent.revision == target.generation
                        && f[4].bytes()? == tombstone,
                    "revocation record differs from exact proposed tombstone"
                );
                let decision = context.governance.capability(
                    self.grant,
                    &Requirement {
                        subject: intent.requester,
                        actions: &[12],
                        scope: (0, scope.network),
                        namespace: None,
                        usage: [0, 1, 0, 1],
                        evaluated_at_ms: executed.evaluated_at_ms,
                        expected: &self.expected,
                    },
                )?;
                let mut required = decision.dependencies.clone();
                required.push(target.clone());
                required.sort_by_key(VersionRef::index);
                required.dedup();
                ensure!(
                    required == self.expected,
                    "revocation dependencies differ from retained pre-state"
                );
                required.push(VersionRef {
                    kind: 126,
                    id: target.id,
                    generation: 1,
                    digest: wire::digest(tombstone),
                });
                required.sort_by_key(VersionRef::index);
                ensure!(
                    versions == required,
                    "revocation versions omit or replace a dependency"
                );
                let mut entries = context
                    .governance
                    .versions()
                    .iter()
                    .map(|v| {
                        Ok((
                            v.index(),
                            context.governance.record_bytes(v.kind, v.id)?.to_vec(),
                        ))
                    })
                    .collect::<Result<BTreeMap<_, _>>>()?;
                let previous = entries.insert((126, target.id), tombstone.clone());
                ensure!(
                    previous.is_none_or(|prior| {
                        prior == *tombstone && creation_height < executed.height
                    }),
                    "revocation cannot replace a permanent tombstone"
                );
                ensure!(
                    entries.len() <= MAX_RECORDS,
                    "governance context capacity exceeded"
                );
                let entries = entries.into_values().collect::<Vec<_>>();
                (
                    Governance::parse(scope.network, scope.incarnation, &entries)?,
                    decision,
                )
            }
        };
        ensure!(
            executed.expires_at_ms <= decision.expires_ms,
            "governance permission exceeds current capability validity"
        );
        Ok(Candidate {
            governance: Some(governance),
            pages: None,
            not_before: decision.not_before_ms,
            versions,
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
                f[2].text()? == self.action()
                    && f[3].array(0)?.is_empty()
                    && executed.maximum_effect == 0,
                "invalid governance refusal"
            );
            return ActionValidation::new(Vec::new());
        }
        ensure!(
            result.disposition == Disposition::Permit,
            "governance actions have no pending result"
        );
        let candidate = self.candidate(intent, result, executed)?;
        match &self.mode {
            Mode::Refresh { .. } => ActionValidation::governance_context(candidate.versions),
            Mode::Tier(tier) => tier.validation(candidate.versions),
            Mode::Policy(policy) => policy.validation(candidate.versions),
            _ => ActionValidation::new(candidate.versions),
        }
    }
    #[cfg(test)]
    fn finish(
        self,
        reply: CertifiedReply,
        ancestry: Vec<Vec<u8>>,
        store: &mut Store,
        session: &mut Session,
        clock: &mut impl FnMut() -> Result<ClockHealth>,
    ) -> Result<Outcome> {
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
    ) -> Result<Outcome> {
        let ancestry = &evidence.nodes;
        ensure!(
            ancestry.last().is_some_and(|v| *v == reply.node),
            "governance ancestry differs from control node"
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
                ancestry,
            },
            |i, r, e| self.validate(i, r, e),
        )?;
        let verified = evidence.attach(store, verified)?;
        if verified.disposition() != Disposition::Permit {
            let code = verified.code();
            store.observe(verified)?;
            session.discard(&self.challenge)?;
            if code == 12 && matches!(self.mode, Mode::Refresh { .. }) {
                bail!(
                    "authority discovery refused code 12; resolve the request, then use context --restart-discovery to fetch a new records view"
                );
            }
            bail!("authority governance refused with code {code}");
        }
        remaining(self.deadline)?;
        let candidate = self.candidate(
            verified.request().ordinary()?,
            &verified.result,
            &verified.executed,
        )?;
        if let Some(governance) = &candidate.governance {
            complete_minima(
                &governance.versions(),
                &store
                    .generations()
                    .iter()
                    .filter(|v| governance_kind(v.kind))
                    .cloned()
                    .collect::<Vec<_>>(),
            )?;
        }
        let prefix = verified.point().prefix().clone();
        let tier_value = if matches!(self.mode, Mode::Tier(_) | Mode::Grant(_) | Mode::Policy(_)) {
            Some(wire::decode(&verified.result.value)?)
        } else {
            None
        };
        let receipt = if matches!(self.mode, Mode::Member(_)) {
            member_offer::receipt(&self.intent, &self.challenge, &self.ordered, &reply)?
        } else {
            Vec::new()
        };
        let permit = store.accept(verified, session, clock()?, candidate.not_before)?;
        remaining(self.deadline)?;
        permit.perform(
            store,
            session,
            clock()?,
            1,
            |r| {
                ensure!(
                    *r == Restrictions::default(),
                    "governance restrictions changed"
                );
                Ok(())
            },
            |_, accepted_store| {
                if let Mode::Grant(_) = &self.mode {
                    let value = tier_value.context("grant result is absent")?;
                    if let Some(governance) = candidate.governance {
                        ContextState {
                            descriptor: self.descriptor.clone(),
                            governance,
                        }
                        .save(accepted_store)?;
                    }
                    return Ok(Outcome::Grant(grant::ResultState { value, prefix }));
                }
                if let Mode::Tier(tier) = &self.mode {
                    let value = tier_value.context("tier result is absent")?;
                    tier.retain(accepted_store, &value)?;
                    return Ok(Outcome::Tier(tier::ResultState { value, prefix }));
                }
                if let Mode::Policy(policy) = &self.mode {
                    let context = ContextState {
                        descriptor: self.descriptor.clone(),
                        governance: candidate.governance.context("policy context missing")?,
                    };
                    context.save(accepted_store)?;
                    policy.retain(accepted_store)?;
                    return Ok(Outcome::Policy(policy::ResultState { prefix }));
                }
                if let Some(pages) = &candidate.pages {
                    pages.save(&self.descriptor, self.grant, accepted_store)?;
                    if candidate.governance.is_none() {
                        return Ok(Outcome::Page);
                    }
                }
                let context = ContextState {
                    descriptor: self.descriptor,
                    governance: candidate
                        .governance
                        .context("complete governance context missing")?,
                };
                context.save(accepted_store)?;
                match self.mode {
                    Mode::Tier(_) | Mode::Grant(_) | Mode::Policy(_) => unreachable!(),
                    Mode::Refresh { .. } => Ok(Outcome::Context(Box::new(context))),
                    Mode::Member(member) => {
                        if let Some(path) = member.receipt {
                            member_offer::save_receipt(path, &receipt, &self.intent)?;
                        }
                        Ok(Outcome::Created(Box::new(CreatedRecord {
                            reference: member.reference,
                            canonical: member.created,
                            prefix,
                            #[cfg(test)]
                            context,
                        })))
                    }
                    Mode::Revoke {
                        target, tombstone, ..
                    } => Ok(Outcome::Revoked(Box::new(CreatedRecord {
                        reference: VersionRef {
                            kind: 126,
                            id: target.id,
                            generation: 1,
                            digest: wire::digest(&tombstone),
                        },
                        canonical: tombstone,
                        prefix,
                        #[cfg(test)]
                        context,
                    }))),
                }
            },
        )
    }
    fn local(
        self,
        control: &LocalControl,
        store: &mut Store,
        session: &mut Session,
        clock: &mut impl FnMut() -> Result<ClockHealth>,
    ) -> Result<Outcome> {
        let challenge = self.challenge.clone();
        let result = (|| {
            let (reply, evidence) = self.exchange(control, store, clock)?;
            self.finish_evidence(reply, evidence, store, session, clock)
        })();
        if result.is_err() {
            session.discard(&challenge)?;
        }
        result
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
            self.descriptor.scope().value(),
            V::Uint(operation),
            b(&payload),
        ]))
    }
    fn exchange(
        &self,
        control: &LocalControl,
        store: &Store,
        clock: &mut impl FnMut() -> Result<ClockHealth>,
    ) -> Result<(CertifiedReply, AncestryEvidence)> {
        let digest = wire::digest(&self.ordered);
        let mut bytes = control.exchange(&self.control(0, &self.ordered)?, self.deadline)?;
        let reply = loop {
            let decoded = wire::decode(&bytes)?;
            let f = record(&decoded, 42, 10)?;
            f[9].array(0)?;
            ensure!(
                proof::Scope::parse(&f[2])? == *self.descriptor.scope()
                    && f[4].uint()? == 0
                    && f[5].fixed::<32>()? == digest,
                "local control refused or returned another governance request"
            );
            match f[3].uint()? {
                0 => {
                    f[6].null()?;
                    f[7].null()?;
                    f[8].null()?;
                }
                1 => {
                    break CertifiedReply {
                        node: f[6].bytes()?.to_vec(),
                        certificate: f[7].bytes()?.to_vec(),
                        result: f[8].bytes()?.to_vec(),
                    };
                }
                _ => bail!("invalid local governance status"),
            }
            clock()?.observe()?;
            std::thread::sleep(Duration::from_millis(remaining(self.deadline)?.min(25)));
            bytes = control.exchange(&self.control(1, &digest)?, self.deadline)?;
        };
        let evidence = AncestryEvidence::fetch(control, store, &reply.node, self.deadline)?;
        Ok((reply, evidence))
    }
}

#[cfg(test)]
#[path = "AuthorityGovernanceClientTests.rs"]
mod tests;

#[path = "AuthorityMemberClient.rs"]
mod member_client;
use member_client::MemberPrepared;
pub use member_client::{MemberMutation, MemberRequest};

#[cfg(test)]
#[path = "AuthorityMemberClientTests.rs"]
mod member_tests;
