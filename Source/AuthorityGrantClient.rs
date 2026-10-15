// SPDX-License-Identifier: MIT
// Grant review preserves the exact mutation while atomically binding apply to its certified policy view.
use super::*;
use crate::{
    authority_grant_review as review,
    authority_membership::{self as membership, Mutation, Reservations, Snapshot},
};

pub struct ResultState {
    pub value: V,
    pub prefix: Prefix,
}
#[derive(Clone)]
pub struct Proposal {
    pub parameters: Vec<u8>,
    pub expected: Vec<VersionRef>,
    pub grant: [u8; 32],
    pub resource: [u8; 32],
    pub revision: u64,
}
pub(super) struct Prepared {
    pub proposal: Proposal,
    token: Option<[u8; 32]>,
    apply: bool,
    source: Vec<Vec<u8>>,
    reservations: Reservations,
}
impl Proposal {
    fn rebased(&self, store: &Store) -> Result<Self> {
        let value = wire::decode(&self.parameters)?;
        let mut fields = value.array(6)?.to_vec();
        fields[5] = a(vec![
            point(store.prefix()),
            a(self.expected.iter().map(version_value).collect()),
        ]);
        Self::parse(
            &wire::encode(&a(fields))?,
            store.descriptor().scope().network,
        )
    }
    pub fn parse(parameters: &[u8], network: [u8; 32]) -> Result<Self> {
        let value = wire::decode(parameters)?;
        let f = record(&value, 200, 6)?;
        let snapshot = Snapshot::parse(&f[5])?;
        let (grant, resource, revision) = match f[2].text()? {
            "AuthorityDelegateGrant" => {
                let parent = membership::version(&f[3])?;
                ensure!(parent.kind == 102, "delegation parent differs");
                let child = membership::ChildSpec::parse(&f[4], network)?;
                (parent.id, child.id, 1)
            }
            "AuthorityRevokeGrant" => {
                let target = membership::version(&f[4])?;
                ensure!(target.kind == 102, "revocation target differs");
                (f[3].fixed()?, target.id, target.generation)
            }
            _ => bail!("unsupported grant proposal"),
        };
        Ok(Self {
            parameters: parameters.to_vec(),
            expected: snapshot.references,
            grant,
            resource,
            revision,
        })
    }
}
fn skeleton(
    store: &Store,
    action: &str,
    resource: [u8; 32],
    revision: u64,
    parameters: Vec<u8>,
    expected: Vec<VersionRef>,
) -> Intent {
    let s = store.descriptor().scope();
    Intent {
        network: s.network,
        incarnation: s.incarnation,
        generation: 1,
        generation_id: [1; 32],
        sequence: 1,
        acknowledged_through: 0,
        requester: store.requester(),
        action: action.into(),
        resource,
        revision,
        profile_generation: 0,
        minimum_policy_epoch: s.epoch,
        minimum_policy_height: store.prefix().height(),
        expected,
        parameters,
        digest: [1; 32],
    }
}
pub fn delegate(
    context: &ContextState,
    bootstrap: &Verified,
    store: &Store,
    parent: VersionRef,
    child: V,
    at: u64,
) -> Result<Proposal> {
    context.current(store)?;
    let id = membership::ChildSpec::parse(&child, store.descriptor().scope().network)?.id;
    let parameters = |refs: &[VersionRef]| {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityDelegateGrant".into()),
            version_value(&parent),
            child.clone(),
            a(vec![
                point(store.prefix()),
                a(refs.iter().map(version_value).collect()),
            ]),
        ]))
    };
    let intent = skeleton(
        store,
        "AuthorityDelegateGrant",
        id,
        1,
        parameters(&[])?,
        vec![],
    );
    let decision = Mutation::parse(&intent)?.prepare(
        &records(&context.governance)?,
        &Reservations(bootstrap.reservations().to_vec()),
        &intent,
        at,
        false,
    )?;
    ensure!(
        decision.code == 0,
        "delegation preflight refused with code {}",
        decision.code
    );
    Proposal::parse(&parameters(&decision.dependencies)?, intent.network)
}
pub fn revoke(
    context: &ContextState,
    store: &Store,
    grant: [u8; 32],
    target: VersionRef,
    at: u64,
) -> Result<Proposal> {
    context.current(store)?;
    ensure!(
        target.kind == 102
            && context.governance.versions().contains(&target)
            && !context
                .governance
                .versions()
                .iter()
                .any(|r| r.kind == 126 && r.id == target.id),
        "revocation target is absent, stale or already revoked"
    );
    let mut expected = context
        .governance
        .current_capability(
            grant,
            &Requirement {
                subject: store.requester(),
                actions: &[12],
                scope: (0, store.descriptor().scope().network),
                namespace: None,
                usage: [0, 1, 0, 1],
                evaluated_at_ms: at,
                expected: &[],
            },
        )?
        .dependencies;
    expected.push(target.clone());
    expected.sort_by_key(VersionRef::index);
    expected.dedup();
    proof::validate_versions(&expected, 64)?;
    Proposal::parse(
        &wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text(REVOKE.into()),
            b(&grant),
            version_value(&target),
            a(vec![
                point(store.prefix()),
                a(expected.iter().map(version_value).collect()),
            ]),
        ]))?,
        store.descriptor().scope().network,
    )
}
impl Prepared {
    pub(super) fn action(&self) -> &'static str {
        if self.apply {
            "AuthorityGrantApply"
        } else {
            "AuthorityGrantPreview"
        }
    }
    pub(super) fn candidate(
        &self,
        intent: &Intent,
        value: &V,
        executed: &ExecutedResult,
    ) -> Result<Candidate> {
        let reviewed = review::Operation::parse(intent)?;
        ensure!(
            reviewed.inner.parameters == self.proposal.parameters
                && intent.expected == self.proposal.expected
                && reviewed.apply == self.apply
                && reviewed.token == self.token,
            "grant review changed its exact proposal"
        );
        let inner = &reviewed.inner;
        let f = record(value, 201, if self.apply { 6 } else { 5 })?;
        ensure!(
            f[2].text()? == self.action(),
            "grant review response action differs"
        );
        let versions = parse_versions(&f[3])?;
        let mut source = self.source.clone();
        let (created, reference, dependencies, not_before, expires) =
            if inner.action == "AuthorityDelegateGrant" {
                let mutation = Mutation::parse(inner)?;
                let created = mutation.derive(inner)?;
                let reference = VersionRef {
                    kind: 102,
                    id: inner.resource,
                    generation: 1,
                    digest: wire::digest(&created),
                };
                let replay = self.apply && f[5].uint()? < executed.height;
                if replay
                    && !Governance::record_versions(inner.network, inner.incarnation, &source)?
                        .contains(&reference)
                {
                    source.push(created.clone());
                    membership::sort_records(&mut source)?;
                }
                let d = mutation.authorise(
                    &source,
                    &self.reservations,
                    inner,
                    executed.evaluated_at_ms,
                    replay,
                )?;
                ensure!(
                    d.code == 0
                        && d.record == created
                        && d.created == reference
                        && d.dependencies == inner.expected,
                    "reviewed delegation lacks exact current authority"
                );
                (
                    created,
                    reference,
                    d.dependencies,
                    d.not_before_ms,
                    d.expires_ms,
                )
            } else {
                let params = wire::decode(&inner.parameters)?;
                let fields = params.array(6)?;
                let target = membership::version(&fields[4])?;
                let governance = Governance::parse(inner.network, inner.incarnation, &source)?;
                ensure!(
                    governance.versions().contains(&target),
                    "reviewed revocation target changed"
                );
                let d = governance.capability(
                    self.proposal.grant,
                    &Requirement {
                        subject: inner.requester,
                        actions: &[12],
                        scope: (0, inner.network),
                        namespace: None,
                        usage: [0, 1, 0, 1],
                        evaluated_at_ms: executed.evaluated_at_ms,
                        expected: &inner.expected,
                    },
                )?;
                let mut deps = d.dependencies;
                deps.push(target.clone());
                deps.sort_by_key(VersionRef::index);
                deps.dedup();
                ensure!(
                    deps == inner.expected,
                    "reviewed revocation dependencies changed"
                );
                let created = wire::encode(&a(vec![
                    V::Uint(126),
                    V::Uint(1),
                    b(&inner.network),
                    b(&inner.incarnation),
                    V::Uint(1),
                    V::Null,
                    version_value(&target),
                    b(&inner.requester),
                    fields[5].clone(),
                ]))?;
                let reference = VersionRef {
                    kind: 126,
                    id: target.id,
                    generation: 1,
                    digest: wire::digest(&created),
                };
                (created, reference, deps, d.not_before_ms, d.expires_ms)
            };
        ensure!(
            executed.expires_at_ms <= expires,
            "grant review exceeds current capability validity"
        );
        let mut expected = dependencies;
        if self.apply {
            let height = f[5].uint()?;
            let snapshot = wire::decode(&inner.parameters)?;
            let snapshot = Snapshot::parse(&snapshot.array(6)?[5])?;
            ensure!(
                height > snapshot.height && height <= executed.height && f[4].bytes()? == created,
                "reviewed grant result changed its exact record or creation height"
            );
            expected.push(reference.clone());
            expected.sort_by_key(VersionRef::index);
            ensure!(
                versions == expected,
                "reviewed grant result dependencies differ"
            );
            let mut map = BTreeMap::new();
            for record in &source {
                let r = Governance::record_versions(
                    inner.network,
                    inner.incarnation,
                    std::slice::from_ref(record),
                )?;
                map.insert(r[0].index(), record.clone());
            }
            ensure!(
                map.get(&reference.index())
                    .is_none_or(|old| *old == created),
                "reviewed grant cannot replace a permanent record"
            );
            map.insert(reference.index(), created);
            source = map.into_values().collect();
        } else {
            ensure!(
                versions == expected,
                "grant preview contains unexpected dependencies"
            );
            let p = f[4].array(7)?;
            ensure!(
                p[0].fixed::<32>()? == reviewed.request_digest()?
                    && p[1].fixed::<32>()? != [0; 32]
                    && p[2].fixed::<32>()? != [0; 32]
                    && p[3].uint()? <= crate::authority_tiers::MAX_IMPACTS as u64
                    && p[4].uint()?
                        < crate::authority_tiers::MAX_IMPACTS
                            .div_ceil(crate::authority_tiers::IMPACT_PAGE)
                            as u64,
                "grant preview binding or bounds differ"
            );
            for row in p[5].list(crate::authority_tiers::IMPACT_PAGE)? {
                let row = row.array(5)?;
                ensure!(
                    row[0].uint()? <= 5
                        && row[1].fixed::<32>()? != [0; 32]
                        && row[2].fixed::<32>()? != [0; 32]
                        && row[3].fixed::<32>()? == p[0].fixed::<32>()?
                        && row[4].uint()? == 4,
                    "invalid grant impact"
                );
            }
            if p[6] != V::Null {
                ensure!(p[6].fixed::<32>()? != [0; 32], "empty grant preview cursor");
            }
        }
        Ok(Candidate {
            governance: if self.apply {
                Some(Governance::parse(
                    inner.network,
                    inner.incarnation,
                    &source,
                )?)
            } else {
                None
            },
            pages: None,
            not_before,
            versions,
        })
    }
}
#[allow(clippy::too_many_arguments)]
pub fn execute(
    context: &ContextState,
    bootstrap: &Verified,
    path: &Path,
    proposal: Proposal,
    token: Option<[u8; 32]>,
    apply: bool,
    signer: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    mut clock: impl FnMut() -> Result<ClockHealth>,
) -> Result<ResultState> {
    context.current(store)?;
    stream_client::ensure_stream(
        &store.descriptor().clone(),
        path,
        signer,
        store,
        session,
        &mut clock,
    )?;
    let mut proposal = proposal.rebased(store)?;
    if let Some(pending) = store.resume_ordinary()? {
        let intent = Intent::from_signed(pending.signed())?;
        let saved = review::Operation::parse(&intent)?;
        let old = wire::decode(&saved.inner.parameters)?;
        let desired = wire::decode(&proposal.parameters)?;
        let mut desired = desired.array(6)?.to_vec();
        desired[5] = old.array(6)?[5].clone();
        ensure!(
            saved.apply == apply
                && saved.token == token
                && a(desired) == old
                && intent.expected == proposal.expected,
            "another exact grant request remains unresolved"
        );
        proposal.parameters = saved.inner.parameters;
    }
    let prepared = Prepared {
        proposal: proposal.clone(),
        token,
        apply,
        source: records(&context.governance)?,
        reservations: Reservations(bootstrap.reservations().to_vec()),
    };
    let canonical = wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text(prepared.action().into()),
        b(&proposal.parameters),
        token.map_or(V::Null, |v| b(&v)),
    ]))?;
    let control = LocalControl::prepare_authority(path, store)?;
    let pending = GovernancePrepared::new(
        Parameters {
            descriptor: store.descriptor().clone(),
            grant: proposal.grant,
            mode: Mode::Grant(prepared),
            expected: proposal.expected,
            canonical,
        },
        signer,
        store,
        session,
        clock()?,
    )?;
    match pending.local(&control, store, session, &mut clock)? {
        Outcome::Grant(value) => Ok(value),
        _ => bail!("unexpected grant review response"),
    }
}

#[cfg(test)]
#[path = "AuthorityGrantClientTests.rs"]
mod tests;
