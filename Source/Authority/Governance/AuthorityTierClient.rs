// SPDX-License-Identifier: MIT
// Tier discovery and reviewed changes use the ordinary durable quorum request stream.
use super::*;
use crate::authority_tiers::{self as tiers, Spec};

const CACHE: &str = "TierContext.cbor";
pub struct ResultState {
    pub value: V,
    pub prefix: Prefix,
}
#[derive(Clone)]
pub enum Request {
    Context(Option<[u8; 32]>),
    List(Option<[u8; 32]>),
    Change {
        previous: Option<Vec<u8>>,
        spec: Box<Spec>,
        expected: Vec<VersionRef>,
        token: Option<[u8; 32]>,
        apply: bool,
    },
}
pub(super) struct Prepared {
    request: Request,
    grant: [u8; 32],
    network: [u8; 32],
    incarnation: [u8; 32],
    source: Vec<Vec<u8>>,
}
fn merge(bootstrap: &Verified, retained: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    let s = bootstrap.descriptor().scope();
    let mut out = BTreeMap::new();
    for bytes in bootstrap.governance_records().iter().chain(retained) {
        let refs =
            Governance::record_versions(s.network, s.incarnation, std::slice::from_ref(bytes))?;
        ensure!(refs.len() == 1, "tier context record is ambiguous");
        out.insert(refs[0].index(), bytes.clone());
    }
    Ok(out.into_values().collect())
}
/// Reconcile tier bytes with the independently retained floor before ordinary cache validation.
pub(crate) fn refresh_cached_tiers(
    bootstrap: &Verified,
    store: &Store,
    records: &mut Vec<Vec<u8>>,
) -> Result<()> {
    let scope = store.descriptor().scope();
    merge_cached_tiers(
        scope.network,
        scope.incarnation,
        store.generations(),
        &load(bootstrap, store)?,
        records,
    )
}
fn merge_cached_tiers(
    network: [u8; 32],
    incarnation: [u8; 32],
    floor: &[VersionRef],
    authenticated: &[Vec<u8>],
    records: &mut Vec<Vec<u8>>,
) -> Result<()> {
    let old = Governance::record_versions(network, incarnation, records)?;
    let mut selected = old
        .into_iter()
        .zip(records.iter().cloned())
        .map(|(r, bytes)| (r.index(), (r, bytes)))
        .collect::<BTreeMap<_, _>>();
    for bytes in authenticated {
        let refs = Governance::record_versions(network, incarnation, std::slice::from_ref(bytes))?;
        let r = &refs[0];
        if r.kind != 101 || !floor.contains(r) {
            continue;
        }
        if let Some((old, _)) = selected.get(&r.index()) {
            ensure!(
                old.generation < r.generation || old == r,
                "cached tier conflicts with its certified successor"
            );
        }
        selected.insert(r.index(), (r.clone(), bytes.clone()));
    }
    *records = selected.into_values().map(|(_, bytes)| bytes).collect();
    Ok(())
}
pub fn load(bootstrap: &Verified, store: &Store) -> Result<Vec<Vec<u8>>> {
    let bytes = match files::read_at(
        store.profile_directory(),
        OsStr::new(CACHE),
        CONTEXT_LIMIT,
        true,
    ) {
        Ok(bytes) => bytes,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return merge(bootstrap, &[]);
        }
        Err(error) => return Err(error),
    };
    let value = wire::decode_state(&bytes)?;
    let mut retained = Vec::new();
    let scope = store.descriptor().scope();
    for bytes in value.list(MAX_RECORDS)? {
        let bytes = bytes.bytes()?.to_vec();
        let refs = Governance::record_versions(
            scope.network,
            scope.incarnation,
            std::slice::from_ref(&bytes),
        )?;
        ensure!(refs.len() == 1, "tier cache contains an ambiguous record");
        // A cache is only a source of bytes for the independently retained exact floor.
        if store.generations().contains(&refs[0]) {
            retained.push(bytes);
        }
    }
    merge(bootstrap, &retained)
}
impl Prepared {
    pub(super) fn action(&self) -> &'static str {
        match self.request {
            Request::Context(_) => "AuthorityTierContext",
            Request::List(_) => "AuthorityTierList",
            Request::Change { apply: false, .. } => "AuthorityTierPreview",
            Request::Change { apply: true, .. } => "AuthorityTierApply",
        }
    }
    pub(super) fn resource(&self) -> [u8; 32] {
        match &self.request {
            Request::Context(tier) => tier.unwrap_or(self.network),
            Request::List(_) => self.network,
            Request::Change { spec, .. } => spec.id,
        }
    }
    pub(super) fn revision(&self) -> Result<u64> {
        match &self.request {
            Request::Change { previous, .. } => previous.as_ref().map_or(Ok(1), |v| {
                Spec::from_record(v, self.network, self.incarnation)?
                    .1
                    .generation
                    .checked_add(1)
                    .context("tier generation exhausted")
            }),
            _ => Ok(0),
        }
    }
    fn parameters(&self, store: &Store) -> Result<Vec<u8>> {
        let mut fields = vec![
            V::Uint(200),
            V::Uint(1),
            V::Text(self.action().into()),
            b(&self.grant),
        ];
        match &self.request {
            Request::Context(id) | Request::List(id) => {
                fields.extend([id.map_or(V::Null, |v| b(&v)), point(store.prefix())])
            }
            Request::Change {
                previous,
                spec,
                expected,
                token,
                ..
            } => fields.extend([
                previous.as_ref().map_or(V::Null, |v| b(v)),
                spec.value(),
                a(vec![
                    point(store.prefix()),
                    a(expected.iter().map(version_value).collect()),
                ]),
                token.map_or(V::Null, |v| b(&v)),
            ]),
        }
        wire::encode(&a(fields))
    }
    fn scopes(&self, governance: &Governance) -> Result<Vec<(u64, [u8; 32])>> {
        let mut scopes = match &self.request {
            Request::Context(Some(id)) => {
                Spec::from_record(
                    governance.record_bytes(101, *id)?,
                    self.network,
                    self.incarnation,
                )?
                .0
                .scopes
            }
            Request::Context(None) => {
                let grant = wire::decode(governance.record_bytes(102, self.grant)?)?;
                let first = grant.array(17)?[11]
                    .list(64)?
                    .first()
                    .context("tier administration grant has no scope")?
                    .array(2)?;
                vec![(first[0].uint()?, first[1].fixed()?)]
            }
            Request::List(_) => vec![(0, self.network)],
            Request::Change { previous, spec, .. } => {
                let mut scopes = spec.scopes.clone();
                if let Some(old) = previous {
                    scopes.extend(
                        Spec::from_record(old, self.network, self.incarnation)?
                            .0
                            .scopes,
                    );
                }
                scopes
            }
        };
        scopes.sort();
        scopes.dedup();
        Ok(scopes)
    }
    fn permission(
        &self,
        source: &[Vec<u8>],
        requester: [u8; 32],
        at: u64,
    ) -> Result<(Vec<VersionRef>, u64, u64)> {
        let governance = Governance::parse(self.network, self.incarnation, source)?;
        ensure!(
            governance.record_bytes(127, requester).is_err(),
            "applications cannot administer tiers"
        );
        let mut expected = BTreeMap::new();
        let (mut not_before, mut expires) = (0, u64::MAX);
        for scope in self.scopes(&governance)? {
            let cap = governance.current_capability(
                self.grant,
                &Requirement {
                    subject: requester,
                    actions: &[9],
                    scope,
                    namespace: None,
                    usage: [0, 1, 0, 1],
                    evaluated_at_ms: at,
                    expected: &[],
                },
            )?;
            not_before = not_before.max(cap.not_before_ms);
            expires = expires.min(cap.expires_ms);
            for r in cap.dependencies {
                expected.insert(r.index(), r);
            }
        }
        let old = match &self.request {
            Request::Context(Some(id)) => Some(
                Spec::from_record(
                    governance.record_bytes(101, *id)?,
                    self.network,
                    self.incarnation,
                )?
                .1,
            ),
            Request::Change {
                previous: Some(old),
                ..
            } => Some(Spec::from_record(old, self.network, self.incarnation)?.1),
            _ => None,
        };
        if let Some(old) = old {
            expected.insert(old.index(), old);
        }
        let expected = expected.into_values().collect::<Vec<_>>();
        proof::validate_versions(&expected, 64)?;
        Ok((expected, not_before, expires))
    }
    pub(super) fn candidate(
        &self,
        intent: &Intent,
        value: &V,
        executed: &ExecutedResult,
    ) -> Result<Candidate> {
        let arity = if matches!(
            self.request,
            Request::List(_) | Request::Change { apply: true, .. }
        ) {
            6
        } else {
            5
        };
        let f = record(value, 201, arity)?;
        ensure!(f[2].text()? == self.action(), "tier result action differs");
        let versions = parse_versions(&f[3])?;
        let mut source = self.source.clone();
        if matches!(self.request, Request::Context(_)) {
            let selected = f[4]
                .list(64)?
                .iter()
                .map(|v| Ok(v.bytes()?.to_vec()))
                .collect::<Result<Vec<_>>>()?;
            let actual = Governance::record_versions(self.network, self.incarnation, &selected)?;
            ensure!(
                actual == versions,
                "tier context bytes differ from certified references"
            );
            let mut map = BTreeMap::new();
            for bytes in source.iter().chain(&selected) {
                let r = Governance::record_versions(
                    self.network,
                    self.incarnation,
                    std::slice::from_ref(bytes),
                )?;
                map.insert(r[0].index(), bytes.clone());
            }
            source = map.into_values().collect();
        }
        let (mut expected, not_before, expires) =
            self.permission(&source, intent.requester, executed.evaluated_at_ms)?;
        ensure!(
            executed.expires_at_ms <= expires,
            "tier permission exceeds current grant validity"
        );
        match &self.request {
            Request::Context(_) => ensure!(
                expected == versions,
                "tier context dependency closure differs"
            ),
            Request::List(after) => {
                let rows = f[4].list(32)?;
                let mut last = *after;
                for bytes in rows {
                    let (_, r) = Spec::from_record(bytes.bytes()?, self.network, self.incarnation)?;
                    ensure!(
                        last.is_none_or(|id| r.id > id),
                        "tier list is not strictly ordered"
                    );
                    last = Some(r.id);
                    expected.push(r);
                }
                expected.sort_by_key(VersionRef::index);
                expected.dedup();
                ensure!(
                    expected == versions
                        && (f[5] == V::Null || rows.len() == 32 && last == Some(f[5].fixed()?)),
                    "tier list references or continuation differ"
                );
            }
            Request::Change {
                expected: reviewed,
                apply,
                ..
            } => {
                ensure!(
                    expected == *reviewed && intent.expected == *reviewed,
                    "tier proposal dependencies changed"
                );
                let operation = tiers::Operation::parse(intent)?;
                if *apply {
                    let created = operation
                        .derive(intent)?
                        .context("tier mutation has no derived record")?;
                    let reference =
                        tiers::record_reference(&created, self.network, self.incarnation)?;
                    let height = f[5].uint()?;
                    ensure!(
                        f[4].bytes()? == created
                            && height > intent.minimum_policy_height
                            && height <= executed.height,
                        "tier result differs from its exact proposed record or creation height"
                    );
                    expected.retain(|r| r.index() != reference.index());
                    expected.push(reference);
                    expected.sort_by_key(VersionRef::index);
                    ensure!(
                        versions == expected,
                        "tier mutation result dependencies differ"
                    );
                } else {
                    let preview = f[4].array(7)?;
                    ensure!(
                        versions == expected
                            && preview[0].fixed::<32>()? == operation.request_digest(intent)?
                            && preview[1].fixed::<32>()? != [0; 32]
                            && preview[2].fixed::<32>()? != [0; 32]
                            && preview[3].uint()? <= tiers::MAX_IMPACTS as u64
                            && preview[4].uint()?
                                < (tiers::MAX_IMPACTS / tiers::IMPACT_PAGE) as u64,
                        "tier preview request or resource bounds differ"
                    );
                    for impact in preview[5].list(tiers::IMPACT_PAGE)? {
                        let impact = impact.array(5)?;
                        ensure!(
                            impact[0].uint()? <= 5
                                && impact[1].fixed::<32>()? != [0; 32]
                                && impact[2].fixed::<32>()? != [0; 32]
                                && impact[3].fixed::<32>()? == preview[0].fixed::<32>()?
                                && impact[4].uint()? == 4,
                            "invalid tier preview impact"
                        );
                    }
                    if preview[6] != V::Null {
                        ensure!(preview[6].fixed::<32>()? != [0; 32], "empty preview cursor");
                    }
                }
            }
        }
        Ok(Candidate {
            governance: None,
            pages: None,
            not_before,
            versions,
        })
    }
    // Called only after candidate has verified the exact derived record and signed predecessor.
    pub(super) fn validation(&self, versions: Vec<VersionRef>) -> Result<ActionValidation> {
        let mut updates = Vec::new();
        if let Request::Change {
            previous: Some(previous),
            apply: true,
            ..
        } = &self.request
        {
            let old = tiers::record_reference(previous, self.network, self.incarnation)?;
            let new = versions
                .iter()
                .find(|reference| reference.index() == old.index())
                .context("validated tier successor is absent")?
                .clone();
            updates.push((old, new));
        }
        ActionValidation::mutation(versions, updates)
    }
    pub(super) fn retain(&self, store: &Store, value: &V) -> Result<()> {
        let f = value.list(6)?;
        let extra = match &self.request {
            Request::Context(_) | Request::List(_) => f[4]
                .list(64)?
                .iter()
                .map(|v| Ok(v.bytes()?.to_vec()))
                .collect::<Result<Vec<_>>>()?,
            Request::Change { apply: true, .. } => vec![f[4].bytes()?.to_vec()],
            _ => vec![],
        };
        let mut records = BTreeMap::new();
        for bytes in self.source.iter().chain(&extra) {
            let r = Governance::record_versions(
                self.network,
                self.incarnation,
                std::slice::from_ref(bytes),
            )?;
            if store.generations().contains(&r[0]) {
                records.insert(r[0].index(), b(bytes));
            }
        }
        files::atomic_at(
            store.profile_directory(),
            OsStr::new(CACHE),
            &wire::encode_state(&a(records.into_values().collect()))?,
            true,
        )
    }
}
pub fn dependencies(
    bootstrap: &Verified,
    store: &Store,
    grant: [u8; 32],
    previous: Option<Vec<u8>>,
    spec: Spec,
    at: u64,
) -> Result<Vec<VersionRef>> {
    let s = bootstrap.descriptor().scope();
    let prepared = Prepared {
        request: Request::Change {
            previous,
            spec: Box::new(spec),
            expected: vec![],
            token: None,
            apply: false,
        },
        grant,
        network: s.network,
        incarnation: s.incarnation,
        source: load(bootstrap, store)?,
    };
    Ok(prepared
        .permission(&prepared.source, store.requester(), at)?
        .0)
}
#[allow(clippy::too_many_arguments)]
pub fn execute(
    bootstrap: &Verified,
    path: &Path,
    grant: [u8; 32],
    request: Request,
    signer: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    mut clock: impl FnMut() -> Result<ClockHealth>,
) -> Result<ResultState> {
    stream_client::ensure_stream(
        &store.descriptor().clone(),
        path,
        signer,
        store,
        session,
        &mut clock,
    )?;
    let scope = store.descriptor().scope();
    let prepared = Prepared {
        request,
        grant,
        network: scope.network,
        incarnation: scope.incarnation,
        source: load(bootstrap, store)?,
    };
    let mut canonical = prepared.parameters(store)?;
    let expected = match &prepared.request {
        Request::Change { expected, .. } => expected.clone(),
        _ => vec![],
    };
    if let Some(pending) = store.resume_ordinary()? {
        let intent = Intent::from_signed(pending.signed())?;
        let saved = wire::decode(&intent.parameters)?;
        let proposed = wire::decode(&canonical)?;
        let mut proposed = proposed.list(8)?.to_vec();
        let old = saved.list(8)?;
        let position = if matches!(prepared.request, Request::Change { .. }) {
            6
        } else {
            5
        };
        ensure!(
            old.len() == proposed.len(),
            "another exact tier request remains unresolved"
        );
        proposed[position] = old[position].clone();
        ensure!(
            a(proposed) == saved,
            "another exact tier request remains unresolved"
        );
        canonical = intent.parameters;
    }
    let control = LocalControl::prepare_authority(path, store)?;
    let pending = GovernancePrepared::new(
        Parameters {
            descriptor: store.descriptor().clone(),
            grant,
            mode: Mode::Tier(prepared),
            expected,
            canonical,
        },
        signer,
        store,
        session,
        clock()?,
    )?;
    match pending.local(&control, store, session, &mut clock)? {
        Outcome::Tier(result) => Ok(result),
        _ => bail!("unexpected tier operation result"),
    }
}

#[cfg(test)]
#[path = "../../../Tests/Unit/Authority/Governance/AuthorityTierClientTests.rs"]
mod tests;
