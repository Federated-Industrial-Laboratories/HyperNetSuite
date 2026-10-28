// SPDX-License-Identifier: MIT
// Certified policy replacement and local trust acceptance remain separate durable decisions.
use super::*;
use crate::authority_policies::{self as policies, Operation};
const CURRENT: &str = "CurrentPolicy.cbor";
const ACCEPTED: &str = "AcceptedPolicy.cbor";
const PENDING: &str = "PendingPolicy.cbor";
#[path = "AuthorityPolicyDiscovery.rs"]
mod discovery;
pub(crate) use discovery::refresh_before_request_with_budget;
pub use discovery::{discover, refresh_before_request};
fn validate_pair(p: &[u8], r: &[u8], n: [u8; 32], i: [u8; 32]) -> Result<()> {
    policies::record_reference(p, n, i, 100)?;
    let reference = policies::record_reference(r, n, i, 114)?;
    ensure!(
        wire::decode(p)?.array(17)?[12] == version_value(&reference),
        "policy pair has mismatched custody"
    );
    Ok(())
}
pub(crate) fn current_reference(bootstrap: &Verified, store: &Store) -> Result<VersionRef> {
    let s = store.descriptor().scope();
    policies::record_reference(&current(bootstrap, store)?.0, s.network, s.incarnation, 100)
}
pub(crate) fn require_pending_policy(
    bootstrap: &Verified,
    store: &Store,
    intent: &Intent,
) -> Result<()> {
    ensure!(
        intent
            .expected
            .contains(&current_reference(bootstrap, store)?),
        "pending operation lacks the accepted current policy; reconcile or fence its exact request before continuing"
    );
    Ok(())
}
fn selected_pair(
    bootstrap: &Verified,
    store: &Store,
    records: &[Vec<u8>],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let s = store.descriptor().scope();
    let initial = Governance::parse(s.network, s.incarnation, bootstrap.governance_records())?;
    let (mut p, mut r) = read_pair(store, CURRENT)?.unwrap_or((
        initial.record_bytes(100, s.network)?.to_vec(),
        initial.record_bytes(114, s.network)?.to_vec(),
    ));
    if let Some((pending_p, pending_r)) = read_pair(store, PENDING)? {
        if store.generations().contains(&policies::record_reference(
            &pending_p,
            s.network,
            s.incarnation,
            100,
        )?) {
            p = pending_p;
        }
        if store.generations().contains(&policies::record_reference(
            &pending_r,
            s.network,
            s.incarnation,
            114,
        )?) {
            r = pending_r;
        }
    }
    for bytes in records {
        let value = wire::decode(bytes)?;
        if !matches!(
            value.list(32)?.first().map(V::uint).transpose()?,
            Some(100 | 114)
        ) {
            continue;
        }
        let refs =
            Governance::record_versions(s.network, s.incarnation, std::slice::from_ref(bytes))?;
        let selected = refs.first().context("empty policy record")?;
        if selected.kind == 100 && selected.id == s.network {
            p = bytes.clone();
        }
        if selected.kind == 114 && selected.id == s.network {
            r = bytes.clone();
        }
    }
    validate_pair(&p, &r, s.network, s.incarnation)?;
    Ok((p, r))
}
pub(crate) fn require_records_accepted(
    bootstrap: &Verified,
    store: &Store,
    records: &[Vec<u8>],
) -> Result<()> {
    let s = store.descriptor().scope();
    let (p, r) = selected_pair(bootstrap, store, records)?;
    crate::authority_domains::result::minimum(
        &[
            policies::record_reference(&p, s.network, s.incarnation, 100)?,
            policies::record_reference(&r, s.network, s.incarnation, 114)?,
        ],
        store.generations(),
    )?;
    let initial = Governance::parse(s.network, s.incarnation, bootstrap.governance_records())?;
    let accepted = read_pair(store, ACCEPTED)?.unwrap_or((
        initial.record_bytes(100, s.network)?.to_vec(),
        initial.record_bytes(114, s.network)?.to_vec(),
    ));
    policies::check_minima(&p, &r, &accepted.0, &accepted.1, s.network, s.incarnation)
}
pub(crate) fn retain_records(
    bootstrap: &Verified,
    store: &Store,
    records: &[Vec<u8>],
) -> Result<()> {
    for bytes in records {
        let value = wire::decode(bytes)?;
        if matches!(
            value.list(32)?.first().map(V::uint).transpose()?,
            Some(100 | 114)
        ) {
            let (p, r) = selected_pair(bootstrap, store, records)?;
            return retain_pair(store, &p, &r);
        }
    }
    // An intrinsic ownership reply can contain no policy evidence. Leave the
    // separately trusted bootstrap/current pair unchanged rather than inventing
    // certified policy generations that this reply did not establish.
    Ok(())
}

pub struct ResultState {
    pub prefix: Prefix,
}
pub(super) struct Prepared {
    operation: Operation,
    source: Vec<Vec<u8>>,
    reservations: crate::authority_membership::Reservations,
    network: [u8; 32],
    incarnation: [u8; 32],
}
impl Prepared {
    pub(super) fn network(&self) -> [u8; 32] {
        self.network
    }
    pub(super) fn revision(&self) -> Result<u64> {
        Ok(
            policies::record_reference(
                &self.operation.policy,
                self.network,
                self.incarnation,
                100,
            )?
            .generation,
        )
    }
    pub(super) fn candidate(
        &self,
        intent: &Intent,
        value: &V,
        executed: &ExecutedResult,
    ) -> Result<Candidate> {
        let selected = policies::authorise(
            &self.operation,
            &self.source,
            &self.reservations,
            intent,
            executed.evaluated_at_ms,
            false,
        )?;
        ensure!(
            selected.code == 0
                && *value == selected.value
                && executed.expires_at_ms <= selected.expires_ms,
            "certified policy result differs from exact authorised successor"
        );
        let records = selected.records.context("policy successor missing")?;
        Ok(Candidate {
            governance: Some(Governance::parse(self.network, self.incarnation, &records)?),
            pages: None,
            not_before: selected.not_before_ms,
            versions: selected.versions,
        })
    }
    pub(super) fn validation(&self, versions: Vec<VersionRef>) -> Result<ActionValidation> {
        ActionValidation::mutation(
            versions,
            self.operation
                .replacements(self.network, self.incarnation)?,
        )
    }
    pub(super) fn retain(&self, store: &Store) -> Result<()> {
        retain_pair(store, &self.operation.policy, &self.operation.recovery)
    }
}
fn pair(policy: &[u8], recovery: &[u8]) -> Result<Vec<u8>> {
    wire::encode(&a(vec![b(policy), b(recovery)]))
}
fn retain_cached_pair(store: &Store, name: &str, policy: &[u8], recovery: &[u8]) -> Result<()> {
    let scope = store.descriptor().scope();
    validate_pair(policy, recovery, scope.network, scope.incarnation)?;
    if let Some((prior_policy, prior_recovery)) = read_pair(store, name)? {
        validate_pair(
            &prior_policy,
            &prior_recovery,
            scope.network,
            scope.incarnation,
        )?;
        // The protected existing inode already durably holds these exact bytes.
        // Every new read still commits its witnessed authority floor separately.
        if prior_policy == policy && prior_recovery == recovery {
            return Ok(());
        }
    }
    files::atomic_at(
        store.profile_directory(),
        OsStr::new(name),
        &pair(policy, recovery)?,
        true,
    )
}
fn retain_pair(store: &Store, policy: &[u8], recovery: &[u8]) -> Result<()> {
    let scope = store.descriptor().scope();
    for (bytes, kind) in [(policy, 100), (recovery, 114)] {
        let r = policies::record_reference(bytes, scope.network, scope.incarnation, kind)?;
        ensure!(
            store.generations().contains(&r),
            "policy cache lacks exact certified generation"
        );
    }
    retain_cached_pair(store, CURRENT, policy, recovery)
}
pub(super) fn retain_context(store: &Store, governance: &Governance) -> Result<()> {
    let n = store.descriptor().scope().network;
    let policy = governance.record_bytes(100, n)?;
    let recovery = governance.record_bytes(114, n)?;
    if store.generations().iter().any(|r| r.kind == 100) {
        retain_pair(store, policy, recovery)?;
    }
    Ok(())
}
fn read_pair(store: &Store, name: &str) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let bytes = match files::read_at(
        store.profile_directory(),
        OsStr::new(name),
        wire::MAXIMUM,
        true,
    ) {
        Ok(bytes) => bytes,
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    let value = wire::decode(&bytes)?;
    let f = value.array(2)?;
    Ok(Some((f[0].bytes()?.to_vec(), f[1].bytes()?.to_vec())))
}
pub(crate) fn refresh_cached_policies(
    bootstrap: &Verified,
    store: &Store,
    records: &mut Vec<Vec<u8>>,
) -> Result<()> {
    let s = bootstrap.descriptor().scope();
    let (p, r) = current(bootstrap, store)?;
    for (bytes, kind) in [(p, 100), (r, 114)] {
        let reference = policies::record_reference(&bytes, s.network, s.incarnation, kind)?;
        if store.generations().contains(&reference) {
            if let Some(previous) = records.iter_mut().find(|v| {
                wire::decode(v).is_ok_and(|v| v.list(32).is_ok_and(|f| f[0] == V::Uint(kind)))
            }) {
                *previous = bytes;
            } else {
                records.push(bytes);
            }
        }
    }
    crate::authority_membership::sort_records(records)
}
pub fn current(bootstrap: &Verified, store: &Store) -> Result<(Vec<u8>, Vec<u8>)> {
    let n = bootstrap.descriptor().scope().network;
    let i = bootstrap.descriptor().scope().incarnation;
    let initial = Governance::parse(n, i, bootstrap.governance_records())?;
    let (mut policy, mut recovery) = read_pair(store, CURRENT)?.unwrap_or((
        initial.record_bytes(100, n)?.to_vec(),
        initial.record_bytes(114, n)?.to_vec(),
    ));
    if let Some((p, r)) = read_pair(store, PENDING)? {
        for (candidate, current, kind) in [(p, &mut policy, 100), (r, &mut recovery, 114)] {
            let reference = policies::record_reference(&candidate, n, i, kind)?;
            if store.generations().contains(&reference) {
                *current = candidate;
            }
        }
    }
    for (bytes, kind) in [(&policy, 100), (&recovery, 114)] {
        let r = policies::record_reference(bytes, n, i, kind)?;
        let expected = store
            .generations()
            .iter()
            .find(|r| r.kind == kind && r.id == n)
            .cloned()
            .unwrap_or_else(|| {
                initial
                    .versions()
                    .into_iter()
                    .find(|r| r.kind == kind)
                    .expect("initial policy")
            });
        ensure!(
            r == expected,
            "current policy bytes require certified context discovery"
        );
    }
    let value = wire::decode(&policy)?;
    ensure!(
        value.array(17)?[12] == version_value(&policies::record_reference(&recovery, n, i, 114)?),
        "current network policy requires its exact recovery policy bytes"
    );
    Ok((policy, recovery))
}
pub fn require_accepted(bootstrap: &Verified, store: &Store) -> Result<()> {
    let s = bootstrap.descriptor().scope();
    let current = current(bootstrap, store)?;
    let initial = Governance::parse(s.network, s.incarnation, bootstrap.governance_records())?;
    let accepted = read_pair(store, ACCEPTED)?.unwrap_or((
        initial.record_bytes(100, s.network)?.to_vec(),
        initial.record_bytes(114, s.network)?.to_vec(),
    ));
    policies::check_minima(
        &current.0,
        &current.1,
        &accepted.0,
        &accepted.1,
        s.network,
        s.incarnation,
    )
}
pub fn acceptance_digest(bootstrap: &Verified, store: &Store) -> Result<[u8; 32]> {
    let (p, r) = current(bootstrap, store)?;
    Ok(wire::digest(&pair(&p, &r)?))
}
pub fn accept(bootstrap: &Verified, store: &Store, expected: [u8; 32]) -> Result<()> {
    let (p, r) = current(bootstrap, store)?;
    let bytes = pair(&p, &r)?;
    ensure!(
        wire::digest(&bytes) == expected,
        "inspected trust contract digest differs"
    );
    files::atomic_at(
        store.profile_directory(),
        OsStr::new(ACCEPTED),
        &bytes,
        true,
    )
}
#[allow(clippy::too_many_arguments)]
pub fn execute_context(
    bootstrap: &Verified,
    context: &ContextState,
    path: &Path,
    operation: Operation,
    signer: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    mut clock: impl FnMut() -> Result<ClockHealth>,
) -> Result<ResultState> {
    if let Some(pending) = store.resume_ordinary()? {
        let intent = Intent::from_signed(pending.signed())?;
        ensure!(
            intent.action == "AuthorityPolicyApply"
                && intent.parameters == operation.parameters()?,
            "another exact operation is pending before policy submission"
        );
    } else {
        require_accepted(bootstrap, store)?;
    }
    stream_client::ensure_stream(
        &store.descriptor().clone(),
        path,
        signer,
        store,
        session,
        &mut clock,
    )?;
    let s = store.descriptor().scope();
    let mut source = records(&context.governance)?;
    for bytes in &mut source {
        let value = wire::decode(bytes)?;
        let f = value.list(32)?;
        if f[0] == V::Uint(100) {
            *bytes = operation.previous_policy.clone();
        } else if f[0] == V::Uint(114) {
            *bytes = operation.previous_recovery.clone();
        }
    }
    files::atomic_at(
        store.profile_directory(),
        OsStr::new(PENDING),
        &pair(&operation.policy, &operation.recovery)?,
        true,
    )?;
    let prepared = Prepared {
        source,
        reservations: crate::authority_membership::Reservations(bootstrap.reservations().to_vec()),
        network: s.network,
        incarnation: s.incarnation,
        operation,
    };
    let canonical = prepared.operation.parameters()?;
    let expected = prepared.operation.snapshot.references.clone();
    let grant = prepared.operation.grant;
    let control = LocalControl::prepare_authority(path, store)?;
    let pending = GovernancePrepared::new(
        Parameters {
            descriptor: store.descriptor().clone(),
            grant,
            mode: Mode::Policy(prepared),
            expected,
            canonical,
        },
        signer,
        store,
        session,
        clock()?,
    )?;
    match pending.local(&control, store, session, &mut clock)? {
        Outcome::Policy(result) => Ok(result),
        _ => bail!("unexpected policy result"),
    }
}

#[cfg(test)]
#[path = "AuthorityPolicyClientTests.rs"]
mod tests;
