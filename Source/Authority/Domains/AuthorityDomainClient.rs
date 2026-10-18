// SPDX-License-Identifier: MIT
// Local domain requests independently validate typed quorum results before retaining or exposing them.
use super::*;
use crate::{
    authority_domains::{self as domains, Command, Operation, State},
    authority_membership::Reservations,
};

use crate::authority_inspection::policy;
const CACHE: &str = "DomainState.cbor";
const CACHE_LIMIT: usize = crate::authority_capacity::MAX_STATE_BYTES;
#[path = "AuthorityDomainReadClient.rs"]
mod fresh;

/// A refusal returned only after the authority response and ancestry are verified.
#[derive(Debug)]
pub(crate) struct Refusal {
    pub code: u64,
}
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "authority domain refused with code {}", self.code)
    }
}
impl std::error::Error for Refusal {}

#[derive(Clone)]
pub struct Cache {
    pub state: State,
    pub records: Vec<Vec<u8>>,
}
fn references(records: &[Vec<u8>], n: [u8; 32], i: [u8; 32]) -> Result<Vec<VersionRef>> {
    Governance::record_versions(n, i, records)
}
pub(super) fn merge(bootstrap: &Verified, records: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    domains::result::merge(bootstrap, records)
}
fn minimum(versions: &[VersionRef], floor: &[VersionRef]) -> Result<()> {
    domains::result::minimum(versions, floor)
}
impl Cache {
    /// A membership result can advance governance without changing domain metadata.
    pub(crate) fn retain_context(
        bootstrap: &Verified,
        store: &Store,
        context: &ContextState,
    ) -> Result<()> {
        let mut cache = Self::load(bootstrap, store)?;
        let scope = store.descriptor().scope();
        cache.records.clear();
        for bytes in context.current_records(store)? {
            let version = references(
                std::slice::from_ref(&bytes),
                scope.network,
                scope.incarnation,
            )?;
            if version.iter().all(|r| store.generations().contains(r)) {
                cache.records.push(bytes);
            }
        }
        cache.save(store)
    }

    pub fn load(bootstrap: &Verified, store: &Store) -> Result<Self> {
        ensure!(
            bootstrap.fully_accepted()
                && bootstrap.descriptor().canonical() == store.initial_descriptor().canonical(),
            "domain cache belongs to another independently accepted bootstrap"
        );
        let scope = store.descriptor().scope();
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let name = CString::new(CACHE)?;
        let present = unsafe {
            libc::fstatat(
                store.profile_directory().as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0;
        if !present {
            let error = std::io::Error::last_os_error();
            ensure!(
                error.raw_os_error() == Some(libc::ENOENT),
                "cannot inspect domain cache: {error}"
            );
            let mut records = vec![];
            crate::authority_inspection::policy::refresh_cached_policies(
                bootstrap,
                store,
                &mut records,
            )?;
            return Ok(Self {
                state: State::empty(scope.network, scope.incarnation),
                records,
            });
        }
        let bytes = files::read_at(
            store.profile_directory(),
            OsStr::new(CACHE),
            CACHE_LIMIT,
            true,
        );
        let mut result = match bytes {
            Ok(bytes) => {
                let value = wire::decode_state(&bytes)?;
                let f = value.array(5)?;
                ensure!(
                    f[0].uint()? == 200
                        && f[1].uint()? == 1
                        && f[2].text()? == "AuthorityDomainCache",
                    "invalid domain cache"
                );
                Self {
                    state: State::parse_context(&f[3], scope.network, scope.incarnation)?,
                    records: f[4]
                        .list(crate::authority_capacity::MAX_RECORDS)?
                        .iter()
                        .map(|v| Ok(v.bytes()?.to_vec()))
                        .collect::<Result<_>>()?,
                }
            }
            Err(error) => return Err(error),
        };
        crate::authority_inspection::policy::refresh_cached_policies(
            bootstrap,
            store,
            &mut result.records,
        )?;
        crate::authority_inspection::tier::refresh_cached_tiers(
            bootstrap,
            store,
            &mut result.records,
        )?;
        crate::authority_inspection::deployment_client::refresh_cached_deployments(
            bootstrap,
            store,
            &mut result.records,
        )?;
        let pending = store
            .resume_ordinary()?
            .map(|p| Intent::from_signed(p.signed()))
            .transpose()?;
        let mut refs = references(&result.records, scope.network, scope.incarnation)?;
        refs.extend(result.state.records.values().map(|r| r.reference.clone()));
        for r in refs {
            ensure!(
                store.generations().contains(&r)
                    || pending
                        .as_ref()
                        .is_some_and(|p| p.action == "AuthorityDomain" && p.expected.contains(&r)),
                "domain cache lacks retained quorum authentication"
            );
        }
        Ok(result)
    }
    pub fn grant(&self, bootstrap: &Verified, id: [u8; 32]) -> Result<VersionRef> {
        let scope = bootstrap.descriptor().scope();
        references(
            &merge(bootstrap, &self.records)?,
            scope.network,
            scope.incarnation,
        )?
        .into_iter()
        .find(|r| r.kind == 102 && r.id == id)
        .context("domain grant is not in retained context")
    }
    fn save(&self, store: &Store) -> Result<()> {
        let mut refs = references(&self.records, self.state.network, self.state.incarnation)?;
        refs.extend(self.state.records.values().map(|r| r.reference.clone()));
        ensure!(
            refs.iter().all(|r| store.generations().contains(r)),
            "domain cache precedes its durable quorum floor"
        );
        let bytes = wire::encode_state(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityDomainCache".into()),
            self.state.value(),
            a(self.records.iter().map(|r| b(r)).collect()),
        ]))?;
        ensure!(bytes.len() <= CACHE_LIMIT, "domain cache exceeds its bound");
        files::atomic_at(store.profile_directory(), OsStr::new(CACHE), &bytes, true)
    }
}

/// Retain exact certified serving metadata before the remote request can be acknowledged.
pub(crate) fn retain_media(
    bootstrap: &Verified,
    store: &mut Store,
    report: &domains::page::MediaReport,
) -> Result<()> {
    let prior = Cache::load(bootstrap, store)?;
    let result = report.result();
    let candidate = domains::result::verify(
        bootstrap,
        &prior.state,
        &prior.records,
        report.request(),
        &result.result,
        &result.executed,
        &[],
    )?;
    minimum(&candidate.versions, store.generations())?;
    policy::require_records_accepted(bootstrap, store, &candidate.records)?;
    store.establish_media_completion(report)?;
    store.retain_media_context(report)?;
    policy::retain_records(bootstrap, store, &candidate.records)?;
    Cache {
        state: candidate.state,
        records: candidate.records,
    }
    .save(store)
}

pub struct Request {
    pub command: Command,
    pub grant: Option<VersionRef>,
}
impl Request {
    fn operation(&self, store: &Store, expected: &[VersionRef]) -> Result<Operation> {
        let value = a(vec![
            a(vec![
                V::Uint(store.prefix().scope().epoch),
                V::Uint(store.prefix().height()),
                b(store.prefix().policy_state()),
            ]),
            a(expected.iter().map(version_value).collect()),
        ]);
        Ok(Operation {
            grant: self.grant.clone(),
            command: self.command.clone(),
            snapshot: domains::snapshot(&value)?,
        })
    }
    fn pending(&self, intent: &Intent) -> Result<()> {
        let operation = Operation::parse(intent)?;
        ensure!(
            operation.grant == self.grant && operation.command.value() == self.command.value(),
            "another exact domain request is pending; resume it or explicitly fence its generation"
        );
        Ok(())
    }
}
pub struct ResultState {
    pub value: V,
    pub prefix: Prefix,
    pub cache: Cache,
    pub(crate) evaluated_at_ms: u64,
    pub(crate) expires_at_ms: u64,
    pub(crate) deadline_boot_ms: u64,
    pub(crate) receipt: Vec<u8>,
}
struct Candidate {
    value: V,
    versions: Vec<VersionRef>,
    updates: Vec<(VersionRef, VersionRef)>,
    cache: Cache,
}
struct Prepared<'a> {
    descriptor: TrustDescriptor,
    bootstrap: &'a Verified,
    request: Request,
    prior: Cache,
    intent: Vec<u8>,
    challenge: Vec<u8>,
    ordered: Vec<u8>,
    deadline: u64,
    objects: Vec<crate::authority_objects::Object>,
}
fn evaluation_inputs(
    command: &Command,
    state: &State,
    objects: &[crate::authority_objects::Object],
) -> Result<crate::authority_objects::Resolved> {
    domains::result::inputs(command, state, objects)
}
pub(crate) fn restrictive(command: &Command) -> bool {
    matches!(
        command.name(),
        "PageWithdraw"
            | "PageHostWithdraw"
            | "SealedPublicationWithdraw"
            | "SealedIdentityRevoke"
            | "BackupWithdraw"
            | "BackupWithdrawDestination"
            | "MailServiceWithdraw"
            | "TransferServiceWithdraw"
            | "TransferCancel"
            | "SshServiceWithdraw"
            | "SshRevoke"
            | "RouteWithdraw"
            | "FederationTrustWithdraw"
            | "FederationWithdraw"
            | "FederationBridgeWithdraw"
            | "FederationPageWithdraw"
    ) || matches!(
        command,
        Command::Page(domains::page::Command::Content(
            domains::page::content::Command::Authorise {
                effect: domains::page::content::Effect::Purge,
                ..
            }
        ))
    )
}
fn policy_exempt(request: &Request) -> bool {
    if restrictive(&request.command) {
        return true;
    }
    if request.grant.is_some() {
        return false;
    }
    // These finite metadata commands independently prove existing ownership. They
    // remain usable to inspect or withdraw resources after discretionary rights end.
    matches!(
        &request.command,
        Command::Backup(
            domains::backup::Command::Destination { .. }
                | domains::backup::Command::Destinations { .. }
                | domains::backup::Command::Get { .. }
                | domains::backup::Command::List { .. }
        ) | Command::Page(domains::page::Command::HostGet { .. })
            | Command::Ssh(
                domains::ssh::Command::Service { .. } | domains::ssh::Command::Grant { .. }
            )
            | Command::Transfer(
                domains::transfer::Command::Service { .. } | domains::transfer::Command::Get { .. }
            )
            | Command::Mail(
                domains::mail::Command::Service { .. }
                    | domains::mail::Command::Get { source: None, .. }
                    | domains::mail::Command::ClaimGet { .. }
            )
            | Command::Federation(
                domains::federation::Command::TrustGet { .. }
                    | domains::federation::Command::Get { .. }
                    | domains::federation::Command::BridgeGet { .. }
            )
    )
}
fn signed_snapshot(command: &Command) -> bool {
    match command {
        Command::SealedIdentity(command) => command.mutation(),
        Command::SealedPublication(
            domains::sealed_publication::Command::Policy { .. }
            | domains::sealed_publication::Command::Stage { .. },
        ) => true,
        _ => false,
    }
}
fn refreshable_page_query(command: &Command) -> bool {
    use domains::page::{Command as Page, content::Command as Content};
    !command.mutation()
        && !command.serving()
        && matches!(
            command,
            Command::Page(
                Page::Context { .. }
                    | Page::Read { .. }
                    | Page::View { .. }
                    | Page::List { .. }
                    | Page::SearchList { .. }
                    | Page::LocalSearchLease { .. }
                    | Page::Content(Content::Get { .. })
            )
        )
}
impl<'a> Prepared<'a> {
    #[cfg(test)]
    fn new(
        bootstrap: &'a Verified,
        request: Request,
        cache: Cache,
        signer: &SigningKey,
        store: &mut Store,
        session: &mut Session,
        health: ClockHealth,
    ) -> Result<Self> {
        Self::new_with_objects(
            bootstrap,
            request,
            cache,
            signer,
            store,
            session,
            vec![],
            &mut || Ok(health),
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn new_with_objects(
        bootstrap: &'a Verified,
        request: Request,
        cache: Cache,
        signer: &SigningKey,
        store: &mut Store,
        session: &mut Session,
        objects: Vec<crate::authority_objects::Object>,
        clock: &mut impl FnMut() -> Result<ClockHealth>,
    ) -> Result<Self> {
        ensure!(
            bootstrap.fully_accepted()
                && bootstrap.descriptor().canonical() == store.initial_descriptor().canonical(),
            "domain bootstrap differs from retained floor"
        );
        if !policy_exempt(&request) {
            policy::require_accepted(bootstrap, store)?;
        }
        store.require_requester(signer.verifying_key().to_bytes())?;
        ensure!(
            store.initial_descriptor().canonical() == bootstrap.descriptor().canonical(),
            "domain store belongs to another accepted bootstrap"
        );
        let descriptor = store.descriptor().clone();
        let now = clock()
            .context("domain preflight clock unavailable")?
            .observe()
            .context("domain preflight clock invalid")?;
        let scope = descriptor.scope();
        let intent = if let Some(pending) = store.resume_ordinary()? {
            let intent = Intent::from_signed(pending.signed())?;
            request.pending(&intent)?;
            if !policy_exempt(&request) {
                policy::require_pending_policy(bootstrap, store, &intent)?;
            }
            pending.signed().to_vec()
        } else {
            let source = merge(bootstrap, &cache.records)?;
            let mut probe = Intent {
                network: scope.network,
                incarnation: scope.incarnation,
                generation: 1,
                generation_id: [1; 32],
                sequence: 1,
                acknowledged_through: 0,
                requester: store.requester(),
                action: "AuthorityDomain".into(),
                resource: request.command.resource(),
                revision: u64::from(request.command.mutation()),
                profile_generation: 0,
                minimum_policy_epoch: scope.epoch,
                minimum_policy_height: store.prefix().height(),
                expected: vec![],
                parameters: request.operation(store, &[])?.parameters()?,
                digest: [1; 32],
            };
            if request.command.mutation() {
                let inputs = evaluation_inputs(&request.command, &cache.state, &objects)?;
                let d = Operation::parse(&probe)?.prepare_with_inputs(
                    &cache.state,
                    &source,
                    &Reservations(bootstrap.reservations().to_vec()),
                    &probe,
                    now.wall_ms,
                    false,
                    false,
                    &inputs,
                )?;
                ensure!(
                    d.code == 0,
                    "domain preflight refused with code {}; refresh the relevant current context",
                    d.code
                );
                probe.expected = d.dependencies;
                probe.parameters = request.operation(store, &probe.expected)?.parameters()?;
            } else if !policy_exempt(&request) {
                probe.expected = vec![policy::current_reference(bootstrap, store)?];
                probe.parameters = request.operation(store, &probe.expected)?.parameters()?;
            }
            if !policy_exempt(&request) {
                policy::require_pending_policy(bootstrap, store, &probe)?;
            }
            prepare_ordinary(
                &descriptor,
                signer,
                store,
                "AuthorityDomain",
                request.command.resource(),
                probe.revision,
                &probe.expected,
                &probe.parameters,
            )?
        };
        // Persisting the immutable request can outlive a clock witness. A new challenge
        // starts only after that work, with a current observation and its own fixed deadline.
        let health = clock().context("domain challenge clock unavailable")?;
        let issued = health.observe().context("domain challenge clock invalid")?;
        let challenge = session
            .issue(&intent, signer, random_id()?, DURATION, health)
            .context("domain challenge issuance failed")?;
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
            descriptor,
            bootstrap,
            request,
            prior: cache,
            objects,
            intent,
            challenge,
            ordered,
            deadline: issued
                .boot_ms
                .checked_add(DURATION)
                .context("domain deadline overflow")?,
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn exchange_with_recovery<T, C: FnMut() -> Result<ClockHealth>>(
        &mut self,
        control: LocalControl,
        store: &Store,
        signer: &SigningKey,
        session: &mut Session,
        clock: &mut C,
        mut prepare: impl FnMut() -> Result<LocalControl>,
        exchange: &mut impl FnMut(&Self, &mut C, &LocalControl) -> Result<T>,
    ) -> Result<(T, LocalControl)> {
        let mut initial = Some(control);
        crate::authority_local_transport::retry_expired_exchange(|| {
            let control = if let Some(control) = initial.take() {
                control
            } else {
                ensure!(
                    store
                        .resume_ordinary()?
                        .is_some_and(|p| p.signed() == self.intent),
                    "expired exchange lost its exact pending intent"
                );
                session.discard(&self.challenge)?;
                let control = prepare()?;
                let health = clock()?;
                let issued = health.observe()?;
                self.challenge =
                    session.issue(&self.intent, signer, random_id()?, DURATION, health)?;
                let parsed = Challenge::from_signed(&self.challenge)?;
                self.ordered = wire::encode(&a(vec![
                    V::Uint(22),
                    V::Uint(1),
                    self.descriptor.scope().value(),
                    b(&self.intent),
                    b(&self.challenge),
                    V::Uint(parsed.expires_at_ms),
                ]))?;
                self.deadline = issued
                    .boot_ms
                    .checked_add(DURATION)
                    .context("domain deadline overflow")?;
                control
            };
            let result =
                self.exchange_with_history(signer, session, clock, &mut |attempt, clock| {
                    exchange(attempt, clock, &control)
                });
            Ok((self.deadline, result.map(|value| (value, control))))
        })
    }
    fn exchange_with_history<T, C: FnMut() -> Result<ClockHealth>>(
        &mut self,
        signer: &SigningKey,
        session: &mut Session,
        clock: &mut C,
        exchange: &mut impl FnMut(&Self, &mut C) -> Result<T>,
    ) -> Result<T> {
        loop {
            match exchange(self, clock) {
                Ok(result) => return Ok(result),
                Err(error) => {
                    if !error.is::<crate::authority_local_transport::HistoryOvertaken>()
                        || !refreshable_page_query(&self.request.command)
                    {
                        return Err(error);
                    }
                    // No result was accepted. Only these read-only queries may request
                    // another evaluation of the exact intent on the existing connection.
                    session.discard(&self.challenge)?;
                    let health = clock().context("domain history refresh clock unavailable")?;
                    let duration = self
                        .deadline
                        .checked_sub(health.observe()?.boot_ms)
                        .filter(|remaining| *remaining > 0)
                        .ok_or(crate::authority_local_transport::RequestDeadlineExpired {
                            deadline: self.deadline,
                        })
                        .context("original domain query deadline expired")?;
                    self.challenge = session
                        .issue(&self.intent, signer, random_id()?, duration, health)
                        .context("domain history refresh challenge issuance failed")?;
                    let parsed = Challenge::from_signed(&self.challenge)?;
                    self.ordered = wire::encode(&a(vec![
                        V::Uint(22),
                        V::Uint(1),
                        self.descriptor.scope().value(),
                        b(&self.intent),
                        b(&self.challenge),
                        V::Uint(parsed.expires_at_ms),
                    ]))?;
                }
            }
        }
    }
    fn candidate(
        &self,
        intent: &Intent,
        result: &OperationResult,
        executed: &ExecutedResult,
    ) -> Result<Candidate> {
        ensure!(
            Intent::from_signed(&self.intent)?.digest == intent.digest,
            "domain result does not bind its exact pending request"
        );
        let candidate = domains::result::verify(
            self.bootstrap,
            &self.prior.state,
            &self.prior.records,
            intent,
            result,
            executed,
            &self.objects,
        )?;
        Ok(Candidate {
            value: candidate.value,
            versions: candidate.versions,
            updates: candidate.updates,
            cache: Cache {
                state: candidate.state,
                records: candidate.records,
            },
        })
    }
    fn validate(
        &self,
        intent: &Intent,
        result: &OperationResult,
        executed: &ExecutedResult,
    ) -> Result<(ActionValidation, Option<Candidate>)> {
        if result.disposition == Disposition::Refuse {
            let value = wire::decode(&result.value)?;
            let f = record(&value, 201, 4)?;
            ensure!(
                f[2].text()? == "AuthorityDomain"
                    && f[3].array(0)?.is_empty()
                    && executed.maximum_effect == 0,
                "invalid domain refusal"
            );
            return Ok((ActionValidation::new(vec![])?, None));
        }
        let candidate = self.candidate(intent, result, executed)?;
        let validation =
            ActionValidation::mutation(candidate.versions.clone(), candidate.updates.clone())?;
        Ok((validation, Some(candidate)))
    }
    #[cfg(test)]
    fn finish(
        self,
        reply: CertifiedReply,
        evidence: AncestryEvidence,
        store: &mut Store,
        session: &mut Session,
        clock: &mut impl FnMut() -> Result<ClockHealth>,
    ) -> Result<ResultState> {
        Ok(self
            .finish_with_objects(
                reply,
                evidence,
                crate::authority_objects::Resolved::default(),
                store,
                session,
                clock,
            )?
            .0)
    }
    fn finish_with_objects(
        mut self,
        reply: CertifiedReply,
        evidence: AncestryEvidence,
        outputs: crate::authority_objects::Resolved,
        store: &mut Store,
        session: &mut Session,
        clock: &mut impl FnMut() -> Result<ClockHealth>,
    ) -> Result<(ResultState, crate::authority_objects::Resolved)> {
        let result = OperationResult::parse(&reply.result)?;
        let intent = Intent::from_signed(&self.intent)?;
        let expected = if result.disposition == Disposition::Permit {
            domains::response_inputs(&intent, &wire::decode(&result.value)?)?
        } else {
            vec![]
        };
        ensure!(
            outputs.references() == expected,
            "domain output closure differs"
        );
        for object in outputs.objects() {
            if let Some(old) = self
                .objects
                .iter()
                .find(|o| o.reference() == object.reference())
            {
                ensure!(
                    old.bytes() == object.bytes(),
                    "domain input/output bytes conflict"
                );
            } else {
                self.objects.push(object.clone());
            }
        }
        remaining(self.deadline)?;
        ensure!(
            evidence.nodes.last().is_some_and(|v| *v == reply.node),
            "domain ancestry differs from certified node"
        );
        let mut candidate = None;
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
            |i, r, e| {
                let (validation, validated) = self.validate(i, r, e)?;
                candidate = validated;
                Ok(validation)
            },
        )?;
        let verified = evidence.attach(store, verified)?;
        if verified.disposition() != Disposition::Permit {
            let code = verified.code();
            store.observe(verified)?;
            session.discard(&self.challenge)?;
            return Err(Refusal { code }.into());
        }
        let candidate = candidate.context("permitted domain result lacks validated candidate")?;
        minimum(&candidate.versions, store.generations())?;
        if !policy_exempt(&self.request) {
            policy::require_records_accepted(self.bootstrap, store, &candidate.cache.records)?;
        }
        let prefix = verified.point().prefix().clone();
        let evaluated_at_ms = verified.executed.evaluated_at_ms;
        let expires_at_ms = verified.executed.expires_at_ms;
        remaining(self.deadline)?;
        let permit = store
            .accept(
                verified,
                session,
                clock().context("domain acceptance clock unavailable")?,
                0,
            )
            .context("domain durable authority acceptance failed")?;
        let deadline = self.deadline;
        let receipt = wire::encode(&a(vec![
            V::Uint(201),
            V::Uint(1),
            V::Text("AuthorityDomainReceipt".into()),
            b(&self.intent),
            b(&self.challenge),
            b(&self.ordered),
            b(&reply.result),
            b(&reply.certificate),
            b(&reply.node),
        ]))?;
        let result = permit
            .perform(
                store,
                session,
                clock().context("domain result publication clock unavailable")?,
                1,
                |r| {
                    ensure!(*r == Restrictions::default(), "domain restrictions changed");
                    Ok(())
                },
                |_, store| {
                    candidate.cache.save(store)?;
                    policy::retain_records(self.bootstrap, store, &candidate.cache.records)?;
                    remaining(deadline)?;
                    Ok((
                        ResultState {
                            value: candidate.value,
                            prefix,
                            cache: candidate.cache,
                            evaluated_at_ms,
                            expires_at_ms,
                            deadline_boot_ms: deadline,
                            receipt,
                        },
                        outputs,
                    ))
                },
            )
            .context("domain durable result publication failed")?;
        remaining(deadline)?;
        Ok(result)
    }
}
pub fn local(
    bootstrap: &Verified,
    request: Request,
    path: &Path,
    signer: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    clock: impl FnMut() -> Result<ClockHealth>,
) -> Result<ResultState> {
    Ok(local_with_objects(
        bootstrap,
        request,
        path,
        signer,
        store,
        session,
        crate::authority_objects::Resolved::default(),
        clock,
    )?
    .0)
}
#[allow(
    clippy::too_many_arguments,
    reason = "Keep protocol inputs, state and validation callbacks explicit."
)]
pub fn local_with_objects(
    bootstrap: &Verified,
    request: Request,
    path: &Path,
    signer: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    inputs: crate::authority_objects::Resolved,
    mut clock: impl FnMut() -> Result<ClockHealth>,
) -> Result<(ResultState, crate::authority_objects::Resolved)> {
    ensure!(
        !request.command.serving(),
        "serving effects require the selected recipient exchange"
    );
    if fresh::handles(&request.command) {
        ensure!(
            inputs.objects().next().is_none(),
            "fresh read carries unexpected objects"
        );
        return Ok((
            fresh::local(bootstrap, request, path, signer, store, session, &mut clock)?,
            crate::authority_objects::Resolved::default(),
        ));
    }
    let descriptor = store.descriptor().clone();
    stream_client::ensure_stream(&descriptor, path, signer, store, session, &mut clock)?;
    // These owner-signed records already bind a Context/Directory/Prepare reply.
    // A discovery between that reply and submission would invalidate its exact pre-state.
    if !policy_exempt(&request) && !signed_snapshot(&request.command) {
        policy::refresh_before_request(bootstrap, path, signer, store, session, &mut clock)?;
    }
    let cache = Cache::load(bootstrap, store)?;
    let control = crate::authority_local_transport::LocalControl::prepare_authority(path, store)?;
    let mut prepared = Prepared::new_with_objects(
        bootstrap,
        request,
        cache,
        signer,
        store,
        session,
        inputs.objects().cloned().collect(),
        &mut clock,
    )
    .context("domain request preparation failed")?;
    let mut challenge = prepared.challenge.clone();
    let result = (|| {
        let intent = Intent::from_signed(&prepared.intent)?;
        let command_refs = prepared.request.command.command_inputs();
        let submission = crate::authority_objects::Resolved::exact(
            &command_refs,
            prepared
                .objects
                .iter()
                .filter(|o| command_refs.contains(o.reference()))
                .cloned()
                .collect(),
        )?;
        let exchange = prepared.exchange_with_recovery(
            control,
            store,
            signer,
            session,
            &mut clock,
            || LocalControl::prepare_authority(path, store),
            &mut |attempt, clock, control| {
                crate::authority_local_transport::exchange_objects(
                    &descriptor,
                    &attempt.ordered,
                    &submission,
                    attempt.deadline,
                    control,
                    store.prefix(),
                    store.tree_head(),
                    clock,
                    &mut |result| {
                        let result = OperationResult::parse(result)?;
                        domains::response_inputs(&intent, &wire::decode(&result.value)?)
                    },
                )
            },
        );
        challenge = prepared.challenge.clone();
        let ((reply, evidence, outputs), control) = exchange?;
        let result = prepared.finish_with_objects(
            reply,
            AncestryEvidence::from_shared(evidence),
            outputs,
            store,
            session,
            &mut clock,
        )?;
        control.retain(store);
        Ok(result)
    })();
    if result.is_err() {
        session.discard(&challenge)?;
    }
    result
}

#[cfg(test)]
#[path = "AuthorityDomainClientTests.rs"]
mod tests;

#[cfg(test)]
#[path = "../../Pages/AuthorityPageClientTests.rs"]
mod page_tests;
