// SPDX-License-Identifier: MIT
// Local domain requests independently validate typed quorum results before retaining or exposing them.
use super::*;
use crate::{
    authority_domains::{self as domains, Command, Operation, State},
    authority_membership::Reservations,
};

const CACHE: &str = "DomainState.cbor";
const CACHE_LIMIT: usize = crate::authority_capacity::MAX_STATE_BYTES;

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
            return Ok(Self {
                state: State::empty(scope.network, scope.incarnation),
                records: vec![],
            });
        }
        let bytes = files::read_at(
            store.profile_directory(),
            OsStr::new(CACHE),
            CACHE_LIMIT,
            true,
        );
        let result = match bytes {
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
    store.retain_media_context(report)?;
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
            health,
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
        health: ClockHealth,
    ) -> Result<Self> {
        ensure!(
            bootstrap.fully_accepted()
                && bootstrap.descriptor().canonical() == store.initial_descriptor().canonical(),
            "domain bootstrap differs from retained floor"
        );
        store.require_requester(signer.verifying_key().to_bytes())?;
        ensure!(
            store.initial_descriptor().canonical() == bootstrap.descriptor().canonical(),
            "domain store belongs to another accepted bootstrap"
        );
        let descriptor = store.descriptor().clone();
        let now = health.observe()?;
        let scope = descriptor.scope();
        let intent = if let Some(pending) = store.resume_ordinary()? {
            request.pending(&Intent::from_signed(pending.signed())?)?;
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
            descriptor,
            bootstrap,
            request,
            prior: cache,
            objects,
            intent,
            challenge,
            ordered,
            deadline: now
                .boot_ms
                .checked_add(DURATION)
                .context("domain deadline overflow")?,
        })
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
    ) -> Result<ActionValidation> {
        if result.disposition == Disposition::Refuse {
            let value = wire::decode(&result.value)?;
            let f = record(&value, 201, 4)?;
            ensure!(
                f[2].text()? == "AuthorityDomain"
                    && f[3].array(0)?.is_empty()
                    && executed.maximum_effect == 0,
                "invalid domain refusal"
            );
            return ActionValidation::new(vec![]);
        }
        let candidate = self.candidate(intent, result, executed)?;
        ActionValidation::mutation(candidate.versions, candidate.updates)
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
            bail!("authority domain refused with code {code}");
        }
        let candidate = self.candidate(
            verified.request().ordinary()?,
            &verified.result,
            &verified.executed,
        )?;
        minimum(&candidate.versions, store.generations())?;
        let prefix = verified.point().prefix().clone();
        remaining(self.deadline)?;
        let permit = store.accept(verified, session, clock()?, 0)?;
        let deadline = self.deadline;
        let result = permit.perform(
            store,
            session,
            clock()?,
            1,
            |r| {
                ensure!(*r == Restrictions::default(), "domain restrictions changed");
                Ok(())
            },
            |_, store| {
                candidate.cache.save(store)?;
                remaining(deadline)?;
                Ok((
                    ResultState {
                        value: candidate.value,
                        prefix,
                        cache: candidate.cache,
                    },
                    outputs,
                ))
            },
        )?;
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
    let descriptor = store.descriptor().clone();
    stream_client::ensure_stream(&descriptor, path, signer, store, session, &mut clock)?;
    let cache = Cache::load(bootstrap, store)?;
    let prepared = Prepared::new_with_objects(
        bootstrap,
        request,
        cache,
        signer,
        store,
        session,
        inputs.objects().cloned().collect(),
        clock()?,
    )?;
    let challenge = prepared.challenge.clone();
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
        let (reply, evidence, outputs) = crate::authority_local_transport::exchange_objects(
            &descriptor,
            &prepared.ordered,
            &submission,
            prepared.deadline,
            path,
            store.prefix(),
            store.tree_head(),
            &mut clock,
            &mut |result| {
                let result = OperationResult::parse(result)?;
                domains::response_inputs(&intent, &wire::decode(&result.value)?)
            },
        )?;
        prepared.finish_with_objects(
            reply,
            AncestryEvidence::from_shared(evidence),
            outputs,
            store,
            session,
            &mut clock,
        )
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
#[path = "AuthorityPageClientTests.rs"]
mod page_tests;
