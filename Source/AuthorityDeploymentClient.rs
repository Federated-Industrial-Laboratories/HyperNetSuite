// SPDX-License-Identifier: MIT
// Exact deployment consent uses the ordinary durable request stream and certified local floors.
use super::*;
use crate::{
    authority_deployment_records as records,
    authority_deployments::{Offer, Operation},
    authority_membership::{self as membership, Reservations},
    runtime_manifest::Manifest,
};
const CACHE_LIMIT: usize = 98304;
#[path = "AuthorityDeploymentCache.rs"]
mod cache;
pub use cache::Cache;
use cache::{merged, minimum, versions};

#[allow(
    clippy::large_enum_variant,
    reason = "Bounded records are processed individually without an additional allocation."
)]
pub enum Request {
    Context {
        grant: [u8; 32],
        deployment: [u8; 32],
    },
    Register {
        grant: VersionRef,
        offer: Offer,
    },
    Get {
        deployment: [u8; 32],
        grant: Option<[u8; 32]>,
    },
    Withdraw {
        admission: VersionRef,
        generation: u64,
    },
}
impl Request {
    pub fn action(&self) -> &'static str {
        match self {
            Self::Context { .. } => "AuthorityDeploymentContext",
            Self::Register { .. } => "AuthorityDeploymentRegister",
            Self::Get { .. } => "AuthorityDeploymentGet",
            Self::Withdraw { .. } => "AuthorityDeploymentWithdraw",
        }
    }
    fn resource(&self) -> [u8; 32] {
        match self {
            Self::Context { deployment, .. } | Self::Get { deployment, .. } => *deployment,
            Self::Register { offer, .. } => offer.manifest.deployment,
            Self::Withdraw { admission, .. } => admission.id,
        }
    }
    fn mutation(&self) -> bool {
        matches!(self, Self::Register { .. } | Self::Withdraw { .. })
    }
    fn grant(&self) -> Option<[u8; 32]> {
        match self {
            Self::Context { grant, .. } => Some(*grant),
            Self::Register { grant, .. } => Some(grant.id),
            Self::Get { grant, .. } => *grant,
            Self::Withdraw { .. } => None,
        }
    }
    fn parameters(
        &self,
        store: &Store,
        expected: &[VersionRef],
        selected: &[VersionRef],
    ) -> Result<Vec<u8>> {
        let point = a(vec![
            V::Uint(store.prefix().scope().epoch),
            V::Uint(store.prefix().height()),
            b(store.prefix().policy_state()),
        ]);
        let snapshot = a(vec![
            point.clone(),
            a(expected.iter().map(version_value).collect()),
        ]);
        let mut p = vec![V::Uint(200), V::Uint(1), V::Text(self.action().into())];
        // The signed point and retained local minima protect discovery without disclosing unrelated records.
        let minimum = a(store
            .generations()
            .iter()
            .filter(|r| {
                selected.iter().any(|s| s.index() == r.index())
                    || matches!(r.kind, 105 | 117 | 129 | 130) && r.id == self.resource()
            })
            .map(version_value)
            .collect());
        match self {
            Self::Context { grant, deployment } => {
                p.extend([b(grant), b(deployment), point, minimum])
            }
            Self::Register { grant, offer } => p.extend([
                version_value(grant),
                b(&offer.manifest_bytes),
                b(&offer.consent),
                offer.possessions_value(),
                snapshot,
            ]),
            Self::Get { deployment, grant } => {
                p.extend([b(deployment), grant.map_or(V::Null, |g| b(&g)), minimum])
            }
            Self::Withdraw {
                admission,
                generation,
            } => p.extend([version_value(admission), V::Uint(*generation), snapshot]),
        }
        wire::encode(&a(p))
    }
    fn matches_pending(&self, intent: &Intent) -> Result<()> {
        ensure!(
            intent.action == self.action()
                && intent.resource == self.resource()
                && intent.revision == u64::from(self.mutation())
                && intent.profile_generation == 0,
            "another exact request is pending; resume it or explicitly fence its generation"
        );
        let operation = Operation::parse(intent)?;
        let equal = match (self, operation) {
            (
                Self::Context { grant, deployment },
                Operation::Context {
                    grant: g,
                    deployment: d,
                    ..
                },
            ) => *grant == g && *deployment == d,
            (
                Self::Register { grant, offer },
                Operation::Register {
                    grant: g, offer: o, ..
                },
            ) => {
                *grant == g
                    && offer.manifest_bytes == o.manifest_bytes
                    && offer.consent == o.consent
                    && offer.possessions == o.possessions
            }
            (
                Self::Get { deployment, grant },
                Operation::Get {
                    deployment: d,
                    grant: g,
                    ..
                },
            ) => *deployment == d && *grant == g,
            (
                Self::Withdraw {
                    admission,
                    generation,
                },
                Operation::Withdraw {
                    admission: r,
                    generation: g,
                    ..
                },
            ) => *admission == r && *generation == g,
            _ => false,
        };
        ensure!(
            equal,
            "request differs from exact durable deployment intent"
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
    cache: Cache,
}
struct Prepared<'a> {
    bootstrap: &'a Verified,
    descriptor: TrustDescriptor,
    request: Request,
    source: Vec<Vec<u8>>,
    selected: Vec<Vec<u8>>,
    prior: Option<Cache>,
    intent: Vec<u8>,
    challenge: Vec<u8>,
    ordered: Vec<u8>,
    deadline: u64,
}
impl<'a> Prepared<'a> {
    fn new(
        bootstrap: &'a Verified,
        request: Request,
        context: Option<&Cache>,
        signer: &SigningKey,
        store: &mut Store,
        session: &mut Session,
        health: ClockHealth,
    ) -> Result<Self> {
        ensure!(
            bootstrap.fully_accepted()
                && bootstrap.descriptor().canonical() == store.initial_descriptor().canonical(),
            "deployment bootstrap differs from retained floor"
        );
        store.require_requester(signer.verifying_key().to_bytes())?;
        if let Some(c) = context {
            c.current(store)?;
            ensure!(
                c.deployment == request.resource() && c.grant == request.grant(),
                "deployment cache has another selection"
            );
        }
        ensure!(
            !matches!(request, Request::Register { .. } | Request::Withdraw { .. })
                || context.is_some(),
            "deployment mutation requires certified current context"
        );
        let selected = context.map_or_else(Vec::new, |c| c.entries.clone());
        let source = merged(bootstrap, &selected)?;
        let descriptor = store.descriptor().clone();
        let scope = descriptor.scope();
        let now = health.observe()?;
        let intent = if let Some(pending) = store.resume_ordinary()? {
            request.matches_pending(&Intent::from_signed(pending.signed())?)?;
            pending.signed().to_vec()
        } else {
            let selected_refs = versions(scope, &selected)?;
            let mut probe = Intent {
                network: scope.network,
                incarnation: scope.incarnation,
                generation: 1,
                generation_id: [1; 32],
                sequence: 1,
                acknowledged_through: 0,
                requester: store.requester(),
                action: request.action().into(),
                resource: request.resource(),
                revision: u64::from(request.mutation()),
                profile_generation: 0,
                minimum_policy_epoch: scope.epoch,
                minimum_policy_height: store.prefix().height(),
                expected: Vec::new(),
                parameters: request.parameters(store, &[], &selected_refs)?,
                digest: [1; 32],
            };
            if request.mutation() {
                let operation = Operation::parse(&probe)?;
                let decision = operation.prepare(
                    &source,
                    &Reservations(bootstrap.reservations().to_vec()),
                    &probe,
                    now.wall_ms,
                    false,
                    None,
                )?;
                ensure!(
                    decision.code == 0,
                    "deployment preflight refused with code {}",
                    decision.code
                );
                let created = operation
                    .derive(&probe)?
                    .iter()
                    .map(|v| records::reference(v))
                    .collect::<Result<Vec<_>>>()?;
                probe.expected = decision
                    .dependencies
                    .into_iter()
                    .filter(|r| !created.contains(r))
                    .collect();
                probe.parameters = request.parameters(store, &probe.expected, &selected_refs)?;
            }
            prepare_ordinary(
                &descriptor,
                signer,
                store,
                request.action(),
                request.resource(),
                u64::from(request.mutation()),
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
            selected,
            prior: context.cloned(),
            intent,
            challenge,
            ordered,
            deadline: now
                .boot_ms
                .checked_add(DURATION)
                .context("deployment deadline overflow")?,
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
            "deployment result differs from immutable request"
        );
        ensure!(
            executed.expires_at_ms
                <= challenge.evaluation_expiry(executed.evaluated_at_ms, executed.expires_at_ms)?,
            "deployment evaluation lies outside conservative challenge interval"
        );
        let value = wire::decode(&result.value)?;
        let f = value.array(match self.request {
            Request::Get { .. } => 9,
            Request::Register { .. } | Request::Withdraw { .. } => 6,
            Request::Context { .. } => 5,
        })?;
        ensure!(
            f[0].uint()? == 201 && f[1].uint()? == 1 && f[2].text()? == self.request.action(),
            "unexpected deployment result schema"
        );
        let scope = self.descriptor.scope();
        let refs = parse_versions(&f[3])?;
        let operation = Operation::parse(intent)?;
        let mut source = self.source.clone();
        let mut cache = Cache {
            scope: scope.clone(),
            deployment: self.request.resource(),
            grant: self.request.grant(),
            entries: self.selected.clone(),
            manifest: None,
            consent: None,
        };
        let mut replay = false;
        match &self.request {
            Request::Context { .. } => {
                cache.entries = f[4]
                    .list(64)?
                    .iter()
                    .map(|v| Ok(v.bytes()?.to_vec()))
                    .collect::<Result<_>>()?;
                ensure!(
                    versions(scope, &cache.entries)? == refs,
                    "deployment context records differ from certified references"
                );
                source = merged(self.bootstrap, &cache.entries)?;
            }
            Request::Get { .. } => {
                let (consent, _) = wire::envelope(f[6].bytes()?, 1)?;
                cache.grant = None;
                cache.entries = vec![f[4].bytes()?.to_vec(), f[5].bytes()?.to_vec(), consent];
                if f[8] != V::Null {
                    cache.entries.push(f[8].bytes()?.to_vec());
                }
                membership::sort_records(&mut cache.entries)?;
                cache.manifest = Some(f[7].bytes()?.to_vec());
                cache.consent = Some(f[6].bytes()?.to_vec());
                cache.provenance()?;
                let mut selected = self.selected.clone();
                // A fresh Get replaces this deployment's cached metadata, preserving selected capability records.
                selected.retain(|v| {
                    !records::reference(v).is_ok_and(|r| {
                        matches!(r.kind, 105 | 117 | 129 | 130) && r.id == self.request.resource()
                    })
                });
                selected.extend(cache.entries.clone());
                membership::sort_records(&mut selected)?;
                source = merged(self.bootstrap, &selected)?;
            }
            Request::Register { .. } | Request::Withdraw { .. } => {
                let created = operation.derive(intent)?;
                let actual = f[4]
                    .list(3)?
                    .iter()
                    .map(|v| Ok(v.bytes()?.to_vec()))
                    .collect::<Result<Vec<_>>>()?;
                ensure!(
                    actual == created,
                    "deployment result differs from exact derived records"
                );
                let snapshot_height = operation
                    .snapshot()
                    .context("deployment mutation lacks snapshot")?
                    .height;
                let creation_height = f[5].uint()?;
                ensure!(
                    creation_height > snapshot_height && creation_height <= executed.height,
                    "deployment creation height differs from its causal floor or execution"
                );
                let old = versions(scope, &source)?;
                let created_refs = created
                    .iter()
                    .map(|v| records::reference(v))
                    .collect::<Result<Vec<_>>>()?;
                let cached = created_refs.iter().all(|r| old.contains(r));
                replay = executed.height > creation_height;
                if replay && !cached {
                    source.extend(created.clone());
                    membership::sort_records(&mut source)?;
                }
                for bytes in created {
                    if !cache.entries.contains(&bytes) {
                        cache.entries.push(bytes);
                    }
                }
                membership::sort_records(&mut cache.entries)?;
                if let Request::Register { offer, .. } = &self.request {
                    cache.manifest = Some(offer.manifest_bytes.clone());
                    cache.consent = Some(offer.consent.clone());
                } else {
                    let prior = self.prior.as_ref().context("withdrawal cache is absent")?;
                    cache.manifest = prior.manifest.clone();
                    cache.consent = prior.consent.clone();
                }
            }
        }
        let retained = if matches!(self.request, Request::Get { .. }) {
            Some((
                cache.manifest.as_deref().unwrap(),
                cache.consent.as_deref().unwrap(),
            ))
        } else {
            None
        };
        let decision = operation.authorise(
            &source,
            &Reservations(self.bootstrap.reservations().to_vec()),
            intent,
            executed.evaluated_at_ms,
            replay,
            retained,
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
            "deployment result differs from exact authorized lifecycle"
        );
        Ok(Candidate {
            value,
            versions: refs,
            cache,
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
                "invalid deployment refusal"
            );
            return ActionValidation::new(vec![]);
        }
        ensure!(
            result.disposition == Disposition::Permit,
            "deployment operations have no pending result"
        );
        ActionValidation::new(self.candidate(intent, result, executed)?.versions)
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
            "deployment ancestry differs from control node"
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
            bail!("authority deployment refused with code {code}");
        }
        remaining(self.deadline)?;
        let candidate = self.candidate(
            verified.request().ordinary()?,
            &verified.result,
            &verified.executed,
        )?;
        minimum(
            &candidate.versions,
            store.generations(),
            self.request.grant().is_some(),
        )?;
        let prefix = verified.point().prefix().clone();
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
                    "deployment restrictions changed"
                );
                Ok(())
            },
            |_, store| {
                candidate.cache.save(store)?;
                if matches!(self.request, Request::Register { .. }) {
                    let mut state = candidate.cache.clone();
                    state.grant = None;
                    state.entries.retain(|v| {
                        records::reference(v).is_ok_and(|r| {
                            matches!(r.kind, 105 | 117 | 129 | 130) && r.id == state.deployment
                        })
                    });
                    state.provenance()?;
                    state.save(store)?;
                }
                Ok(ResultState {
                    value: candidate.value,
                    prefix,
                    cache: candidate.cache,
                })
            },
        )
    }
}
#[allow(
    clippy::too_many_arguments,
    reason = "Keep protocol inputs, state and validation callbacks explicit."
)]
pub fn local(
    bootstrap: &Verified,
    request: Request,
    context: Option<&Cache>,
    path: &Path,
    signer: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    mut clock: impl FnMut() -> Result<ClockHealth>,
) -> Result<ResultState> {
    // Mutations use the immediately preceding certified snapshot without ordering stream status between them.
    if !request.mutation() && context.is_none() {
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
        signer,
        store,
        session,
        clock()?,
    )?;
    let challenge = pending.challenge.clone();
    let result = (|| {
        let (reply, evidence) = application_client::exchange(
            &pending.descriptor,
            &pending.ordered,
            pending.deadline,
            &control,
            store,
            &mut clock,
        )?;
        pending.finish(reply, evidence, store, session, &mut clock)
    })();
    if result.is_err() {
        session.discard(&challenge)?;
    }
    result
}
#[cfg(test)]
#[path = "AuthorityDeploymentClientTests.rs"]
mod tests;

#[path = "AuthorityActivationClient.rs"]
pub(crate) mod activation_client;
