// SPDX-License-Identifier: MIT
// A single companion actor serialises the requester floor and keeps network forwarding independent.
use super::*;
use crate::{
    authority_challenge::Session,
    authority_floor::Store,
    authority_inspection::{
        domain_client::{self, Cache, Request},
        stream_client,
    },
    authority_proof::Intent,
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
pub(super) struct Client {
    pub bootstrap: trust_bootstrap::Verified,
    pub store: Store,
    session: Session,
    pub key: SigningKey,
    pub clock: crate::authority_clock::Source,
    socket: PathBuf,
    preparation: Option<crate::authority_inspection::read_client::RetryBudget>,
}
impl Client {
    pub fn new(online: &Online) -> Result<Self> {
        let bootstrap = control::bootstrap(&online.location)?;
        let mut store = Store::open(&online.location.directory, bootstrap.descriptor().clone())?;
        let clock = control::clock(&online.location, store.descriptor().voters())?;
        let key = control::signer(&online.key)?;
        store.require_requester(key.verifying_key().to_bytes())?;
        let mut session = Session::new()?;
        stream_client::resolve_refusal_local(
            &store.descriptor().clone(),
            &online.socket,
            &key,
            &mut store,
            &mut session,
            || clock.health(),
        )?;
        Ok(Self {
            bootstrap,
            store,
            session,
            key,
            clock,
            socket: online.socket.clone(),
            preparation: None,
        })
    }
    pub fn grant(&self, value: &str) -> Result<VersionRef> {
        if value.contains(':') {
            reference(value, 102)
        } else {
            Cache::load(&self.bootstrap, &self.store)?.grant(&self.bootstrap, id(value)?)
        }
    }
    fn health(&self) -> Result<crate::authority_challenge::ClockHealth> {
        match &self.preparation {
            Some(budget) => budget.clock(|| self.clock.health()),
            None => self.clock.health(),
        }
    }
    pub fn execute(
        &mut self,
        grant: Option<VersionRef>,
        command: domain::Command,
    ) -> Result<domain_client::ResultState> {
        ensure!(
            !crate::private_route_client::cancelled(),
            "application agent is stopping"
        );
        if let Some(budget) = self.preparation.as_mut() {
            domain_client::local_with_read_budget(
                &self.bootstrap,
                Request { grant, command },
                &self.socket,
                &self.key,
                &mut self.store,
                &mut self.session,
                || self.clock.health(),
                budget,
            )
        } else {
            domain_client::local(
                &self.bootstrap,
                Request { grant, command },
                &self.socket,
                &self.key,
                &mut self.store,
                &mut self.session,
                || self.clock.health(),
            )
        }
    }
    pub fn stream(
        &mut self,
        grant: Option<VersionRef>,
        command: streams::Command,
    ) -> Result<domain_client::ResultState> {
        self.execute(grant, domain::Command::Stream(command))
    }
    pub fn register(
        &mut self,
        grant: VersionRef,
        registration: streams::Registration,
        renew: bool,
    ) -> Result<domain_client::ResultState> {
        let requests = registration_requests(grant, registration, renew);
        let pending = self.store.resume_ordinary()?;
        let start = registration_start(&requests, pending.as_ref().map(|p| p.signed()))?;
        let mut result = None;
        for Request { grant, command } in requests.into_iter().skip(start) {
            result = Some(self.execute(grant, command)?);
        }
        result.context("registration has no operation")
    }
    pub fn resume_agent(&mut self, targets: &[Target]) -> Result<()> {
        self.resume_agent_observed(targets, None)
    }
    fn resolve_refusal_status(&mut self) -> Result<()> {
        ensure!(
            !crate::private_route_client::cancelled(),
            "application agent is stopping"
        );
        if let Some(budget) = &self.preparation {
            budget.check()?;
        }
        stream_client::resolve_refusal_local_with_budget(
            &self.store.descriptor().clone(),
            &self.socket,
            &self.key,
            &mut self.store,
            &mut self.session,
            || match &self.preparation {
                Some(budget) => budget.clock(|| self.clock.health()),
                None => self.clock.health(),
            },
            self.preparation.as_ref().map(|budget| budget.transport()),
        )?;
        if let Some(budget) = &self.preparation {
            budget.check()?;
        }
        ensure!(
            !crate::private_route_client::cancelled(),
            "application agent is stopping"
        );
        Ok(())
    }
    fn recover_retained_refusal(&mut self, signed: &[u8], error: anyhow::Error) -> Result<()> {
        if !error.is::<domain_client::Refusal>() {
            return Err(error);
        }
        ensure!(
            self.store
                .resume_ordinary()?
                .is_some_and(|pending| pending.signed() == signed),
            "retained requester operation changed during recovery"
        );
        // A new disclosure refusal does not establish the original outcome. Only
        // authenticated own-stream status may complete this exact retained request.
        self.resolve_refusal_status()?;
        if self.store.resume_ordinary()?.is_none() {
            Ok(())
        } else {
            Err(error)
        }
    }
    fn resume_agent_observed(
        &mut self,
        targets: &[Target],
        timing: Option<&timing::Timing>,
    ) -> Result<()> {
        if let Some(timing) = timing {
            timing.event("Resume", "Begin");
        }
        let mut stage = timing::ResumeStage::RefusalStatus;
        let result = (|| {
            self.resolve_refusal_status()?;
            stage = timing::ResumeStage::RetainedOperation;
            if let Some(pending) = self.store.resume_ordinary()? {
                let intent = Intent::from_signed(pending.signed())?;
                ensure!(
                    intent.action == "AuthorityDomain",
                    "another exact requester operation needs resolution before starting the agent"
                );
                let operation = domain::Operation::parse(&intent)?;
                let allowed = match &operation.command {
                    domain::Command::Stream(c) => {
                        !c.mutation() || matches!(c, streams::Command::Close { .. })
                    }
                    domain::Command::Route(domain::routes::Command::Issue { id, .. }) => {
                        targets.iter().any(|t| {
                            crate::private_route_client::Endpoint::load(&t.route).is_ok_and(|e| {
                                domain::Record::parse(
                                    &e.route.voucher,
                                    e.route.network,
                                    e.route.incarnation,
                                )
                                .is_ok_and(|r| r.reference.id == *id)
                            })
                        })
                    }
                    domain::Command::Route(c) => !c.mutation(),
                    _ => false,
                };
                ensure!(
                    allowed,
                    "another exact mutation needs resolution before starting the agent"
                );
                if let Some(timing) = timing {
                    timing.event(operation.command.name(), "ResumeRetained");
                }
                if let Err(error) = self.execute(operation.grant, operation.command) {
                    self.recover_retained_refusal(pending.signed(), error)?;
                }
            }
            Ok(())
        })();
        if let Some(timing) = timing {
            match &result {
                Ok(()) => timing.event("Resume", "Complete"),
                Err(error) => timing.resume_failure(stage, error),
            }
        }
        result
    }
    fn endpoint(&mut self, target: &Target) -> Result<crate::private_route_client::Endpoint> {
        let mut endpoint = crate::private_route_client::Endpoint::load(&target.route)?;
        let scope = self.store.descriptor().scope();
        ensure!(
            endpoint.route.network == scope.network
                && endpoint.route.incarnation == scope.incarnation
                && endpoint.route.protocol == streams::PROTOCOL,
            "stream target route belongs to another network or protocol"
        );
        let mut record =
            domain::Record::parse(&endpoint.route.voucher, scope.network, scope.incarnation)?;
        let cached = Cache::load(&self.bootstrap, &self.store)?;
        if let Some(current) = cached.state.records.get(&(166, record.reference.id))
            && current.reference.generation > record.reference.generation
        {
            record = current.clone();
            endpoint.route.voucher = record.bytes.clone();
        }
        let voucher = domain::routes::Voucher::parse(&record.payload)?;
        let now = self.health()?.observe()?.wall_ms;
        if now >= voucher.expires {
            ensure!(
                target.renewal_ms > 0 && voucher.sponsor == self.key.verifying_key().to_bytes(),
                "expired voucher requires its sponsor to renew it"
            );
            let grant = if let Ok(current) =
                Cache::load(&self.bootstrap, &self.store)?.grant(&self.bootstrap, voucher.grant.id)
            {
                current
            } else {
                voucher.grant.clone()
            };
            let context = self.execute(
                Some(grant.clone()),
                domain::Command::Route(domain::routes::Command::RenewContext {
                    voucher: record.reference.clone(),
                }),
            )?;
            let current = context.cache.state.record(166, record.reference.id)?;
            let old = domain::routes::Voucher::parse(&current.payload)?;
            let baseline = old.baseline.unwrap_or((0, 0));
            let connections = old
                .connections
                .checked_sub(baseline.0)
                .context("voucher connection allowance differs from baseline")?;
            let bytes = old
                .bytes
                .checked_sub(baseline.1)
                .context("voucher byte allowance differs from baseline")?;
            let expires = now
                .checked_add(target.renewal_ms)
                .context("voucher expiry overflow")?;
            let result = self.execute(
                Some(grant),
                domain::Command::Route(domain::routes::Command::Issue {
                    id: record.reference.id,
                    relay: old.relay.id,
                    destination: old.destination.id,
                    possession: old.possession,
                    action: old.action,
                    scope: old.scope,
                    connections,
                    bytes,
                    expires,
                }),
            )?;
            record = result.cache.state.record(166, record.reference.id)?.clone();
            endpoint.route.voucher = record.bytes.clone();
        }
        endpoint.route.validate()?;
        // Only the private companion copy changes; endpoint identities and route limits remain pinned.
        let parent = files::private_directory(
            target
                .route
                .parent()
                .context("target route has no directory")?,
        )?;
        files::atomic_at(
            &parent,
            target
                .route
                .file_name()
                .context("target route has no name")?,
            &serde_json::to_vec(&endpoint)?,
            true,
        )?;
        Ok(endpoint)
    }
    pub fn plan(
        &mut self,
        target: &Target,
        used: &BTreeSet<(Digest, u64)>,
        start_slot: u64,
        budget: crate::authority_inspection::read_client::RetryBudget,
        targets: &[Target],
        timing: &timing::Timing,
    ) -> Result<Plan> {
        budget.check()?;
        self.preparation = Some(budget);
        let result = self
            .resume_agent_observed(targets, Some(timing))
            .and_then(|()| self.plan_inner(target, used, start_slot, timing))
            .and_then(|plan| {
                self.preparation
                    .as_ref()
                    .expect("preparation budget installed")
                    .check()?;
                Ok(plan)
            });
        self.preparation = None;
        result
    }
    fn plan_inner(
        &mut self,
        target: &Target,
        used: &BTreeSet<(Digest, u64)>,
        start_slot: u64,
        timing: &timing::Timing,
    ) -> Result<Plan> {
        let service = id(&target.service)?;
        let endpoint = timing.run("Endpoint", || self.endpoint(target))?;
        let grant = self.grant(&target.grant)?;
        select_slot(service, used, start_slot, |slot| {
            let result = timing.run("SlotLookup", || {
                self.stream(
                    Some(grant.clone()),
                    streams::Command::Lookup { service, slot },
                )
            })?;
            let r = result.cache.state.record(172, service)?;
            let registered = streams::Service::parse(
                &r.payload,
                endpoint.route.network,
                endpoint.route.incarnation,
            )?;
            ensure!(
                !registered.withdrawn
                    && registered.registration.protocol == target.protocol
                    && registered.registration.route.id == endpoint.route.destination.service,
                "target differs from certified application service"
            );
            let route_record = result
                .cache
                .state
                .record(165, registered.registration.route.id)?;
            ensure!(
                route_record.reference == registered.registration.route,
                "certified application endpoint generation differs"
            );
            let route_service = domain::routes::Service::parse(
                &route_record.payload,
                endpoint.route.network,
                endpoint.route.incarnation,
            )?;
            let slot_id = streams::slot_id(service, self.key.verifying_key().to_bytes(), slot)?;
            let now = self.health()?.observe()?.wall_ms;
            let generation = if let Some(old) = result.cache.state.records.get(&(173, slot_id)) {
                let old_session = streams::Session::parse(
                    &old.payload,
                    endpoint.route.network,
                    endpoint.route.incarnation,
                )?;
                if !old_session.retired && now < old_session.proof.expires {
                    return Ok(None);
                }
                old.reference
                    .generation
                    .checked_add(1)
                    .context("stream slot generation exhausted")?
            } else {
                1
            };
            let limits = crate::route_profile::Limits {
                bytes: registered
                    .registration
                    .limits
                    .bytes
                    .min(endpoint.route.limits.bytes),
                duration_ms: registered
                    .registration
                    .limits
                    .duration_ms
                    .min(endpoint.route.limits.duration_ms),
                idle_ms: registered
                    .registration
                    .limits
                    .idle_ms
                    .min(endpoint.route.limits.idle_ms),
            };
            let expires = now
                .checked_add(limits.duration_ms)
                .context("stream expiry overflow")?
                .min(registered.registration.validity.1);
            ensure!(
                expires > now.saturating_add(1250),
                "stream service is too close to expiry"
            );
            let proof = streams::Proof {
                service: r.reference.clone(),
                principal: self.key.verifying_key().to_bytes(),
                grant: grant.clone(),
                protocol: target.protocol.clone(),
                slot,
                generation,
                nonce: [1; 32],
                challenge: [1; 32],
                exporter: [1; 32],
                limits,
                expires,
                envelope: vec![],
            };
            let endpoint_provenance =
                (route_service.profile.identity == endpoint.route.destination).then(|| {
                    json!({
                        "source":"certifiedServiceLookup",
                        "service":hex::encode(route_record.reference.id),
                        "generation":route_record.reference.generation,
                        "recordDigest":hex::encode(route_record.reference.digest),
                        "profileDigest":hex::encode(wire::digest(&route_service.profile.envelope)),
                        "endpointMode":route_service.profile.mode,
                        "evaluatedAtMs":result.evaluated_at_ms,
                        "expiresAtMs":result.expires_at_ms,
                        "notAfterBootMs":result.deadline_boot_ms
                    })
                });
            Ok(Some(Plan {
                endpoint_provenance,
                proof,
                binding: registered.registration.binding,
                owner: registered.registration.owner,
                endpoint_key: route_service.profile.service,
                endpoint: endpoint.clone(),
                key: self.key.clone(),
            }))
        })
    }
    pub fn cleanup(
        &mut self,
        proof: &streams::Proof,
        deadline: u64,
        targets: &[Target],
    ) -> Result<()> {
        let budget = crate::authority_inspection::read_client::RetryBudget::new(deadline, || false);
        budget.check()?;
        self.preparation = Some(budget);
        let result = self.resume_agent(targets).and_then(|()| {
            self.preparation
                .as_ref()
                .expect("cleanup budget installed")
                .check()?;
            // No application admission was submitted before the proof was signed.
            // A signed proof can have an unknown outcome and still needs exact cleanup.
            if proof.envelope.is_empty() {
                Ok(())
            } else {
                self.close(proof)
            }
        });
        self.preparation = None;
        result
    }
    pub fn close(&mut self, proof: &streams::Proof) -> Result<()> {
        let result = self.stream(
            Some(proof.grant.clone()),
            streams::Command::Lookup {
                service: proof.service.id,
                slot: proof.slot,
            },
        )?;
        let Some(record) = result.cache.state.records.get(&(173, proof.id()?)) else {
            return Ok(());
        };
        let current = streams::Session::parse(
            &record.payload,
            self.store.descriptor().scope().network,
            self.store.descriptor().scope().incarnation,
        )?;
        if current.proof.generation == proof.generation
            && current.proof.nonce == proof.nonce
            && !current.closed
        {
            self.stream(
                None,
                streams::Command::Close {
                    session: record.reference.clone(),
                },
            )?;
        }
        Ok(())
    }
}
fn registration_requests(
    grant: VersionRef,
    registration: streams::Registration,
    renew: bool,
) -> Vec<Request> {
    let mut requests = Vec::new();
    if renew {
        // Disclose the owned record without requiring its old grant or route to remain live.
        requests.push(Request {
            grant: None,
            command: domain::Command::Stream(streams::Command::Lookup {
                service: registration.id,
                slot: 0,
            }),
        });
        requests.push(Request {
            grant: Some(grant.clone()),
            command: domain::Command::Route(domain::routes::Command::Context {
                action: streams::MANAGE,
                scope: (3, registration.id),
            }),
        });
    } else {
        requests.push(Request {
            grant: Some(grant.clone()),
            command: domain::Command::Stream(streams::Command::Context {
                service: registration.id,
                action: streams::MANAGE,
            }),
        });
    }
    requests.push(Request {
        grant: Some(grant.clone()),
        command: domain::Command::Route(domain::routes::Command::Lookup {
            service: registration.route.id,
        }),
    });
    requests.push(Request {
        grant: Some(grant),
        command: domain::Command::Stream(streams::Command::Register { registration }),
    });
    requests
}
fn registration_start(requests: &[Request], pending: Option<&[u8]>) -> Result<usize> {
    let Some(signed) = pending else {
        return Ok(0);
    };
    let intent = Intent::from_signed(signed)?;
    ensure!(
        intent.action == "AuthorityDomain",
        "another exact operation remains pending before registration"
    );
    let operation = domain::Operation::parse(&intent)?;
    requests
        .iter()
        .position(|request| {
            request.grant == operation.grant && request.command.value() == operation.command.value()
        })
        .context("another exact operation remains pending before registration")
}
// Ordering is local only: every unreserved candidate must complete a fresh lookup.
pub(super) fn select_slot<T>(
    service: Digest,
    used: &BTreeSet<(Digest, u64)>,
    start: u64,
    mut lookup: impl FnMut(u64) -> Result<Option<T>>,
) -> Result<T> {
    for offset in 0..streams::SLOTS {
        let slot = (start % streams::SLOTS + offset) % streams::SLOTS;
        if !used.contains(&(service, slot))
            && let Some(plan) = lookup(slot)?
        {
            return Ok(plan);
        }
    }
    anyhow::bail!(Capacity::Slots)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Target {
    pub service: String,
    pub protocol: String,
    pub grant: String,
    pub route: PathBuf,
    #[serde(default = "renewal_default")]
    pub renewal_ms: u64,
}
fn renewal_default() -> u64 {
    60000
}
pub(super) struct Plan {
    pub endpoint_provenance: Option<serde_json::Value>,
    pub proof: streams::Proof,
    pub binding: Digest,
    pub owner: Digest,
    pub endpoint_key: Digest,
    pub endpoint: crate::private_route_client::Endpoint,
    pub key: SigningKey,
}

#[cfg(test)]
#[path = "../../Tests/Unit/Applications/ApplicationStreamCleanupTests.rs"]
mod tests;

#[cfg(test)]
#[path = "../../Tests/Unit/Applications/ApplicationStreamRegistrationTests.rs"]
mod registration_tests;
