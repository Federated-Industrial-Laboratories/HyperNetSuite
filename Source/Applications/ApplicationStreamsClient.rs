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
    pub fn context(&mut self, grant: &VersionRef, service: Digest, action: u64) -> Result<()> {
        if self.store.resume_ordinary()?.is_none() {
            self.stream(
                Some(grant.clone()),
                streams::Command::Context { service, action },
            )?;
        }
        Ok(())
    }
    pub fn resume_agent(&mut self, targets: &[Target]) -> Result<()> {
        stream_client::resolve_refusal_local(
            &self.store.descriptor().clone(),
            &self.socket,
            &self.key,
            &mut self.store,
            &mut self.session,
            || match &self.preparation {
                Some(budget) => budget.clock(|| self.clock.health()),
                None => self.clock.health(),
            },
        )?;
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
            self.execute(operation.grant, operation.command)?;
        }
        Ok(())
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
        budget: crate::authority_inspection::read_client::RetryBudget,
        targets: &[Target],
    ) -> Result<Plan> {
        budget.check()?;
        self.preparation = Some(budget);
        let result = self
            .resume_agent(targets)
            .and_then(|()| self.plan_inner(target, used))
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
    fn plan_inner(&mut self, target: &Target, used: &BTreeSet<(Digest, u64)>) -> Result<Plan> {
        let service = id(&target.service)?;
        let endpoint = self.endpoint(target)?;
        let grant = self.grant(&target.grant)?;
        for slot in 0..streams::SLOTS {
            if used.contains(&(service, slot)) {
                continue;
            }
            let result = self.stream(
                Some(grant.clone()),
                streams::Command::Lookup { service, slot },
            )?;
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
                    continue;
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
            return Ok(Plan {
                proof,
                binding: registered.registration.binding,
                owner: registered.registration.owner,
                endpoint_key: route_service.profile.service,
                endpoint,
                key: self.key.clone(),
            });
        }
        anyhow::bail!("all application stream slots remain live")
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
    pub proof: streams::Proof,
    pub binding: Digest,
    pub owner: Digest,
    pub endpoint_key: Digest,
    pub endpoint: crate::private_route_client::Endpoint,
    pub key: SigningKey,
}
