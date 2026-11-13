// SPDX-License-Identifier: MIT
// Route administration and voucher renewal retain exact authority results before producing client material.
use crate::{
    authority_challenge::Session,
    authority_domains::{self as domain, routes},
    authority_floor::Store,
    authority_inspection::{
        domain_client::{self, Cache, Request},
        stream_client,
    },
    authority_inspection_cli::{
        self as control,
        domain_cli::{self, Online},
    },
    authority_proof::{Digest, VersionRef},
    transfer_files as files, trust_bootstrap, trust_wire as wire,
};
use anyhow::{Context as _, Result, ensure};
use clap::Subcommand;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::path::PathBuf;
#[path = "PrivateRouteAuthoring.rs"]
mod authoring;
#[path = "PrivateRouteRegistration.rs"]
mod registration;
#[derive(Subcommand)]
pub enum Command {
    /// Sign a route profile derived from an independently reviewed role5 deployment.
    Profile(authoring::Profile),
    /// Assemble an inert client route template from two exact signed profiles.
    Template(authoring::Template),
    /// Register exact service consent and its pinned relay transport.
    Register {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        grant: String,
        #[arg(long)]
        profile: PathBuf,
        /// Predict the exact record from certified context without registering it.
        #[arg(long, conflicts_with = "expected_record")]
        preview: bool,
        /// Refuse mutation unless its exact next record matches this reviewed ID:generation:digest.
        #[arg(long)]
        expected_record: Option<String>,
    },
    /// Fence only an expired registration from this exact retained certificate transaction.
    RecoverExpiredRegistration {
        #[command(flatten)]
        online: Online,
        /// Reviewed deployment ID:manifest RecordDigest pairs; at most eight.
        #[arg(long, required=true, num_args=1..=8)]
        candidate: Vec<String>,
        #[arg(long, requires = "route_profile")]
        accepted: Option<PathBuf>,
        #[arg(long, requires = "accepted")]
        route_profile: Option<PathBuf>,
    },
    /// Fetch the current registered service and its dependency closure.
    Lookup {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        grant: String,
        #[arg(long)]
        service: String,
    },
    /// Issue a finite voucher or renew its stable identifier after the old admission expires.
    Issue {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        grant: String,
        #[arg(long)]
        id: String,
        #[arg(long)]
        relay: String,
        #[arg(long)]
        destination: String,
        #[arg(long)]
        possession: String,
        #[arg(long, default_value_t = 0)]
        action: u64,
        #[arg(long, default_value_t = 0)]
        scope_kind: u64,
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        connections: u64,
        #[arg(long)]
        bytes: u64,
        #[arg(long)]
        expires_ms: u64,
        /// Exact authenticated TLS route template; the new voucher replaces its voucher field.
        #[arg(long)]
        route_template: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Fence only an expired interrupted Issue or Handover for this exact voucher identifier.
    RecoverExpiredIssue {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        id: String,
    },
    /// Register a pending candidate offer; this permits only its scoped join workflow.
    Invite {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        grant: String,
        #[arg(long)]
        offer: PathBuf,
    },
    /// Withdraw an exact registered service generation.
    Withdraw {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        service: String,
        #[arg(long)]
        generation: u64,
    },
}
fn id(value: &str) -> Result<Digest> {
    trust_bootstrap::hex32(value)
}
struct Client {
    bootstrap: trust_bootstrap::Verified,
    store: Store,
    session: Session,
    key: ed25519_dalek::SigningKey,
    clock: crate::authority_clock::Source,
    socket: PathBuf,
}
impl Client {
    fn open(online: &Online) -> Result<Self> {
        let bootstrap = control::bootstrap(&online.location)?;
        let store = Store::open(&online.location.directory, bootstrap.descriptor().clone())?;
        let clock = control::clock(&online.location, store.descriptor().voters())?;
        let key = domain_cli::signer(&online.key)?;
        store.require_requester(key.verifying_key().to_bytes())?;
        Ok(Self {
            bootstrap,
            store,
            session: Session::new()?,
            key,
            clock,
            socket: online.socket.clone(),
        })
    }
    fn new(online: &Online) -> Result<Self> {
        let mut client = Self::open(online)?;
        stream_client::resolve_refusal_local(
            &client.store.descriptor().clone(),
            &online.socket,
            &client.key,
            &mut client.store,
            &mut client.session,
            || client.clock.health(),
        )?;
        if let Some(pending) = client.store.resume_ordinary()? {
            let intent = crate::authority_proof::Intent::from_signed(pending.signed())?;
            if intent.action == "AuthorityDomain" {
                let operation = domain::Operation::parse(&intent)?;
                if let domain::Command::Route(command) = operation.command
                    && !command.mutation()
                {
                    client.execute(operation.grant, command)?;
                }
            }
        }
        Ok(client)
    }
    fn grant(&self, grant: &str) -> Result<VersionRef> {
        Cache::load(&self.bootstrap, &self.store)?.grant(&self.bootstrap, id(grant)?)
    }
    fn execute(
        &mut self,
        grant: Option<VersionRef>,
        command: routes::Command,
    ) -> Result<domain_client::ResultState> {
        let name = command.name();
        domain_client::local(
            &self.bootstrap,
            Request {
                command: domain::Command::Route(command),
                grant,
            },
            &self.socket,
            &self.key,
            &mut self.store,
            &mut self.session,
            || self.clock.health(),
        )
        .with_context(|| format!("{name} failed"))
    }
    fn context(&mut self, grant: &VersionRef, action: u64, scope: (u64, Digest)) -> Result<()> {
        if self.store.resume_ordinary()?.is_none() {
            self.execute(
                Some(grant.clone()),
                routes::Command::Context { action, scope },
            )?;
        }
        Ok(())
    }
}
fn issue_expiry(intent: &crate::authority_proof::Intent, identifier: Digest) -> Result<u64> {
    ensure!(
        intent.action == "AuthorityDomain",
        "pending request is not route issuance"
    );
    let (actual, expires) = match domain::Operation::parse(intent)?.command {
        domain::Command::Route(routes::Command::Issue { id, expires, .. }) => (id, expires),
        domain::Command::Route(routes::Command::Handover { voucher, expires }) => {
            (voucher.id, expires)
        }
        _ => anyhow::bail!(
            "pending request is not Issue or Handover; resume its exact normal command"
        ),
    };
    ensure!(
        actual == identifier && expires > 0,
        "pending route issuance has another identifier"
    );
    Ok(expires)
}
fn recovery_stream(
    intent: &crate::authority_proof::Intent,
    metadata: &crate::authority_proof::OwnStreamMetadata,
) -> Result<()> {
    let state = metadata
        .state()
        .context("requester has no admitted stream")?;
    ensure!(
        metadata.scope().network == intent.network
            && metadata.scope().incarnation == intent.incarnation
            && metadata.requester() == intent.requester
            && state.generation == intent.generation
            && state.generation_id == intent.generation_id,
        "expired issuance belongs to another current stream generation; retain its unresolved outcome"
    );
    Ok(())
}
fn recover_expired(online: &Online, identifier: &str) -> Result<()> {
    let identifier = id(identifier)?;
    let mut c = Client::open(online)?;
    let fencing = c.store.resume_fence()?.is_some();
    let pending = if fencing {
        c.store.fence_subject()?
    } else {
        c.store.resume_ordinary()?
    };
    let Some(pending) = pending else {
        ensure!(
            !fencing,
            "outstanding fence has no retained route issuance; resume the exact explicit fence"
        );
        return crate::print_value(
            &json!({"state":"RouteIssueRecovery","status":"NothingPending","id":hex::encode(identifier)}),
        );
    };
    let intent = crate::authority_proof::Intent::from_signed(pending.signed())?;
    let expires = issue_expiry(&intent, identifier)?;
    let now = c.clock.health()?.observe()?.wall_ms;
    if now < expires {
        return crate::print_value(
            &json!({"state":"RouteIssueRecovery","status":"Waiting","id":hex::encode(identifier),
            "pendingRequest":hex::encode(intent.digest),"expiresAtMs":expires}),
        );
    }
    let result = stream_client::fence_local_guarded(
        &c.store.descriptor().clone(),
        &c.socket,
        &c.key,
        &mut c.store,
        &mut c.session,
        || c.clock.health(),
        |metadata| recovery_stream(&intent, metadata),
    )?;
    let crate::authority_proof::StreamResponse::Fence { outcome, .. } = result else {
        anyhow::bail!("route recovery returned another stream control result");
    };
    let complete = c.store.resume_fence()?.is_none() && c.store.resume_ordinary()?.is_none();
    crate::print_value(
        &json!({"state":"RouteIssueRecovery","status":if complete {"Recovered"} else {"RecoveryPending"},
        "id":hex::encode(identifier),"pendingRequest":hex::encode(intent.digest),"expiresAtMs":expires,
        "outcome":format!("{outcome:?}"),"committedHeight":c.store.prefix().height()}),
    )
}
pub fn run(command: Command) -> Result<()> {
    let command = match command {
        Command::Profile(arguments) => return authoring::profile(arguments),
        Command::Template(arguments) => return authoring::template(arguments),
        Command::RecoverExpiredIssue { online, id } => return recover_expired(&online, &id),
        Command::RecoverExpiredRegistration {
            online,
            candidate,
            accepted,
            route_profile,
        } => {
            return registration::recover(
                &online,
                &candidate,
                accepted.as_deref(),
                route_profile.as_deref(),
            );
        }
        command => command,
    };
    let online = match &command {
        Command::Register { online, .. }
        | Command::Lookup { online, .. }
        | Command::Issue { online, .. }
        | Command::Invite { online, .. }
        | Command::Withdraw { online, .. } => online,
        Command::Profile(_)
        | Command::Template(_)
        | Command::RecoverExpiredIssue { .. }
        | Command::RecoverExpiredRegistration { .. } => {
            unreachable!("offline route command was handled")
        }
    };
    let mut c = Client::new(online)?;
    let mut issued = None;
    let result = match command {
        Command::Profile(_)
        | Command::Template(_)
        | Command::RecoverExpiredIssue { .. }
        | Command::RecoverExpiredRegistration { .. } => {
            unreachable!("offline route command was handled")
        }
        Command::Register {
            grant,
            profile,
            preview,
            expected_record,
            ..
        } => {
            let profile = routes::RegisteredProfile::parse(
                &files::read_single(&profile, wire::MAXIMUM, true)?,
                c.bootstrap.descriptor().scope().network,
                c.bootstrap.descriptor().scope().incarnation,
            )?;
            let grant = c.grant(&grant)?;
            if preview || expected_record.is_some() {
                return registration::run(&mut c, grant, profile, preview, expected_record);
            }
            c.context(&grant, 26, (5, profile.deployment))?;
            c.execute(
                Some(grant),
                routes::Command::Register {
                    profile: Box::new(profile),
                },
            )?
        }
        Command::Lookup { grant, service, .. } => {
            let grant = c.grant(&grant)?;
            c.execute(
                Some(grant),
                routes::Command::Lookup {
                    service: id(&service)?,
                },
            )?
        }
        Command::Invite { grant, offer, .. } => {
            let grant = c.grant(&grant)?;
            let offer = crate::authority_inspection::member_offer::Offer::parse(
                &c.bootstrap,
                &files::read_single(&offer, 8192, true)?,
                false,
            )?
            .envelope;
            if c.store.resume_ordinary()?.is_none() {
                c.execute(
                    Some(grant.clone()),
                    routes::Command::InviteContext {
                        offer: offer.clone(),
                    },
                )?;
            }
            c.execute(Some(grant), routes::Command::Invite { offer })?
        }
        Command::Withdraw {
            service,
            generation,
            ..
        } => {
            if c.store.resume_ordinary()?.is_none() {
                c.execute(
                    None,
                    routes::Command::Lookup {
                        service: id(&service)?,
                    },
                )?;
            }
            c.execute(
                None,
                routes::Command::Withdraw {
                    service: id(&service)?,
                    generation,
                },
            )?
        }
        Command::Issue {
            grant,
            id: identifier,
            relay,
            destination,
            possession,
            action,
            scope_kind,
            scope,
            connections,
            bytes,
            expires_ms,
            route_template,
            output,
            ..
        } => {
            let grant = c.grant(&grant)?;
            let scope = (
                scope_kind,
                scope
                    .as_deref()
                    .map(id)
                    .transpose()?
                    .unwrap_or(c.bootstrap.descriptor().scope().network),
            );
            c.context(&grant, action, scope)?;
            if c.store.resume_ordinary()?.is_none() {
                c.execute(
                    Some(grant.clone()),
                    routes::Command::Lookup {
                        service: id(&relay)?,
                    },
                )?;
                c.execute(
                    Some(grant.clone()),
                    routes::Command::Lookup {
                        service: id(&destination)?,
                    },
                )?;
            }
            if c.store.resume_ordinary()?.is_none() {
                let cache = Cache::load(&c.bootstrap, &c.store)?;
                let prior = cache.state.records.get(&(166, id(&identifier)?)).cloned();
                let prior = if prior.is_some() {
                    prior
                } else {
                    let template: crate::route_profile::Profile = serde_json::from_slice(
                        &files::read_single(&route_template, 600000, false)?,
                    )?;
                    domain::Record::parse(&template.voucher, template.network, template.incarnation)
                        .ok()
                        .filter(|r| {
                            r.reference.kind == 166
                                && r.reference.id == id(&identifier).unwrap_or([0; 32])
                        })
                };
                if let Some(previous) = prior {
                    c.execute(
                        Some(grant.clone()),
                        routes::Command::RenewContext {
                            voucher: previous.reference,
                        },
                    )?;
                }
            }
            let result = c.execute(
                Some(grant),
                routes::Command::Issue {
                    id: id(&identifier)?,
                    relay: id(&relay)?,
                    destination: id(&destination)?,
                    possession: id(&possession)?,
                    action,
                    scope,
                    connections,
                    bytes,
                    expires: expires_ms,
                },
            )?;
            let record = result.cache.state.record(166, id(&identifier)?)?;
            let mut template: crate::route_profile::Profile =
                serde_json::from_slice(&files::read_single(&route_template, 600000, false)?)?;
            ensure!(
                template.network == c.bootstrap.descriptor().scope().network
                    && template.incarnation == c.bootstrap.descriptor().scope().incarnation
                    && template.relay.service == id(&relay)?
                    && template.destination.service == id(&destination)?,
                "route template differs from issued voucher"
            );
            let registered_relay = routes::Service::parse(
                &result.cache.state.record(165, id(&relay)?)?.payload,
                template.network,
                template.incarnation,
            )?
            .profile;
            let registered_destination = routes::Service::parse(
                &result.cache.state.record(165, id(&destination)?)?.payload,
                template.network,
                template.incarnation,
            )?
            .profile;
            ensure!(
                template.relay == registered_relay.identity
                    && template.destination == registered_destination.identity
                    && Some(template.relay_address) == registered_relay.address
                    && template.relay_domain == registered_relay.domain
                    && template.domain == registered_destination.domain
                    && template.protocol == registered_destination.protocol
                    && template.assurance <= registered_relay.assurance
                    && template.limits.bytes
                        <= registered_relay
                            .limits
                            .bytes
                            .min(registered_destination.limits.bytes)
                    && template.limits.duration_ms
                        <= registered_relay
                            .limits
                            .duration_ms
                            .min(registered_destination.limits.duration_ms)
                    && template.limits.idle_ms
                        <= registered_relay
                            .limits
                            .idle_ms
                            .min(registered_destination.limits.idle_ms),
                "route template differs from current certified service identities or limits"
            );
            template.voucher = record.bytes.clone();
            template.validate()?;
            let bytes = serde_json::to_vec(&template)?;
            files::write_new(&output, &bytes)?;
            issued = Some(json!({"output":output,
                "routeDigest":hex::encode(Sha256::digest(&bytes))}));
            result
        }
    };
    crate::print_value(
        &json!({"state":"RouteAuthorityResult","certifiedHeight":result.prefix.height(),
            "result":control::diagnostic(result.value),"issuedRoute":issued}),
    )
}

#[cfg(test)]
#[path = "../../Tests/Unit/Routing/PrivateRouteRecoveryTests.rs"]
mod recovery_tests;
