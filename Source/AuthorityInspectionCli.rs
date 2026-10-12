// SPDX-License-Identifier: MIT
// An operator authenticates bootstrap independently before accepting a local quorum floor.
use crate::{
    authority_challenge::Session,
    authority_clock,
    authority_floor::Store,
    authority_inspection::{ContextState, Request, RevokeRequest},
    transfer_files as files, trust_bootstrap,
    trust_wire::{self, Value},
};
use anyhow::{Result, ensure};
use clap::{Args, Subcommand};
use ed25519_dalek::SigningKey;
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[derive(Clone, Args)]
pub struct Location {
    #[arg(long)]
    bootstrap: PathBuf,
    /// SHA256 of the complete bootstrap, verified through an independent channel.
    #[arg(long)]
    bootstrap_digest: String,
    #[arg(long)]
    pub(crate) directory: PathBuf,
    /// Private JSON observation, or signed ClockHealth.cbor with both monitor pins.
    #[arg(long)]
    clock_witness: PathBuf,
    /// Independently pinned Ed25519 public key for the host clock monitor.
    #[arg(long, requires = "host_kernel_boot")]
    clock_monitor_key: Option<String>,
    /// Independently pinned current host kernel boot identifier.
    #[arg(long, requires = "clock_monitor_key")]
    host_kernel_boot: Option<String>,
}
impl Location {
    pub(crate) fn with_directory(&self, directory: PathBuf) -> Self {
        Self {
            directory,
            ..self.clone()
        }
    }
}
#[derive(Subcommand)]
pub enum Command {
    /// Manage recipient roots, devices, contact trust and publication audiences.
    Recipients {
        #[command(subcommand)]
        command: sealed_cli::Command,
    },
    /// Nominate a fresh committee, collect its quorums and adopt its exact successor.
    Epoch {
        #[command(subcommand)]
        command: epoch_cli::Command,
    },
    /// Manage registered SSH services and exact session requests.
    Ssh {
        #[command(subcommand)]
        command: domain_cli::Command,
    },
    /// Prepare consent, register exact services, inspect ownership and publish withdrawal.
    Deployments {
        #[command(subcommand)]
        command: deployment_cli::Command,
    },
    /// Create a new operator trust floor without opening a network connection.
    Initialise {
        #[command(flatten)]
        location: Location,
        /// Ed25519 public key permanently bound to this request tracker.
        #[arg(long)]
        requester: String,
    },
    /// Inspect this requester's stream without authorising a domain operation.
    StreamStatus {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        socket: PathBuf,
    },
    /// Close the previous stream generation; unresolved effects remain uncertain.
    StreamFence {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        socket: PathBuf,
    },
    /// Refresh the complete certified governance context through the private local socket.
    Context {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        grant: String,
        /// Discard incomplete pages after resolving or explicitly fencing the pending request.
        #[arg(long)]
        restart_discovery: bool,
    },
    /// Permanently revoke an exact grant against the retained committed state.
    RevokeGrant {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        grant: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        target_generation: u64,
        #[arg(long)]
        target_digest: String,
    },
    /// Create one explicitly attenuated grant; this does not admit its subject.
    DelegateGrant(member_cli::Delegate),
    /// Write an immutable offline invitation containing one exact reader grant.
    InviteMember(member_cli::Invite),
    /// Sign the exact invitation after authenticating its inviter independently.
    AcceptMember(member_cli::Accept),
    /// Inspect an authenticated offer and exact grant without signing or connecting.
    InspectOffer(member_cli::InspectOffer),
    /// Submit dual consent with a fresh committed snapshot and save a historical receipt.
    AdmitMember(member_cli::Admit),
    /// Authenticate historical admission without creating current authority or a trust floor.
    ConfirmMember(member_cli::Confirm),
    /// Verify and display one exact current governance record through the private local socket.
    Inspect {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        grant: String,
        #[arg(long)]
        kind: u64,
        #[arg(long)]
        lookup: String,
    },
}
pub(crate) fn bootstrap(location: &Location) -> Result<trust_bootstrap::Verified> {
    let pin = trust_bootstrap::hex32(&location.bootstrap_digest)?;
    let bytes = files::read_single(&location.bootstrap, trust_wire::MAXIMUM, true)?;
    ensure!(
        Sha256::digest(&bytes).as_slice() == pin,
        "bootstrap differs from the independently verified digest"
    );
    let verified = trust_bootstrap::inspect(&bytes, true)?;
    ensure!(
        verified.fully_accepted(),
        "bootstrap recovery custody is not fully accepted"
    );
    Ok(verified)
}
pub(crate) fn diagnostic(value: Value) -> Json {
    match value {
        Value::Uint(v) => json!(v),
        Value::Bytes(v) => json!({"hex":hex::encode(v)}),
        Value::Text(v) => json!(v),
        Value::Array(v) => Json::Array(v.into_iter().map(diagnostic).collect()),
        Value::Bool(v) => json!(v),
        Value::Null => Json::Null,
    }
}
pub(crate) fn clock(location: &Location, voters: &[[u8; 32]]) -> Result<authority_clock::Source> {
    let source = authority_clock::Source::select(
        &location.clock_witness,
        location.clock_monitor_key.as_deref(),
        location.host_kernel_boot.as_deref(),
    )?;
    ensure!(
        source.monitor_key().is_none_or(|key| !voters.contains(key)),
        "clock monitor identity must be distinct from authority voters"
    );
    Ok(source)
}
pub(crate) fn signer(path: &std::path::Path) -> Result<SigningKey> {
    let identity = crate::load_identity(path)?;
    let raw = zeroize::Zeroizing::new(trust_bootstrap::hex32(&identity.secret_key)?);
    Ok(SigningKey::from_bytes(&raw))
}
pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Recipients { command } => sealed_cli::run(command),
        Command::Epoch { command } => epoch_cli::run(command),
        Command::Ssh { command } => domain_cli::run(command),
        Command::Deployments { command } => deployment_cli::run(command),
        Command::DelegateGrant(command) => member_cli::delegate(command),
        Command::InviteMember(command) => member_cli::invite(command),
        Command::AcceptMember(command) => member_cli::accept(command),
        Command::InspectOffer(command) => member_cli::inspect_offer(command),
        Command::AdmitMember(command) => member_cli::admit(command),
        Command::ConfirmMember(command) => member_cli::confirm(command),
        Command::Initialise {
            location,
            requester,
        } => {
            let verified = bootstrap(&location)?;
            let source = clock(&location, verified.descriptor().voters())?;
            let health = source.health()?;
            let requester = trust_bootstrap::hex32(&requester)?;
            trust_wire::valid_key(&requester)?;
            // Initialisation never repairs an existing or partly written trust directory.
            files::create_directory(&location.directory)?;
            let store = Store::initialise(
                &location.directory,
                verified.descriptor().clone(),
                requester,
                health,
            )?;
            ContextState::bootstrap(&verified, &store)?.save(&store)?;
            crate::print_value(
                &json!({"status":"Initialised","requester":hex::encode(store.requester()),"network":hex::encode(verified.descriptor().scope().network),"committedHeight":store.prefix().height()}),
            )
        }
        Command::StreamStatus {
            location,
            key,
            socket,
        } => {
            let verified = bootstrap(&location)?;
            let mut store = Store::open(&location.directory, verified.descriptor().clone())?;
            let source = clock(&location, store.descriptor().voters())?;
            let signer = signer(&key)?;
            let mut session = Session::new()?;
            let metadata = crate::authority_inspection::stream_client::status_local(
                &store.descriptor().clone(),
                &socket,
                &signer,
                &mut store,
                &mut session,
                || source.health(),
            )?;
            crate::print_value(
                &json!({"status":"StreamStatus","metadata":diagnostic(trust_wire::decode(metadata.canonical())?),"committedHeight":store.prefix().height()}),
            )
        }
        Command::StreamFence {
            location,
            key,
            socket,
        } => {
            let verified = bootstrap(&location)?;
            let mut store = Store::open(&location.directory, verified.descriptor().clone())?;
            let source = clock(&location, store.descriptor().voters())?;
            let signer = signer(&key)?;
            let mut session = Session::new()?;
            let result = crate::authority_inspection::stream_client::fence_local(
                &store.descriptor().clone(),
                &socket,
                &signer,
                &mut store,
                &mut session,
                || source.health(),
            )?;
            let crate::authority_proof::StreamResponse::Fence { outcome, metadata } = result else {
                anyhow::bail!("fence returned another control result");
            };
            crate::print_value(
                &json!({"status":"StreamFence","outcome":format!("{outcome:?}"),"metadata":diagnostic(trust_wire::decode(metadata.canonical())?),"committedHeight":store.prefix().height()}),
            )
        }
        Command::Context {
            location,
            key,
            socket,
            grant,
            restart_discovery,
        } => {
            let verified = bootstrap(&location)?;
            let mut store = Store::open(&location.directory, verified.descriptor().clone())?;
            let source = clock(&location, store.descriptor().voters())?;
            let signer = signer(&key)?;
            let mut session = Session::new()?;
            if restart_discovery {
                ContextState::restart_discovery(&store)?;
            }
            ContextState::refresh_local(
                &verified,
                &socket,
                trust_bootstrap::hex32(&grant)?,
                &signer,
                &mut store,
                &mut session,
                || source.health(),
            )?;
            crate::print_value(
                &json!({"status":"ContextRefreshed","committedHeight":store.prefix().height(),"stateDigest":hex::encode(store.prefix().policy_state())}),
            )
        }
        Command::RevokeGrant {
            location,
            key,
            socket,
            grant,
            target,
            target_generation,
            target_digest,
        } => {
            let verified = bootstrap(&location)?;
            let mut store = Store::open(&location.directory, verified.descriptor().clone())?;
            let source = clock(&location, store.descriptor().voters())?;
            let context = ContextState::load(&verified, &store, &location.directory)?;
            let signer = signer(&key)?;
            let target = crate::authority_proof::VersionRef {
                kind: 102,
                id: trust_bootstrap::hex32(&target)?,
                generation: target_generation,
                digest: trust_bootstrap::hex32(&target_digest)?,
            };
            let mut session = Session::new()?;
            let result = context.revoke_grant_local(
                &socket,
                RevokeRequest {
                    grant: trust_bootstrap::hex32(&grant)?,
                    target,
                },
                &signer,
                &mut store,
                &mut session,
                || source.health(),
            )?;
            crate::print_value(
                &json!({"status":"GrantRevoked","grant":hex::encode(result.reference().id),"recordDigest":hex::encode(result.reference().digest),"committedHeight":result.prefix().height(),"record":diagnostic(trust_wire::decode(result.canonical())?)}),
            )
        }
        Command::Inspect {
            location,
            key,
            socket,
            grant,
            kind,
            lookup,
        } => {
            let verified = bootstrap(&location)?;
            let mut store = Store::open(&location.directory, verified.descriptor().clone())?;
            let source = clock(&location, store.descriptor().voters())?;
            let context = ContextState::load(&verified, &store, &location.directory)?;
            let signer = signer(&key)?;
            let mut session = Session::new()?;
            let result = context.inspect_local(
                &socket,
                Request {
                    grant: trust_bootstrap::hex32(&grant)?,
                    kind,
                    lookup: trust_bootstrap::hex32(&lookup)?,
                },
                &signer,
                &mut store,
                &mut session,
                || source.health(),
            )?;
            let reference = result.reference();
            crate::print_value(
                &json!({"kind":reference.kind,"generation":reference.generation,"lookup":hex::encode(reference.id),"recordDigest":hex::encode(reference.digest),"committedHeight":result.prefix().height(),"record":diagnostic(trust_wire::decode(result.canonical())?)}),
            )
        }
    }
}

#[cfg(test)]
#[path = "AuthorityInspectionCliTests.rs"]
mod tests;

#[path = "AuthorityMemberCli.rs"]
mod member_cli;

#[path = "AuthorityDeploymentCli.rs"]
mod deployment_cli;

#[path = "AuthorityDomainCli.rs"]
pub(crate) mod domain_cli;

#[path = "AuthorityEpochCli.rs"]
mod epoch_cli;

#[path = "AuthoritySealedIdentityCli.rs"]
pub(crate) mod sealed_cli;
