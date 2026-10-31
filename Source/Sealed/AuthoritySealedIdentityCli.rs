// SPDX-License-Identifier: MIT
// Explicit recipient workflows keep user roots, device secrets and endpoint challenges separate.
use super::{
    Location,
    domain_cli::{Capability, Online},
};
use crate::{
    authority_challenge::Session,
    authority_clock,
    authority_domains::{self as domain, sealed_identity as identity},
    authority_floor::Store,
    authority_inspection::{
        domain_client::{self, Cache, Request, ResultState},
        stream_client,
    },
    authority_membership::{Reservations, reference},
    authority_proof::{Digest, Intent, Key, VersionRef},
    sealed_crypto as crypto,
    sealed_vault::Vault,
    transfer_files as files,
    trust_bootstrap::Verified,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::path::{Path, PathBuf};
#[path = "AuthoritySealedIdentityCliClient.rs"]
mod client;
use client::Client;
#[path = "AuthoritySealedIdentityCliChallenge.rs"]
mod challenge;
#[path = "AuthoritySealedIdentityCliLocal.rs"]
mod local;
#[path = "AuthoritySealedIdentityCliOnline.rs"]
mod online;
#[path = "AuthoritySealedIdentityCliRecovery.rs"]
mod recovery;
#[path = "AuthoritySealedIdentityCliRotation.rs"]
mod rotation;

#[derive(Args)]
pub struct VaultArgs {
    #[arg(long)]
    pub(crate) vault: PathBuf,
    #[arg(long)]
    pub(crate) age_key: PathBuf,
}
#[derive(Args)]
pub struct Local {
    #[command(flatten)]
    pub(crate) location: Location,
    #[command(flatten)]
    pub(crate) vault: VaultArgs,
}
#[derive(Clone, ValueEnum)]
pub enum Role {
    Root,
    Device,
}
#[derive(Subcommand)]
pub enum Command {
    /// Create a separate encrypted recipient vault and its local age identity.
    Init {
        #[command(flatten)]
        local: Local,
    },
    /// Create a user root and its explicitly selected recovery custody commitment.
    RootCreate {
        #[command(flatten)]
        local: Local,
        #[arg(long)]
        member: String,
        #[arg(long, default_value_t = 1)]
        threshold: u64,
        #[arg(long = "recovery-key", required = true)]
        recovery_keys: Vec<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Register a generated root with explicit member acceptance and current network admission.
    RootRegister {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[command(flatten)]
        vault: VaultArgs,
        #[arg(long)]
        member: String,
        #[arg(long)]
        member_key: PathBuf,
        #[arg(long)]
        custody: PathBuf,
        #[arg(long)]
        trust_context: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Prepare an exact successor for separate offline owner approval.
    RootPrepare {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        member: String,
        #[arg(long)]
        new_root_key: String,
        #[arg(long)]
        custody: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Sign a prepared successor using the new root, prior root and member consent.
    RootSign {
        #[command(flatten)]
        local: Local,
        #[arg(long)]
        prior_vault: PathBuf,
        #[arg(long)]
        prior_age_key: PathBuf,
        #[arg(long)]
        proposal: PathBuf,
        #[arg(long)]
        member_key: PathBuf,
        #[arg(long)]
        trust_context: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Submit an exact owner-approved successor through current admission authority.
    RootSubmit {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        submission: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Prepare lost-root recovery against the exact current recipient and custody policy.
    RecoveryPrepare {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        member: String,
        #[arg(long)]
        new_root_key: String,
        #[arg(long)]
        custody: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Inspect the exact public replacement, prior root and accepted recovery custody offline.
    RecoveryInspect {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        proposal: PathBuf,
    },
    /// Sign an inspected recipient recovery using one independently held custody identity.
    RecoverySign {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        proposal: PathBuf,
        #[arg(long)]
        proposal_digest: String,
        #[arg(long)]
        custody_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Combine custody approval with replacement-root possession and explicit member acceptance.
    RecoveryAssemble {
        #[command(flatten)]
        local: Local,
        #[arg(long)]
        proposal: PathBuf,
        #[arg(long)]
        proposal_digest: String,
        #[arg(long, required=true, num_args=1..=3)]
        share: Vec<PathBuf>,
        #[arg(long)]
        member_key: PathBuf,
        #[arg(long)]
        trust_context: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        recovery_output: PathBuf,
    },
    /// Create candidate device keys and export a signed public key request.
    DeviceCreate {
        #[command(flatten)]
        local: Local,
        #[arg(long)]
        member: String,
        #[arg(long)]
        device: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Root-sign a candidate device's exact keys and reading or enrolment purpose.
    DeviceBind {
        #[command(flatten)]
        local: Local,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        device_keys: PathBuf,
        #[arg(long)]
        not_before_ms: u64,
        #[arg(long)]
        expires_ms: u64,
        #[arg(long)]
        enrol_devices: bool,
        #[arg(long)]
        previous: Option<PathBuf>,
        /// Exact current binding for a device authorised to enrol other devices.
        #[arg(long, requires = "delegate_admission")]
        delegate_binding: Option<PathBuf>,
        /// Exact current admission for the selected enrolment device.
        #[arg(long, requires = "delegate_binding")]
        delegate_admission: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Issue one private encrypted challenge from the authenticated admission endpoint.
    Challenge {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        binding: PathBuf,
        /// Exact binding of the device that signed delegated enrolment.
        #[arg(long)]
        delegate_binding: Option<PathBuf>,
        #[arg(long)]
        challenge_directory: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Decrypt an explicitly pinned endpoint's challenge and sign exact possession evidence.
    Respond {
        #[command(flatten)]
        local: Local,
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        challenge: PathBuf,
        #[arg(long)]
        endpoint_key: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Consume one exact response and commit current device admission once.
    Admit {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        challenge_directory: PathBuf,
        #[arg(long)]
        response: PathBuf,
        #[arg(long = "scope", required = true)]
        scopes: Vec<String>,
        #[arg(long)]
        not_before_ms: u64,
        #[arg(long)]
        expires_ms: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Initialise the dedicated requester floor for a locally held root or admitted device.
    FloorInitialise {
        #[command(flatten)]
        local: Local,
        #[arg(long, value_enum)]
        role: Role,
        #[arg(long)]
        identity: String,
    },
    /// Pin an exact recipient root using independently verified fingerprint and trust context.
    ContactAccept {
        #[command(flatten)]
        local: Local,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        root_digest: String,
        #[arg(long)]
        trust_context: String,
        #[arg(long)]
        previous_digest: Option<String>,
        #[arg(long)]
        recovery: Option<PathBuf>,
        #[arg(long)]
        custody: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Fetch one exact public recipient record under a scoped capability.
    Context {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        kind: u64,
        #[arg(long)]
        lookup: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Fetch all current recipient records for exactly one authorised member.
    Directory {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        member: String,
    },
    /// Commit an audience using separately signed author consent from pinned contacts.
    AudienceSet {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[command(flatten)]
        vault: VaultArgs,
        #[arg(long)]
        audience: String,
        #[arg(long = "member", required = true)]
        members: Vec<String>,
        #[arg(long = "exclude-device")]
        excluded: Vec<String>,
        /// Separate retained capability for current recipient metadata reads.
        #[arg(long)]
        read_grant: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Freeze the complete current admitted roster for one immutable publication instance.
    Freeze {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        audience: PathBuf,
        #[arg(long)]
        publication: String,
        #[arg(long)]
        revision: u64,
        #[arg(long)]
        encryption_generation: u64,
        #[arg(long)]
        scope: String,
        /// Separate retained capability for current audience and recipient metadata reads.
        #[arg(long)]
        read_grant: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Withdraw exact network device admission under RegisterRecipientDevice authority.
    Revoke {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Revoke an exact owned root or device with the local user root, using its own requester floor.
    RootRevoke {
        #[command(flatten)]
        local: Local,
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        member: String,
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
fn id(v: &str) -> Result<Digest> {
    let id = crate::trust_bootstrap::hex32(v)?;
    ensure!(id != [0; 32], "zero recipient identifier");
    Ok(id)
}
fn now() -> Result<u64> {
    crate::now()?
        .checked_mul(1000)
        .context("recipient clock overflow")
}
fn scope(text: &str, n: Digest) -> Result<(u64, Digest)> {
    let (kind, value) = text.split_once(':').context("scope requires Kind:Id")?;
    let kind = match kind {
        "Network" => 0,
        "Namespace" => 1,
        "Object" => 2,
        "Member" => 4,
        _ => anyhow::bail!("unsupported recipient scope"),
    };
    let value = id(value)?;
    ensure!(
        kind != 0 || value == n,
        "recipient scope belongs to another network"
    );
    Ok((kind, value))
}
fn read(path: &Path) -> Result<Vec<u8>> {
    files::read_public_single(path, wire::MAXIMUM)
}
fn record(bytes: &[u8], bootstrap: &Verified) -> Result<domain::Record> {
    let s = bootstrap.descriptor().scope();
    identity::signed_record(bytes, s.network, s.incarnation)
}
fn signed(
    kind: u64,
    generation: u64,
    previous: Option<Digest>,
    body: Vec<V>,
    bootstrap: &Verified,
    key: &SigningKey,
) -> Result<Vec<u8>> {
    let s = bootstrap.descriptor().scope();
    let mut values = vec![
        V::Uint(kind),
        V::Uint(1),
        b(&s.network),
        b(&s.incarnation),
        V::Uint(generation),
        previous.as_ref().map_or(V::Null, |v| b(v)),
    ];
    values.extend(body);
    wire::sign_envelope(&wire::encode(&a(values))?, key)
}
fn vault(args: &VaultArgs, location: &Location) -> Result<Vault> {
    let verified = super::bootstrap(location)?;
    let s = verified.descriptor().scope();
    Vault::open(
        &args.vault,
        &args.age_key,
        s.network,
        s.incarnation,
        id(&location.bootstrap_digest)?,
    )
}
fn emit(status: &str, record: &domain::Record, output: &Path) -> Result<()> {
    files::write_new(output, &record.bytes)?;
    crate::print_value(
        &json!({"status":status,"kind":record.reference.kind,"id":hex::encode(record.reference.id),"generation":record.reference.generation,"recordDigest":hex::encode(record.reference.digest)}),
    )
}
pub fn run(command: Command) -> Result<()> {
    match command {
        Command::RecoveryPrepare { .. }
        | Command::RecoveryInspect { .. }
        | Command::RecoverySign { .. }
        | Command::RecoveryAssemble { .. } => recovery::run(command),
        Command::RootPrepare { .. } | Command::RootSign { .. } | Command::RootSubmit { .. } => {
            rotation::run(command)
        }
        Command::Init { .. }
        | Command::RootCreate { .. }
        | Command::DeviceCreate { .. }
        | Command::DeviceBind { .. }
        | Command::FloorInitialise { .. }
        | Command::ContactAccept { .. } => local::run(command),
        Command::Challenge { .. } | Command::Respond { .. } | Command::Admit { .. } => {
            challenge::run(command)
        }
        _ => online::run(command),
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Sealed/AuthoritySealedIdentityCliUnitTests.rs"]
mod tests;
