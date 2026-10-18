// SPDX-License-Identifier: MIT
// Mail uses certified metadata, owner-held MLS keys and explicit local store exchanges.
use crate::{
    Identity,
    authority_challenge::Session,
    authority_clock,
    authority_domains::{
        self as domain,
        mail::{self, Command as Action, Effect},
    },
    authority_floor::Store,
    authority_inspection::{
        domain_client::{self, Cache, Request as DomainRequest},
        mail_client, stream_client,
    },
    authority_inspection_cli::{
        self as control, Location,
        domain_cli::{self, Capability, Online},
    },
    authority_proof::{Digest, VersionRef},
    mail_crypto as crypto, mail_protocol as protocol, transfer_files as files,
    trust_bootstrap::Verified,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command as Process,
};
#[path = "../Forms/AuthorityForms.rs"]
pub(crate) mod forms;
pub use forms::{Arguments as FormsArguments, run as run_forms};
#[path = "AuthorityMailVault.rs"]
mod vault;
use vault::{Mailbox, Outgoing, Vault};
#[derive(Args)]
pub struct Arguments {
    #[command(subcommand)]
    command: Command,
}
#[derive(Clone, Args)]
pub struct VaultLocation {
    #[arg(long)]
    vault: PathBuf,
    #[arg(long)]
    age_key: PathBuf,
}
#[derive(Clone, Args)]
pub struct DeviceOnline {
    #[command(flatten)]
    location: Location,
    #[command(flatten)]
    vault: VaultLocation,
    #[arg(long)]
    mailbox: String,
    #[arg(long)]
    socket: PathBuf,
}
#[derive(Clone, Args)]
pub struct Transport {
    #[arg(long)]
    service: String,
    #[arg(
        long,
        conflicts_with = "service_directory",
        required_unless_present = "service_directory"
    )]
    service_socket: Option<PathBuf>,
    #[arg(long, conflicts_with = "service_socket")]
    service_directory: Option<PathBuf>,
    #[arg(long, default_value = "HyperNet")]
    core: PathBuf,
}
impl Transport {
    pub(crate) fn socket(service: Digest, path: PathBuf) -> Self {
        Self {
            service: hex::encode(service),
            service_socket: Some(path),
            service_directory: None,
            core: PathBuf::from("HyperNet"),
        }
    }
    pub(crate) fn installed(service: Digest, directory: PathBuf, core: PathBuf) -> Self {
        Self {
            service: hex::encode(service),
            service_socket: None,
            service_directory: Some(directory),
            core,
        }
    }
}
#[derive(Subcommand)]
enum Command {
    Init {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        vault: VaultLocation,
    },
    Profile {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        profile_digest: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        volume: String,
        #[arg(long)]
        state_bytes: u64,
        #[arg(long,default_value_t=mail::MAXIMUM_PAYLOAD)]
        maximum_payload: u64,
        #[arg(long,default_value_t=mail::MAXIMUM_LIFETIME_MS)]
        maximum_lifetime_ms: u64,
        #[arg(long)]
        output: PathBuf,
    },
    Register {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        profile: PathBuf,
    },
    Withdraw {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        service: String,
    },
    Hosts {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        after: Option<String>,
    },
    AddressCreate {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        vault: VaultLocation,
        #[arg(long)]
        mailbox: String,
        #[arg(long = "host", required = true)]
        hosts: Vec<String>,
        #[arg(long, default_value_t = 1)]
        copies: u16,
        #[arg(long)]
        private: bool,
        #[arg(long)]
        expires: u64,
        #[arg(long, default_value_t = 86400)]
        retention: u64,
    },
    Publish {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[command(flatten)]
        vault: VaultLocation,
        #[arg(long)]
        mailbox: String,
    },
    DeviceInitialise {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        vault: VaultLocation,
        #[arg(long)]
        mailbox: String,
    },
    Sync {
        #[command(flatten)]
        online: DeviceOnline,
    },
    Refill {
        #[command(flatten)]
        online: DeviceOnline,
        #[arg(long, default_value_t = 4)]
        count: usize,
    },
    ContactVerify {
        #[command(flatten)]
        online: DeviceOnline,
        #[arg(long)]
        address: String,
        #[arg(long)]
        owner_key: String,
    },
    Placement {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        vault: VaultLocation,
        #[arg(long)]
        mailbox: String,
        #[arg(long = "host", required = true)]
        hosts: Vec<String>,
        #[arg(long, default_value_t = 1)]
        copies: u16,
        #[arg(long)]
        private: bool,
    },
    AddressRenew {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        vault: VaultLocation,
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        expires: u64,
    },
    DeviceCreate {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        vault: VaultLocation,
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        address: String,
        #[arg(long)]
        expires: u64,
        #[arg(long = "permission", required = true)]
        permissions: Vec<String>,
        #[arg(long)]
        output: PathBuf,
    },
    DeviceExport {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        vault: VaultLocation,
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        output: PathBuf,
    },
    DeviceEnrol {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        vault: VaultLocation,
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        binding: PathBuf,
    },
    DeviceRenew {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        vault: VaultLocation,
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        device: String,
        #[arg(long)]
        expires: u64,
    },
    DeviceRevoke {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        vault: VaultLocation,
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        device: String,
    },
    AddressDelete {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        vault: VaultLocation,
        #[arg(long)]
        mailbox: String,
    },
    Compose {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        vault: VaultLocation,
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        body_file: PathBuf,
        #[arg(long)]
        expires: u64,
    },
    Send {
        #[command(flatten)]
        online: DeviceOnline,
        #[command(flatten)]
        transport: Transport,
        #[arg(long)]
        message: String,
    },
    Inbox {
        #[command(flatten)]
        online: DeviceOnline,
        #[command(flatten)]
        transport: Transport,
        #[arg(long)]
        after: Option<String>,
    },
    Read {
        #[command(flatten)]
        online: DeviceOnline,
        #[command(flatten)]
        transport: Transport,
        #[arg(long)]
        message: String,
    },
    Delete {
        #[command(flatten)]
        online: DeviceOnline,
        #[command(flatten)]
        transport: Transport,
        #[arg(long)]
        message: String,
    },
    Addresses {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        vault: VaultLocation,
    },
    Outbox {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        vault: VaultLocation,
    },
    ArchiveDisclose {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        vault: VaultLocation,
        #[command(flatten)]
        arguments: disclosure::Arguments,
    },
    ArchiveRead {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        vault: VaultLocation,
        #[arg(long)]
        message: String,
    },
    ArchiveDelete {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        vault: VaultLocation,
        #[arg(long)]
        message: String,
    },
}
#[path = "AuthorityMailDisclosure.rs"]
mod disclosure;
#[path = "AuthorityMailWorkflow.rs"]
mod workflow;
use workflow::*;
#[path = "AuthorityMailLocal.rs"]
mod local;
#[path = "AuthorityMailOnline.rs"]
mod online;
pub fn run(configuration: Option<&Path>, arguments: Arguments) -> Result<()> {
    ensure!(
        configuration.is_none(),
        "mail uses an independently pinned bootstrap and explicit private sockets; --config is not accepted"
    );
    match arguments.command {
        command @ (Command::Profile { .. }
        | Command::Register { .. }
        | Command::Withdraw { .. }
        | Command::Hosts { .. }
        | Command::Publish { .. }
        | Command::DeviceInitialise { .. }
        | Command::Sync { .. }
        | Command::Refill { .. }
        | Command::ContactVerify { .. }
        | Command::Send { .. }
        | Command::Inbox { .. }
        | Command::Read { .. }
        | Command::Delete { .. }) => online::run(command),
        command => local::run(command),
    }
}
