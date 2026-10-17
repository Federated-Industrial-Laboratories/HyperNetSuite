#[path = "AuthorityCapacity.rs"]
mod authority_capacity;
#[path = "AuthorityDeploymentRecords.rs"]
mod authority_deployment_records;
#[path = "AuthorityDeployments.rs"]
mod authority_deployments;
#[path = "AuthorityHistory.rs"]
mod authority_history;
#[path = "RuntimeBootstrapKeys.rs"]
mod runtime_bootstrap_keys;
#[path = "RuntimeManifest.rs"]
mod runtime_manifest;
#[path = "SealedCrypto.rs"]
mod sealed_crypto;
#[path = "SealedPageData.rs"]
mod sealed_page_data;
#[path = "SealedVault.rs"]
mod sealed_vault;
// SPDX-License-Identifier: MIT
#[path = "AuthorityApplications.rs"]
mod authority_applications;
#[path = "AuthorityChallenge.rs"]
mod authority_challenge;
#[path = "AuthorityClock.rs"]
mod authority_clock;
#[path = "AuthorityDomains.rs"]
mod authority_domains;
#[path = "AuthorityEpoch.rs"]
mod authority_epoch;
#[path = "AuthorityFloor.rs"]
mod authority_floor;
#[path = "AuthorityGovernance.rs"]
mod authority_governance;
#[path = "AuthorityGrantReview.rs"]
mod authority_grant_review;
#[path = "AuthorityInspection.rs"]
mod authority_inspection;
#[path = "AuthorityInspectionCli.rs"]
mod authority_inspection_cli;
#[path = "AuthorityLocalTransport.rs"]
mod authority_local_transport;
#[path = "AuthorityMembership.rs"]
mod authority_membership;
#[path = "AuthorityObjects.rs"]
mod authority_objects;
#[path = "AuthorityOperationalConsent.rs"]
mod authority_operational_consent;
#[path = "AuthorityPolicies.rs"]
mod authority_policies;
#[path = "AuthorityProof.rs"]
mod authority_proof;
#[path = "AuthorityRead.rs"]
mod authority_read;
#[cfg(test)]
#[path = "AuthorityRecipient.rs"]
mod authority_recipient;
#[path = "AuthorityRecovery.rs"]
mod authority_recovery;
#[path = "AuthorityRuntimeActivation.rs"]
mod authority_runtime_activation;
#[path = "AuthorityTiers.rs"]
mod authority_tiers;
// Independent signed HyperNet command client and local device-key management.
#[path = "AdapterFiles.rs"]
mod adapter_files;
#[path = "Applications.rs"]
mod applications;
#[path = "AuthorityMail.rs"]
mod authority_mail;
#[path = "AuthorityPages.rs"]
mod authority_pages;
#[path = "AuthorityRouteReader.rs"]
mod authority_route_reader;
#[path = "Borders.rs"]
mod borders;
#[path = "Files.rs"]
mod files;
#[path = "FormUi.rs"]
mod form_ui;
#[path = "MailCrypto.rs"]
mod mail_crypto;
#[path = "MailProtocol.rs"]
mod mail_protocol;
#[path = "Markup.rs"]
mod markup;
#[path = "Media.rs"]
mod media;
#[path = "MediaImport.rs"]
mod media_import;
#[path = "MediaWorker.rs"]
mod media_worker;
#[path = "Motion.rs"]
mod motion;
#[path = "NativeFederation.rs"]
mod native_federation;
#[path = "Networks.rs"]
mod networks;
#[path = "PageLayout.rs"]
mod page_layout;
#[path = "PageView.rs"]
mod page_view;
#[path = "PrivateRouteClient.rs"]
mod private_route_client;
#[path = "PrivateRouteClock.rs"]
mod private_route_clock;
#[path = "PrivateRouteCommands.rs"]
mod private_route_commands;
#[path = "Protocol.rs"]
mod protocol;
#[path = "Reader.rs"]
mod reader;
#[path = "RouteConnector.rs"]
mod route_connector;
#[path = "RouteProfile.rs"]
mod route_profile;
#[path = "RouteProtocol.rs"]
mod route_protocol;
#[path = "RouteTls.rs"]
mod route_tls;
#[path = "Search.rs"]
mod search;
#[path = "SearchText.rs"]
mod search_text;
#[path = "Services.rs"]
mod services;
#[path = "SshProof.rs"]
mod ssh_proof;
#[path = "TerminalGraphics.rs"]
mod terminal_graphics;
#[path = "TerminalInput.rs"]
mod terminal_input;
#[path = "TransferFiles.rs"]
mod transfer_files;
pub(crate) use transfer_files as authority_files;
#[path = "TransferProtocol.rs"]
mod transfer_protocol;
#[path = "TransferVault.rs"]
mod transfer_vault;
#[path = "Transfers.rs"]
mod transfers;
#[path = "TrustBootstrap.rs"]
mod trust_bootstrap;
#[path = "TrustWire.rs"]
mod trust_wire;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;

#[derive(Parser)]
#[command(
    name = "HyperNetSuite",
    version,
    about = "Independent HyperNet command-line client"
)]
struct Options {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify current governance through a private local authority control socket.
    #[command(subcommand)]
    AuthorityInspection(authority_inspection_cli::Command),
    /// Prepare and inspect independently authenticated offline network trust.
    #[command(subcommand)]
    Network(networks::Command),
    /// Register relay services and issue bounded possession-key route vouchers.
    #[command(subcommand)]
    Routes(private_route_commands::Command),
    /// Browse the configured network catalogue or a verified page address.
    Browse(authority_pages::Browse),
    /// Search an explicitly selected network or encrypted retained content.
    #[command(subcommand)]
    Search(search::Command),
    /// Fill and exchange explicitly accepted encrypted form submissions.
    Forms(authority_mail::FormsArguments),
    /// Manage separate least-privilege application credentials.
    #[command(subcommand)]
    Applications(applications::Command),
    /// Exchange explicit inert review jobs and bounded recommendations.
    #[command(subcommand)]
    Adapters(authority_pages::adapters::Command),
    /// Consented encrypted file exchange.
    Transfers(transfers::Arguments),
    /// Discover, request and invoke separately consented SSH services.
    #[command(subcommand)]
    Services(services::Command),
    /// Private encrypted mail, selected storage and device management.
    Mail(authority_mail::Arguments),
    /// Agree, share, review and read explicitly federated Pages.
    #[command(subcommand)]
    Federation(native_federation::Command),
    /// Import, store, review and reveal explicitly consented page media.
    #[command(subcommand)]
    Media(authority_pages::media::Command),
    /// Author, review and read inert HyperNet Pages.
    #[command(subcommand)]
    Pages(authority_pages::Command),
    /// Generate a device key locally. The secret is written only to a new private file.
    Keygen {
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[zeroize(drop)]
struct Identity {
    secret_key: String,
    public_key: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!(
            "HyperNetSuite: {}",
            terminal_text(&format!("{error:#}"), false)
        );
        std::process::exit(1);
    }
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn random_hex<const N: usize>() -> String {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
fn print_value(value: &Value) -> Result<()> {
    let raw = serde_json::to_string_pretty(value)?;
    println!("{}", terminal_text(&raw, true));
    Ok(())
}

fn terminal_text(raw: &str, multiline: bool) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        // Only formatting newlines may pass. Imported text never supplies terminal controls.
        if (ch.is_control() && !(multiline && ch == '\n'))
            || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}')
            || ('\u{202a}'..='\u{202e}').contains(&ch)
            || ('\u{2066}'..='\u{2069}').contains(&ch)
        {
            use std::fmt::Write;
            write!(out, "\\u{:04x}", ch as u32).expect("writing to a string cannot fail");
        } else {
            out.push(ch);
        }
    }
    out
}

fn run() -> Result<()> {
    if std::env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new("--internal-media-worker"))
    {
        anyhow::ensure!(std::env::args_os().count() == 2, "invalid worker arguments");
        return media_worker::run();
    }
    files::disable_dumps()?;
    private_route_client::install_cancellation()?;
    let options = match Options::try_parse() {
        Ok(options) => options,
        Err(error) => {
            let text = terminal_text(&error.to_string(), true);
            if error.use_stderr() {
                eprint!("{text}");
            } else {
                print!("{text}");
            }
            std::process::exit(error.exit_code());
        }
    };
    dispatch(options.command)
}
fn dispatch(command: Command) -> Result<()> {
    match command {
        Command::AuthorityInspection(command) => authority_inspection_cli::run(command),
        Command::Network(command) => networks::run(command),
        Command::Routes(command) => private_route_commands::run(command),
        Command::Browse(arguments) => authority_pages::browse(arguments),
        Command::Search(command) => search::run(command),
        Command::Applications(command) => applications::run(command),
        Command::Adapters(command) => authority_pages::adapters::run(command),
        Command::Transfers(arguments) => transfers::run(None, arguments),
        Command::Services(command) => services::run(None, command),
        Command::Forms(arguments) => authority_mail::run_forms(None, arguments),
        Command::Mail(arguments) => authority_mail::run(None, arguments),
        Command::Federation(command) => native_federation::run(command),
        Command::Media(command) => authority_pages::media::run(command),
        Command::Pages(command) => authority_pages::run(command),
        Command::Keygen { output } => {
            let key = SigningKey::generate(&mut OsRng);
            let identity = Identity {
                secret_key: hex::encode(key.to_bytes()),
                public_key: hex::encode(key.verifying_key().to_bytes()),
            };
            files::write_new(&output, &serde_json::to_vec_pretty(&identity)?)?;
            print_value(&json!({"publicKey":identity.public_key,"identity":output}))
        }
    }
}

fn load_identity(path: &Path) -> Result<Identity> {
    let raw = zeroize::Zeroizing::new(files::read_bounded(path, true)?);
    let identity: Identity = serde_json::from_slice(&raw).context("invalid identity file")?;
    let key = SigningKey::from_bytes(&protocol::hex_bytes::<32>(&identity.secret_key)?);
    if hex::encode(key.verifying_key().to_bytes()) != identity.public_key {
        bail!("identity key pair does not match");
    }
    Ok(identity)
}

#[cfg(test)]
#[path = "AuthorityDeploymentTests.rs"]
mod authority_deployment_tests;
