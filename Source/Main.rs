#[path = "Authority/AuthorityCapacity.rs"]
mod authority_capacity;
#[path = "Authority/Deployments/AuthorityDeploymentRecords.rs"]
mod authority_deployment_records;
#[path = "Authority/Deployments/AuthorityDeployments.rs"]
mod authority_deployments;
#[path = "Authority/AuthorityHistory.rs"]
mod authority_history;
#[path = "Runtime/RuntimeBootstrapKeys.rs"]
mod runtime_bootstrap_keys;
#[path = "Runtime/RuntimeManifest.rs"]
mod runtime_manifest;
#[path = "Sealed/SealedCrypto.rs"]
mod sealed_crypto;
#[path = "Sealed/SealedPageData.rs"]
mod sealed_page_data;
#[path = "Sealed/SealedVault.rs"]
mod sealed_vault;
// SPDX-License-Identifier: MIT
#[path = "Authority/Governance/AuthorityApplications.rs"]
mod authority_applications;
#[path = "Authority/AuthorityChallenge.rs"]
mod authority_challenge;
#[path = "Authority/AuthorityClock.rs"]
mod authority_clock;
#[path = "Authority/Domains/AuthorityDomains.rs"]
mod authority_domains;
#[path = "Authority/Epochs/AuthorityEpoch.rs"]
mod authority_epoch;
#[path = "Authority/AuthorityFloor.rs"]
mod authority_floor;
#[path = "Authority/Governance/AuthorityGovernance.rs"]
mod authority_governance;
#[path = "Authority/Governance/AuthorityGrantReview.rs"]
mod authority_grant_review;
#[path = "Authority/AuthorityInspection.rs"]
mod authority_inspection;
#[path = "Authority/AuthorityInspectionCli.rs"]
mod authority_inspection_cli;
#[path = "Authority/AuthorityLocalTransport.rs"]
mod authority_local_transport;
#[path = "Authority/Governance/AuthorityMembership.rs"]
mod authority_membership;
#[path = "Authority/AuthorityObjects.rs"]
mod authority_objects;
#[path = "Authority/Deployments/AuthorityOperationalConsent.rs"]
mod authority_operational_consent;
#[path = "Authority/Governance/AuthorityPolicies.rs"]
mod authority_policies;
#[path = "Authority/AuthorityProof.rs"]
mod authority_proof;
#[path = "Authority/AuthorityRead.rs"]
mod authority_read;
#[cfg(test)]
#[path = "Authority/Recipients/AuthorityRecipient.rs"]
mod authority_recipient;
#[path = "Authority/AuthorityRecovery.rs"]
mod authority_recovery;
#[path = "Authority/Deployments/AuthorityRuntimeActivation.rs"]
mod authority_runtime_activation;
#[path = "Authority/Governance/AuthorityTiers.rs"]
mod authority_tiers;
// Independent signed HyperNet command client and local device-key management.
#[path = "Storage/AdapterFiles.rs"]
mod adapter_files;
#[path = "Applications/Applications.rs"]
mod applications;
#[path = "Mail/AuthorityMail.rs"]
mod authority_mail;
#[path = "Pages/AuthorityPages.rs"]
mod authority_pages;
#[path = "Routing/AuthorityRouteReader.rs"]
mod authority_route_reader;
#[path = "Presentation/Borders.rs"]
mod borders;
#[path = "Storage/Files.rs"]
mod files;
#[path = "Presentation/FormUi.rs"]
mod form_ui;
#[path = "Mail/MailCrypto.rs"]
mod mail_crypto;
#[path = "Mail/MailProtocol.rs"]
mod mail_protocol;
#[path = "HyperPage/Markup.rs"]
mod markup;
#[path = "Media/Media.rs"]
mod media;
#[path = "Media/MediaImport.rs"]
mod media_import;
#[path = "Media/MediaWorker.rs"]
mod media_worker;
#[path = "Presentation/Motion.rs"]
mod motion;
#[path = "Federation/NativeFederation.rs"]
mod native_federation;
#[path = "Networks/Networks.rs"]
mod networks;
#[path = "Presentation/PageLayout.rs"]
mod page_layout;
#[path = "Presentation/PageView.rs"]
mod page_view;
#[path = "Routing/PrivateRouteClient.rs"]
mod private_route_client;
#[path = "Routing/PrivateRouteClock.rs"]
mod private_route_clock;
#[path = "Routing/PrivateRouteCommands.rs"]
mod private_route_commands;
#[path = "Protocol/Protocol.rs"]
mod protocol;
#[path = "Terminal/Reader.rs"]
mod reader;
#[path = "Routing/RouteConnector.rs"]
mod route_connector;
#[path = "Routing/RouteProfile.rs"]
mod route_profile;
#[path = "Routing/RouteProtocol.rs"]
mod route_protocol;
#[path = "Routing/RouteTls.rs"]
mod route_tls;
#[path = "Search/Search.rs"]
mod search;
#[path = "Search/SearchText.rs"]
mod search_text;
#[path = "Services/Services.rs"]
mod services;
#[path = "Services/SshProof.rs"]
mod ssh_proof;
#[path = "Terminal/TerminalGraphics.rs"]
mod terminal_graphics;
#[path = "Terminal/TerminalInput.rs"]
mod terminal_input;
#[path = "Transfers/TransferFiles.rs"]
mod transfer_files;
pub(crate) use transfer_files as authority_files;
#[path = "Transfers/TransferProtocol.rs"]
mod transfer_protocol;
#[path = "Transfers/TransferVault.rs"]
mod transfer_vault;
#[path = "Transfers/Transfers.rs"]
mod transfers;
#[path = "Protocol/TrustBootstrap.rs"]
mod trust_bootstrap;
#[path = "Protocol/TrustWire.rs"]
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
#[path = "Authority/Deployments/AuthorityDeploymentTests.rs"]
mod authority_deployment_tests;
