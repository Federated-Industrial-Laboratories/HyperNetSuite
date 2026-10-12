// SPDX-License-Identifier: MIT
// Sealed Page authors and reviewers exchange encrypted input and explicit exact approval.
use super::{Capability, Client, Online, content_cli, control, domain, files, page};
use crate::{
    authority_domains::{sealed_identity as identity, sealed_publication as publication},
    authority_membership::{Reservations, reference},
    authority_proof::{Digest, Intent, VersionRef},
    sealed_crypto as crypto, sealed_page_data as data,
    sealed_vault::Vault,
    trust_bootstrap::Verified,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand, ValueEnum};
use control::sealed_cli::{Local, VaultArgs};
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
#[path = "AuthoritySealedPagesAttempt.rs"]
mod attempt;
#[path = "AuthoritySealedPagesAuthor.rs"]
mod author;
#[path = "AuthoritySealedPagesContext.rs"]
mod context;
#[path = "AuthoritySealedPagesReview.rs"]
mod review;
#[path = "AuthoritySealedPagesView.rs"]
mod view;

#[derive(Clone, ValueEnum)]
pub enum Mode {
    HostReadable,
    Sealed,
}
#[derive(Args)]
pub struct Display {
    #[arg(long)]
    tui: bool,
    #[arg(long)]
    ascii: bool,
    #[command(flatten)]
    graphics: crate::terminal_graphics::Options,
}
#[derive(Subcommand)]
pub enum Command {
    /// Set the finite namespace publication modes under explicit policy authority.
    Namespace {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        namespace: String,
        #[arg(long = "mode", value_enum, required = true)]
        modes: Vec<Mode>,
    },
    /// Sign object placement and an exact independently accepted audience.
    Policy {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[command(flatten)]
        vault: VaultArgs,
        #[arg(long)]
        object: String,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        audience: PathBuf,
        #[arg(long = "host", required = true)]
        hosts: Vec<String>,
        #[arg(long = "volume", required = true)]
        volumes: Vec<String>,
        #[arg(long)]
        copies: u64,
        #[arg(long)]
        read_grant: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Encrypt an exact signed source submission to an independently pinned reviewer device.
    Submit {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[command(flatten)]
        vault: VaultArgs,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        source: PathBuf,
        #[arg(long = "asset")]
        assets: Vec<String>,
        #[arg(long)]
        reviewer_binding: PathBuf,
        #[arg(long)]
        revision: u64,
        #[arg(long)]
        expires_ms: u64,
        #[arg(long)]
        read_grant: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Decrypt and display exactly one private submission for human inspection.
    Inspect {
        #[command(flatten)]
        local: Local,
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        submission: PathBuf,
        #[command(flatten)]
        display: Display,
    },
    /// Approve the explicitly inspected input, freeze recipients and retain one fresh encrypted attempt.
    Finalise {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[command(flatten)]
        vault: VaultArgs,
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        submission: PathBuf,
        #[arg(long)]
        inspected_digest: String,
        #[arg(long, required = true)]
        approve: bool,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        publication: String,
        #[arg(long)]
        encryption_generation: u64,
        #[arg(long, default_value_t = 1)]
        failure_domains: u64,
        #[arg(long)]
        expires_ms: u64,
        #[arg(long)]
        attempt_directory: PathBuf,
    },
    /// Resume exact ciphertext staging, direct durable upload and publication commit.
    Publish {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[command(flatten)]
        vault: VaultArgs,
        #[arg(long)]
        device: String,
        #[arg(long)]
        attempt_directory: PathBuf,
    },
    /// Fetch one currently authorised encrypted publication and display it only in memory.
    Read {
        #[command(flatten)]
        local: Local,
        #[arg(long)]
        socket: PathBuf,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        device: String,
        #[arg(long)]
        object: String,
        #[command(flatten)]
        display: Display,
    },
    /// Withdraw the exact current publication with its publisher authority.
    Withdraw {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        object: String,
    },
}
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
fn id(v: &str) -> Result<Digest> {
    let v = crate::trust_bootstrap::hex32(v)?;
    ensure!(v != [0; 32], "zero sealed identity");
    Ok(v)
}
fn ids(v: &[String]) -> Result<Vec<Digest>> {
    let mut values = v.iter().map(|v| id(v)).collect::<Result<Vec<_>>>()?;
    values.sort();
    ensure!(
        values.windows(2).all(|w| w[0] < w[1]),
        "sealed identifiers repeat"
    );
    Ok(values)
}
fn now(c: &Client) -> Result<u64> {
    Ok(c.clock.health()?.observe()?.wall_ms)
}
fn local_now() -> Result<u64> {
    crate::now()?
        .checked_mul(1000)
        .context("sealed clock overflow")
}
fn read(path: &Path) -> Result<Vec<u8>> {
    files::read_public_single(path, wire::MAXIMUM)
}
fn vault(args: &VaultArgs, verified: &Verified) -> Result<Vault> {
    let s = verified.descriptor().scope();
    Vault::open(
        &args.vault,
        &args.age_key,
        s.network,
        s.incarnation,
        verified.file_digest(),
    )
}
fn policy(bytes: &[u8], verified: &Verified) -> Result<publication::ObjectPolicy> {
    let s = verified.descriptor().scope();
    let r = publication::signed_record(bytes, s.network, s.incarnation)?;
    publication::ObjectPolicy::parse(&publication::payload(&r)?, s.network, s.incarnation)
}
fn binding(bytes: &[u8], verified: &Verified) -> Result<identity::Binding> {
    let s = verified.descriptor().scope();
    let r = identity::signed_record(bytes, s.network, s.incarnation)?;
    identity::Binding::parse(&identity::payload(&r)?, s.network, s.incarnation)
}
fn signed(
    kind: u64,
    generation: u64,
    previous: Option<Digest>,
    body: Vec<V>,
    verified: &Verified,
    key: &SigningKey,
) -> Result<Vec<u8>> {
    let s = verified.descriptor().scope();
    let mut f = vec![
        V::Uint(kind),
        V::Uint(1),
        b(&s.network),
        b(&s.incarnation),
        V::Uint(generation),
        previous.as_ref().map_or(V::Null, |v| b(v)),
    ];
    f.extend(body);
    wire::sign_envelope(&wire::encode(&a(f))?, key)
}
fn saved(status: &str, r: &domain::Record, path: &Path) -> Result<()> {
    files::write_new(path, &r.bytes)?;
    crate::print_value(
        &json!({"status":status,"kind":r.reference.kind,"id":hex::encode(r.reference.id),"generation":r.reference.generation,"digest":hex::encode(r.reference.digest)}),
    )
}
pub(super) fn run(command: Command) -> Result<()> {
    match command {
        Command::Namespace { .. }
        | Command::Policy { .. }
        | Command::Submit { .. }
        | Command::Withdraw { .. } => author::run(command),
        Command::Inspect { .. } | Command::Read { .. } => view::run(command),
        Command::Finalise { .. } | Command::Publish { .. } => review::run(command),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};
    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        command: Command,
    }
    fn local(command: &str) -> Vec<String> {
        [
            "sealed",
            command,
            "--bootstrap",
            "Bootstrap.cbor",
            "--bootstrap-digest",
            "pin",
            "--directory",
            "Private",
            "--clock-witness",
            "Clock.json",
            "--vault",
            "Vault",
            "--age-key",
            "Identity.age",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
    #[test]
    fn sealed_finalisation_requires_human_approval_and_exact_inspection() {
        Cli::command().debug_assert();
        let mut args = local("finalise");
        args.extend(
            [
                "--key",
                "Reviewer.json",
                "--socket",
                "Authority.sock",
                "--grant",
                "grant",
                "--binding",
                "Device.cbor",
                "--policy",
                "Policy.cbor",
                "--submission",
                "Submission.age",
                "--inspected-digest",
                "digest",
                "--approve",
                "--namespace",
                "Books",
                "--publication",
                "publication",
                "--encryption-generation",
                "1",
                "--expires-ms",
                "10000",
                "--attempt-directory",
                "Attempt",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        assert!(Cli::try_parse_from(&args).is_ok());
        let mut missing_approval = args.clone();
        missing_approval.retain(|v| v != "--approve");
        assert!(Cli::try_parse_from(missing_approval).is_err());
        let index = args.iter().position(|v| v == "--inspected-digest").unwrap();
        args.drain(index..index + 2);
        assert!(Cli::try_parse_from(args).is_err());
    }
    #[test]
    fn sealed_reader_uses_device_vault_and_never_accepts_plaintext_output() {
        let mut args = local("read");
        args.extend(
            [
                "--socket",
                "Authority.sock",
                "--grant",
                "grant",
                "--device",
                "device",
                "--object",
                "object",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        assert!(Cli::try_parse_from(&args).is_ok());
        let mut output = args.clone();
        output.extend(["--output", "Plaintext.txt"].into_iter().map(str::to_owned));
        assert!(Cli::try_parse_from(output).is_err());
        args.extend(["--key", "Unrelated.json"].into_iter().map(str::to_owned));
        assert!(Cli::try_parse_from(args).is_err());
    }
}
