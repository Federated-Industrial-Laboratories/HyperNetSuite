// SPDX-License-Identifier: MIT
// Page authors, reviewers and readers use independently verified current authority state.
use crate::{
    authority_challenge::Session,
    authority_clock,
    authority_domains::{
        self as domain,
        page::{
            self, Command as Action,
            objects::{Author, Bundle, Reviewer},
        },
    },
    authority_floor::Store,
    authority_inspection::{
        domain_client::{self, Cache, Request, ResultState},
        stream_client,
    },
    authority_inspection_cli::{
        self as control,
        domain_cli::{self, Capability, Online},
    },
    authority_objects::{Class, Object, Reference, Resolved},
    authority_proof::{Digest, VersionRef},
    transfer_files as files,
    trust_bootstrap::Verified,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::path::{Path, PathBuf};

#[path = "AuthorityPageConnection.rs"]
mod connection;
pub(crate) use connection::Client;
#[path = "AuthorityReviewAdapter.rs"]
pub(crate) mod adapters;
#[path = "AuthorityPageApplications.rs"]
mod applications;
#[path = "AuthorityPageHosts.rs"]
mod hosts;
#[path = "AuthorityPageInteractions.rs"]
mod interactions;
#[path = "AuthorityPageMedia.rs"]
pub(crate) mod media;
#[path = "AuthorityPagePublication.rs"]
pub(crate) mod publication;
#[path = "AuthorityPageStatements.rs"]
mod statements;
#[path = "AuthorityPageView.rs"]
mod view;
#[path = "AuthorityPageWorkflow.rs"]
mod workflow;
pub use view::browse;

#[derive(Args)]
pub struct Browse {
    #[command(flatten)]
    online: Online,
    #[command(flatten)]
    capability: Capability,
    #[arg(conflicts_with = "after")]
    uri: Option<String>,
    #[arg(long)]
    namespace: Option<String>,
    #[arg(long)]
    after: Option<String>,
    #[command(flatten)]
    display: Display,
}

#[derive(Args)]
pub struct Display {
    #[arg(long)]
    tui: bool,
    #[arg(long)]
    ascii: bool,
    #[command(flatten)]
    graphics: crate::terminal_graphics::Options,
    /// Bind one asset ID to an explicit canonical local file for inspection.
    #[arg(long = "media")]
    media: Vec<String>,
    #[command(flatten)]
    interactions: interactions::Options,
}
#[derive(Clone, ValueEnum)]
pub enum Decision {
    Approve,
    Reject,
}
#[derive(Subcommand)]
pub enum Command {
    /// Manage explicit Page or media hosting consent.
    Host {
        #[command(subcommand)]
        command: hosts::Command,
    },
    /// Manage jointly signed, native Page permissions for an admitted application.
    Application {
        #[command(subcommand)]
        command: applications::Command,
    },
    /// Request one approved Page from an exact consenting replica host.
    ReplicaRequest {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        page_id: String,
        #[arg(long)]
        host: String,
        #[arg(long)]
        host_generation: u64,
        #[arg(long)]
        host_digest: String,
        #[arg(long)]
        expires_ms: u64,
    },
    /// Check one exact ticket and optionally retain its verified delivered bundle.
    ReplicaResult {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        ticket: String,
        #[arg(long)]
        ticket_generation: u64,
        #[arg(long)]
        ticket_digest: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Validate and display a local inert draft.
    Preview {
        file: PathBuf,
        #[command(flatten)]
        display: Display,
    },
    /// Sign exact source bytes and revision for later explicit submission.
    Author {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        page_id: String,
        #[arg(long)]
        revision: u64,
        #[arg(long)]
        expires_ms: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Submit the exact retained author statement and source for review.
    Submit {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        statement: PathBuf,
        #[arg(long)]
        source: PathBuf,
    },
    /// List current pending revisions within an explicitly permitted namespace.
    Queue {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        after: Option<String>,
    },
    /// Retain and display one exact pending revision for a manual decision.
    Inspect {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        page_id: String,
        #[arg(long)]
        output: PathBuf,
        #[command(flatten)]
        display: Display,
    },
    /// Sign a decision after rechecking the exact retained review input.
    ReviewSign {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        input: PathBuf,
        #[arg(long, value_enum)]
        decision: Decision,
        #[arg(long)]
        expires_ms: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Commit the retained review statement and optional approved bundle.
    Review {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        input: PathBuf,
    },
    /// Withdraw the current publication and pending replacement.
    Withdraw {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        page_id: String,
        #[arg(long)]
        as_reviewer: bool,
    },
    List {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        after: Option<String>,
    },
    /// Verify the current publication and display its approved source.
    Read {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        page_id: String,
        #[arg(long)]
        output: Option<PathBuf>,
        #[command(flatten)]
        display: Display,
    },
}
fn id(text: &str) -> Result<Digest> {
    crate::trust_bootstrap::hex32(text)
}
fn raw(text: &str) -> Result<[u8; 16]> {
    let bytes = hex::decode(text)?;
    ensure!(
        hex::encode(&bytes) == text,
        "Page identity must use canonical lowercase hex"
    );
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Page identity must contain sixteen bytes"))
}
fn source(path: &Path) -> Result<Vec<u8>> {
    let bytes = files::read_public_single(path, crate::authority_objects::PAGE_SOURCE_BYTES)?;
    crate::markup::parse(std::str::from_utf8(&bytes)?).map_err(anyhow::Error::msg)?;
    Ok(bytes)
}
fn input(class: Class, bytes: Vec<u8>) -> Result<Resolved> {
    let reference = Reference::for_bytes(class, &bytes)?;
    Resolved::exact(
        std::slice::from_ref(&reference),
        vec![Object::verify(reference.clone(), bytes)?],
    )
}
fn summary(result: &ResultState) -> Result<()> {
    let f = result.value.array(5)?;
    let body = f[4].array(4)?;
    let scope = result.prefix.scope();
    let records = body[1].list(page::MAXIMUM_CONTEXT_RECORDS)?.iter().map(|v| {
        let r = domain::Record::parse(v.bytes()?, scope.network, scope.incarnation)?;
        let mut value = json!({"kind":r.reference.kind,"id":hex::encode(r.reference.id),"generation":r.reference.generation,"digest":hex::encode(r.reference.digest)});
        if r.reference.kind == 140 {
            let head = page::Ledger::parse(&r.payload)?;
            value["pageId"] = json!(hex::encode(head.raw_page));
            value["namespace"] = json!(head.namespace);
            value["revision"] = json!(head.last_revision);
            value["pending"] = json!(head.pending.is_some());
            value["published"] = json!(head.published.is_some());
        }
        if r.reference.kind == 144 {
            let asset = page::Asset::parse(&r.payload)?;
            value["assetId"] = json!(asset.manifest.id);
            value["bytes"] = json!(asset.manifest.bytes);
            value["sha256"] = json!(asset.manifest.digest);
            value["hosts"] = json!(asset.hosts.iter().map(|h|hex::encode(h.id)).collect::<Vec<_>>());
        }
        Ok(value)
    }).collect::<Result<Vec<_>>>()?;
    crate::print_value(
        &json!({"status":"PageQuorumResult","action":body[0].text()?,"height":result.prefix.height(),"records":records,"next":if body[3]==V::Null{None}else{Some(hex::encode(body[3].bytes()?))}}),
    )
}
pub fn run(command: Command) -> Result<()> {
    workflow::run(command)
}
