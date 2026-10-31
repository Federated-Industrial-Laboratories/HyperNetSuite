// SPDX-License-Identifier: MIT
// Providers receive explicitly selected inert data; only a current native reviewer can apply a decision.
use super::{
    Action, Cache, Capability, Client, Digest, Online, Path, PathBuf, ResultState, V, VersionRef,
    domain, domain_cli, files, id, media, page, publication, raw, statements, wire,
};
use crate::{adapter_files as disclosure, authority_inspection_cli as control};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use clap::{Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;

#[path = "AuthorityReviewAdapterModel.rs"]
mod model;
use model::*;
#[path = "AuthorityReviewAdapterWorkflow.rs"]
mod workflow;

#[derive(Clone, Debug, Serialize, Deserialize, ValueEnum, PartialEq, Eq)]
pub enum Decision {
    Approve,
    Reject,
    Abstain,
}

#[derive(Subcommand)]
pub enum Command {
    /// Disclose one current pending source after explicit plaintext consent.
    #[command(name = "review-export")]
    Export {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        page_id: String,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        purpose: String,
        #[arg(long)]
        policy_digest: String,
        #[arg(long)]
        expires: u64,
        #[arg(long)]
        consent_disclosure: bool,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        receipt: PathBuf,
    },
    /// Validate and display an inert recommendation without network requests.
    #[command(name = "review-import")]
    Import {
        #[command(flatten)]
        location: control::Location,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        receipt: PathBuf,
        #[arg(long)]
        result: PathBuf,
    },
    /// Apply an explicit decision, retaining its exact signed bytes before submission.
    #[command(name = "review-apply")]
    Apply {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        receipt: PathBuf,
        #[arg(long)]
        result: PathBuf,
        #[arg(
            long,
            value_enum,
            conflicts_with = "automatic",
            required_unless_present = "automatic"
        )]
        decision: Option<Decision>,
        /// Requires the exact current application policy with review mode one.
        #[arg(long, conflicts_with = "decision")]
        automatic: bool,
        /// Immutable signed local apply receipt, reused unchanged after interruption.
        #[arg(long)]
        decision_output: PathBuf,
    },
    /// Inspect one exact current asset and disclose it with separate media consent.
    #[command(name = "media-export")]
    MediaExport {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        receipt: PathBuf,
        #[arg(long)]
        asset: String,
        #[command(flatten)]
        transport: media::Transport,
        #[arg(long)]
        progress_directory: PathBuf,
        #[arg(long)]
        consent_media_disclosure: bool,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        media_receipt: PathBuf,
    },
}
pub fn run(command: Command) -> Result<()> {
    workflow::run(command)
}

#[cfg(test)]
#[path = "../../Tests/Unit/Applications/AuthorityReviewAdapterTests.rs"]
mod tests;
