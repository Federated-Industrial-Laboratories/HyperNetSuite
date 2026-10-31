// SPDX-License-Identifier: MIT
// Federation keeps independently accepted networks, source authors and local publication decisions distinct.
use crate::{
    authority_challenge::Session,
    authority_clock,
    authority_domains::{
        self as domain,
        federation::{self as fed, Command as Action},
        page,
    },
    authority_floor::Store,
    authority_inspection::{
        domain_client::{self, Cache, Request, ResultState},
        stream_client,
    },
    authority_inspection_cli::{
        self as control, Location,
        domain_cli::{self, Capability, Online},
    },
    authority_objects::Resolved,
    authority_proof::{Digest, Intent, VersionRef},
    transfer_files as files,
    trust_bootstrap::{self, Verified},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::path::{Path, PathBuf};
#[path = "NativeFederationCli.rs"]
mod cli;
pub use cli::Command;
#[path = "NativeFederationConnection.rs"]
mod connection;
use connection::Client;
#[path = "NativeFederationConsent.rs"]
mod consent;
#[path = "NativeFederationExchange.rs"]
mod exchange;
#[path = "NativeFederationMedia.rs"]
mod media;
#[path = "NativeFederationPages.rs"]
mod pages;
pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Trust { command } => consent::trust(command),
        Command::Treaty { command } => consent::treaty(command),
        Command::Bridge { command } => consent::bridge(command),
        Command::ShareSign { .. }
        | Command::Share { .. }
        | Command::ShareStatus { .. }
        | Command::Unshare { .. } => consent::share(command),
        Command::Media { command } => media::run(command),
        _ => pages::run(command),
    }
}
fn id(text: &str) -> Result<Digest> {
    trust_bootstrap::hex32(text)
}
fn raw(text: &str) -> Result<[u8; 16]> {
    ensure!(
        text.len() == 32
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "Page identity requires 16 lowercase hex bytes"
    );
    hex::decode(text)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Page identity length differs"))
}
fn reference(r: &VersionRef) -> Result<String> {
    Ok(hex::encode(wire::encode(
        &crate::authority_membership::reference(r),
    )?))
}
fn read(path: &Path) -> Result<Vec<u8>> {
    files::read_single(path, wire::MAXIMUM, true)
}
fn summary(result: &ResultState) -> Result<()> {
    let v = result.value.array(5)?;
    let body = v[4].array(4)?;
    let s = result.prefix.scope();
    let records = body[1].list(fed::MAXIMUM_CONTEXT_RECORDS)?.iter().map(|v| {
        let r = domain::Record::parse(v.bytes()?, s.network, s.incarnation)?;
        Ok(json!({"kind":r.reference.kind,"id":hex::encode(r.reference.id),"generation":r.reference.generation,
            "digest":hex::encode(r.reference.digest),"reference":reference(&r.reference)?}))
    }).collect::<Result<Vec<_>>>()?;
    crate::print_value(
        &json!({"status":"FederationVerified","action":body[0].text()?,"height":result.prefix.height(),
        "records":records,"next":if body[3] == V::Null {None} else {Some(hex::encode(body[3].fixed::<32>()?))}}),
    )
}
#[cfg(test)]
#[path = "../../Tests/Unit/Federation/NativeFederationTests.rs"]
mod tests;
