// SPDX-License-Identifier: MIT
// Search scopes are explicit actions; local matching has no network transport dependency.
use crate::{
    authority_floor::Store,
    authority_inspection_cli::{self as control, Location, domain_cli::Capability},
    authority_proof::{Digest, VersionRef},
    search_text::{self, Request},
    trust_bootstrap::Verified,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use serde_json::json;
use std::path::{Path, PathBuf};

#[path = "SearchLibrary.rs"]
pub(crate) mod library;
#[path = "SearchLocal.rs"]
mod local;
#[path = "SearchNetwork.rs"]
mod network;

#[path = "SearchRetain.rs"]
mod retain;
#[path = "SearchSource.rs"]
mod source;

#[derive(Clone, Args)]
pub struct Corpus {
    /// Explicit private retained-content directory.
    #[arg(long)]
    corpus: PathBuf,
    /// Separate private age identity for this retained corpus.
    #[arg(long)]
    corpus_key: PathBuf,
}
#[derive(Clone, Args)]
pub struct Recipient {
    #[arg(long, requires = "recipient_age_key")]
    recipient_vault: Option<PathBuf>,
    #[arg(long, requires = "recipient_vault")]
    recipient_age_key: Option<PathBuf>,
}
impl Recipient {
    fn open(&self, bootstrap: &Verified) -> Result<Option<crate::sealed_vault::Vault>> {
        match (&self.recipient_vault, &self.recipient_age_key) {
            (Some(path), Some(key)) => {
                let s = bootstrap.descriptor().scope();
                Ok(Some(crate::sealed_vault::Vault::open(
                    path,
                    key,
                    s.network,
                    s.incarnation,
                    bootstrap.file_digest(),
                )?))
            }
            (None, None) => Ok(None),
            _ => anyhow::bail!("recipient vault requires its separate age identity"),
        }
    }
}
#[derive(Args)]
pub struct Connection {
    #[command(flatten)]
    location: Location,
    /// Explicit authority relay profile, or a local socket with --local-diagnostics.
    #[arg(long)]
    socket: PathBuf,
    #[arg(long, conflicts_with = "device", required_unless_present = "device")]
    key: Option<PathBuf>,
    /// Recipient device whose signing key remains in the encrypted vault.
    #[arg(long, requires = "recipient_vault", conflicts_with = "key")]
    device: Option<String>,
    #[command(flatten)]
    recipient: Recipient,
    /// Explicit local operator diagnostics; no reader-address privacy claim is made.
    #[arg(long)]
    local_diagnostics: bool,
}
impl Connection {
    fn open(
        &self,
    ) -> Result<(
        crate::authority_pages::Client,
        Option<crate::sealed_vault::Vault>,
    )> {
        network::endpoint(&self.socket, self.local_diagnostics, 1)?;
        let bootstrap = control::bootstrap(&self.location)?;
        let vault = self.recipient.open(&bootstrap)?;
        let signer = match (&self.key, &self.device) {
            (Some(path), None) => control::domain_cli::signer(path)?,
            (None, Some(device)) => vault
                .as_ref()
                .context("recipient device requires its vault")?
                .device_signer(id(device)?)?,
            _ => anyhow::bail!("choose one signing key or recipient device"),
        };
        Ok((
            crate::authority_pages::Client::owned(&self.location, &self.socket, signer)?,
            vault,
        ))
    }
}
#[derive(Clone, Args)]
pub struct Query {
    /// Literal terms; absence lists the authorised catalogue.
    #[arg(long = "term")]
    terms: Vec<String>,
    /// Match any literal term; the default requires every term.
    #[arg(long)]
    any: bool,
    #[arg(long = "namespace")]
    namespaces: Vec<String>,
    #[arg(long, default_value_t = 20)]
    limit: usize,
    #[arg(long)]
    cursor: Option<String>,
}
impl Query {
    fn request(&self, store: &Store, scope: u64, historical: bool) -> Result<Request> {
        let mut namespaces = self
            .namespaces
            .iter()
            .map(|n| crate::authority_domains::page::namespace_id(n))
            .collect::<Result<Vec<_>>>()?;
        namespaces.sort();
        let r = Request {
            network: store.prefix().scope().network,
            incarnation: store.prefix().scope().incarnation,
            operation: rand::random(),
            scope,
            terms: self.terms.clone(),
            combination: u64::from(self.any),
            namespaces,
            limit: self.limit,
            cursor: self.cursor.as_deref().map(id).transpose()?,
            historical,
            snapshot: snapshot(store),
        };
        r.validate()?;
        Ok(r)
    }
}
#[derive(Subcommand)]
pub enum Retain {
    /// Retain an exact current native publication in the encrypted corpus.
    Native {
        #[command(flatten)]
        connection: Connection,
        #[command(flatten)]
        capability: Capability,
        #[command(flatten)]
        corpus: Corpus,
        #[arg(long)]
        page_id: String,
    },
    /// Retain an exact locally approved import through its destination Bridge.
    Imported {
        #[command(flatten)]
        connection: Connection,
        #[command(flatten)]
        capability: Capability,
        #[command(flatten)]
        corpus: Corpus,
        #[arg(long)]
        agreement: String,
        #[arg(long)]
        page_id: String,
        #[arg(long)]
        bridge: PathBuf,
    },
    /// Retain sealed ciphertext; local search still needs the recipient device key.
    Sealed {
        #[command(flatten)]
        connection: Connection,
        #[command(flatten)]
        capability: Capability,
        #[command(flatten)]
        corpus: Corpus,
        #[arg(long)]
        object: String,
        #[arg(long)]
        namespace: String,
    },
}
#[derive(Subcommand)]
pub enum Command {
    /// Create an encrypted corpus without connecting to any network.
    Init {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        corpus: Corpus,
    },
    /// Search only explicitly retained content; query entry never refreshes authority.
    Local {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        corpus: Corpus,
        #[command(flatten)]
        recipient: Recipient,
        #[command(flatten)]
        query: Query,
        /// Read retained approvals without claiming current revocation enforcement.
        #[arg(long)]
        historical: bool,
    },
    /// Send literal terms to the selected network's consenting content and import services.
    Network {
        #[command(flatten)]
        connection: Connection,
        #[command(flatten)]
        capability: Capability,
        #[command(flatten)]
        query: Query,
        /// Explicit import agreement=destination-Bridge-route; repeat to include more imports.
        #[arg(long = "bridge")]
        bridges: Vec<String>,
    },
    #[command(subcommand)]
    Retain(Retain),
    /// Refresh selected retained content and current leases without accepting any query terms.
    Sync {
        #[command(flatten)]
        connection: Connection,
        #[command(flatten)]
        capability: Capability,
        #[command(flatten)]
        corpus: Corpus,
        /// Retained item ID; absence refreshes every retained item within the batch bound.
        #[arg(long = "item")]
        items: Vec<String>,
        #[arg(long = "bridge")]
        bridges: Vec<String>,
    },
    /// Remove one retained publication from this encrypted corpus.
    Forget {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        corpus: Corpus,
        #[arg(long)]
        item: String,
    },
}
fn id(text: &str) -> Result<Digest> {
    crate::trust_bootstrap::hex32(text)
}
fn raw(text: &str) -> Result<[u8; 16]> {
    let bytes = hex::decode(text)?;
    ensure!(
        hex::encode(&bytes) == text,
        "Page identity requires canonical hex"
    );
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Page identity requires sixteen bytes"))
}
fn snapshot(store: &Store) -> V {
    V::Array(vec![
        V::Array(vec![
            V::Uint(store.prefix().scope().epoch),
            V::Uint(store.prefix().height()),
            V::Bytes(store.prefix().policy_state().to_vec()),
        ]),
        V::Array(vec![]),
    ])
}
fn library(corpus: &Corpus, bootstrap: &Verified, store: &Store) -> Result<library::Library> {
    let s = bootstrap.descriptor().scope();
    library::Library::open(
        &corpus.corpus,
        &corpus.corpus_key,
        s.network,
        s.incarnation,
        store.requester(),
        bootstrap.file_digest(),
    )
}
pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Init { location, corpus } => {
            let bootstrap = control::bootstrap(&location)?;
            let store = Store::open(&location.directory, bootstrap.descriptor().clone())?;
            let s = bootstrap.descriptor().scope();
            library::Library::initialise(
                &corpus.corpus,
                &corpus.corpus_key,
                s.network,
                s.incarnation,
                store.requester(),
                bootstrap.file_digest(),
            )?;
            crate::print_value(
                &json!({"status":"SearchCorpusInitialised","network":hex::encode(s.network),"requester":hex::encode(store.requester()),"queryLeavesDevice":false}),
            )
        }
        Command::Local {
            location,
            corpus,
            recipient,
            query,
            historical,
        } => local::run(location, corpus, recipient, query, historical),
        Command::Network {
            connection,
            capability,
            query,
            bridges,
        } => network::run(connection, capability, query, bridges),
        Command::Retain(command) => retain::run(command),
        Command::Sync {
            connection,
            capability,
            corpus,
            items,
            bridges,
        } => retain::sync(connection, capability, corpus, items, bridges),
        Command::Forget {
            location,
            corpus,
            item,
        } => {
            let bootstrap = control::bootstrap(&location)?;
            let store = Store::open(&location.directory, bootstrap.descriptor().clone())?;
            library(&corpus, &bootstrap, &store)?.forget(id(&item)?)?;
            crate::print_value(
                &json!({"status":"SearchPublicationForgotten","queryLeavesDevice":false}),
            )
        }
    }
}

#[cfg(test)]
include!("../../Tests/Support/Search/Search.rs");
