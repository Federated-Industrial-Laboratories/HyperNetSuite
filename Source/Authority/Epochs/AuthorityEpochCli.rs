// SPDX-License-Identifier: MIT
//! Offline quorum collection and explicit adoption preserve the initial independent trust pin.
use super::*;
use crate::{
    authority_epoch as epoch, authority_inspection::epoch_client as client,
    authority_proof::TrustDescriptor,
};
use anyhow::Context;
use std::path::Path;

#[derive(Args)]
pub struct Pin {
    #[arg(long)]
    bootstrap: PathBuf,
    /// SHA256 of the full bootstrap, authenticated through an independent channel.
    #[arg(long)]
    bootstrap_digest: String,
    /// Verified predecessor epoch archive; omit only for the initial committee.
    #[arg(long)]
    prior_epochs: Option<PathBuf>,
}
#[derive(Args)]
pub struct Consumer {
    #[arg(long)]
    bootstrap: PathBuf,
    #[arg(long)]
    bootstrap_digest: String,
    #[arg(long)]
    directory: PathBuf,
}
#[derive(Subcommand)]
pub enum Command {
    /// Bind a NetworkAdmin grant and four admitted deployments to the exact retained state.
    Draft {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        grant: String,
        #[arg(long, num_args = 4)]
        deployment: Vec<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Submit exactly one drafted transition; this halts a successful old committee.
    Propose {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        declaration: PathBuf,
    },
    /// Combine three or four old terminal checkpoint shares.
    Checkpoint {
        #[command(flatten)]
        pin: Pin,
        #[arg(long, num_args=3..=4)]
        share: Vec<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Combine three or four old handoff shares for one successor.
    Handoff {
        #[command(flatten)]
        pin: Pin,
        #[arg(long, num_args=3..=4)]
        share: Vec<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Combine three or four durably installed successor readiness shares.
    Ready {
        #[command(flatten)]
        pin: Pin,
        #[arg(long)]
        transition: PathBuf,
        /// History from the predecessor epoch genesis, for fresh installation.
        #[arg(long)]
        history: PathBuf,
        #[arg(long, num_args=3..=4)]
        share: Vec<PathBuf>,
        #[arg(long)]
        ready_output: PathBuf,
        #[arg(long)]
        transition_output: PathBuf,
        /// Verified archive including this activation for a later committee replacement.
        #[arg(long)]
        epochs_output: PathBuf,
    },
    /// Export the exact retained floor and tree checkpoint required by a history producer.
    Retained {
        #[command(flatten)]
        consumer: Consumer,
        #[arg(long)]
        output: PathBuf,
    },
    /// Retain terminal evidence durably and stop all old-epoch effects.
    Seal {
        #[command(flatten)]
        consumer: Consumer,
        #[arg(long)]
        transition: PathBuf,
        #[arg(long)]
        history: PathBuf,
    },
    /// Adopt the matching ready quorum while preserving pending requests and restrictive floors.
    Activate {
        #[command(flatten)]
        consumer: Consumer,
        #[arg(long)]
        transition: PathBuf,
        #[arg(long)]
        history: PathBuf,
        #[arg(long)]
        ready: PathBuf,
    },
}
fn initial(path: &Path, pin: &str) -> Result<trust_bootstrap::Verified> {
    let bytes = files::read_single(path, trust_wire::MAXIMUM, true)?;
    ensure!(
        Sha256::digest(&bytes).as_slice() == trust_bootstrap::hex32(pin)?,
        "Bootstrap differs from the independently authenticated digest"
    );
    let bootstrap = trust_bootstrap::inspect(&bytes, true)?;
    ensure!(
        bootstrap.fully_accepted(),
        "Bootstrap custody is not fully accepted"
    );
    Ok(bootstrap)
}
fn pinned(pin: &Pin) -> Result<(TrustDescriptor, Vec<epoch::archive::Activated>)> {
    let bootstrap = initial(&pin.bootstrap, &pin.bootstrap_digest)?;
    let epochs = pin
        .prior_epochs
        .as_ref()
        .map(|p| -> Result<Vec<epoch::archive::Activated>> {
            Ok(serde_json::from_slice(&files::read_single(
                p,
                epoch::archive::MAX_ARCHIVE_BYTES,
                true,
            )?)?)
        })
        .transpose()?
        .unwrap_or_default();
    let descriptor = epoch::archive::resolve(bootstrap.descriptor(), &epochs)?.descriptor;
    Ok((descriptor, epochs))
}
fn open(consumer: &Consumer) -> Result<Store> {
    let bootstrap = initial(&consumer.bootstrap, &consumer.bootstrap_digest)?;
    Store::open(&consumer.directory, bootstrap.descriptor().clone())
}
fn output(path: &Path, bytes: &[u8]) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    files::private_directory(absolute.parent().context("Output parent missing")?)?;
    if absolute.exists() {
        ensure!(
            files::read_single(&absolute, bytes.len().max(1), true)? == bytes,
            "Existing epoch output differs; no file replaced"
        );
    } else {
        files::write_new(&absolute, bytes)?;
    }
    Ok(())
}
fn shares(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>> {
    paths
        .iter()
        .map(|p| files::read_single(p, 131072, true))
        .collect()
}
fn terminal(store: &Store, transition: &Path, history: &Path) -> Result<epoch::ValidatedTerminal> {
    store.verify_epoch_terminal(
        &files::read_single(transition, 131072, true)?,
        &files::read_single(history, trust_wire::MAXIMUM, true)?,
    )
}
pub fn run(command: Command) -> Result<()> {
    let result = match command {
        Command::Draft {
            location,
            grant,
            deployment,
            output: path,
        } => {
            let bootstrap = bootstrap(&location)?;
            let store = Store::open(&location.directory, bootstrap.descriptor().clone())?;
            let source = clock(&location, store.descriptor().voters())?;
            let context = ContextState::load(&bootstrap, &store, &location.directory)?;
            let deployments = deployment
                .iter()
                .map(|d| trust_bootstrap::hex32(d))
                .collect::<Result<Vec<_>>>()?;
            let declaration = client::draft(
                &bootstrap,
                &context,
                &store,
                trust_bootstrap::hex32(&grant)?,
                &deployments,
                source.health()?,
            )?;
            output(&path, &declaration.bytes)?;
            json!({"status":"Drafted","nextEpoch":declaration.next_epoch,
                "declarationDigest":hex::encode(declaration.digest()),"preStateHeight":declaration.snapshot.height})
        }
        Command::Propose {
            location,
            key,
            socket,
            declaration,
        } => {
            let bootstrap = bootstrap(&location)?;
            let mut store = Store::open(&location.directory, bootstrap.descriptor().clone())?;
            let source = clock(&location, store.descriptor().voters())?;
            let declaration = epoch::Declaration::parse(&files::read_single(
                &declaration,
                epoch::MAX_DECLARATION,
                true,
            )?)?;
            let key = signer(&key)?;
            let mut session = Session::new()?;
            crate::authority_inspection::policy::require_accepted(&bootstrap, &store)?;
            let prefix = client::propose_local(
                &declaration,
                &socket,
                &key,
                &mut store,
                &mut session,
                || source.health(),
            )?;
            json!({"status":"TerminalCommitted","epoch":prefix.scope().epoch,"height":prefix.height(),
                "nextEpoch":declaration.next_epoch,"declarationDigest":hex::encode(declaration.digest())})
        }
        Command::Checkpoint {
            pin,
            share,
            output: path,
        } => {
            let (descriptor, _) = pinned(&pin)?;
            let bytes = epoch::assemble_checkpoint(&descriptor, &shares(&share)?)?;
            output(&path, &bytes)?;
            json!({"status":"TerminalCheckpointCollected","digest":hex::encode(trust_wire::digest(&bytes))})
        }
        Command::Handoff {
            pin,
            share,
            output: path,
        } => {
            let (descriptor, _) = pinned(&pin)?;
            let bytes = epoch::assemble_handoff(&descriptor, &shares(&share)?)?;
            output(&path, &bytes)?;
            json!({"status":"HandoffCollected","digest":hex::encode(trust_wire::digest(&bytes))})
        }
        Command::Ready {
            pin,
            transition,
            history,
            share,
            ready_output,
            transition_output,
            epochs_output,
        } => {
            let (descriptor, mut epochs) = pinned(&pin)?;
            let evidence = files::read_single(&transition, 131072, true)?;
            let terminal = epoch::verify_terminal(
                &descriptor,
                &descriptor.genesis()?,
                None,
                &evidence,
                &files::read_single(&history, trust_wire::MAXIMUM, true)?,
            )?;
            let activation = epoch::assemble_ready(terminal.clone(), &shares(&share)?)?;
            let seal = epoch::archive::Seal::new(
                &terminal,
                epoch::archive::Retained {
                    certificate: None,
                    node: None,
                    checkpoint: None,
                },
            )?;
            epochs.push(seal.activate(&activation)?);
            let archive = serde_json::to_vec_pretty(&epochs)?;
            ensure!(
                archive.len() <= epoch::archive::MAX_ARCHIVE_BYTES,
                "Epoch archive byte budget exhausted"
            );
            let mut fields = trust_wire::decode(&evidence)?.array(8)?.to_vec();
            fields[5] = Value::Bytes(activation.ready().to_vec());
            output(&ready_output, activation.ready())?;
            output(
                &transition_output,
                &trust_wire::encode(&Value::Array(fields))?,
            )?;
            output(&epochs_output, &archive)?;
            json!({"status":"ReadyQuorumCollected","epoch":activation.descriptor()?.scope().epoch})
        }
        Command::Retained {
            consumer,
            output: path,
        } => {
            let store = open(&consumer)?;
            output(&path, &serde_json::to_vec_pretty(&store.epoch_retained()?)?)?;
            json!({"status":"RetainedExported","epoch":store.descriptor().scope().epoch,"height":store.prefix().height()})
        }
        Command::Seal {
            consumer,
            transition,
            history,
        } => {
            let mut store = open(&consumer)?;
            let terminal = terminal(&store, &transition, &history)?;
            store.seal_epoch(&terminal)?;
            json!({"status":"EpochSealed","epoch":store.descriptor().scope().epoch})
        }
        Command::Activate {
            consumer,
            transition,
            history,
            ready,
        } => {
            let mut store = open(&consumer)?;
            let terminal = terminal(&store, &transition, &history)?;
            let activation =
                epoch::verify_activation(terminal, &files::read_single(&ready, 2048, true)?)?;
            store.activate_epoch(&activation)?;
            json!({"status":"EpochActivated","epoch":store.descriptor().scope().epoch,"height":store.prefix().height()})
        }
    };
    crate::print_value(&result)
}
