// SPDX-License-Identifier: MIT
//! Separate offline profiles preserve predecessor state and durable recovery conflicts.
use super::*;
use crate::authority_epoch::archive;

use crate::authority_recovery as recovery;
use clap::Args;
use std::{collections::BTreeMap, ffi::OsStr, fs::File};

const LEDGER: &str = "RecoveryState.json";
// Profile, bootstrap, sixteen declarations and JSON encoding, plus the bounded epoch archive.
const LEDGER_LIMIT: usize = 3 * 1024 * 1024 + archive::MAX_ARCHIVE_BYTES;
#[derive(Args)]
pub struct PredecessorArgs {
    /// Existing requester floor retaining the latest authenticated recovery policy.
    #[arg(long)]
    predecessor_directory: PathBuf,
    #[arg(long)]
    predecessor_bootstrap: PathBuf,
    /// Independently authenticated complete predecessor bootstrap fingerprint.
    #[arg(long)]
    predecessor_fingerprint: String,
}
#[derive(Subcommand)]
pub enum Command {
    /// Propose a fresh, fully accepted bootstrap; do not copy permissions or private state.
    Draft {
        #[command(flatten)]
        predecessor: PredecessorArgs,
        #[arg(long)]
        successor_bootstrap: PathBuf,
        /// Optional inventory commitment. This command never imports its contents.
        #[arg(long)]
        historical_import_digest: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Sign the exact inspected declaration with one predecessor offline custody key.
    Sign {
        #[command(flatten)]
        predecessor: PredecessorArgs,
        #[arg(long)]
        draft: PathBuf,
        /// Independently inspected unsigned declaration digest.
        #[arg(long)]
        declaration_digest: String,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Combine independently produced shares without activating a successor.
    Assemble {
        #[command(flatten)]
        predecessor: PredecessorArgs,
        #[arg(long)]
        draft: PathBuf,
        #[arg(long,required=true,num_args=1..=3)]
        share: Vec<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify proposal structure or threshold signatures without accepting new trust.
    Inspect {
        #[command(flatten)]
        predecessor: PredecessorArgs,
        #[arg(long)]
        declaration: PathBuf,
        #[arg(long)]
        unsigned: bool,
    },
    /// Create one private, conflict-retaining ledger for an existing client profile.
    Initialise {
        #[arg(long)]
        predecessor_directory: PathBuf,
        #[arg(long)]
        previous_profile: PathBuf,
        #[arg(long)]
        directory: PathBuf,
    },
    /// Retain a verified declaration before detecting conflicts; never choose a winner.
    Observe {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        declaration: PathBuf,
    },
    /// Accept independently authenticated new trust into a separate offline profile.
    Accept {
        #[arg(long)]
        previous_profile: PathBuf,
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        declaration: PathBuf,
        #[arg(long)]
        successor_bootstrap: PathBuf,
        /// Exact successor bootstrap fingerprint verified through an independent channel.
        #[arg(long)]
        successor_fingerprint: String,
        #[arg(long)]
        output_profile: PathBuf,
        #[arg(long)]
        output_acceptance: PathBuf,
    },
    /// Inspect retained declarations, conflicts and acceptance without exposing keys.
    Status {
        #[arg(long)]
        directory: PathBuf,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Binding {
    directory: PathBuf,
    declaration_digest: String,
    acceptance_digest: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Accepted {
    declaration_digest: String,
    fingerprint: String,
    acceptance: String,
    profile: String,
    profile_path: PathBuf,
    acceptance_path: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ledger {
    format: String,
    bootstrap: String,
    predecessor_directory: PathBuf,
    client: String,
    declarations: BTreeMap<String, String>,
    saturated: bool,
    accepted: Option<Accepted>,
}
struct Store {
    directory: File,
    _lock: files::ProfileLock,
    state: Ledger,
}

fn retained_predecessor(bootstrap: &[u8], directory: &Path) -> Result<recovery::Predecessor> {
    let checked = trust::inspect(bootstrap, true)?;
    let store = crate::authority_floor::Store::open(directory, checked.descriptor().clone())?;
    let (_, policy) = crate::authority_inspection::policy::current(&checked, &store)?;
    let scope = checked.descriptor().scope();
    let reference = crate::authority_policies::record_reference(
        &policy,
        scope.network,
        scope.incarnation,
        114,
    )?;
    recovery::Predecessor::retained(&checked, store.prefix(), &policy, &reference)
}
fn inputs(args: &PredecessorArgs) -> Result<recovery::Predecessor> {
    let bytes = files::read_public_single(&args.predecessor_bootstrap, trust_wire::MAXIMUM)?;
    fingerprint(&bytes, &args.predecessor_fingerprint)?;
    retained_predecessor(&bytes, &args.predecessor_directory)
}

fn absolute_directory(path: &Path) -> Result<PathBuf> {
    files::private_directory(path)?;
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    })
}
fn absolute(path: &Path) -> Result<PathBuf> {
    let value = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let parent = value.parent().context("output parent missing")?;
    files::private_directory(parent)?;
    ensure!(value.file_name().is_some(), "output filename missing");
    Ok(value)
}
fn identity_key(identity: &Identity) -> Result<SigningKey> {
    let secret = Zeroizing::new(trust::hex32(&identity.secret_key)?);
    let key = SigningKey::from_bytes(&secret);
    ensure!(
        hex::encode(key.verifying_key().to_bytes()) == identity.public_key,
        "identity key pair differs"
    );
    Ok(key)
}
impl Ledger {
    fn predecessor(&self) -> Result<recovery::Predecessor> {
        retained_predecessor(&hex::decode(&self.bootstrap)?, &self.predecessor_directory)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.format == "HyperNetRecoveryLedger/1"
                && self.declarations.len() <= recovery::MAX_CONFLICTS,
            "unsupported or oversized recovery ledger"
        );
        let client = trust::hex32(&self.client)?;
        trust_wire::valid_key(&client)?;
        let prior = self.predecessor()?;
        for (digest, envelope) in &self.declarations {
            ensure!(
                hex::encode(
                    recovery::verify(&prior, &hex::decode(envelope)?)?
                        .declaration()
                        .digest()
                ) == *digest,
                "retained recovery declaration digest differs"
            );
        }
        if let Some(accepted) = &self.accepted {
            let envelope = self
                .declarations
                .get(&accepted.declaration_digest)
                .context("accepted declaration missing")?;
            let declaration = recovery::verify(&prior, &hex::decode(envelope)?)?;
            let profile: Profile = serde_json::from_slice(&hex::decode(&accepted.profile)?)?;
            let bootstrap = hex::decode(&profile.bootstrap)?;
            ensure!(
                profile.fingerprint == accepted.fingerprint,
                "accepted bootstrap fingerprint differs"
            );
            fingerprint(&bootstrap, &accepted.fingerprint)?;
            recovery::verify_acceptance(
                &declaration,
                &bootstrap,
                &hex::decode(&accepted.acceptance)?,
                client,
            )?;
            let binding = profile
                .recovery
                .as_ref()
                .context("recovered profile lacks conflict binding")?;
            ensure!(
                binding.declaration_digest == accepted.declaration_digest
                    && binding.acceptance_digest
                        == hex::encode(trust_wire::digest(&hex::decode(&accepted.acceptance)?)),
                "recovered profile binding differs"
            );
        }
        Ok(())
    }
    fn conflicts(&self) -> bool {
        self.saturated || self.declarations.len() > 1
    }
}
impl Store {
    fn open(path: &Path) -> Result<Self> {
        let directory = files::private_directory(path)?;
        let lock = files::profile_lock(&directory, OsStr::new(LEDGER))?;
        let bytes = Zeroizing::new(files::read_at(
            &directory,
            OsStr::new(LEDGER),
            LEDGER_LIMIT,
            true,
        )?);
        let state: Ledger = serde_json::from_slice(&bytes)?;
        state.validate()?;
        Ok(Self {
            directory,
            _lock: lock,
            state,
        })
    }
    fn save(&self) -> Result<()> {
        self.state.validate()?;
        let bytes = Zeroizing::new(serde_json::to_vec(&self.state)?);
        ensure!(
            bytes.len() <= LEDGER_LIMIT,
            "recovery ledger exceeds capacity"
        );
        files::atomic_at(&self.directory, OsStr::new(LEDGER), &bytes, true)
    }
    fn observe(&mut self, envelope: &[u8]) -> Result<recovery::ValidatedDeclaration> {
        let value = recovery::verify(&self.state.predecessor()?, envelope)?;
        let digest = hex::encode(value.declaration().digest());
        if !self.state.declarations.contains_key(&digest) {
            if self.state.declarations.len() == recovery::MAX_CONFLICTS {
                self.state.saturated = true;
            } else {
                self.state
                    .declarations
                    .insert(digest, hex::encode(envelope));
            }
            // The restrictive observation survives an acceptance failure or restart.
            self.save()?;
        }
        ensure!(
            !self.state.conflicts(),
            "RecoveryConflict: conflicting declarations are retained; no automatic successor is selected"
        );
        Ok(value)
    }
}
fn publish_exact(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.try_exists()? {
        ensure!(
            files::read_single(path, PROFILE_LIMIT, true)? == bytes,
            "recovery output already exists with different bytes"
        );
        Ok(())
    } else {
        output(path, bytes)
    }
}
pub(super) fn verify_profile_binding(profile: &Profile) -> Result<()> {
    let Some(binding) = &profile.recovery else {
        return Ok(());
    };
    let store = Store::open(&binding.directory)?;
    ensure!(
        !store.state.conflicts(),
        "RecoveryConflict: the accepted profile has observed conflicting succession"
    );
    let accepted = store
        .state
        .accepted
        .as_ref()
        .context("independent recovery acceptance missing")?;
    ensure!(
        binding.declaration_digest == accepted.declaration_digest
            && serde_json::to_vec(profile)? == hex::decode(&accepted.profile)?,
        "recovered profile differs from its retained independent acceptance"
    );
    Ok(())
}
pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Draft {
            predecessor: args,
            successor_bootstrap,
            historical_import_digest,
            output: destination,
        } => {
            let prior = inputs(&args)?;
            let next = files::read_public_single(&successor_bootstrap, trust_wire::MAXIMUM)?;
            let historical = historical_import_digest
                .as_deref()
                .map(trust::hex32)
                .transpose()?;
            let draft = recovery::draft(&prior, &next, random(), random(), historical)?;
            output(&destination, draft.payload())?;
            crate::print_value(&json!(draft.inspect()))
        }
        Command::Sign {
            predecessor: args,
            draft,
            declaration_digest,
            identity,
            output: destination,
        } => {
            let prior = inputs(&args)?;
            let bytes = files::read_public_single(&draft, recovery::MAX_DECLARATION)?;
            ensure!(
                trust_wire::digest(&bytes) == trust::hex32(&declaration_digest)?,
                "inspected declaration digest differs"
            );
            let raw = Zeroizing::new(files::read_single(&identity, 4096, true)?);
            let key = identity_key(&serde_json::from_slice(&raw)?)?;
            output(&destination, &recovery::sign(&prior, &bytes, &key)?)?;
            crate::print_value(
                &json!({"state":"RecoveryShare","declarationDigest":declaration_digest,"networkUsed":false,"currentAuthority":false}),
            )
        }
        Command::Assemble {
            predecessor: args,
            draft,
            share,
            output: destination,
        } => {
            let prior = inputs(&args)?;
            let bytes = files::read_public_single(&draft, recovery::MAX_DECLARATION)?;
            let shares = share
                .iter()
                .map(|p| files::read_public_single(p, recovery::MAX_DECLARATION))
                .collect::<Result<Vec<_>>>()?;
            let validated = recovery::assemble(&prior, &bytes, &shares)?;
            output(&destination, validated.envelope())?;
            crate::print_value(&json!(validated.summary()))
        }
        Command::Inspect {
            predecessor: args,
            declaration,
            unsigned,
        } => {
            let prior = inputs(&args)?;
            let bytes = files::read_public_single(&declaration, recovery::MAX_DECLARATION)?;
            crate::print_value(&json!(if unsigned {
                recovery::inspect_draft(&prior, &bytes)?.inspect()
            } else {
                recovery::verify(&prior, &bytes)?.summary()
            }))
        }
        Command::Initialise {
            predecessor_directory,
            previous_profile,
            directory,
        } => {
            let (profile, _) = load(&previous_profile)?;
            let state = Ledger {
                format: "HyperNetRecoveryLedger/1".into(),
                bootstrap: profile.bootstrap,
                predecessor_directory: absolute_directory(&predecessor_directory)?,
                client: profile.device.public_key.clone(),
                declarations: BTreeMap::new(),
                saturated: false,
                accepted: None,
            };
            state.validate()?;
            let dir = files::create_directory(&directory)?;
            let bytes = Zeroizing::new(serde_json::to_vec(&state)?);
            files::atomic_at(&dir, OsStr::new(LEDGER), &bytes, false)?;
            crate::print_value(
                &json!({"state":"RecoveryLedgerInitialised","networkUsed":false,"currentAuthority":false}),
            )
        }
        Command::Observe {
            directory,
            declaration,
        } => {
            let bytes = files::read_public_single(&declaration, recovery::MAX_DECLARATION)?;
            let mut store = Store::open(&directory)?;
            let value = store.observe(&bytes)?;
            crate::print_value(&json!(value.summary()))
        }
        Command::Accept {
            previous_profile,
            directory,
            declaration,
            successor_bootstrap,
            successor_fingerprint,
            output_profile,
            output_acceptance,
        } => {
            // Load before locking this ledger: an older recovered profile has its own predecessor ledger.
            let (old, _) = load(&previous_profile)?;
            let next = files::read_public_single(&successor_bootstrap, trust_wire::MAXIMUM)?;
            fingerprint(&next, &successor_fingerprint)?;
            let current = trust::check(&next, true, time()?)?;
            let envelope = files::read_public_single(&declaration, recovery::MAX_DECLARATION)?;
            let profile_path = absolute(&output_profile)?;
            let acceptance_path = absolute(&output_acceptance)?;
            ensure!(
                profile_path != absolute(&previous_profile)? && profile_path != acceptance_path,
                "recovery outputs must be separate from the predecessor profile"
            );
            let ledger_directory = if directory.is_absolute() {
                directory
            } else {
                std::env::current_dir()?.join(directory)
            };
            let mut store = Store::open(&ledger_directory)?;
            ensure!(
                store.state.bootstrap == old.bootstrap
                    && store.state.client == old.device.public_key,
                "recovery ledger is bound to another predecessor client"
            );
            let validated = store.observe(&envelope)?;
            validated
                .declaration()
                .exact_predecessor(&store.state.predecessor()?)?;
            validated.declaration().verify_successor(&next)?;
            let declaration_digest = hex::encode(validated.declaration().digest());
            if let Some(accepted) = &store.state.accepted {
                ensure!(
                    accepted.declaration_digest == declaration_digest
                        && accepted.fingerprint == successor_fingerprint
                        && accepted.profile_path == profile_path
                        && accepted.acceptance_path == acceptance_path,
                    "independent recovery acceptance is already bound to another decision or output"
                );
            } else {
                let signed = recovery::accept(
                    &validated,
                    &next,
                    trust::hex32(&successor_fingerprint)?,
                    &identity_key(&old.device)?,
                    &[],
                )?;
                let profile = Profile {
                    format: "HyperNetOfflineClient/1".into(),
                    bootstrap: hex::encode(&next),
                    fingerprint: successor_fingerprint.clone(),
                    descriptor_digest: current.summary.descriptor_digest.clone(),
                    client_id: hex::encode(random()),
                    device: identity(),
                    relay_identity: identity(),
                    minimum_route: old.minimum_route,
                    accepted_relay_domains: vec![current.summary.route.relay_domain.clone()],
                    required_publication_modes: old.required_publication_modes,
                    permit_network_search: old.permit_network_search,
                    recovery: None,
                    joined: None,
                };
                // Preserve the client's minimum privacy and publication requirements before publishing anything.
                verify_profile(&profile, &next, true)?;
                let mut profile = profile;
                profile.recovery = Some(Binding {
                    directory: ledger_directory,
                    declaration_digest: declaration_digest.clone(),
                    acceptance_digest: hex::encode(trust_wire::digest(&signed)),
                });
                let encoded = Zeroizing::new(serde_json::to_vec(&profile)?);
                ensure!(
                    encoded.len() <= PROFILE_LIMIT,
                    "recovered profile exceeds capacity"
                );
                store.state.accepted = Some(Accepted {
                    declaration_digest: declaration_digest.clone(),
                    fingerprint: successor_fingerprint,
                    acceptance: hex::encode(&signed),
                    profile: hex::encode(&encoded),
                    profile_path,
                    acceptance_path,
                });
                store.save()?;
            }
            let accepted = store.state.accepted.as_ref().expect("saved acceptance");
            publish_exact(
                &accepted.acceptance_path,
                &hex::decode(&accepted.acceptance)?,
            )?;
            let profile = Zeroizing::new(hex::decode(&accepted.profile)?);
            publish_exact(&accepted.profile_path, &profile)?;
            crate::print_value(
                &json!({"state":"IndependentlyAcceptedOfflineSuccessor","declarationDigest":declaration_digest,
                "profile":accepted.profile_path,"acceptance":accepted.acceptance_path,"networkUsed":false,"currentAuthority":false,
                "membership":false,"inheritedPermissions":false,"historicalImportPerformed":false}),
            )
        }
        Command::Status { directory } => {
            let store = Store::open(&directory)?;
            crate::print_value(
                &json!({"state":if store.state.conflicts(){"RecoveryConflict"}else if store.state.accepted.is_some(){"IndependentlyAcceptedOfflineSuccessor"}else{"AwaitingIndependentAcceptance"},
                "observedDeclarations":store.state.declarations.keys().collect::<Vec<_>>(),"capacityExhausted":store.state.saturated,
                "acceptedDeclaration":store.state.accepted.as_ref().map(|a|&a.declaration_digest),"networkUsed":false,"currentAuthority":false}),
            )
        }
    }
}
#[cfg(test)]
#[path = "../../Tests/Unit/Authority/AuthorityRecoveryCliTests.rs"]
mod tests;

#[cfg(test)]
include!("../../Tests/Support/Authority/AuthorityRecoveryCli.rs");
