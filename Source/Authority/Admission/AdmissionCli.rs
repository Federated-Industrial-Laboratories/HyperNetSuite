// SPDX-License-Identifier: MIT
// Packaged admission commands expose bounded public messages and keep keys in fixed private configuration.
use super::*;
use crate::{
    authority_admission as native,
    authority_inspection::{admission as client, admission::types::*},
    authority_membership::{Snapshot, reference},
    trust_wire::{self as wire, Value as V},
};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{io::Read, path::Path};
#[path = "AdmissionCandidate.rs"]
mod candidate;
#[path = "AdmissionRegistrar.rs"]
mod registrar;

#[derive(Subcommand)]
pub enum Command {
    /// Install a fixed, owner-authorised registrar policy or withdraw its exact purpose.
    Policy {
        #[command(flatten)]
        online: domain_cli::Online,
        #[arg(long)]
        spec: PathBuf,
    },
    /// Run one bounded registrar operation under a fixed private configuration.
    Registrar {
        #[arg(long)]
        configuration: PathBuf,
        #[arg(long, required = true)]
        json_stdin: bool,
    },
    /// Prepare and operate this local user's independently generated role identities.
    Candidate {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        clock_witness: Option<PathBuf>,
        /// Reuse an explicitly selected local profile for the owner-rostered migration.
        #[arg(long, value_name = "ROLE=PROFILE")]
        adopt_profile: Vec<String>,
        #[arg(long, required = true)]
        json_stdin: bool,
    },
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Configuration {
    format: String,
    bootstrap: PathBuf,
    bootstrap_digest: String,
    directory: PathBuf,
    clock_witness: PathBuf,
    #[serde(default)]
    clock_monitor_key: Option<String>,
    #[serde(default)]
    host_kernel_boot: Option<String>,
    key_file: PathBuf,
    socket: PathBuf,
    policy: String,
}
impl Configuration {
    fn location(&self) -> Location {
        Location {
            bootstrap: self.bootstrap.clone(),
            bootstrap_digest: self.bootstrap_digest.clone(),
            directory: self.directory.clone(),
            clock_witness: self.clock_witness.clone(),
            clock_monitor_key: self.clock_monitor_key.clone(),
            host_kernel_boot: self.host_kernel_boot.clone(),
        }
    }
}
pub(super) struct Connection {
    bootstrap: trust_bootstrap::Verified,
    store: Store,
    key: SigningKey,
    session: Session,
    clock: authority_clock::Source,
    socket: PathBuf,
}
impl Connection {
    fn open(location: &Location, key: &Path, socket: &Path) -> Result<Self> {
        let bootstrap = super::bootstrap(location)?;
        let key = domain_cli::signer(key)?;
        let clock = super::clock(location, bootstrap.descriptor().voters())?;
        let mut store = if location.directory.exists() {
            Store::open(&location.directory, bootstrap.descriptor().clone())?
        } else {
            files::create_directory(&location.directory)?;
            let store = Store::initialise(
                &location.directory,
                bootstrap.descriptor().clone(),
                key.verifying_key().to_bytes(),
                clock.health()?,
            )?;
            crate::authority_inspection::ContextState::bootstrap(&bootstrap, &store)?
                .save(&store)?;
            store
        };
        store.require_requester(key.verifying_key().to_bytes())?;
        let mut session = Session::new()?;
        crate::authority_inspection::stream_client::resolve_refusal_local(
            &store.descriptor().clone(),
            socket,
            &key,
            &mut store,
            &mut session,
            || clock.health(),
        )?;
        if store.resume_ordinary()?.is_some() {
            client::mutate(
                &bootstrap,
                socket,
                &key,
                &mut store,
                &mut session,
                &mut || clock.health(),
                None,
            )?;
        }
        // Stream discovery can advance the floor. Complete it before authoring
        // any operation snapshot, never between that snapshot and its signature.
        crate::authority_inspection::stream_client::ensure_stream(
            &store.descriptor().clone(),
            socket,
            &key,
            &mut store,
            &mut session,
            &mut || clock.health(),
        )?;
        Ok(Self {
            bootstrap,
            store,
            key,
            session,
            clock,
            socket: socket.to_path_buf(),
        })
    }
    fn query(
        &mut self,
        policy: [u8; 32],
        claim: Option<[u8; 32]>,
    ) -> Result<(native::Disclosure, Vec<u8>)> {
        client::query(
            &self.bootstrap,
            &self.socket,
            &self.key,
            &mut self.store,
            &mut self.session,
            &mut || self.clock.health(),
            policy,
            claim,
        )
    }
    fn apply(&mut self, operation: native::Operation) -> Result<()> {
        client::mutate(
            &self.bootstrap,
            &self.socket,
            &self.key,
            &mut self.store,
            &mut self.session,
            &mut || self.clock.health(),
            Some(operation),
        )
    }
    fn snapshot(
        &self,
        records: &[Vec<u8>],
        policy: &native::Policy,
        slot: Option<&native::Slot>,
        authority_required: bool,
    ) -> Result<Snapshot> {
        snapshot(
            &self.store,
            self.clock.health()?.observe()?.wall_ms,
            records,
            policy,
            slot,
            authority_required,
        )
    }
}
pub(crate) fn snapshot(
    store: &Store,
    at: u64,
    records: &[Vec<u8>],
    policy: &native::Policy,
    slot: Option<&native::Slot>,
    authority_required: bool,
) -> Result<Snapshot> {
    let scope = store.descriptor().scope();
    let g =
        crate::authority_governance::Governance::parse(scope.network, scope.incarnation, records)?;
    let mut refs = if authority_required {
        policy.authorise(&g, scope.network, at)?
    } else {
        vec![]
    };
    if g.versions().contains(&policy.reference) {
        refs.push(policy.reference.clone());
    }
    if let Some(slot) = slot {
        refs.push(slot.reference.clone());
        refs.extend(crate::authority_governance::Governance::record_versions(
            scope.network,
            scope.incarnation,
            &slot.material,
        )?);
    }
    refs.sort_by_key(crate::authority_proof::VersionRef::index);
    refs.dedup();
    Snapshot::parse(&V::Array(vec![
        V::Array(vec![
            V::Uint(scope.epoch),
            V::Uint(store.prefix().height()),
            V::Bytes(store.prefix().policy_state().to_vec()),
        ]),
        V::Array(refs.iter().map(reference).collect()),
    ]))
}
pub(super) fn id(value: &str) -> Result<[u8; 32]> {
    trust_bootstrap::hex32(value)
}
pub(super) fn bytes(value: &str) -> Result<Vec<u8>> {
    ensure!(
        value.len() <= MAX_OUTPUT_BYTES * 2
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "native artifact must be bounded lowercase hexadecimal"
    );
    Ok(hex::decode(value)?)
}
pub(super) fn record(
    kind: u64,
    id: [u8; 32],
    payload: V,
    snapshot: &Snapshot,
    scope: &crate::authority_proof::Scope,
    old: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let previous = old
        .map(|x| native::record_reference(x, scope.network, scope.incarnation))
        .transpose()?;
    wire::encode(&V::Array(vec![
        V::Uint(kind),
        V::Uint(1),
        V::Bytes(scope.network.to_vec()),
        V::Bytes(scope.incarnation.to_vec()),
        V::Uint(previous.as_ref().map_or(Ok(1), |r| {
            r.generation
                .checked_add(1)
                .context("admission record generation exhausted")
        })?),
        previous.map_or(V::Null, |r| V::Bytes(r.digest.to_vec())),
        V::Bytes(id.to_vec()),
        payload,
        snapshot.value.clone(),
    ]))
}
pub(super) fn binding(slot: &native::Slot) -> Claim {
    Claim {
        policy: hex::encode(slot.policy),
        slot: slot.slot,
        generation: slot.assignment,
        claim: hex::encode(slot.claim),
        request_digest: hex::encode(slot.request),
    }
}
pub(super) fn exact_binding(slot: &native::Slot, expected: &Claim) -> Result<()> {
    ensure!(
        binding(slot) == *expected,
        "admission claim binding differs"
    );
    Ok(())
}
fn input<T: serde::de::DeserializeOwned>() -> Result<T> {
    let mut bytes = vec![];
    std::io::stdin()
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_INPUT_BYTES,
        "admission input exceeds its bound"
    );
    let envelope: Envelope<T> = serde_json::from_slice(&bytes)?;
    ensure!(envelope.format == FORMAT, "admission input version differs");
    Ok(envelope.body)
}
fn output(response: Response) -> Result<()> {
    let bytes = serde_json::to_vec(&Envelope {
        format: FORMAT.into(),
        body: response,
    })?;
    ensure!(
        bytes.len() <= MAX_OUTPUT_BYTES,
        "admission output exceeds its bound"
    );
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    out.write_all(&bytes)?;
    out.write_all(b"\n")?;
    Ok(())
}
pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Policy { online, spec } => registrar::policy(online, &spec),
        Command::Registrar { configuration, .. } => {
            let config: Configuration =
                serde_json::from_slice(&files::read_single(&configuration, 65536, true)?)?;
            ensure!(
                config.format == "HyperNetAdmissionRegistrar/1",
                "registrar configuration version differs"
            );
            let request = input()?;
            output(registrar::run(&config, request)?)
        }
        Command::Candidate {
            directory,
            clock_witness,
            adopt_profile,
            ..
        } => {
            let request = input()?;
            let clock = clock_witness.unwrap_or_else(|| directory.join("Clock/ClockHealth.json"));
            output(candidate::run(&directory, &clock, &adopt_profile, request)?)
        }
    }
}
