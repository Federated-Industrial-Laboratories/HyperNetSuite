// SPDX-License-Identifier: MIT
// Explicit transfer workflows keep ciphertext local until a named recipient accepts an exact consenting store.
use crate::{
    authority_challenge::Session,
    authority_clock,
    authority_domains::{
        self as domain,
        transfer::{self, Agreement, Command as Action, Effect, Offer, Profile},
    },
    authority_floor::Store,
    authority_inspection::{
        domain_client::{self, Cache, Request as DomainRequest},
        stream_client, transfer_client,
    },
    authority_inspection_cli::{
        self as control, Location,
        domain_cli::{self, Capability, Online},
    },
    authority_proof::Digest,
    transfer_files as files,
    trust_bootstrap::Verified,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    process::Command as Process,
};
#[path = "AuthorityTransferVault.rs"]
mod vault;
use vault::Vault;
#[derive(Args)]
pub struct Arguments {
    #[command(subcommand)]
    command: Command,
}
#[derive(Args)]
pub struct VaultLocation {
    #[arg(long)]
    vault: PathBuf,
    #[arg(long)]
    age_key: PathBuf,
}
#[derive(Args)]
pub struct Transport {
    #[arg(
        long,
        conflicts_with = "service_directory",
        required_unless_present = "service_directory"
    )]
    service_socket: Option<PathBuf>,
    #[arg(long, conflicts_with = "service_socket")]
    service_directory: Option<PathBuf>,
    #[arg(long, default_value = "HyperNet")]
    core: PathBuf,
}
#[derive(Clone, Copy, ValueEnum)]
pub enum Mode {
    Put,
    Commit,
    Fetch,
    Status,
    Delete,
}
impl Mode {
    fn effect(self) -> Effect {
        match self {
            Self::Put => Effect::Put,
            Self::Commit => Effect::Commit,
            Self::Fetch => Effect::Fetch,
            Self::Status => Effect::Status,
            Self::Delete => Effect::Delete,
        }
    }
}
#[derive(Subcommand)]
pub enum Command {
    /// Create a private encrypted vault and independent age recipient key.
    Init {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        key: PathBuf,
        #[command(flatten)]
        vault: VaultLocation,
    },
    /// Sign the exact local opaque-store profile as its deployment operator.
    Profile {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        profile_digest: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        volume: String,
        #[arg(long)]
        state_bytes: u64,
        #[arg(long,default_value_t=transfer::MAXIMUM_PAYLOAD)]
        maximum_payload: u64,
        #[arg(long,default_value_t=transfer::MAXIMUM_LIFETIME_MS)]
        maximum_lifetime_ms: u64,
        #[arg(long)]
        output: PathBuf,
    },
    Register {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        profile: PathBuf,
    },
    Withdraw {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        service: String,
    },
    Hosts {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long, default_value_t = 18)]
        action: u64,
        #[arg(long)]
        after: Option<String>,
    },
    /// Encrypt a file for its named recipient, retain it locally and publish its immutable offer.
    Offer {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[command(flatten)]
        vault: VaultLocation,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        recipient_age: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        expires_ms: u64,
        #[arg(long)]
        label: String,
    },
    /// Publish a previously retained offer after an interrupted authority request.
    Publish {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[command(flatten)]
        vault: VaultLocation,
        #[arg(long)]
        transfer: String,
    },
    List {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long, default_value_t = 19)]
        action: u64,
        #[arg(long)]
        after: Option<String>,
    },
    Inspect {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        transfer: String,
    },
    Outbox {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        key: PathBuf,
        #[command(flatten)]
        vault: VaultLocation,
    },
    /// Accept the immutable age key and select one store and a local destination label.
    Accept {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[command(flatten)]
        vault: VaultLocation,
        #[arg(long)]
        transfer: String,
        #[arg(long)]
        service: String,
        #[arg(long)]
        destination: String,
        #[arg(long)]
        expires_ms: u64,
    },
    Cancel {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        transfer: String,
    },
    Send {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        vault: VaultLocation,
        #[command(flatten)]
        transport: Transport,
        #[arg(long)]
        transfer: String,
        #[arg(long, default_value_t = 0)]
        maximum_chunks: u64,
    },
    Receive {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        vault: VaultLocation,
        #[command(flatten)]
        transport: Transport,
        #[arg(long)]
        transfer: String,
        #[arg(long)]
        destination: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 0)]
        maximum_chunks: u64,
    },
    Status {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        transport: Transport,
        #[arg(long)]
        transfer: String,
    },
    Delete {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        transport: Transport,
        #[arg(long)]
        transfer: String,
    },
    /// Write a tracked request packet for a local headless service exchange.
    Packet {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        transfer: String,
        #[arg(long, value_enum)]
        effect: Mode,
        #[arg(long, default_value_t = 0)]
        offset: u64,
        #[arg(long, default_value_t = 0)]
        bytes: u64,
        #[arg(long)]
        payload: Option<PathBuf>,
        #[arg(long, requires = "age_key", conflicts_with = "payload")]
        vault: Option<PathBuf>,
        #[arg(long, requires = "vault")]
        age_key: Option<PathBuf>,
        #[arg(long)]
        reconcile: bool,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify a store receipt and durably retain received bytes before acknowledging it.
    Receipt {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        vault: VaultLocation,
        #[arg(long)]
        receipt: PathBuf,
    },
    /// Remove only this participant's local retained ciphertext.
    Forget {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        key: PathBuf,
        #[command(flatten)]
        vault: VaultLocation,
        #[arg(long)]
        transfer: String,
    },
}
fn id(value: &str) -> Result<Digest> {
    crate::trust_bootstrap::hex32(value)
}
struct Client {
    bootstrap: Verified,
    key: SigningKey,
    store: Store,
    session: Session,
    clock: authority_clock::Source,
    authority: PathBuf,
    directory: PathBuf,
}
impl Client {
    fn open(online: Online) -> Result<Self> {
        let bootstrap = control::bootstrap(&online.location)?;
        let clock = control::clock(&online.location, bootstrap.descriptor().voters())?;
        let key = domain_cli::signer(&online.key)?;
        let mut store = Store::open(&online.location.directory, bootstrap.descriptor().clone())?;
        let mut session = Session::new()?;
        let descriptor = store.descriptor().clone();
        stream_client::resolve_refusal_local(
            &descriptor,
            &online.socket,
            &key,
            &mut store,
            &mut session,
            || clock.health(),
        )?;
        store.require_requester(key.verifying_key().to_bytes())?;
        Ok(Self {
            bootstrap,
            key,
            store,
            session,
            clock,
            authority: online.socket,
            directory: online.location.directory,
        })
    }
    fn vault(&self, location: &VaultLocation) -> Result<Vault> {
        let s = self.bootstrap.descriptor().scope();
        Vault::open(
            &location.vault,
            &location.age_key,
            s.network,
            s.incarnation,
            self.bootstrap.fingerprint(),
            self.store.requester(),
        )
    }
    fn capability(
        &self,
        cap: Option<Capability>,
    ) -> Result<Option<crate::authority_proof::VersionRef>> {
        domain_cli::capability(
            cap,
            &self.bootstrap,
            &Cache::load(&self.bootstrap, &self.store)?,
        )
    }
    fn action(
        &mut self,
        command: Action,
        grant: Option<crate::authority_proof::VersionRef>,
    ) -> Result<domain_client::ResultState> {
        domain_client::local(
            &self.bootstrap,
            DomainRequest {
                command: command.into(),
                grant,
            },
            &self.authority,
            &self.key,
            &mut self.store,
            &mut self.session,
            || self.clock.health(),
        )
    }
    fn pending(&self) -> Result<bool> {
        Ok(self.store.resume_ordinary()?.is_some())
    }
    fn refresh(&mut self, id: Digest) -> Result<Agreement> {
        if !self.pending()? {
            self.action(Action::Get { id }, None)?;
        }
        self.agreement(id)
    }
    fn agreement(&self, id: Digest) -> Result<Agreement> {
        let cache = Cache::load(&self.bootstrap, &self.store)?;
        Agreement::parse(
            &cache.state.record(135, id)?.payload,
            cache.state.network,
            cache.state.incarnation,
        )
    }
    fn effect(
        &mut self,
        transport: &Transport,
        command: Action,
        payload: &[u8],
        apply: impl FnOnce(&transfer::Request, &[u8]) -> Result<()>,
    ) -> Result<V> {
        transfer_client::ensure(
            &self.bootstrap,
            &mut self.store,
            &self.authority,
            &self.key,
            &mut self.session,
            || self.clock.health(),
        )?;
        let reconcile = self.pending()?;
        let request = transfer_client::prepare(
            &self.bootstrap,
            &self.key,
            &mut self.store,
            command,
            self.clock.health()?,
        )?;
        let packet = transfer_client::packet(&request, payload, reconcile)?;
        let bytes = transport.exchange(&self.directory, &packet)?;
        transfer_client::complete(
            &self.bootstrap,
            &bytes,
            &self.authority,
            &self.key,
            &mut self.store,
            &mut self.session,
            || self.clock.health(),
            |r, b| {
                apply(r, b)?;
                wire::decode(b)
            },
        )
    }
}
impl Transport {
    fn exchange(&self, directory: &Path, packet: &[u8]) -> Result<Vec<u8>> {
        if let Some(socket) = &self.service_socket {
            let control = crate::authority_local_transport::LocalControl::open(socket)?;
            return control.exchange_limit(
                packet,
                crate::authority_challenge::boot_time_ms()?
                    .checked_add(10_000)
                    .context("transfer deadline overflow")?,
                transfer::RECEIPT_LIMIT,
            );
        }
        crate::private_route_client::require_local_allowed()?;
        let service = self
            .service_directory
            .as_ref()
            .context("select an installed local service or private socket")?;
        let temporary = directory.join(format!(
            "TransferExchange{}",
            hex::encode(rand::random::<[u8; 16]>())
        ));
        let _dir = files::create_directory(&temporary)?;
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(temporary.clone());
        let request = temporary.join("Packet.cbor");
        let receipt = temporary.join("Receipt.cbor");
        files::write_new(&request, packet)?;
        let output = Process::new(&self.core)
            .args(["runtime", "services", "exchange", "--directory"])
            .arg(service)
            .arg("--packet")
            .arg(&request)
            .arg("--receipt")
            .arg(&receipt)
            .output()?;
        ensure!(
            output.status.success(),
            "installed transfer exchange failed: {}",
            String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(2048)])
        );
        files::read_single(&receipt, transfer::RECEIPT_LIMIT, true)
    }
}
fn summary(result: domain_client::ResultState) -> Result<()> {
    let value = result.value.array(5)?;
    let body = value[4].array(4)?;
    let mut objects = vec![];
    for raw in body[1].list(16)? {
        let r = domain::Record::parse(
            raw.bytes()?,
            result.cache.state.network,
            result.cache.state.incarnation,
        )?;
        match r.reference.kind {
            134 => {
                let s = transfer::Service::parse(
                    &r.payload,
                    result.cache.state.network,
                    result.cache.state.incarnation,
                )?;
                objects.push(json!({"kind":"TransferService","service":hex::encode(s.profile.service),"generation":r.reference.generation,"withdrawn":s.withdrawn,"stateBytes":s.profile.state_bytes,"maximumPayload":s.profile.maximum_payload}));
            }
            135 => objects.push(offer_summary(&Agreement::parse(
                &r.payload,
                result.cache.state.network,
                result.cache.state.incarnation,
            )?)),
            _ => {}
        }
    }
    crate::print_value(
        &json!({"status":"TransferQuorumResult","committedHeight":result.prefix.height(),"objects":objects,"next":if body[3]==V::Null{None}else{Some(hex::encode(body[3].bytes()?))}}),
    )
}
fn offer_summary(t: &Agreement) -> serde_json::Value {
    json!({"transfer":hex::encode(t.offer.id),"sender":hex::encode(t.offer.sender),"recipient":hex::encode(t.offer.recipient),"recipientAge":t.offer.encryption_key,"label":t.offer.label,"fileBytes":t.offer.file_bytes,"ciphertextBytes":t.offer.payload_bytes,"expiresMs":t.offer.expires,"cancelled":t.cancelled,"accepted":t.acceptance.as_ref().map(|a|json!({"service":hex::encode(a.service.id),"destination":a.destination,"expiresMs":a.expires}))})
}
fn output_effect(value: &V) -> Result<()> {
    let f = value.array(12)?;
    crate::print_value(
        &json!({"status":"TransferEffectReported","transfer":hex::encode(f[3].bytes()?),"effect":f[5].text()?,"storedBytes":f[8].uint()?,"committed":f[9].boolean()?,"deleted":f[10].boolean()?,"currentPermission":false}),
    )
}
fn storage(location: &Location, key: &Path, v: &VaultLocation, create: bool) -> Result<Vault> {
    let accepted = control::bootstrap(location)?;
    let signer = domain_cli::signer(key)?;
    let s = accepted.descriptor().scope();
    if create {
        Vault::initialise(
            &v.vault,
            &v.age_key,
            s.network,
            s.incarnation,
            accepted.fingerprint(),
            signer.verifying_key().to_bytes(),
        )
    } else {
        Vault::open(
            &v.vault,
            &v.age_key,
            s.network,
            s.incarnation,
            accepted.fingerprint(),
            signer.verifying_key().to_bytes(),
        )
    }
}
fn execute(id: Digest, effect: Effect, offset: u64, bytes: u64, digest: Option<Digest>) -> Action {
    Action::Execute {
        id,
        effect,
        offset,
        bytes,
        digest,
    }
}
fn fresh_effect(c: &mut Client, t: &Transport, id: Digest, effect: Effect) -> Result<V> {
    c.effect(t, execute(id, effect, 0, 0, None), &[], |_, _| Ok(()))
}
fn pending_effect(c: &Client, id: Digest) -> Result<Option<Action>> {
    let Some(r) = transfer_client::pending(&c.store)? else {
        return Ok(None);
    };
    ensure!(
        matches!(r.command(),Action::Execute{id:other,..} if *other==id),
        "another transfer is pending; recover its exact request first"
    );
    Ok(Some(r.command().clone()))
}
fn send(c: &mut Client, v: &Vault, t: &Transport, id: Digest, maximum: u64) -> Result<()> {
    let (offer, cipher) = v.outgoing(id)?;
    let accepted = c.refresh(id)?;
    ensure!(
        accepted.offer.envelope == offer.envelope,
        "retained outgoing offer differs from accepted agreement"
    );
    if let Some(command) = pending_effect(c, id)? {
        match &command {
            Action::Execute {
                effect: Effect::Put,
                offset,
                bytes,
                ..
            } => {
                let end = offset
                    .checked_add(*bytes)
                    .context("pending extent overflow")?;
                let data = cipher
                    .get(*offset as usize..end as usize)
                    .context("pending chunk exceeds retained ciphertext")?;
                c.effect(t, command, data, |_, _| Ok(()))?;
            }
            Action::Execute {
                effect: Effect::Commit | Effect::Status,
                ..
            } => {
                c.effect(t, command, &[], |_, _| Ok(()))?;
            }
            _ => anyhow::bail!("pending recipient operation cannot be resumed by send"),
        }
    }
    let mut state = fresh_effect(c, t, id, Effect::Status)?;
    let f = state.array(12)?;
    ensure!(!f[10].boolean()?, "transfer has been deleted");
    let mut offset = f[8].uint()?;
    let mut count = 0;
    while offset < offer.payload_bytes && (maximum == 0 || count < maximum) {
        let end = (offset + transfer::CHUNK).min(offer.payload_bytes);
        let data = &cipher[offset as usize..end as usize];
        state = c.effect(
            t,
            execute(
                id,
                Effect::Put,
                offset,
                end - offset,
                Some(wire::digest(data)),
            ),
            data,
            |_, _| Ok(()),
        )?;
        offset = end;
        count += 1;
    }
    if offset == offer.payload_bytes && !state.array(12)?[9].boolean()? {
        state = fresh_effect(c, t, id, Effect::Commit)?;
    }
    output_effect(&state)
}
fn receive(
    c: &mut Client,
    v: &mut Vault,
    t: &Transport,
    id: Digest,
    destination: &str,
    output: &Path,
    maximum: u64,
) -> Result<()> {
    let agreement = c.refresh(id)?;
    let offer = &agreement.offer;
    ensure!(
        offer.recipient == c.store.requester() && offer.encryption_key == v.recipient(),
        "transfer was not offered to this verified recipient key"
    );
    ensure!(
        agreement
            .acceptance
            .as_ref()
            .is_some_and(|a| a.destination == destination),
        "destination differs from explicit acceptance"
    );
    if let Some(command) = pending_effect(c, id)? {
        match &command {
            Action::Execute {
                effect: Effect::Fetch,
                offset,
                ..
            } => {
                let offset = *offset;
                c.effect(t, command, &[], |_, b| {
                    let val = wire::decode(b)?;
                    v.receive(offer, offset, val.array(12)?[11].bytes()?)
                })?;
            }
            Action::Execute {
                effect: Effect::Status,
                ..
            } => {
                c.effect(t, command, &[], |_, _| Ok(()))?;
            }
            _ => anyhow::bail!("pending sender operation cannot be resumed by receive"),
        }
    }
    let mut offset = v.received(offer)?.len() as u64;
    let mut count = 0;
    while offset < offer.payload_bytes && (maximum == 0 || count < maximum) {
        let bytes = transfer::CHUNK.min(offer.payload_bytes - offset);
        c.effect(
            t,
            execute(id, Effect::Fetch, offset, bytes, None),
            &[],
            |_, b| {
                let value = wire::decode(b)?;
                v.receive(offer, offset, value.array(12)?[11].bytes()?)
            },
        )?;
        offset += bytes;
        count += 1;
    }
    if offset < offer.payload_bytes {
        return crate::print_value(
            &json!({"status":"TransferReceiveRetained","transfer":hex::encode(id),"ciphertextBytes":offset,"complete":false}),
        );
    }
    let (header, plain) = v.open_file(offer)?;
    files::write_new(output, &plain)?;
    crate::print_value(
        &json!({"status":"TransferReceived","transfer":hex::encode(id),"fileName":header.file_name,"fileBytes":header.file_bytes,"output":output}),
    )
}
fn publish(c: &mut Client, cap: Capability, v: &Vault, id: Digest) -> Result<()> {
    let (offer, _) = v.outgoing(id)?;
    let grant = c.capability(Some(cap))?;
    if !c.pending()? {
        c.action(
            Action::Context {
                action: 18,
                scope_kind: 2,
                resource: id,
            },
            grant.clone(),
        )?;
    }
    let result = c.action(Action::Offer { offer }, grant)?;
    summary(result)
}
pub fn run(_configuration: Option<&Path>, arguments: Arguments) -> Result<()> {
    match arguments.command {
        Command::Init {
            location,
            key,
            vault,
        } => {
            let v = storage(&location, &key, &vault, true)?;
            crate::print_value(
                &json!({"status":"TransferVaultInitialised","recipientAge":v.recipient()}),
            )
        }
        Command::Profile {
            location,
            manifest,
            profile_digest,
            key,
            volume,
            state_bytes,
            maximum_payload,
            maximum_lifetime_ms,
            output,
        } => {
            let accepted = control::bootstrap(&location)?;
            let m = crate::runtime_manifest::Manifest::parse(&files::read_public_single(
                &manifest,
                crate::runtime_manifest::MAXIMUM,
            )?)?;
            let scope = accepted.descriptor().scope();
            ensure!(
                m.network == scope.network
                    && m.incarnation == scope.incarnation
                    && m.bootstrap_digest == accepted.file_digest()
                    && wire::digest(&m.desired()?) == id(&profile_digest)?,
                "manifest differs from independently reviewed deployment"
            );
            let signer = domain_cli::signer(&key)?;
            ensure!(
                signer.verifying_key().to_bytes() == m.operator,
                "profile signer is not the deployment operator"
            );
            let service = *m
                .services()
                .get(&4)
                .context("deployment has no transfer store role")?;
            ensure!(
                m.roles
                    .iter()
                    .filter(|r| r.role == 4)
                    .all(|r| r.bind_endpoint_ids.is_empty() && r.outbound_endpoint_ids.is_empty()),
                "local transfer profile requires no network endpoints"
            );
            let p = Profile {
                manifest: m,
                service,
                endpoint: None,
                volume: id(&volume)?,
                state_bytes,
                maximum_payload,
                maximum_lifetime_ms,
                envelope: vec![],
            };
            let signed = wire::sign_envelope(&p.payload()?, &signer)?;
            Profile::parse(&signed, scope.network, scope.incarnation)?;
            files::write_new(&output, &signed)?;
            crate::print_value(
                &json!({"status":"TransferProfileSigned","service":hex::encode(service),"profileDigest":hex::encode(wire::digest(&signed)),"output":output}),
            )
        }
        Command::Register {
            online,
            capability,
            profile,
        } => {
            let mut c = Client::open(online)?;
            let scope = c.bootstrap.descriptor().scope();
            let p = Profile::parse(
                &files::read_public_single(&profile, crate::runtime_manifest::MAXIMUM + 1024)?,
                scope.network,
                scope.incarnation,
            )?;
            let grant = c.capability(Some(capability))?;
            if !c.pending()? {
                c.action(
                    Action::Context {
                        action: 26,
                        scope_kind: 5,
                        resource: p.manifest.deployment,
                    },
                    grant.clone(),
                )?;
            }
            let r = c.action(Action::Register { profile: p }, grant)?;
            summary(r)
        }
        Command::Withdraw { online, service } => {
            let mut c = Client::open(online)?;
            let service = id(&service)?;
            let generation = if let Some(p) = c.store.resume_ordinary()? {
                let intent = crate::authority_proof::Intent::from_signed(p.signed())?;
                match domain::Operation::parse(&intent)?.command {
                    domain::Command::Transfer(Action::Withdraw {
                        service: s,
                        generation,
                    }) if s == service => generation,
                    _ => anyhow::bail!("another exact domain operation is pending"),
                }
            } else {
                c.action(
                    Action::Service {
                        service,
                        action: 18,
                    },
                    None,
                )?
                .cache
                .state
                .record(134, service)?
                .reference
                .generation
            };
            let r = c.action(
                Action::Withdraw {
                    service,
                    generation,
                },
                None,
            )?;
            summary(r)
        }
        Command::Hosts {
            online,
            capability,
            action,
            after,
        } => {
            ensure!(matches!(action, 18 | 19), "select transfer action18 or19");
            let mut c = Client::open(online)?;
            let grant = c.capability(Some(capability))?;
            let r = c.action(
                Action::Services {
                    network: c.bootstrap.descriptor().scope().network,
                    action,
                    after: after.map(|v| id(&v)).transpose()?,
                },
                grant,
            )?;
            summary(r)
        }
        Command::Offer {
            online,
            capability,
            vault,
            recipient,
            recipient_age,
            file,
            expires_ms,
            label,
        } => {
            let mut c = Client::open(online)?;
            ensure!(
                !c.pending()?,
                "another request is pending; resume it before preparing a new offer"
            );
            let mut v = c.vault(&vault)?;
            let plain = zeroize::Zeroizing::new(files::read_public_single(
                &file,
                transfer::MAXIMUM_PAYLOAD as usize,
            )?);
            let scope = c.bootstrap.descriptor().scope();
            let mut offer = Offer {
                network: scope.network,
                incarnation: scope.incarnation,
                id: rand::random(),
                sender: c.store.requester(),
                recipient: id(&recipient)?,
                encryption_key: recipient_age,
                payload_bytes: 0,
                payload_digest: [0; 32],
                file_bytes: plain.len() as u64,
                label,
                expires: expires_ms,
                envelope: vec![],
            };
            let name = file
                .file_name()
                .and_then(|v| v.to_str())
                .context("file name is not UTF-8")?;
            let cipher = vault::seal(&offer, name, &plain)?;
            offer.payload_bytes = cipher.len() as u64;
            offer.payload_digest = wire::digest(&cipher);
            let signed = wire::sign_envelope(&offer.payload()?, &c.key)?;
            let offer = Offer::parse(&signed, scope.network, scope.incarnation)?;
            v.insert(&offer, &cipher)?;
            publish(&mut c, capability, &v, offer.id)
        }
        Command::Publish {
            online,
            capability,
            vault,
            transfer,
        } => {
            let mut c = Client::open(online)?;
            let v = c.vault(&vault)?;
            publish(&mut c, capability, &v, id(&transfer)?)
        }
        Command::List {
            online,
            capability,
            action,
            after,
        } => {
            ensure!(matches!(action, 18 | 19), "select transfer action18 or19");
            let mut c = Client::open(online)?;
            let grant = c.capability(Some(capability))?;
            let r = c.action(
                Action::List {
                    network: c.bootstrap.descriptor().scope().network,
                    action,
                    after: after.map(|v| id(&v)).transpose()?,
                },
                grant,
            )?;
            summary(r)
        }
        Command::Inspect { online, transfer } => {
            let mut c = Client::open(online)?;
            let r = c.action(Action::Get { id: id(&transfer)? }, None)?;
            summary(r)
        }
        Command::Outbox {
            location,
            key,
            vault,
        } => {
            let v = storage(&location, &key, &vault, false)?;
            crate::print_value(
                &json!({"recipientAge":v.recipient(),"offers":v.outbox()?.iter().map(|o|json!({"transfer":hex::encode(o.id),"recipient":hex::encode(o.recipient),"recipientAge":o.encryption_key,"label":o.label,"fileBytes":o.file_bytes,"expiresMs":o.expires})).collect::<Vec<_>>()}),
            )
        }
        Command::Accept {
            online,
            capability,
            vault,
            transfer,
            service,
            destination,
            expires_ms,
        } => {
            let mut c = Client::open(online)?;
            let v = c.vault(&vault)?;
            let transfer = id(&transfer)?;
            let a = c.refresh(transfer)?;
            ensure!(
                a.offer.recipient == c.store.requester() && a.offer.encryption_key == v.recipient(),
                "offer is not bound to this recipient's independently retained encryption key"
            );
            let service = id(&service)?;
            let grant = c.capability(Some(capability))?;
            if !c.pending()? {
                c.action(
                    Action::Service {
                        service,
                        action: 19,
                    },
                    grant.clone(),
                )?;
            }
            let r = c.action(
                Action::Accept {
                    id: transfer,
                    service,
                    destination,
                    expires: expires_ms,
                },
                grant,
            )?;
            summary(r)
        }
        Command::Cancel { online, transfer } => {
            let mut c = Client::open(online)?;
            let transfer = id(&transfer)?;
            c.refresh(transfer)?;
            let r = c.action(Action::Cancel { id: transfer }, None)?;
            summary(r)
        }
        Command::Send {
            online,
            vault,
            transport,
            transfer,
            maximum_chunks,
        } => {
            let mut c = Client::open(online)?;
            let v = c.vault(&vault)?;
            send(&mut c, &v, &transport, id(&transfer)?, maximum_chunks)
        }
        Command::Receive {
            online,
            vault,
            transport,
            transfer,
            destination,
            output,
            maximum_chunks,
        } => {
            let mut c = Client::open(online)?;
            let mut v = c.vault(&vault)?;
            receive(
                &mut c,
                &mut v,
                &transport,
                id(&transfer)?,
                &destination,
                &output,
                maximum_chunks,
            )
        }
        Command::Status {
            online,
            transport,
            transfer,
        } => {
            let mut c = Client::open(online)?;
            let id = id(&transfer)?;
            c.refresh(id)?;
            let result = fresh_effect(&mut c, &transport, id, Effect::Status)?;
            output_effect(&result)
        }
        Command::Delete {
            online,
            transport,
            transfer,
        } => {
            let mut c = Client::open(online)?;
            let id = id(&transfer)?;
            c.refresh(id)?;
            let result = fresh_effect(&mut c, &transport, id, Effect::Delete)?;
            output_effect(&result)
        }
        Command::Packet {
            online,
            transfer,
            effect,
            offset,
            bytes,
            payload,
            vault,
            age_key,
            reconcile,
            output,
        } => {
            let mut c = Client::open(online)?;
            let transfer = id(&transfer)?;
            let accepted = c.refresh(transfer)?;
            let e = effect.effect();
            let data = if let Some(path) = vault {
                ensure!(e == Effect::Put, "vault payload applies only to Put");
                let v = c.vault(&VaultLocation {
                    vault: path,
                    age_key: age_key.context("vault requires its age identity")?,
                })?;
                let (offer, ciphertext) = v.outgoing(transfer)?;
                ensure!(
                    offer.envelope == accepted.offer.envelope,
                    "vault differs from the accepted offer"
                );
                ensure!(bytes <= transfer::CHUNK, "transfer chunk exceeds its bound");
                let end = offset
                    .checked_add(bytes)
                    .context("transfer extent overflow")?;
                ensure!(
                    end <= ciphertext.len() as u64,
                    "transfer extent exceeds retained ciphertext"
                );
                ciphertext[offset as usize..end as usize].to_vec()
            } else {
                payload
                    .map(|p| files::read_public_single(&p, transfer::CHUNK as usize))
                    .transpose()?
                    .unwrap_or_default()
            };
            transfer_client::ensure(
                &c.bootstrap,
                &mut c.store,
                &c.authority,
                &c.key,
                &mut c.session,
                || c.clock.health(),
            )?;
            ensure!(
                (e == Effect::Put && data.len() as u64 == bytes)
                    || (e != Effect::Put && data.is_empty()),
                "payload differs from finite effect extent"
            );
            let cmd = execute(
                transfer,
                e,
                offset,
                bytes,
                (e == Effect::Put).then(|| wire::digest(&data)),
            );
            let s = c.bootstrap.descriptor().scope();
            let cmd = Action::parse(&cmd.value(), s.network, s.incarnation)?;
            let request = transfer_client::prepare(
                &c.bootstrap,
                &c.key,
                &mut c.store,
                cmd,
                c.clock.health()?,
            )?;
            files::write_new(
                &output,
                &transfer_client::packet(&request, &data, reconcile)?,
            )?;
            crate::print_value(
                &json!({"status":"TransferPacketPrepared","intent":hex::encode(request.intent().digest),"output":output}),
            )
        }
        Command::Receipt {
            online,
            vault,
            receipt,
        } => {
            let mut c = Client::open(online)?;
            let mut v = c.vault(&vault)?;
            let bytes = files::read_single(&receipt, transfer::RECEIPT_LIMIT, true)?;
            let parsed = transfer::Receipt::parse(&bytes)?;
            let descriptor = c.store.descriptor_for_scope(&parsed.scope()?)?;
            let report = parsed.verify(&c.bootstrap, &descriptor)?;
            let request = transfer_client::pending(&c.store)?
                .context("receipt has no pending transfer request")?;
            let offer =
                if report.result().disposition() == crate::authority_proof::Disposition::Permit {
                    Some(
                        request
                            .result_agreement(&crate::authority_proof::OperationResult::parse(
                                report.result().operation_result_bytes(),
                            )?)?
                            .1
                            .offer,
                    )
                } else {
                    None
                };
            let response = transfer_client::complete(
                &c.bootstrap,
                &bytes,
                &c.authority,
                &c.key,
                &mut c.store,
                &mut c.session,
                || c.clock.health(),
                |r, b| {
                    let value = wire::decode(b)?;
                    if let Action::Execute {
                        effect: Effect::Fetch,
                        offset,
                        ..
                    } = r.command()
                    {
                        v.receive(
                            offer.as_ref().context("missing accepted offer")?,
                            *offset,
                            value.array(12)?[11].bytes()?,
                        )?;
                    }
                    Ok(value)
                },
            )?;
            output_effect(&response)
        }
        Command::Forget {
            location,
            key,
            vault,
            transfer,
        } => {
            let mut v = storage(&location, &key, &vault, false)?;
            v.forget(id(&transfer)?)?;
            crate::print_value(&json!({"status":"TransferLocalDataForgotten","transfer":transfer}))
        }
    }
}
