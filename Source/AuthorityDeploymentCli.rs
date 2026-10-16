// SPDX-License-Identifier: MIT
// Explicit offline consent precedes scoped deployment registration and durable local withdrawal.
use super::*;
use crate::{
    authority_deployments::Offer,
    authority_inspection::{
        deployment_client::{self as client, Cache, Request},
        stream_client,
    },
    authority_proof::Intent,
    runtime_manifest::{self, Manifest},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, bail};
use clap::ValueEnum;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use rand::RngCore;
use std::path::Path;
use zeroize::Zeroizing;

#[derive(Args)]
pub struct Offline {
    #[arg(long)]
    bootstrap: PathBuf,
    /// SHA256 independently authenticated for the complete accepted bootstrap.
    #[arg(long)]
    bootstrap_digest: String,
}
#[derive(Args)]
pub struct Online {
    #[command(flatten)]
    location: Location,
    /// Private identity JSON or installed raw 32-byte Ed25519 key.
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    socket: PathBuf,
}
#[derive(Clone, Copy, ValueEnum)]
pub enum Class {
    Service,
    Transport,
    Monitor,
}
impl Class {
    fn number(self) -> u64 {
        match self {
            Self::Service => 0,
            Self::Transport => 1,
            Self::Monitor => 2,
        }
    }
}
#[derive(Subcommand)]
pub enum Command {
    /// Import the serving recipient's historical completion after checking the current outgoing stream.
    ActivationComplete {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        receipt: PathBuf,
    },
    /// Save one tracked manager request for activation by its dedicated serving recipient.
    ActivationRequest {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        deployment: String,
        #[arg(long)]
        grant: String,
        #[arg(long)]
        role: u64,
        #[arg(long)]
        generation: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate strict manifest JSON and write its single canonical representation.
    Prepare {
        #[command(flatten)]
        trust: Offline,
        #[arg(long)]
        manifest_json: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Sign the exact displayed profile as its operator; this does not register or activate it.
    Consent {
        #[command(flatten)]
        trust: Offline,
        #[arg(long)]
        manifest: PathBuf,
        /// RecordDigest of profile117, checked against the reviewed manifest.
        #[arg(long)]
        profile_digest: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Sign purpose-bound possession using a service, TLS transport, or monitor key.
    Possess {
        #[command(flatten)]
        trust: Offline,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, value_enum)]
        class: Class,
        #[arg(long, required_unless_present = "tls_key", conflicts_with = "tls_key")]
        key: Option<PathBuf>,
        /// Ed25519 PKCS8 PEM, only for the Transport class.
        #[arg(long, required_unless_present = "key", conflicts_with = "key")]
        tls_key: Option<PathBuf>,
        #[arg(long)]
        not_before_ms: u64,
        #[arg(long)]
        expires_ms: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Import exact signed consent and all possession envelopes without contacting a host.
    Assemble {
        #[command(flatten)]
        trust: Offline,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        consent: PathBuf,
        #[arg(long, required = true)]
        possession: Vec<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    InspectOffer {
        #[command(flatten)]
        trust: Offline,
        #[arg(long)]
        offer: PathBuf,
    },
    /// Discover only the selected registrar capability and immutable roots.
    Context {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        deployment: String,
        #[arg(long)]
        grant: String,
    },
    /// Admit the exact operator consent and all permanent service identities.
    Register {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        grant: String,
        #[arg(long)]
        offer: PathBuf,
    },
    /// Commit retained signed operational successors in order, including expired non-serving intermediates.
    Synchronise {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        grant: String,
        #[arg(long)]
        offers_directory: PathBuf,
    },
    /// Inspect as a current registrar, or omit grant for the recorded operator.
    Get {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        deployment: String,
        #[arg(long)]
        grant: Option<String>,
    },
    /// Publish a restriction after a signed assertion of durable local withdrawal.
    Withdraw {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        deployment: String,
        /// Signed HyperNetLocalWithdrawal after the host durably sets its local veto.
        #[arg(long)]
        local_withdrawal: PathBuf,
    },
}
fn id(value: &str) -> Result<[u8; 32]> {
    trust_bootstrap::hex32(value)
}
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
fn offline(trust: &Offline) -> Result<trust_bootstrap::Verified> {
    let bytes = files::read_single(&trust.bootstrap, wire::MAXIMUM, true)?;
    ensure!(
        Sha256::digest(&bytes).as_slice() == id(&trust.bootstrap_digest)?,
        "bootstrap differs from independently verified digest"
    );
    trust_bootstrap::inspect(&bytes, true)
}
fn bind(manifest: &Manifest, verified: &trust_bootstrap::Verified, pin: [u8; 32]) -> Result<()> {
    let scope = verified.descriptor().scope();
    ensure!(
        verified.fully_accepted()
            && manifest.network == scope.network
            && manifest.incarnation == scope.incarnation
            && manifest.bootstrap_digest == pin,
        "manifest differs from accepted bootstrap"
    );
    Ok(())
}
fn manifest(trust: &Offline, path: &Path) -> Result<Manifest> {
    let verified = offline(trust)?;
    let parsed = Manifest::parse(&files::read_public_single(path, runtime_manifest::MAXIMUM)?)?;
    bind(&parsed, &verified, id(&trust.bootstrap_digest)?)?;
    Ok(parsed)
}
fn offer(bytes: &[u8]) -> Result<Offer> {
    let value = wire::decode(bytes)?;
    let f = value.array(6)?;
    ensure!(
        f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "AuthorityDeploymentOffer",
        "unexpected deployment offer"
    );
    Offer::parse(f[3].bytes()?, f[4].bytes()?, &f[5])
}
fn offer_bytes(offer: &Offer) -> Result<Vec<u8>> {
    let bytes = wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("AuthorityDeploymentOffer".into()),
        b(&offer.manifest_bytes),
        b(&offer.consent),
        offer.possessions_value(),
    ]))?;
    ensure!(
        bytes.len() <= 98304,
        "deployment offer exceeds command envelope budget"
    );
    Ok(bytes)
}
fn output(status: &str, manifest: &Manifest) -> Result<()> {
    crate::print_value(
        &json!({"status":status,"deployment":hex::encode(manifest.deployment),"profileDigest":hex::encode(wire::digest(&manifest.desired()?)),"consentDigest":hex::encode(wire::digest(&manifest.unsigned_consent(0)?)),"manifest":manifest,"currentPermission":false}),
    )
}
fn deployment_signer(path: &Path) -> Result<SigningKey> {
    let bytes = Zeroizing::new(files::read_single(path, 8192, true)?);
    if bytes.len() == 32 {
        return Ok(SigningKey::from_bytes(bytes.as_slice().try_into()?));
    }
    let identity: crate::Identity = serde_json::from_slice(&bytes)
        .context("key must be private identity JSON or a raw 32-byte Ed25519 seed")?;
    let secret = Zeroizing::new(id(&identity.secret_key)?);
    let signer = SigningKey::from_bytes(&secret);
    ensure!(
        hex::encode(signer.verifying_key().to_bytes()) == identity.public_key,
        "identity key pair does not match"
    );
    Ok(signer)
}
fn possession_key(class: Class, key: Option<&Path>, tls_key: Option<&Path>) -> Result<SigningKey> {
    match (key, tls_key) {
        (Some(path), None) => deployment_signer(path),
        (None, Some(path)) => {
            ensure!(
                matches!(class, Class::Transport),
                "TLS private keys sign only Transport possession"
            );
            let bytes = Zeroizing::new(files::read_single(path, 8192, true)?);
            let text = std::str::from_utf8(&bytes).context("TLS key is not PEM text")?;
            SigningKey::from_pkcs8_pem(text).context("TLS key must be Ed25519 PKCS8 PEM")
        }
        _ => bail!("provide exactly one identity JSON or TLS PEM key"),
    }
}
fn sign_possession(
    manifest: &Manifest,
    class: Class,
    signer: &SigningKey,
    start: u64,
    end: u64,
) -> Result<Vec<u8>> {
    let key = signer.verifying_key().to_bytes();
    let matches = match class {
        Class::Service => manifest.roles.iter().any(|r| r.service_key == key),
        Class::Transport => manifest.owned_transports()?.into_values().any(|k| k == key),
        Class::Monitor => manifest.clock.monitor_key == key,
    };
    ensure!(
        matches
            && start >= manifest.validity.0
            && end <= manifest.validity.1
            && start < end
            && end - start <= 86400000,
        "possession key or validity differs from approved manifest"
    );
    let mut nonce = [0; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut nonce)?;
    ensure!(nonce != [0; 32], "possession nonce generation failed");
    wire::sign_envelope(
        &Offer::possession(manifest, class.number(), key, nonce, (start, end))?,
        signer,
    )
}
#[allow(
    clippy::too_many_arguments,
    reason = "Keep protocol inputs, state and validation callbacks explicit."
)]
fn scoped(
    verified: &trust_bootstrap::Verified,
    online: &Online,
    deployment: [u8; 32],
    grant: [u8; 32],
    pending_action: Option<&str>,
    signer: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    source: &authority_clock::Source,
) -> Result<Cache> {
    if let Some(pending) = store.resume_ordinary()? {
        let intent = Intent::from_signed(pending.signed())?;
        if intent.action != "AuthorityDeploymentContext" {
            ensure!(
                pending_action == Some(intent.action.as_str()) && intent.resource == deployment,
                "another exact deployment request remains unresolved"
            );
            return Cache::load(verified, store, deployment, Some(grant));
        }
    }
    Ok(client::local(
        verified,
        Request::Context { grant, deployment },
        None,
        &online.socket,
        signer,
        store,
        session,
        || source.health(),
    )?
    .cache)
}
enum Work {
    Context([u8; 32], [u8; 32]),
    Register([u8; 32], PathBuf),
    Get([u8; 32], Option<[u8; 32]>),
    Withdraw([u8; 32], PathBuf),
}
fn connected(online: Online, work: Work) -> Result<()> {
    let verified = bootstrap(&online.location)?;
    let signer = deployment_signer(&online.key)?;
    let mut store = Store::open(&online.location.directory, verified.descriptor().clone())?;
    let source = clock(&online.location, store.descriptor().voters())?;
    store.require_requester(signer.verifying_key().to_bytes())?;
    let mut session = Session::new()?;
    stream_client::resolve_refusal_local(
        &store.descriptor().clone(),
        &online.socket,
        &signer,
        &mut store,
        &mut session,
        || source.health(),
    )?;
    let (status, result) = match work {
        Work::Context(deployment, grant) => (
            "DeploymentContext",
            client::local(
                &verified,
                Request::Context { grant, deployment },
                None,
                &online.socket,
                &signer,
                &mut store,
                &mut session,
                || source.health(),
            )?,
        ),
        Work::Register(grant, path) => {
            let offer = offer(&files::read_public_single(&path, 98304)?)?;
            bind(
                &offer.manifest,
                &verified,
                id(&online.location.bootstrap_digest)?,
            )?;
            let context = scoped(
                &verified,
                &online,
                offer.manifest.deployment,
                grant,
                Some("AuthorityDeploymentRegister"),
                &signer,
                &mut store,
                &mut session,
                &source,
            )?;
            let request = Request::Register {
                grant: context.version(102, grant)?,
                historical: false,
                offer,
            };
            (
                "DeploymentRegistered",
                client::local(
                    &verified,
                    request,
                    Some(&context),
                    &online.socket,
                    &signer,
                    &mut store,
                    &mut session,
                    || source.health(),
                )?,
            )
        }
        Work::Get(deployment, grant) => {
            let context = if let Some(grant) = grant {
                Some(scoped(
                    &verified,
                    &online,
                    deployment,
                    grant,
                    Some("AuthorityDeploymentGet"),
                    &signer,
                    &mut store,
                    &mut session,
                    &source,
                )?)
            } else {
                None
            };
            (
                "DeploymentState",
                client::local(
                    &verified,
                    Request::Get { deployment, grant },
                    context.as_ref(),
                    &online.socket,
                    &signer,
                    &mut store,
                    &mut session,
                    || source.health(),
                )?,
            )
        }
        Work::Withdraw(deployment, path) => {
            let receipt = files::read_public_single(&path, 4096)?;
            // Authenticate the local assertion before making even an intrinsic network lookup.
            let (payload, signatures) = wire::envelope(&receipt, 1)?;
            let value = wire::decode(&payload)?;
            let f = value.array(10)?;
            let scope = verified.descriptor().scope();
            ensure!(
                f[0].uint()? == 200
                    && f[1].uint()? == 1
                    && f[2].text()? == "HyperNetLocalWithdrawal"
                    && f[3].fixed::<32>()? == scope.network
                    && f[4].fixed::<32>()? == scope.incarnation
                    && f[5].fixed::<32>()? == deployment
                    && f[6].fixed::<32>()? == signer.verifying_key().to_bytes()
                    && signatures.len() == 1
                    && signatures[0].0 == signer.verifying_key().to_bytes(),
                "local withdrawal assertion has another operator or scope"
            );
            let cache = if let Some(pending) = store.resume_ordinary()? {
                let intent = Intent::from_signed(pending.signed())?;
                if intent.action == "AuthorityDeploymentWithdraw" {
                    ensure!(
                        intent.resource == deployment,
                        "another deployment withdrawal remains unresolved"
                    );
                    Cache::load(&verified, &store, deployment, None)?
                } else {
                    ensure!(
                        intent.action == "AuthorityDeploymentGet" && intent.resource == deployment,
                        "another exact request remains unresolved"
                    );
                    client::local(
                        &verified,
                        Request::Get {
                            deployment,
                            grant: None,
                        },
                        None,
                        &online.socket,
                        &signer,
                        &mut store,
                        &mut session,
                        || source.health(),
                    )?
                    .cache
                }
            } else {
                client::local(
                    &verified,
                    Request::Get {
                        deployment,
                        grant: None,
                    },
                    None,
                    &online.socket,
                    &signer,
                    &mut store,
                    &mut session,
                    || source.health(),
                )?
                .cache
            };
            let (admission, generation) = cache.withdrawal(&receipt)?;
            (
                "DeploymentWithdrawn",
                client::local(
                    &verified,
                    Request::Withdraw {
                        admission,
                        generation,
                    },
                    Some(&cache),
                    &online.socket,
                    &signer,
                    &mut store,
                    &mut session,
                    || source.health(),
                )?,
            )
        }
    };
    crate::print_value(
        &json!({"status":status,"deployment":hex::encode(result.cache.deployment),"committedHeight":result.prefix.height(),"value":diagnostic(result.value),"currentPermission":false}),
    )
}
fn synchronise(online: Online, grant: [u8; 32], directory: &Path) -> Result<()> {
    let verified = bootstrap(&online.location)?;
    let signer = deployment_signer(&online.key)?;
    let mut store = Store::open(&online.location.directory, verified.descriptor().clone())?;
    store.require_requester(signer.verifying_key().to_bytes())?;
    let source = clock(&online.location, store.descriptor().voters())?;
    let mut session = Session::new()?;
    let mut paths = std::fs::read_dir(directory)?
        .map(|entry| Ok(entry?.path()))
        .collect::<Result<Vec<_>>>()?;
    paths.sort();
    let mut target = None;
    let mut previous: Option<Manifest> = None;
    let mut final_generation = 0;
    for path in paths {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .context("Invalid retained offer filename")?;
        ensure!(
            name.starts_with("Generation") && name.ends_with(".cbor"),
            "Unexpected retained offer entry"
        );
        let offer = offer(&files::read_public_single(&path, 98304)?)?;
        bind(
            &offer.manifest,
            &verified,
            id(&online.location.bootstrap_digest)?,
        )?;
        if let Some(old) = &previous {
            offer.manifest.successor_of(old)?;
        }
        ensure!(
            target.is_none_or(|id| id == offer.manifest.deployment),
            "Offer history contains different deployments"
        );
        target = Some(offer.manifest.deployment);
        let context = scoped(
            &verified,
            &online,
            offer.manifest.deployment,
            grant,
            Some("AuthorityDeploymentRegister"),
            &signer,
            &mut store,
            &mut session,
            &source,
        )?;
        let current = context.version(129, offer.manifest.deployment).ok();
        let resumed = if let Some(pending) = store.resume_ordinary()? {
            let intent = Intent::from_signed(pending.signed())?;
            let crate::authority_deployments::Operation::Register {
                offer: retained,
                historical,
                ..
            } = crate::authority_deployments::Operation::parse(&intent)?
            else {
                bail!("Pending deployment synchronisation has another operation");
            };
            (retained.manifest.generation == offer.manifest.generation).then_some(historical)
        } else {
            None
        };
        if resumed.is_none()
            && current
                .as_ref()
                .is_some_and(|r| r.generation >= offer.manifest.generation)
        {
            if current
                .as_ref()
                .is_some_and(|r| r.generation == offer.manifest.generation)
            {
                ensure!(
                    context.version(117, offer.manifest.deployment)?.digest
                        == wire::digest(&offer.manifest.desired()?),
                    "Retained offer conflicts with current admitted generation"
                );
            }
        } else {
            ensure!(
                resumed.is_some()
                    || current.as_ref().is_some_and(
                        |r| r.generation.checked_add(1) == Some(offer.manifest.generation)
                    ),
                "Initial admission or a missing predecessor must be completed before operational synchronisation"
            );
            let historical = match resumed {
                Some(value) => value,
                None => source.health()?.observe()?.wall_ms >= offer.manifest.validity.1,
            };
            let request = Request::Register {
                grant: context.version(102, grant)?,
                offer: offer.clone(),
                historical,
            };
            client::local(
                &verified,
                request,
                Some(&context),
                &online.socket,
                &signer,
                &mut store,
                &mut session,
                || source.health(),
            )?;
        }
        final_generation = offer.manifest.generation;
        previous = Some(offer.manifest);
    }
    ensure!(
        store.resume_ordinary()?.is_none(),
        "Retained offer history did not complete the exact pending registration"
    );
    let final_manifest = previous.context("No retained operational offers found")?;
    crate::print_value(
        &json!({"status":"DeploymentSynchronised","deployment":hex::encode(final_manifest.deployment),
        "generation":final_generation,"currentPermission":false,"freshFinalConsent":source.health()?.observe()?.wall_ms < final_manifest.validity.1}),
    )
}
pub fn run(command: Command) -> Result<()> {
    match command {
        Command::ActivationComplete { online, receipt } => {
            let verified = bootstrap(&online.location)?;
            let signer = deployment_signer(&online.key)?;
            let mut store = Store::open(&online.location.directory, verified.descriptor().clone())?;
            store.require_requester(signer.verifying_key().to_bytes())?;
            let receipt =
                crate::authority_runtime_activation::Receipt::parse(&files::read_single(
                    &receipt,
                    crate::authority_runtime_activation::RECEIPT_LIMIT,
                    true,
                )?)?;
            let historical = store.descriptor_for_scope(&receipt.scope()?)?;
            let report = receipt.verify(&verified, &historical)?;
            ensure!(
                report.request().requester == store.requester(),
                "activation report has another manager"
            );
            let intent = store.complete_activation(report, |store| {
                let descriptor = store.descriptor().clone();
                let source = clock(&online.location, descriptor.voters())?;
                stream_client::status_local(
                    &descriptor,
                    &online.socket,
                    &signer,
                    store,
                    &mut Session::new()?,
                    || source.health(),
                )?;
                Ok(())
            })?;
            crate::print_value(
                &json!({"status":"ActivationReported","intent":hex::encode(intent),"currentPermission":false,"serviceReadiness":"NotProbed"}),
            )
        }
        Command::ActivationRequest {
            location,
            key,
            deployment,
            grant,
            role,
            generation,
            output,
        } => {
            let verified = bootstrap(&location)?;
            let signer = deployment_signer(&key)?;
            let mut store = Store::open(&location.directory, verified.descriptor().clone())?;
            let source = clock(&location, store.descriptor().voters())?;
            let cache = Cache::load(&verified, &store, id(&deployment)?, Some(id(&grant)?))?;
            let request = client::activation_client::prepare(
                &verified,
                &cache,
                &signer,
                &mut store,
                role,
                generation,
                source.health()?,
            )?;
            files::write_new(&output, &request.encode()?)?;
            crate::print_value(
                &json!({"status":"ActivationRequestPrepared","deployment":deployment,"role":role,"localGeneration":generation,"intent":hex::encode(request.intent().digest),"recipient":hex::encode(request.operation().recipient),"currentPermission":false}),
            )
        }
        Command::Prepare {
            trust,
            manifest_json,
            output: path,
        } => {
            let verified = offline(&trust)?;
            let manifest: Manifest =
                serde_json::from_slice(&files::read_single(&manifest_json, 262144, true)?)?;
            bind(&manifest, &verified, id(&trust.bootstrap_digest)?)?;
            let bytes = manifest.encode()?;
            files::write_new(&path, &bytes)?;
            output("DeploymentPrepared", &manifest)
        }
        Command::Consent {
            trust,
            manifest: path,
            profile_digest,
            key,
            output: pathout,
        } => {
            let manifest = manifest(&trust, &path)?;
            ensure!(
                wire::digest(&manifest.desired()?) == id(&profile_digest)?,
                "profile differs from reviewed digest"
            );
            let signer = deployment_signer(&key)?;
            ensure!(
                signer.verifying_key().to_bytes() == manifest.operator,
                "consent key is not the manifest operator"
            );
            files::write_new(
                &pathout,
                &wire::sign_envelope(&manifest.unsigned_consent(0)?, &signer)?,
            )?;
            output("DeploymentConsented", &manifest)
        }
        Command::Possess {
            trust,
            manifest: path,
            class,
            key,
            tls_key,
            not_before_ms,
            expires_ms,
            output: pathout,
        } => {
            let manifest = manifest(&trust, &path)?;
            let signer = possession_key(class, key.as_deref(), tls_key.as_deref())?;
            let bytes = sign_possession(&manifest, class, &signer, not_before_ms, expires_ms)?;
            files::write_new(&pathout, &bytes)?;
            crate::print_value(
                &json!({"status":"DeploymentPossession","deployment":hex::encode(manifest.deployment),"class":class.number(),"key":hex::encode(signer.verifying_key().to_bytes()),"profileDigest":hex::encode(wire::digest(&manifest.desired()?)),"output":pathout}),
            )
        }
        Command::Assemble {
            trust,
            manifest: path,
            consent,
            possession,
            output: pathout,
        } => {
            ensure!(possession.len() <= 19, "too many possession envelopes");
            let manifest = manifest(&trust, &path)?;
            let consent = files::read_public_single(&consent, 65536)?;
            let mut proofs = possession
                .iter()
                .map(|p| {
                    let bytes = files::read_public_single(p, 1024)?;
                    let (payload, _) = wire::envelope(&bytes, 1)?;
                    let v = wire::decode(&payload)?;
                    let f = v.array(12)?;
                    Ok(((f[6].uint()?, f[7].fixed::<32>()?), bytes))
                })
                .collect::<Result<Vec<_>>>()?;
            proofs.sort_by_key(|(identity, _)| *identity);
            let offer = Offer::parse(
                &manifest.encode()?,
                &consent,
                &a(proofs.iter().map(|(_, v)| b(v)).collect()),
            )?;
            files::write_new(&pathout, &offer_bytes(&offer)?)?;
            output("DeploymentOfferPrepared", &manifest)
        }
        Command::InspectOffer { trust, offer: path } => {
            let verified = offline(&trust)?;
            let offer = offer(&files::read_public_single(&path, 98304)?)?;
            bind(&offer.manifest, &verified, id(&trust.bootstrap_digest)?)?;
            output("DeploymentOfferVerified", &offer.manifest)
        }
        Command::Context {
            online,
            deployment,
            grant,
        } => connected(online, Work::Context(id(&deployment)?, id(&grant)?)),
        Command::Register {
            online,
            grant,
            offer,
        } => connected(online, Work::Register(id(&grant)?, offer)),
        Command::Synchronise {
            online,
            grant,
            offers_directory,
        } => synchronise(online, id(&grant)?, &offers_directory),
        Command::Get {
            online,
            deployment,
            grant,
        } => connected(
            online,
            Work::Get(id(&deployment)?, grant.as_deref().map(id).transpose()?),
        ),
        Command::Withdraw {
            online,
            deployment,
            local_withdrawal,
        } => connected(online, Work::Withdraw(id(&deployment)?, local_withdrawal)),
    }
}
#[cfg(test)]
#[path = "AuthorityDeploymentCliTests.rs"]
mod tests;
