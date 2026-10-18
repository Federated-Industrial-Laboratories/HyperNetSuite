// SPDX-License-Identifier: MIT
// Explicit local SSH management checks quorum state and separately signed operator consent.
use super::*;
use crate::{
    authority_domains::{Operation, ssh},
    authority_inspection::domain_client::{self as client, Cache, Request},
    authority_proof::{Intent, VersionRef},
    runtime_manifest::Manifest,
};
use anyhow::Context;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::path::Path;
use zeroize::Zeroizing;
#[derive(Args)]
pub struct Online {
    #[command(flatten)]
    pub(crate) location: Location,
    #[arg(long)]
    pub(crate) key: PathBuf,
    #[arg(long)]
    pub(crate) socket: PathBuf,
}
#[derive(Args)]
pub struct Capability {
    #[arg(long)]
    grant: String,
    /// Exact canonical delegated Grant record when it is not already retained.
    #[arg(long)]
    grant_record: Option<PathBuf>,
}
#[derive(Subcommand)]
pub enum Command {
    /// Sign the exact SSH endpoint and fixed command as its deployment operator.
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
        ssh_host_public_key: PathBuf,
        #[arg(long)]
        command_file: PathBuf,
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        purpose: String,
        #[arg(long, default_value_t = 300)]
        maximum_session_seconds: u64,
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
    Service {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        service: String,
        #[arg(long)]
        grant: Option<String>,
        #[arg(long)]
        grant_record: Option<PathBuf>,
    },
    #[command(name = "list")]
    Services {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        after: Option<String>,
    },
    /// Request one short session and prove possession using a maintained OpenSSH key.
    Request {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        service: String,
        #[arg(long)]
        session: String,
        #[arg(long)]
        ssh: PathBuf,
        #[arg(long)]
        ssh_identity: PathBuf,
        #[arg(long)]
        ssh_public_key: PathBuf,
        #[arg(long)]
        purpose: String,
        #[arg(long)]
        expires_ms: u64,
    },
    Accept {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        session: String,
    },
    Revoke {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        session: String,
    },
    Session {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        session: String,
    },
    /// Inspect a fresh lease as its registered service without launching a process.
    Authorise {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        service: String,
        #[arg(long)]
        session: String,
    },
}
fn id(value: &str) -> Result<[u8; 32]> {
    trust_bootstrap::hex32(value)
}
pub(crate) fn signer(path: &Path) -> Result<SigningKey> {
    let bytes = Zeroizing::new(files::read_single(path, 8192, true)?);
    if bytes.len() == 32 {
        return Ok(SigningKey::from_bytes(bytes.as_slice().try_into()?));
    }
    let identity: crate::Identity = serde_json::from_slice(&bytes)?;
    let seed = Zeroizing::new(id(&identity.secret_key)?);
    let signer = SigningKey::from_bytes(&seed);
    ensure!(
        hex::encode(signer.verifying_key().to_bytes()) == identity.public_key,
        "identity key pair differs"
    );
    Ok(signer)
}
fn native(path: &Path) -> Result<([u8; 32], String)> {
    let bytes = files::read_public_single(path, 4096)?;
    let text = std::str::from_utf8(&bytes)?.trim();
    let raw = STANDARD.decode(
        text.strip_prefix("ssh-ed25519 ")
            .context("native Ed25519 SSH public key required")?,
    )?;
    ensure!(
        raw.len() == 51 && &raw[..19] == b"\0\0\0\x0bssh-ed25519\0\0\0\x20",
        "invalid native SSH public key"
    );
    let key = raw[19..].try_into()?;
    trust_wire::valid_key(&key)?;
    ensure!(
        ssh::native_public(key) == text,
        "SSH public key must contain one canonical key without a comment"
    );
    Ok((key, text.into()))
}
pub(crate) fn capability(
    value: Option<Capability>,
    verified: &trust_bootstrap::Verified,
    cache: &Cache,
) -> Result<Option<VersionRef>> {
    let Some(value) = value else { return Ok(None) };
    let lookup = id(&value.grant)?;
    if let Some(path) = value.grant_record {
        let bytes = files::read_public_single(&path, 16384)?;
        let scope = verified.descriptor().scope();
        let refs = crate::authority_governance::Governance::record_versions(
            scope.network,
            scope.incarnation,
            &[bytes],
        )?;
        ensure!(
            refs.len() == 1 && refs[0].kind == 102 && refs[0].id == lookup,
            "grant input has another identity"
        );
        Ok(Some(refs[0].clone()))
    } else {
        Ok(Some(cache.grant(verified, lookup)?))
    }
}
#[allow(
    clippy::too_many_arguments,
    reason = "Keep protocol inputs, state and validation callbacks explicit."
)]
fn profile(
    location: Location,
    manifest: PathBuf,
    expected: String,
    key: PathBuf,
    public: PathBuf,
    command: PathBuf,
    endpoint: String,
    purpose: String,
    maximum: u64,
    output: PathBuf,
) -> Result<()> {
    let verified = bootstrap(&location)?;
    let bytes = files::read_public_single(&manifest, crate::runtime_manifest::MAXIMUM)?;
    let manifest = Manifest::parse(&bytes)?;
    let scope = verified.descriptor().scope();
    ensure!(
        manifest.network == scope.network
            && manifest.incarnation == scope.incarnation
            && manifest.bootstrap_digest == id(&location.bootstrap_digest)?
            && trust_wire::digest(&manifest.desired()?) == id(&expected)?,
        "manifest differs from reviewed deployment"
    );
    let signer = signer(&key)?;
    ensure!(
        signer.verifying_key().to_bytes() == manifest.operator,
        "profile signer is not deployment operator"
    );
    let service = *manifest
        .services()
        .get(&8)
        .context("deployment has no SSH role")?;
    let endpoint = id(&endpoint)?;
    ensure!(
        manifest
            .roles
            .iter()
            .any(|r| r.role == 8 && r.bind_endpoint_ids.contains(&endpoint)),
        "endpoint is not bound to SSH role"
    );
    let command = files::read_public_single(&command, 32 * 1024 * 1024)?;
    let mut profile = ssh::Profile {
        manifest: manifest.clone(),
        network: scope.network,
        incarnation: scope.incarnation,
        deployment: manifest.deployment,
        service,
        operator: manifest.operator,
        native: native(&public)?.0,
        command_digest: Sha256::digest(&command).into(),
        endpoint,
        purpose,
        maximum_seconds: maximum,
        validity: manifest.validity,
        deployment_profile: crate::authority_deployment_records::reference(&manifest.desired()?)?,
        consent: crate::authority_deployment_records::reference(&manifest.unsigned_consent(0)?)?,
        envelope: vec![],
    };
    profile.envelope = trust_wire::sign_envelope(&profile.payload()?, &signer)?;
    ssh::Profile::parse(&profile.envelope, scope.network, scope.incarnation)?;
    files::write_new(&output, &profile.envelope)?;
    crate::print_value(
        &json!({"status":"SshProfileSigned","service":hex::encode(service),"deployment":hex::encode(manifest.deployment),
        "profileDigest":hex::encode(trust_wire::digest(&profile.payload()?)),"currentPermission":false}),
    )
}
enum Work {
    Register(PathBuf),
    Withdraw(String),
    Service(String),
    Services(Option<String>),
    Request {
        service: String,
        session: String,
        ssh: PathBuf,
        identity: PathBuf,
        public: PathBuf,
        purpose: String,
        expires: u64,
    },
    Accept(String),
    Revoke(String),
    Session(String),
    Authorise(String, String),
}
fn connected(online: Online, cap: Option<Capability>, work: Work) -> Result<()> {
    let verified = bootstrap(&online.location)?;
    let source = clock(&online.location, verified.descriptor().voters())?;
    let signer = signer(&online.key)?;
    let mut store = Store::open(&online.location.directory, verified.descriptor().clone())?;
    let mut session = Session::new()?;
    let descriptor = store.descriptor().clone();
    crate::authority_inspection::stream_client::resolve_refusal_local(
        &descriptor,
        &online.socket,
        &signer,
        &mut store,
        &mut session,
        || source.health(),
    )?;
    let cache = Cache::load(&verified, &store)?;
    let grant = capability(cap, &verified, &cache)?;
    let scope = verified.descriptor().scope();
    let pending = store
        .resume_ordinary()?
        .map(|p| Intent::from_signed(p.signed()))
        .transpose()?;
    let mut run = |command: ssh::Command, grant| {
        client::local(
            &verified,
            Request {
                command: command.into(),
                grant,
            },
            &online.socket,
            &signer,
            &mut store,
            &mut session,
            || source.health(),
        )
    };
    let command = match work {
        Work::Register(path) => {
            let profile = ssh::Profile::parse(
                &files::read_public_single(&path, crate::runtime_manifest::MAXIMUM + 4096)?,
                scope.network,
                scope.incarnation,
            )?;
            if pending.is_none() {
                run(
                    ssh::Command::Context {
                        action: 26,
                        scope_kind: 5,
                        resource: profile.deployment,
                    },
                    grant.clone(),
                )?;
            }
            ssh::Command::Register {
                profile: Box::new(profile),
            }
        }
        Work::Withdraw(service) => {
            let service = id(&service)?;
            let generation = if let Some(p) = &pending {
                let operation = Operation::parse(p)?;
                let crate::authority_domains::Command::Ssh(ssh::Command::Withdraw {
                    service: old,
                    generation,
                }) = operation.command
                else {
                    anyhow::bail!("another exact domain request is pending")
                };
                ensure!(old == service, "pending withdrawal is for another service");
                generation
            } else {
                run(ssh::Command::Service { service }, None)?
                    .cache
                    .state
                    .record(132, service)?
                    .reference
                    .generation
            };
            ssh::Command::Withdraw {
                service,
                generation,
            }
        }
        Work::Service(service) => ssh::Command::Service {
            service: id(&service)?,
        },
        Work::Services(after) => ssh::Command::Services {
            network: scope.network,
            after: after.map(|v| id(&v)).transpose()?,
        },
        Work::Request {
            service,
            session,
            ssh,
            identity,
            public,
            purpose,
            expires,
        } => {
            let service = id(&service)?;
            if pending.is_none() {
                run(ssh::Command::Service { service }, grant.clone())?;
            }
            let (native, public) = native(&public)?;
            let proof = crate::ssh_proof::generate(
                &online.location.directory,
                &ssh,
                &identity,
                &hex::encode(scope.network),
                &hex::encode(signer.verifying_key().to_bytes()),
                &public,
            )?;
            ssh::Command::Create {
                id: id(&session)?,
                service,
                native,
                proof,
                purpose,
                expires,
            }
        }
        Work::Accept(session) => {
            let id = id(&session)?;
            if pending.is_none() {
                run(ssh::Command::Grant { id }, None)?;
            }
            ssh::Command::Accept { id }
        }
        Work::Revoke(session) => {
            let id = id(&session)?;
            if pending.is_none() {
                run(ssh::Command::Grant { id }, None)?;
            }
            ssh::Command::Revoke { id }
        }
        Work::Session(session) => ssh::Command::Grant { id: id(&session)? },
        Work::Authorise(service, session) => ssh::Command::Authorise {
            service: id(&service)?,
            id: id(&session)?,
        },
    };
    let result = run(command, grant)?;
    crate::print_value(
        &json!({"status":"SshQuorumResult","committedHeight":result.prefix.height(),"result":diagnostic(result.value)}),
    )
}
pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Profile {
            location,
            manifest,
            profile_digest,
            key,
            ssh_host_public_key,
            command_file,
            endpoint,
            purpose,
            maximum_session_seconds,
            output,
        } => profile(
            location,
            manifest,
            profile_digest,
            key,
            ssh_host_public_key,
            command_file,
            endpoint,
            purpose,
            maximum_session_seconds,
            output,
        ),
        Command::Register {
            online,
            capability,
            profile,
        } => connected(online, Some(capability), Work::Register(profile)),
        Command::Withdraw { online, service } => connected(online, None, Work::Withdraw(service)),
        Command::Service {
            online,
            service,
            grant,
            grant_record,
        } => {
            ensure!(
                grant_record.is_none() || grant.is_some(),
                "a grant record requires its exact grant ID"
            );
            connected(
                online,
                grant.map(|grant| Capability {
                    grant,
                    grant_record,
                }),
                Work::Service(service),
            )
        }
        Command::Services {
            online,
            capability,
            after,
        } => connected(online, Some(capability), Work::Services(after)),
        Command::Request {
            online,
            capability,
            service,
            session,
            ssh,
            ssh_identity,
            ssh_public_key,
            purpose,
            expires_ms,
        } => connected(
            online,
            Some(capability),
            Work::Request {
                service,
                session,
                ssh,
                identity: ssh_identity,
                public: ssh_public_key,
                purpose,
                expires: expires_ms,
            },
        ),
        Command::Accept { online, session } => connected(online, None, Work::Accept(session)),
        Command::Revoke { online, session } => connected(online, None, Work::Revoke(session)),
        Command::Session { online, session } => connected(online, None, Work::Session(session)),
        Command::Authorise {
            online,
            service,
            session,
        } => connected(online, None, Work::Authorise(service, session)),
    }
}
