// SPDX-License-Identifier: MIT
// Host operators sign exact storage and namespace limits before a manager registers them.
use super::*;
use crate::{authority_inspection_cli::Location, runtime_manifest::Manifest};

#[derive(Clone, Copy, ValueEnum)]
pub enum Role {
    Pages,
    Media,
}
impl Role {
    fn code(self) -> u64 {
        match self {
            Self::Pages => 1,
            Self::Media => 2,
        }
    }
    fn kind(self) -> u64 {
        match self {
            Self::Pages => 147,
            Self::Media => 143,
        }
    }
}
#[derive(Subcommand)]
pub enum Command {
    /// Save an operator-signed profile for one independently accepted deployment.
    Profile {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        profile_digest: String,
        #[arg(long, value_enum)]
        role: Role,
        #[arg(long)]
        volume: String,
        #[arg(long, required = true)]
        namespace: Vec<String>,
        #[arg(long)]
        state_bytes: u64,
        #[arg(long)]
        maximum_asset_bytes: u64,
        #[arg(long)]
        retention_ms: u64,
        /// Explicit JSON capacity partitions and opaque-hosting consent.
        #[arg(long)]
        content_policy: Option<PathBuf>,
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
    Get {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long, value_enum)]
        role: Role,
        #[arg(long)]
        host: String,
    },
    List {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long, value_enum)]
        role: Role,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        after: Option<String>,
    },
    /// Withdraw one exact current generation as its manager or operator.
    Withdraw {
        #[command(flatten)]
        online: Online,
        #[arg(long, value_enum)]
        role: Role,
        #[arg(long)]
        host: String,
        #[arg(long)]
        generation: u64,
    },
}
fn withdrawal_needs_context(
    pending: Option<&crate::authority_proof::Intent>,
    role: u64,
    host: Digest,
    generation: u64,
) -> Result<bool> {
    let Some(pending) = pending else {
        return Ok(true);
    };
    let operation = domain::Operation::parse(pending)?;
    ensure!(
        operation.grant.is_none(),
        "another exact domain request is pending"
    );
    match operation.command {
        domain::Command::Page(Action::HostGet {
            role: old_role,
            host: old_host,
        }) if old_role == role && old_host == host => Ok(true),
        domain::Command::Page(Action::HostWithdraw {
            role: old_role,
            host: old_host,
            generation: old_generation,
        }) if old_role == role && old_host == host && old_generation == generation => Ok(false),
        _ => anyhow::bail!(
            "another exact domain request is pending; resume it or explicitly fence its generation"
        ),
    }
}
pub(super) fn run(command: Command) -> Result<()> {
    match command {
        Command::Profile {
            location,
            key,
            manifest,
            profile_digest,
            role,
            volume,
            mut namespace,
            state_bytes,
            maximum_asset_bytes,
            retention_ms,
            content_policy,
            output,
        } => {
            let bootstrap = control::bootstrap(&location)?;
            let scope = bootstrap.descriptor().scope();
            let manifest = Manifest::parse(&files::read_public_single(
                &manifest,
                crate::runtime_manifest::MAXIMUM,
            )?)?;
            ensure!(
                manifest.network == scope.network
                    && manifest.incarnation == scope.incarnation
                    && manifest.bootstrap_digest == bootstrap.file_digest()
                    && wire::digest(&manifest.desired()?) == id(&profile_digest)?,
                "manifest differs from independently accepted deployment"
            );
            let key = domain_cli::signer(&key)?;
            ensure!(
                key.verifying_key().to_bytes() == manifest.operator,
                "Page profile signer is not operator"
            );
            let admitted = manifest
                .roles
                .iter()
                .find(|r| r.role == role.code())
                .context("Page host role is absent")?;
            ensure!(
                admitted.bind_endpoint_ids.is_empty() && admitted.outbound_endpoint_ids.is_empty(),
                "Page host requires the private local control route"
            );
            namespace.sort();
            let mut profile = page::HostProfile {
                service: admitted.service_key,
                manifest,
                role: role.code(),
                volume: id(&volume)?,
                namespaces: namespace,
                state_bytes,
                maximum_asset_bytes,
                retention_ms,
                content: content_policy
                    .map(|path| content_policy_file(&path))
                    .transpose()?,
                envelope: vec![],
            };
            profile.envelope = wire::sign_envelope(&profile.payload()?, &key)?;
            page::HostProfile::parse(&profile.envelope, scope.network, scope.incarnation)?;
            files::write_new(&output, &profile.envelope)?;
            crate::print_value(
                &json!({"status":"PageHostProfileSigned","role":profile.role,
                "service":hex::encode(profile.service),"deployment":hex::encode(profile.manifest.deployment),"currentPermission":false}),
            )
        }
        Command::Register {
            online,
            capability,
            profile,
        } => {
            let mut c = Client::new(&online)?;
            let scope = c.bootstrap.descriptor().scope();
            let profile = page::HostProfile::parse(
                &files::read_public_single(&profile, crate::runtime_manifest::MAXIMUM + 2048)?,
                scope.network,
                scope.incarnation,
            )?;
            let grant = c.grant(capability)?;
            if c.store.resume_ordinary()?.is_none() {
                c.action(
                    Action::Context {
                        action: 26,
                        scope_kind: 5,
                        resource: profile.manifest.deployment,
                        namespace: None,
                    },
                    Some(grant.clone()),
                    Resolved::default(),
                )?;
            }
            let (result, _) = c.action(
                Action::HostRegister {
                    profile: Box::new(profile),
                },
                Some(grant),
                Resolved::default(),
            )?;
            summary(&result)
        }
        Command::Get {
            online,
            capability,
            role,
            host,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let host = id(&host)?;
            let (result, _) = c.action(
                Action::HostGet {
                    role: role.code(),
                    host,
                },
                Some(grant),
                Resolved::default(),
            )?;
            let record = result.cache.state.record(role.kind(), host)?;
            let scope = result.prefix.scope();
            let host = page::Host::parse(&record.payload, scope.network, scope.incarnation)?;
            crate::print_value(
                &json!({"status":"PageHostVerified","height":result.prefix.height(),"generation":record.reference.generation,
                "digest":hex::encode(record.reference.digest),"service":hex::encode(record.reference.id),"role":role.code(),
                "namespaces":host.profile.namespaces,"stateBytes":host.profile.state_bytes,"maximumAssetBytes":host.profile.maximum_asset_bytes,
                "retentionMs":host.profile.retention_ms,"withdrawn":host.withdrawn}),
            )
        }
        Command::List {
            online,
            capability,
            role,
            namespace,
            after,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let (result, _) = c.action(
                Action::Hosts {
                    role: role.code(),
                    namespace,
                    after: after.as_deref().map(id).transpose()?,
                },
                Some(grant),
                Resolved::default(),
            )?;
            summary(&result)
        }
        Command::Withdraw {
            online,
            role,
            host,
            generation,
        } => {
            let mut c = Client::new(&online)?;
            let host = id(&host)?;
            let pending = c
                .store
                .resume_ordinary()?
                .map(|request| crate::authority_proof::Intent::from_signed(request.signed()))
                .transpose()?;
            if withdrawal_needs_context(pending.as_ref(), role.code(), host, generation)? {
                let (current, _) = c.action(
                    Action::HostGet {
                        role: role.code(),
                        host,
                    },
                    None,
                    Resolved::default(),
                )?;
                ensure!(
                    current
                        .cache
                        .state
                        .record(role.kind(), host)?
                        .reference
                        .generation
                        == generation,
                    "Page host generation differs; use its current exact reference"
                );
            }
            let (result, _) = c.action(
                Action::HostWithdraw {
                    role: role.code(),
                    host,
                    generation,
                },
                None,
                Resolved::default(),
            )?;
            summary(&result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{authority_deployment_tests as fixture, authority_proof::Intent};

    #[test]
    fn page_host_withdrawal_resumes_only_its_exact_context_or_mutation() {
        let host = fixture::key(100).verifying_key().to_bytes();
        let pending = |command: Action, grant| {
            let operation = domain::Operation {
                command: command.into(),
                grant,
                snapshot: domain::snapshot(&fixture::snapshot(&[])).unwrap(),
            };
            Intent::from_signed(&fixture::signed(
                &fixture::key(90),
                "AuthorityDomain",
                operation.command.resource(),
                u64::from(operation.mutation()),
                wire::decode(&operation.parameters().unwrap()).unwrap(),
                vec![],
            ))
            .unwrap()
        };
        assert!(withdrawal_needs_context(None, 1, host, 1).unwrap());
        let read = pending(Action::HostGet { role: 1, host }, None);
        assert!(withdrawal_needs_context(Some(&read), 1, host, 1).unwrap());
        assert!(withdrawal_needs_context(Some(&read), 2, host, 1).is_err());
        let mutation = pending(
            Action::HostWithdraw {
                role: 1,
                host,
                generation: 1,
            },
            None,
        );
        assert!(!withdrawal_needs_context(Some(&mutation), 1, host, 1).unwrap());
        assert!(withdrawal_needs_context(Some(&mutation), 1, host, 2).is_err());
        assert!(
            withdrawal_needs_context(
                Some(&mutation),
                1,
                fixture::key(101).verifying_key().to_bytes(),
                1
            )
            .is_err()
        );
        let discretionary = pending(
            Action::HostGet { role: 1, host },
            Some(VersionRef {
                kind: 102,
                id: [23; 32],
                generation: 1,
                digest: [24; 32],
            }),
        );
        assert!(withdrawal_needs_context(Some(&discretionary), 1, host, 1).is_err());
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContentPolicyFile {
    metadata_bytes: u64,
    data_bytes: u64,
    staging_bytes: u64,
    quarantine_bytes: u64,
    maximum_objects: u64,
    opaque: bool,
    failure_domain: String,
    reviewer_keys: Vec<String>,
    search: bool,
}
fn content_policy_file(path: &std::path::Path) -> Result<page::ContentPolicy> {
    let p: ContentPolicyFile = serde_json::from_slice(&files::read_public_single(path, 4096)?)?;
    let policy = page::ContentPolicy {
        metadata_bytes: p.metadata_bytes,
        data_bytes: p.data_bytes,
        staging_bytes: p.staging_bytes,
        quarantine_bytes: p.quarantine_bytes,
        maximum_objects: p.maximum_objects,
        opaque: p.opaque,
        failure_domain: id(&p.failure_domain)?,
        reviewers: p
            .reviewer_keys
            .iter()
            .map(|k| id(k))
            .collect::<Result<_>>()?,
        search: p.search,
    };
    page::ContentPolicy::parse(&policy.value())
}
