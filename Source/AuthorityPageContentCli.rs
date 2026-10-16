// SPDX-License-Identifier: MIT
// Content participants retain exact transfers and complete-copy evidence before acknowledging effects.
use super::*;
use crate::authority_inspection::page_media_client as client;
use media::Transport;
use page::content::{self, Effect};
#[path = "AuthorityPageContentProgress.rs"]
mod progress;
use progress::Progress;
#[path = "AuthorityPageContentRoutes.rs"]
mod routes;
pub(crate) use routes::search_route;
pub(crate) use routes::{
    fetch_source, fetch_source_from, fetch_view_source, repair_source, selected_transport,
    upload_source,
};
#[derive(Args)]
pub struct PlacementRef {
    #[arg(long)]
    placement: String,
    #[arg(long)]
    placement_generation: u64,
    #[arg(long)]
    placement_digest: String,
}
impl PlacementRef {
    fn value(&self) -> Result<VersionRef> {
        ensure!(
            self.placement_generation > 0,
            "placement generation is zero"
        );
        Ok(VersionRef {
            kind: 159,
            id: id(&self.placement)?,
            generation: self.placement_generation,
            digest: id(&self.placement_digest)?,
        })
    }
}
#[derive(Args)]
pub struct Exchange {
    #[command(flatten)]
    online: Online,
    #[command(flatten)]
    capability: Capability,
    #[command(flatten)]
    placement: PlacementRef,
    #[command(flatten)]
    transport: Transport,
    /// Private retained directory for this exact placement, host and effect.
    #[arg(long)]
    progress_directory: PathBuf,
}
#[derive(Subcommand)]
pub enum Command {
    /// Bind an exact host to an explicit local socket or installed service directory.
    Route(routes::Options),
    /// Bind one pending revision to exact consenting storage profiles.
    Place {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        revision: String,
        #[arg(long)]
        revision_generation: u64,
        #[arg(long)]
        revision_digest: String,
        /// Exact host ID:generation:digest. Repeat for each permitted host.
        #[arg(long = "host-version", required = true)]
        hosts: Vec<String>,
        #[arg(long)]
        copies: u64,
        #[arg(long)]
        failure_domains: u64,
        #[arg(long)]
        expires_ms: u64,
    },
    Get {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[command(flatten)]
        placement: PlacementRef,
    },
    Upload {
        #[command(flatten)]
        exchange: Exchange,
        #[arg(long)]
        input: PathBuf,
    },
    Read {
        #[command(flatten)]
        exchange: Exchange,
        #[arg(long)]
        output: PathBuf,
    },
    Inspect {
        #[command(flatten)]
        exchange: Exchange,
        #[arg(long)]
        output: PathBuf,
    },
    Repair {
        #[command(flatten)]
        exchange: Exchange,
        #[arg(long)]
        input: PathBuf,
    },
    Withdraw {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[command(flatten)]
        placement: PlacementRef,
    },
    Purge {
        #[command(flatten)]
        exchange: Exchange,
    },
}
pub(crate) fn resume_source(c: &mut Client, grant: &VersionRef, effect: Effect) -> Result<()> {
    let Some(pending) = c.store.resume_ordinary()? else {
        return Ok(());
    };
    let operation = domain::Operation::parse(&crate::authority_proof::Intent::from_signed(
        pending.signed(),
    )?)?;
    if let domain::Command::Page(Action::Content(content::Command::Authorise {
        placement,
        effect: old,
        ..
    })) = operation.command
    {
        ensure!(old == effect, "another content effect is pending");
        fetch_source(c, grant, &placement, effect)?;
    }
    Ok(())
}
pub(crate) fn selected_placement(
    state: &domain::State,
    revision: &page::Revision,
) -> Result<VersionRef> {
    let record = state.record(159, content::placement_id(revision)?)?;
    let placement = content::Placement::parse(&record.payload)?;
    ensure!(
        placement.digest == revision.author.source.content_sha256()
            && placement.bytes == revision.author.source.len() as u64,
        "content placement differs from signed source"
    );
    Ok(record.reference.clone())
}
fn digest(bytes: &[u8]) -> Digest {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(bytes).into()
}
fn resume_metadata(c: &mut Client, placement: &VersionRef) -> Result<()> {
    let Some(pending) = c.store.resume_ordinary()? else {
        return Ok(());
    };
    let op = domain::Operation::parse(&crate::authority_proof::Intent::from_signed(
        pending.signed(),
    )?)?;
    let domain::Command::Page(Action::Content(command)) = op.command else {
        anyhow::bail!("another operation is pending")
    };
    if matches!(command, content::Command::Authorise { .. }) {
        return Ok(());
    }
    let same = match &command {
        content::Command::Get { placement: r } => r == placement,
        content::Command::Receipt { receipt } => receipt.placement == *placement,
        _ => false,
    };
    ensure!(same, "another content metadata operation is pending");
    c.action(Action::Content(command), op.grant, Resolved::default())?;
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub(super) fn job(
    c: &mut Client,
    grant: VersionRef,
    placement: VersionRef,
    transport: &Transport,
    path: &Path,
    effect: Effect,
    upload: Option<&[u8]>,
) -> Result<Vec<u8>> {
    resume_metadata(c, &placement)?;
    if c.store.resume_ordinary()?.is_none() {
        c.action(
            Action::Content(content::Command::Get {
                placement: placement.clone(),
            }),
            Some(grant.clone()),
            Resolved::default(),
        )?;
    }
    job_with_metadata(c, grant, placement, transport, path, effect, upload)
}
#[allow(clippy::too_many_arguments)]
fn job_with_metadata(
    c: &mut Client,
    grant: VersionRef,
    placement: VersionRef,
    transport: &Transport,
    path: &Path,
    effect: Effect,
    upload: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let scope = c.bootstrap.descriptor().scope();
    let mut progress = Progress::open(
        path,
        (
            scope.network,
            scope.incarnation,
            c.key.verifying_key().to_bytes(),
        ),
        &c.cache()?.state,
        &placement,
        transport.host()?,
        effect,
        upload,
    )?;
    progress.begin_repair(c.store.resume_ordinary()?.is_some())?;
    transfer_progress(c, grant, transport, path, &mut progress)?;
    Ok(progress.bytes)
}
fn transfer_progress(
    c: &mut Client,
    grant: VersionRef,
    transport: &Transport,
    path: &Path,
    progress: &mut Progress,
) -> Result<()> {
    let placement = progress.placement_ref.clone();
    let effect = progress.effect;
    loop {
        let complete = progress.offset == progress.placement.bytes
            || (effect == Effect::Purge && progress.offset == 1);
        if complete && c.store.resume_ordinary()?.is_none() {
            break;
        }
        client::ensure(
            &c.bootstrap,
            &mut c.store,
            &c.socket,
            &c.key,
            &mut c.session,
            || c.clock.health(),
        )?;
        let pending = client::pending(&c.store)?;
        let reconcile = pending.is_some();
        let command = if let Some(pending) = pending {
            let Action::Content(content::Command::Authorise {
                placement: p,
                host,
                effect: e,
                offset,
                bytes,
                ..
            }) = pending.command()
            else {
                anyhow::bail!("another effect is pending")
            };
            ensure!(
                *p == placement
                    && *host == progress.host
                    && *e == effect
                    && *offset <= progress.offset
                    && offset
                        .checked_add(*bytes)
                        .is_some_and(|end| end <= progress.placement.bytes),
                "pending effect belongs to another content job"
            );
            pending.command().clone()
        } else {
            if complete {
                break;
            }
            let offset = if effect == Effect::Purge {
                0
            } else {
                progress.offset
            };
            let bytes = if effect == Effect::Purge {
                0
            } else {
                (progress.placement.bytes - offset).min(32768)
            };
            let digest = if matches!(effect, Effect::Upload | Effect::Repair) {
                Some(digest(
                    &progress.bytes[offset as usize..(offset + bytes) as usize],
                ))
            } else {
                None
            };
            Action::Content(content::Command::Authorise {
                placement: placement.clone(),
                host: progress.host.clone(),
                effect,
                offset,
                bytes,
                digest,
            })
        };
        let Action::Content(content::Command::Authorise { offset, bytes, .. }) = &command else {
            unreachable!()
        };
        let payload = if matches!(effect, Effect::Upload | Effect::Repair) {
            progress.bytes[*offset as usize..(offset + bytes) as usize].to_vec()
        } else {
            vec![]
        };
        let request = client::prepare(
            &c.bootstrap,
            &c.key,
            &mut c.store,
            command,
            grant.clone(),
            c.clock.health()?,
        )?;
        let packet = client::packet(&request, &payload, reconcile)?;
        let receipt = transport.exchange(&packet, path)?;
        client::complete(
            &c.bootstrap,
            &receipt,
            &c.socket,
            &c.key,
            &mut c.store,
            &mut c.session,
            || c.clock.health(),
            |request, response| progress.apply(request, response),
        )?;
    }
    if matches!(effect, Effect::Upload | Effect::Repair) {
        let receipt = progress
            .receipt
            .clone()
            .context("content completion lacks a durable receipt")?;
        c.action(
            Action::Content(content::Command::Receipt { receipt }),
            Some(grant),
            Resolved::default(),
        )?;
    }
    Ok(())
}
fn transfer(
    exchange: Exchange,
    effect: Effect,
    input: Option<PathBuf>,
    output: Option<PathBuf>,
) -> Result<()> {
    let mut c = Client::new(&exchange.online)?;
    let grant = c.grant(exchange.capability)?;
    let placement = exchange.placement.value()?;
    let upload = input
        .as_ref()
        .map(|p| files::read_public_single(p, progress::MAXIMUM_BYTES))
        .transpose()?;
    let bytes = job(
        &mut c,
        grant,
        placement,
        &exchange.transport,
        &exchange.progress_directory,
        effect,
        upload.as_deref(),
    )?;
    if let Some(path) = output {
        if path.try_exists()? {
            ensure!(
                files::read_single(&path, progress::MAXIMUM_BYTES, true)? == bytes,
                "content output already contains different bytes"
            );
        } else {
            files::write_new(&path, &bytes)?;
        }
    }
    crate::print_value(
        &json!({"status":"ContentComplete","effect":effect.code(),"bytes":bytes.len(),"sha256":hex::encode(digest(&bytes))}),
    )
}
pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Route(options) => routes::retain(options),
        Command::Place {
            online,
            capability,
            revision,
            revision_generation,
            revision_digest,
            hosts,
            copies,
            failure_domains,
            expires_ms,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let revision = VersionRef {
                kind: 141,
                id: id(&revision)?,
                generation: revision_generation,
                digest: id(&revision_digest)?,
            };
            let mut hosts = hosts
                .iter()
                .map(|text| {
                    let parts = text.split(':').collect::<Vec<_>>();
                    ensure!(
                        parts.len() == 3,
                        "host version must be ID:generation:digest"
                    );
                    Ok(VersionRef {
                        kind: 147,
                        id: id(parts[0])?,
                        generation: parts[1].parse()?,
                        digest: id(parts[2])?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            hosts.sort_by_key(|v| v.id);
            let (result, _) = c.action(
                Action::Content(content::Command::Place {
                    revision,
                    hosts,
                    copies,
                    failure_domains,
                    expires_ms,
                }),
                Some(grant),
                Resolved::default(),
            )?;
            summary(&result)
        }
        Command::Get {
            online,
            capability,
            placement,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let command = content::Command::Get {
                placement: placement.value()?,
            };
            let (result, _) =
                c.action(Action::Content(command), Some(grant), Resolved::default())?;
            summary(&result)
        }
        Command::Withdraw {
            online,
            capability,
            placement,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let (result, _) = c.action(
                Action::Content(content::Command::Withdraw {
                    placement: placement.value()?,
                }),
                Some(grant),
                Resolved::default(),
            )?;
            summary(&result)
        }
        Command::Upload { exchange, input } => {
            transfer(exchange, Effect::Upload, Some(input), None)
        }
        Command::Repair { exchange, input } => {
            transfer(exchange, Effect::Repair, Some(input), None)
        }
        Command::Read { exchange, output } => transfer(exchange, Effect::Read, None, Some(output)),
        Command::Inspect { exchange, output } => {
            transfer(exchange, Effect::Inspect, None, Some(output))
        }
        Command::Purge { exchange } => transfer(exchange, Effect::Purge, None, None),
    }
}

#[cfg(test)]
#[path = "AuthorityPageViewConsumerTests.rs"]
pub(crate) mod view_tests;
