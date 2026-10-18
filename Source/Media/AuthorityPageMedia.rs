// SPDX-License-Identifier: MIT
// Media uses explicit exact metadata, resumable finite store requests and complete validation.
use super::*;
use crate::authority_inspection::page_media_client as client;
use std::process::Command as Process;
#[path = "AuthorityPageMediaProgress.rs"]
pub(crate) mod progress;
use progress::Progress;
#[derive(Args)]
pub struct AssetRef {
    #[arg(long)]
    asset: String,
    #[arg(long)]
    asset_generation: u64,
    #[arg(long)]
    asset_digest: String,
}
impl AssetRef {
    fn value(&self) -> Result<VersionRef> {
        ensure!(self.asset_generation > 0, "asset generation is zero");
        Ok(VersionRef {
            kind: 144,
            id: id(&self.asset)?,
            generation: self.asset_generation,
            digest: id(&self.asset_digest)?,
        })
    }
}
#[derive(Clone, Args)]
pub struct Transport {
    #[arg(long)]
    host: String,
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
pub(crate) struct ContentExchange {
    bytes: Vec<u8>,
    route: Option<crate::private_route_client::Prepared>,
    duration: u64,
}
impl ContentExchange {
    /// Verified completion continuity and durable progress must succeed before transport retention.
    pub(crate) fn complete<T>(
        self,
        pool: &mut crate::private_route_client::ContentPool,
        verify: impl FnOnce(&[u8]) -> Result<T>,
    ) -> Result<T> {
        let result = verify(&self.bytes)?;
        if let Some(route) = self.route {
            pool.retain(route, self.duration);
        }
        Ok(result)
    }
}
#[derive(Args)]
pub struct Exchange {
    #[command(flatten)]
    online: Online,
    #[command(flatten)]
    capability: Capability,
    #[command(flatten)]
    asset: AssetRef,
    #[command(flatten)]
    transport: Transport,
    /// Private persistent directory for this exact asset, host and effect.
    #[arg(long)]
    progress_directory: PathBuf,
}
#[derive(Subcommand)]
pub enum Command {
    /// Import an image or inert vector through the isolated canonical decoder.
    Import(crate::media_import::ImportArgs),
    /// Export validated canonical geometry as static SVG paths and literal paints.
    ExportSvg {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Get {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[command(flatten)]
        asset: AssetRef,
    },
    Policy {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        copies: u64,
    },
    Upload {
        #[command(flatten)]
        exchange: Exchange,
        #[arg(long)]
        input: PathBuf,
    },
    /// Repair exact currently published bytes as their author.
    Repair {
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
    /// Fetch and validate the whole pending asset before recording inspection.
    Inspect {
        #[command(flatten)]
        exchange: Exchange,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        expires_ms: u64,
    },
}
impl Transport {
    pub(crate) fn host(&self) -> Result<Digest> {
        id(&self.host)
    }
    pub(crate) fn socket(host: Digest, path: PathBuf) -> Self {
        Self {
            host: hex::encode(host),
            service_socket: Some(path),
            service_directory: None,
            core: PathBuf::from("HyperNet"),
        }
    }
    pub(super) fn installed(host: Digest, directory: PathBuf, core: PathBuf) -> Self {
        Self {
            host: hex::encode(host),
            service_socket: None,
            service_directory: Some(directory),
            core,
        }
    }
    pub(crate) fn exchange_content(
        &self,
        packet: &[u8],
        progress: &Path,
        pool: &mut crate::private_route_client::ContentPool,
    ) -> Result<ContentExchange> {
        self.exchange_pooled(packet, progress, pool, 2)
    }
    pub(crate) fn exchange_media_read(
        &self,
        packet: &[u8],
        progress: &Path,
        pool: &mut crate::private_route_client::ContentPool,
    ) -> Result<ContentExchange> {
        self.exchange_pooled(packet, progress, pool, 3)
    }
    fn exchange_pooled(
        &self,
        packet: &[u8],
        progress: &Path,
        pool: &mut crate::private_route_client::ContentPool,
        protocol: u64,
    ) -> Result<ContentExchange> {
        use std::os::unix::fs::FileTypeExt;
        let result = (|| {
            let value = wire::decode(packet)?;
            let request = page::MediaRequest::parse(value.array(6)?[3].bytes()?)?;
            let host = match (protocol, request.command()) {
                (2, Action::Content(page::content::Command::Authorise { host, .. })) => host,
                (
                    3,
                    Action::MediaAuthorise {
                        host,
                        effect: page::MediaEffect::Read,
                        ..
                    },
                ) => host,
                _ => anyhow::bail!(
                    "pooled exchange requires its exact finite Content or MediaRead effect"
                ),
            };
            ensure!(
                host.id == self.host()?,
                "content or media transport differs from the requested host"
            );
            let duration = exchange_duration(&request)?;
            if let Some(path) = &self.service_socket
                && !std::fs::symlink_metadata(path)?.file_type().is_socket()
            {
                let reservation = crate::route_connector::exchange_reservation(
                    packet.len(),
                    page::MEDIA_RECEIPT_LIMIT,
                )?;
                let route = pool.prepare(path, duration, protocol, reservation, |endpoint| {
                    ensure!(
                        endpoint.route.network == request.intent().network
                            && endpoint.route.incarnation == request.intent().incarnation
                            && crate::networks::route_subject(&endpoint.profile, &endpoint.route)? == host.id,
                        "content or media route differs from the requested network, incarnation or retained host"
                    );
                    Ok(())
                })?;
                let deadline = crate::authority_challenge::boot_time_ms()?
                    .checked_add(duration)
                    .context("content or media exchange deadline overflow")?;
                let bytes = route.exchange(packet, deadline, page::MEDIA_RECEIPT_LIMIT)?;
                return Ok(ContentExchange {
                    bytes,
                    route: Some(route),
                    duration,
                });
            }
            pool.clear();
            Ok(ContentExchange {
                bytes: self.exchange(packet, progress)?,
                route: None,
                duration,
            })
        })();
        if result.is_err() {
            pool.clear();
        }
        result
    }
    pub(crate) fn exchange(&self, packet: &[u8], progress: &Path) -> Result<Vec<u8>> {
        if let Some(socket) = &self.service_socket {
            let value = wire::decode(packet)?;
            let request = page::MediaRequest::parse(value.array(6)?[3].bytes()?)?;
            let duration = exchange_duration(&request)?;
            return crate::authority_local_transport::LocalControl::open(socket)?.exchange_limit(
                packet,
                crate::authority_challenge::boot_time_ms()?
                    .checked_add(duration)
                    .context("media exchange deadline overflow")?,
                page::MEDIA_RECEIPT_LIMIT,
            );
        }
        crate::private_route_client::require_local_allowed()?;
        let directory = self
            .service_directory
            .as_ref()
            .context("media service directory absent")?;
        let suffix = crate::random_hex::<16>();
        let input = progress.join(format!("Packet{suffix}.cbor"));
        let output = progress.join(format!("Receipt{suffix}.cbor"));
        struct Cleanup(PathBuf, PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
                let _ = std::fs::remove_file(&self.1);
            }
        }
        let _cleanup = Cleanup(input.clone(), output.clone());
        files::write_new(&input, packet)?;
        let result = Process::new(&self.core)
            .args(["runtime", "services", "exchange", "--directory"])
            .arg(directory)
            .arg("--packet")
            .arg(input)
            .arg("--receipt")
            .arg(&output)
            .output()?;
        ensure!(
            result.status.success(),
            "installed media exchange failed: {}",
            crate::reader::bounded_status(&String::from_utf8_lossy(
                &result.stderr[..result.stderr.len().min(2048)]
            ))
        );
        files::read_single(&output, page::MEDIA_RECEIPT_LIMIT, true)
    }
}
fn exchange_duration(request: &page::MediaRequest) -> Result<u64> {
    crate::authority_challenge::maximum_duration_ms(&crate::authority_proof::SignedRequest::Intent(
        request.intent().clone(),
    ))
    .checked_add(crate::authority_challenge::MAXIMUM_DURATION_MS)
    .context("media exchange duration overflow")
}
fn resume_metadata(c: &mut Client, asset: &VersionRef) -> Result<()> {
    let Some(pending) = c.store.resume_ordinary()? else {
        return Ok(());
    };
    let op = domain::Operation::parse(&crate::authority_proof::Intent::from_signed(
        pending.signed(),
    )?)?;
    let domain::Command::Page(command) = op.command else {
        anyhow::bail!("another domain operation is pending")
    };
    if matches!(command, Action::MediaAuthorise { .. }) {
        return Ok(());
    }
    let same = match &command {
        Action::MediaGet { asset: r } | Action::MediaInspect { asset: r, .. } => r == asset,
        Action::MediaReceipt { receipt } => &receipt.asset == asset,
        _ => false,
    };
    ensure!(
        same,
        "another Page metadata operation is pending; resume its exact command"
    );
    c.action(command, op.grant, Resolved::default())?;
    Ok(())
}
fn digest(bytes: &[u8]) -> Digest {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(bytes).into()
}
fn publish(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        ensure!(
            files::read_single(path, crate::markup::media::MAX_PAGE_BYTES as usize, true)? == bytes,
            "media output exists with different bytes"
        );
        Ok(())
    } else {
        files::write_new(path, bytes)
    }
}
fn transfer(
    exchange: Exchange,
    effect: page::MediaEffect,
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    inspection_expiry: Option<u64>,
) -> Result<()> {
    let mut c = Client::new(&exchange.online)?;
    let grant = c.grant(exchange.capability)?;
    let asset = exchange.asset.value()?;
    let upload = input
        .as_ref()
        .map(|p| files::read_public_single(p, crate::markup::media::MAX_PAGE_BYTES as usize))
        .transpose()?;
    let progress = job(
        &mut c,
        grant,
        asset,
        &exchange.transport,
        &exchange.progress_directory,
        effect,
        upload.as_deref(),
        inspection_expiry,
    )?;
    if let Some(output) = output {
        publish(&output, &progress.bytes)?;
    }
    crate::print_value(
        &json!({"status":"MediaComplete","assetId":progress.asset.manifest.id,"effect":effect.code(),"bytes":progress.offset,"sha256":progress.asset.manifest.digest,"host":exchange.transport.host}),
    )
}
#[allow(clippy::too_many_arguments)]
fn job(
    c: &mut Client,
    grant: VersionRef,
    asset: VersionRef,
    transport: &Transport,
    progress_directory: &Path,
    effect: page::MediaEffect,
    upload: Option<&[u8]>,
    inspection_expiry: Option<u64>,
) -> Result<Progress> {
    resume_metadata(c, &asset)?;
    if c.store.resume_ordinary()?.is_none() {
        c.action(
            Action::MediaGet {
                asset: asset.clone(),
            },
            Some(grant.clone()),
            Resolved::default(),
        )?;
    }
    let mut progress = Progress::open(
        progress_directory,
        (
            c.bootstrap.descriptor().scope().network,
            c.bootstrap.descriptor().scope().incarnation,
            c.key.verifying_key().to_bytes(),
        ),
        &c.cache()?.state,
        &asset,
        id(&transport.host)?,
        effect,
        upload,
    )?;
    progress.begin_repair(c.store.resume_ordinary()?.is_some())?;
    // Retain only this read's transport; each range still receives fresh quorum authorization.
    let mut pool = crate::private_route_client::ContentPool::default();
    loop {
        if progress.offset == progress.asset.manifest.bytes && c.store.resume_ordinary()?.is_none()
        {
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
            let Action::MediaAuthorise {
                asset: a,
                host,
                effect: e,
                offset,
                bytes,
                ..
            } = pending.command()
            else {
                unreachable!()
            };
            ensure!(
                *a == asset
                    && *host == progress.host
                    && *e == effect
                    && *offset <= progress.offset
                    && offset
                        .checked_add(*bytes)
                        .is_some_and(|end| end <= progress.asset.manifest.bytes),
                "pending media effect belongs to another progress job"
            );
            pending.command().clone()
        } else {
            if progress.offset == progress.asset.manifest.bytes {
                break;
            }
            let offset = progress.offset;
            let bytes = (progress.asset.manifest.bytes - offset).min(32768);
            let digest = if effect.writes() {
                Some(digest(
                    &progress.bytes[offset as usize..(offset + bytes) as usize],
                ))
            } else {
                None
            };
            Action::MediaAuthorise {
                asset: asset.clone(),
                host: progress.host.clone(),
                effect,
                offset,
                bytes,
                digest,
            }
        };
        let Action::MediaAuthorise { offset, bytes, .. } = &command else {
            unreachable!()
        };
        let payload = if effect.writes() {
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
        let mut complete = |receipt: &[u8]| {
            client::complete(
                &c.bootstrap,
                receipt,
                &c.socket,
                &c.key,
                &mut c.store,
                &mut c.session,
                || c.clock.health(),
                |request, response| progress.apply(request, response),
            )
        };
        if effect == page::MediaEffect::Read {
            transport
                .exchange_media_read(&packet, progress_directory, &mut pool)?
                .complete(&mut pool, complete)?;
        } else {
            complete(&transport.exchange(&packet, progress_directory)?)?;
        }
    }
    let receipt = progress
        .receipt
        .clone()
        .context("media completion lacks a complete-copy receipt")?;
    match effect {
        page::MediaEffect::Upload | page::MediaEffect::Repair => {
            c.action(
                Action::MediaReceipt { receipt },
                Some(grant),
                Resolved::default(),
            )?;
        }
        page::MediaEffect::Inspect => {
            c.action(
                Action::MediaInspect {
                    asset,
                    receipt,
                    expires_ms: inspection_expiry.context("inspection expiry absent")?,
                },
                Some(grant),
                Resolved::default(),
            )?;
        }
        page::MediaEffect::Read => {}
    }
    Ok(progress)
}

pub(crate) fn read_asset(
    c: &mut Client,
    grant: &VersionRef,
    asset: VersionRef,
    transport: &Transport,
    progress_directory: &Path,
) -> Result<Vec<u8>> {
    Ok(job(
        c,
        grant.clone(),
        asset,
        transport,
        progress_directory,
        page::MediaEffect::Read,
        None,
        None,
    )?
    .bytes)
}

pub(crate) fn repair_asset(
    c: &mut Client,
    grant: &VersionRef,
    asset: VersionRef,
    transport: &Transport,
    progress_directory: &Path,
    bytes: &[u8],
) -> Result<()> {
    job(
        c,
        grant.clone(),
        asset,
        transport,
        progress_directory,
        page::MediaEffect::Repair,
        Some(bytes),
        None,
    )?;
    Ok(())
}
pub(super) fn inspect_asset(
    c: &mut Client,
    grant: &VersionRef,
    asset: VersionRef,
    transport: &Transport,
    progress_directory: &Path,
    expires_ms: u64,
) -> Result<Vec<u8>> {
    Ok(job(
        c,
        grant.clone(),
        asset,
        transport,
        progress_directory,
        page::MediaEffect::Inspect,
        None,
        Some(expires_ms),
    )?
    .bytes)
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Import(args) => {
            crate::print_value(&serde_json::to_value(crate::media_import::import(&args)?)?)
        }
        Command::ExportSvg { input, output } => {
            let bytes = files::read_public_single(&input, crate::markup::media::MAX_VECTOR_BYTES)?;
            let vector = crate::markup::media::vector(&bytes).map_err(anyhow::Error::msg)?;
            let svg = crate::markup::media::vector_svg(&vector).map_err(anyhow::Error::msg)?;
            files::write_new(&output, svg.as_bytes())?;
            crate::print_value(
                &json!({"profile":crate::markup::media::VECTOR_PROFILE,"svgBytes":svg.len()}),
            )
        }
        Command::Get {
            online,
            capability,
            asset,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let asset = asset.value()?;
            let (result, _) = c.action(
                Action::MediaGet {
                    asset: asset.clone(),
                },
                Some(grant),
                Resolved::default(),
            )?;
            let record = result.cache.state.record(144, asset.id)?;
            ensure!(
                record.reference == asset,
                "media query returned another version"
            );
            let asset = page::Asset::parse(&record.payload)?;
            crate::print_value(
                &json!({"status":"MediaVerified","asset":asset.manifest,"requiredCopies":asset.required_copies,
                "uploadExpiresMs":asset.upload_expires_ms,"expiresMs":asset.expires_ms,"height":result.prefix.height()}),
            )
        }
        Command::Policy {
            online,
            capability,
            namespace,
            copies,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let (result, _) = c.action(
                Action::MediaPolicy { namespace, copies },
                Some(grant),
                Resolved::default(),
            )?;
            summary(&result)
        }
        Command::Upload { exchange, input } => {
            transfer(exchange, page::MediaEffect::Upload, Some(input), None, None)
        }
        Command::Repair { exchange, input } => {
            transfer(exchange, page::MediaEffect::Repair, Some(input), None, None)
        }
        Command::Read { exchange, output } => {
            transfer(exchange, page::MediaEffect::Read, None, Some(output), None)
        }
        Command::Inspect {
            exchange,
            output,
            expires_ms,
        } => transfer(
            exchange,
            page::MediaEffect::Inspect,
            None,
            Some(output),
            Some(expires_ms),
        ),
    }
}
