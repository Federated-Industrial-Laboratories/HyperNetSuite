// SPDX-License-Identifier: MIT
// Foreign media uses fresh bilateral permission and the existing exact durable local-store consumer.
use super::*;
use crate::{
    authority_inspection::page_media_client as client,
    authority_pages::media::{Transport, progress::Progress},
};
#[derive(Args)]
pub struct BridgeRoute {
    #[arg(
        long,
        conflicts_with = "bridge_socket",
        required_unless_present = "bridge_socket"
    )]
    bridge_directory: Option<PathBuf>,
    #[arg(long, conflicts_with = "bridge_directory")]
    bridge_socket: Option<PathBuf>,
    #[arg(long, default_value = "HyperNet")]
    bridge_core: PathBuf,
}
impl BridgeRoute {
    fn route(&self) -> cli::Route {
        cli::Route {
            service_directory: self.bridge_directory.clone(),
            service_socket: self.bridge_socket.clone(),
            core: self.bridge_core.clone(),
            exchange_timeout_ms: 120000,
        }
    }
}
#[derive(Args)]
pub struct Selection {
    #[command(flatten)]
    access: cli::Access,
    #[command(flatten)]
    page: cli::PageSelection,
    #[command(flatten)]
    bridge: BridgeRoute,
    /// Canonical kind144 reference printed by the current foreign inspection or read.
    #[arg(long)]
    asset_reference: String,
}
#[derive(Args)]
pub struct Exchange {
    #[command(flatten)]
    selection: Selection,
    #[command(flatten)]
    transport: Transport,
    #[arg(long)]
    progress_directory: PathBuf,
    #[arg(long)]
    output: PathBuf,
}
#[derive(Subcommand)]
pub enum Command {
    Get {
        #[command(flatten)]
        selection: Selection,
        #[arg(long)]
        inspect: bool,
    },
    Read {
        #[command(flatten)]
        exchange: Exchange,
    },
    Inspect {
        #[command(flatten)]
        exchange: Exchange,
        #[arg(long)]
        expires_ms: u64,
    },
}
fn asset_reference(text: &str) -> Result<VersionRef> {
    let r = domain::version(&wire::decode(&hex::decode(text)?)?)?;
    ensure!(
        r.kind == 144,
        "foreign media requires an exact asset reference"
    );
    Ok(r)
}
fn proof(
    c: &mut Client,
    grant: &VersionRef,
    route: &cli::Route,
    agreement: Digest,
    raw: [u8; 16],
    inspect: bool,
) -> Result<fed::ForeignProof> {
    let (_, revision) = pages::publication_context(c, grant, agreement, raw, inspect)?;
    exchange::lease(
        c,
        route,
        agreement,
        Some(raw),
        Some(revision.native),
        None,
        (grant, if inspect { 3 } else { 0 }),
    )
}
fn refresh(
    c: &mut Client,
    grant: &VersionRef,
    route: &cli::Route,
    agreement: Digest,
    raw: [u8; 16],
    asset: &VersionRef,
    inspect: bool,
) -> Result<()> {
    let proof = proof(c, grant, route, agreement, raw, inspect)?;
    c.action(
        Action::MediaGet {
            asset: asset.clone(),
            proof,
        },
        Some(grant.clone()),
        Resolved::default(),
    )?;
    Ok(())
}
fn resume_metadata(c: &mut Client, asset: &VersionRef) -> Result<()> {
    let Some((pending, _)) = c.pending()? else {
        return Ok(());
    };
    if matches!(pending, Action::MediaAuthorise { .. }) {
        return Ok(());
    }
    let same = matches!(&pending,Action::MediaGet{asset:a,..}|Action::MediaInspect{asset:a,..} if a==asset);
    c.resume(|_| same)?;
    Ok(())
}
pub(super) fn run(command: Command) -> Result<()> {
    match command {
        Command::Get { selection, inspect } => {
            let asset = asset_reference(&selection.asset_reference)?;
            let (mut c, g) = connection::access(selection.access)?;
            resume_metadata(&mut c, &asset)?;
            refresh(
                &mut c,
                &g,
                &selection.bridge.route(),
                id(&selection.page.agreement)?,
                raw(&selection.page.source_page_id)?,
                &asset,
                inspect,
            )?;
            let cache = c.cache()?;
            let r = cache.state.record(144, asset.id)?;
            ensure!(r.reference == asset, "foreign asset changed");
            let value = page::Asset::parse(&r.payload)?;
            crate::print_value(
                &json!({"status":"ForeignMediaVerified","reference":reference(&asset)?,"manifest":value.manifest,
                "destinationHosts":value.hosts.iter().map(reference).collect::<Result<Vec<_>>>()?,"sourceHostsAreNotRoutes":true}),
            )
        }
        Command::Read { exchange } => job(exchange, page::MediaEffect::Read, None),
        Command::Inspect {
            exchange,
            expires_ms,
        } => job(exchange, page::MediaEffect::Inspect, Some(expires_ms)),
    }
}
fn job(exchange: Exchange, effect: page::MediaEffect, expires: Option<u64>) -> Result<()> {
    let s = exchange.selection;
    let asset = asset_reference(&s.asset_reference)?;
    let agreement = id(&s.page.agreement)?;
    let raw = raw(&s.page.source_page_id)?;
    let route = s.bridge.route();
    let (mut c, grant) = connection::access(s.access)?;
    resume_metadata(&mut c, &asset)?;
    if c.store.resume_ordinary()?.is_none() {
        refresh(
            &mut c,
            &grant,
            &route,
            agreement,
            raw,
            &asset,
            effect == page::MediaEffect::Inspect,
        )?;
    }
    let (n, i) = c.scope();
    let mut progress = Progress::open(
        &exchange.progress_directory,
        (n, i, c.key.verifying_key().to_bytes()),
        &c.cache()?.state,
        &asset,
        exchange.transport.host()?,
        effect,
        None,
    )?;
    loop {
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
            let domain::Command::Federation(
                command @ Action::MediaAuthorise {
                    asset: a,
                    host,
                    effect: e,
                    offset,
                    bytes,
                    ..
                },
            ) = pending.domain_command()
            else {
                anyhow::bail!("pending effect is not foreign media")
            };
            ensure!(
                *a == asset
                    && *host == progress.host
                    && *e == effect
                    && *offset <= progress.offset
                    && offset
                        .checked_add(*bytes)
                        .is_some_and(|v| v <= progress.asset.manifest.bytes),
                "pending foreign media belongs to another exact progress job"
            );
            // The retained bilateral proof is part of the signed request; retry never substitutes a fresh one.
            command.clone()
        } else {
            if progress.offset == progress.asset.manifest.bytes {
                break;
            }
            let proof = proof(
                &mut c,
                &grant,
                &route,
                agreement,
                raw,
                effect == page::MediaEffect::Inspect,
            )?;
            Action::MediaAuthorise {
                asset: asset.clone(),
                host: progress.host.clone(),
                effect,
                offset: progress.offset,
                bytes: (progress.asset.manifest.bytes - progress.offset).min(32768),
                digest: None,
                proof,
            }
        };
        let request = client::prepare_domain(
            &c.bootstrap,
            &c.key,
            &mut c.store,
            command.into(),
            Some(grant.clone()),
            c.clock.health()?,
        )?;
        let packet = client::packet(&request, &[], reconcile)?;
        let receipt = exchange
            .transport
            .exchange(&packet, &exchange.progress_directory)?;
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
    if effect == page::MediaEffect::Inspect {
        let proof = proof(&mut c, &grant, &route, agreement, raw, true)?;
        c.action(
            Action::MediaInspect {
                asset: asset.clone(),
                receipt: progress
                    .receipt
                    .clone()
                    .context("foreign media lacks a complete-copy receipt")?,
                expires_ms: expires.context("inspection expiry absent")?,
                proof,
            },
            Some(grant),
            Resolved::default(),
        )?;
    }
    if exchange.output.exists() {
        ensure!(
            files::read_single(
                &exchange.output,
                crate::markup::media::MAX_PAGE_BYTES as usize,
                true
            )? == progress.bytes,
            "foreign media output differs from exact completed bytes"
        );
    } else {
        files::write_new(&exchange.output, &progress.bytes)?;
    }
    crate::print_value(
        &json!({"status":"ForeignMediaComplete","asset":reference(&asset)?,"bytes":progress.offset,
        "sha256":progress.asset.manifest.digest,"effect":effect.code(),"destinationHost":hex::encode(progress.host.id)}),
    )
}
