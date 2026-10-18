// SPDX-License-Identifier: MIT
// Restart resumes only the exact pending archive effect before issuing another command.
use super::*;
fn pending(c: &Client) -> Result<Option<domain::Operation>> {
    c.store
        .resume_ordinary()?
        .map(|r| crate::authority_proof::Intent::from_signed(r.signed()))
        .transpose()?
        .map(|i| domain::Operation::parse(&i))
        .transpose()
}
pub(super) fn create(
    c: &mut Client,
    grant: &VersionRef,
    placement: &VersionRef,
    destination: Id,
) -> Result<()> {
    let Some(op) = pending(c)? else {
        return Ok(());
    };
    match op.command {
        domain::Command::Backup(action) => {
            ensure!(
                match &action {
                    Action::Destination { destination: id } => *id == destination,
                    Action::Prepare {
                        placement: p,
                        destination: d,
                    } => p == placement && d.id == destination,
                    _ => false,
                },
                "pending request belongs to another backup workflow"
            );
            c.domain_action(action.into(), op.grant)?;
        }
        domain::Command::Page(action) => match &action {
            page::Command::Content(page::content::Command::Get { placement: p })
            | page::Command::Content(page::content::Command::Authorise {
                placement: p,
                effect: page::content::Effect::Read,
                ..
            }) => {
                ensure!(p == placement, "pending content belongs to another backup");
                content_cli::fetch_source(c, grant, placement, page::content::Effect::Read)?;
            }
            page::Command::MediaGet { asset }
            | page::Command::MediaAuthorise {
                asset,
                effect: page::MediaEffect::Read,
                ..
            } => {
                let cache = c.cache()?;
                let p = page::content::Placement::parse(
                    &cache.state.record(159, placement.id)?.payload,
                )?;
                let r = cache.state.record(144, asset.id)?;
                let a = page::Asset::parse(&r.payload)?;
                ensure!(
                    r.reference == *asset && a.revision == p.revision,
                    "pending asset belongs to another backup"
                );
                let hosts = match &action {
                    page::Command::MediaAuthorise { host, .. } => vec![host.clone()],
                    _ => a.hosts,
                };
                let route = content_cli::selected_transport(c, &hosts)?;
                let path = c
                    .directory
                    .join(format!("BackupRead{}", hex::encode(asset.digest)));
                media::read_asset(c, grant, asset.clone(), &route, &path)?;
            }
            _ => anyhow::bail!("another Page request is pending before backup creation"),
        },
        _ => anyhow::bail!("another domain workflow is pending before backup creation"),
    }
    Ok(())
}
pub(super) fn restore(
    c: &mut Client,
    grant: &VersionRef,
    p: &Package,
    source: &[u8],
    assets: &[(domain::Record, page::Asset, &[u8])],
    staging: &Path,
) -> Result<()> {
    let Some(op) = pending(c)? else {
        return Ok(());
    };
    match op.command {
        domain::Command::Backup(action) => {
            ensure!(
                match &action {
                    Action::Get { archive } => *archive == p.archive.id,
                    Action::Restore { archive } => archive.id == p.archive.id,
                    _ => false,
                },
                "pending backup belongs to another restore"
            );
            c.domain_action(action.into(), op.grant)?;
        }
        domain::Command::Page(action) => match &action {
            page::Command::Content(page::content::Command::Get { placement })
            | page::Command::Content(page::content::Command::Authorise {
                placement,
                effect: page::content::Effect::Repair,
                ..
            }) => {
                ensure!(
                    placement == &p.archive.placement,
                    "pending source repair differs"
                );
                content_cli::repair_source(c, grant, placement, source)?;
            }
            page::Command::Content(page::content::Command::Receipt { receipt }) => {
                ensure!(
                    receipt.placement == p.archive.placement,
                    "pending source receipt differs"
                );
                c.action(
                    action,
                    op.grant,
                    crate::authority_objects::Resolved::default(),
                )?;
            }
            page::Command::MediaGet { asset }
            | page::Command::MediaAuthorise {
                asset,
                effect: page::MediaEffect::Repair,
                ..
            } => {
                let (r, a, bytes) = assets
                    .iter()
                    .find(|(r, _, _)| r.reference == *asset)
                    .context("pending media repair belongs to another archive")?;
                let hosts = match &action {
                    page::Command::MediaAuthorise { host, .. } => vec![host.clone()],
                    _ => a.hosts.clone(),
                };
                let route = content_cli::selected_transport(c, &hosts)?;
                let path =
                    staging.join(format!("MediaRepair{}", hex::encode_upper(r.reference.id)));
                media::repair_asset(c, grant, r.reference.clone(), &route, &path, bytes)?;
            }
            page::Command::MediaReceipt { receipt } => {
                ensure!(
                    p.archive.assets.contains(&receipt.asset),
                    "pending media receipt belongs to another archive"
                );
                c.action(
                    action,
                    op.grant,
                    crate::authority_objects::Resolved::default(),
                )?;
            }
            _ => anyhow::bail!("another Page request is pending before restore"),
        },
        _ => anyhow::bail!("another domain workflow is pending before restore"),
    }
    Ok(())
}
