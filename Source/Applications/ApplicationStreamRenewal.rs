// SPDX-License-Identifier: MIT
// The companion renews only its own finite authority credential on its existing requester stream.
use super::*;
use crate::private_route_client::Endpoint;
use std::os::unix::fs::FileTypeExt;

const HANDOVER_MS: u64 = 60_000;
const RENEWAL_MS: u64 = 120_000;
const WORK_MS: u64 = 15_000;

fn own(path: &Path, member: Digest) -> Result<Option<(Endpoint, domain::Record)>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_socket() {
        return Ok(None);
    }
    ensure!(
        metadata.is_file(),
        "authority route is not a regular private file"
    );
    let endpoint = Endpoint::load(path)?;
    ensure!(
        endpoint.route.protocol == 1,
        "companion authority route protocol differs"
    );
    let record = domain::Record::parse(
        &endpoint.route.voucher,
        endpoint.route.network,
        endpoint.route.incarnation,
    )?;
    let voucher = domain::routes::Voucher::parse(&record.payload)?;
    Ok((voucher.sponsor == member).then_some((endpoint, record)))
}

pub(super) fn owns(path: &Path, member: Digest, id: Digest) -> Result<bool> {
    Ok(own(path, member)?.is_some_and(|(_, record)| record.reference.id == id))
}

fn successor(previous: &domain::Record, current: &domain::Record) -> Result<bool> {
    ensure!(
        current.reference.kind == 166 && current.reference.id == previous.reference.id,
        "authority voucher identity changed"
    );
    if current.reference.generation <= previous.reference.generation {
        return Ok(false);
    }
    let old = domain::routes::Voucher::parse(&previous.payload)?;
    let new = domain::routes::Voucher::parse(&current.payload)?;
    ensure!(
        new.continues(&old),
        "authority voucher successor changes pinned authority or budget"
    );
    Ok(true)
}

fn publish(path: &Path, endpoint: &mut Endpoint, record: &domain::Record) -> Result<()> {
    endpoint.route.voucher = record.bytes.clone();
    endpoint.route.validate()?;
    let parent =
        files::private_directory(path.parent().context("authority route has no directory")?)?;
    files::atomic_at(
        &parent,
        path.file_name().context("authority route has no name")?,
        &serde_json::to_vec(endpoint)?,
        true,
    )
}

/// Recover a certified renewal interrupted between cache retention and private route publication.
pub(super) fn recover(
    bootstrap: &trust_bootstrap::Verified,
    store: &Store,
    path: &Path,
    member: Digest,
) -> Result<()> {
    let Some((mut endpoint, old)) = own(path, member)? else {
        return Ok(());
    };
    let scope = store.descriptor().scope();
    ensure!(
        endpoint.route.network == scope.network && endpoint.route.incarnation == scope.incarnation,
        "authority route belongs to another network"
    );
    let cache = Cache::load(bootstrap, store)?;
    if let Some(current) = cache.state.records.get(&(166, old.reference.id))
        && successor(&old, current)?
    {
        publish(path, &mut endpoint, current)?;
    }
    Ok(())
}

impl Client {
    pub fn authority_route_status(&self, failed: bool) -> Result<serde_json::Value> {
        if std::fs::symlink_metadata(&self.socket)?
            .file_type()
            .is_socket()
        {
            return Ok(
                serde_json::json!({"mode":"local","state":"current","expiresAtMs":null,"recoveryAfterMs":null}),
            );
        }
        let endpoint = Endpoint::load(&self.socket)?;
        let record = domain::Record::parse(
            &endpoint.route.voucher,
            endpoint.route.network,
            endpoint.route.incarnation,
        )?;
        let voucher = domain::routes::Voucher::parse(&record.payload)?;
        let automatic = voucher.sponsor == self.key.verifying_key().to_bytes();
        let cache = Cache::load(&self.bootstrap, &self.store)?;
        let exhausted = match (
            cache.state.records.get(&(165, voucher.relay.id)),
            cache.state.records.get(&(165, voucher.destination.id)),
        ) {
            (Some(relay), Some(destination))
                if relay.reference == voucher.relay
                    && destination.reference == voucher.destination =>
            {
                let relay = domain::routes::Service::parse(
                    &relay.payload,
                    endpoint.route.network,
                    endpoint.route.incarnation,
                )?;
                let destination = domain::routes::Service::parse(
                    &destination.payload,
                    endpoint.route.network,
                    endpoint.route.incarnation,
                )?;
                let usage = cache
                    .state
                    .records
                    .get(&(167, record.reference.id))
                    .map(|r| domain::routes::Usage::parse(&r.payload))
                    .transpose()?;
                !voucher.permits_next(
                    usage.as_ref(),
                    relay
                        .profile
                        .limits
                        .bytes
                        .min(destination.profile.limits.bytes),
                )
            }
            _ => false,
        };
        let state = if exhausted {
            "quotaExhausted"
        } else if failed || self.health()?.observe()?.wall_ms >= voucher.expires {
            "unavailable"
        } else {
            "current"
        };
        Ok(
            serde_json::json!({"mode":if automatic {"automatic"} else {"manual"},"state":state,
            "expiresAtMs":voucher.expires,"recoveryAfterMs":if state == "current" {None} else {Some(voucher.expires)}}),
        )
    }
    pub fn maintain_authority_route(&mut self, targets: &[Target]) -> Result<()> {
        ensure!(
            self.preparation.is_none(),
            "companion already owns an operation budget"
        );
        let deadline = crate::authority_challenge::boot_time_ms()?
            .checked_add(WORK_MS)
            .context("authority maintenance deadline overflow")?;
        self.preparation = Some(crate::authority_inspection::read_client::RetryBudget::new(
            deadline,
            crate::private_route_client::cancelled,
        ));
        let result = self.renew_authority_route(targets);
        self.preparation = None;
        result
    }

    fn renew_authority_route(&mut self, targets: &[Target]) -> Result<()> {
        recover(
            &self.bootstrap,
            &self.store,
            &self.socket,
            self.key.verifying_key().to_bytes(),
        )?;
        let Some((_, record)) = own(&self.socket, self.key.verifying_key().to_bytes())? else {
            return Ok(());
        };
        let old = domain::routes::Voucher::parse(&record.payload)?;
        let now = self.health()?.observe()?.wall_ms;
        if old.expires.saturating_sub(now) > HANDOVER_MS {
            return Ok(());
        }
        ensure!(
            now < old.expires,
            "expired authority route requires external renewal"
        );
        self.resume_agent(targets)?;
        recover(
            &self.bootstrap,
            &self.store,
            &self.socket,
            self.key.verifying_key().to_bytes(),
        )?;
        let Some((mut endpoint, record)) = own(&self.socket, self.key.verifying_key().to_bytes())?
        else {
            anyhow::bail!("authority route ownership changed during maintenance");
        };
        let old = domain::routes::Voucher::parse(&record.payload)?;
        let now = self.health()?.observe()?.wall_ms;
        if old.expires.saturating_sub(now) > HANDOVER_MS {
            return Ok(());
        }
        ensure!(
            now < old.expires,
            "expired authority route requires external renewal"
        );
        self.execute(
            Some(old.grant.clone()),
            domain::Command::Route(domain::routes::Command::RenewContext {
                voucher: record.reference.clone(),
            }),
        )?;
        let expires = now
            .checked_add(RENEWAL_MS)
            .context("authority voucher expiry overflow")?;
        let result = self.execute(
            Some(old.grant.clone()),
            domain::Command::Route(domain::routes::Command::Handover {
                voucher: record.reference.clone(),
                expires,
            }),
        )?;
        let current = result.cache.state.record(166, record.reference.id)?;
        ensure!(
            successor(&record, current)?,
            "authority renewal did not advance its generation"
        );
        publish(&self.socket, &mut endpoint, current)
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Applications/ApplicationStreamRenewalTests.rs"]
mod tests;
