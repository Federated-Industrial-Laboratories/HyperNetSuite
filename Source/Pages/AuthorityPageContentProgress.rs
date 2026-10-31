// SPDX-License-Identifier: MIT
// A private durable content job retains exact ranges before requester acknowledgement.
use super::*;
use std::{ffi::OsStr, fs::File};
pub(super) const MAXIMUM_BYTES: usize = 8 * 1024 * 1024;
fn validate(placement: &content::Placement, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() as u64 == placement.bytes && digest(bytes) == placement.digest,
        "content bytes differ from exact placement"
    );
    if !placement.opaque {
        crate::markup::parse(std::str::from_utf8(bytes)?).map_err(anyhow::Error::msg)?;
    }
    Ok(())
}
const FILE: &str = "ContentProgress.cbor";
pub(crate) struct Progress {
    directory: File,
    _lock: files::VaultLock,
    context: (Digest, Digest, Digest),
    pub placement_ref: VersionRef,
    pub host: VersionRef,
    pub placement: content::Placement,
    pub effect: content::Effect,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub receipt: Option<content::Copy>,
}
impl Progress {
    pub fn open(
        path: &Path,
        context: (Digest, Digest, Digest),
        state: &domain::State,
        placement_ref: &VersionRef,
        host: Digest,
        effect: content::Effect,
        upload: Option<&[u8]>,
    ) -> Result<Self> {
        ensure!(
            state.network == context.0 && state.incarnation == context.1,
            "content progress state belongs to another network"
        );
        let exists = path.exists();
        let directory = if exists {
            files::private_directory(path)?
        } else {
            files::create_directory(path)?
        };
        let lock = files::lock(&directory)?;
        let mut p = if exists {
            let bytes = files::read_at(&directory, OsStr::new(FILE), MAXIMUM_BYTES + 16384, true)?;
            let value = wire::decode_state(&bytes)?;
            let f = value.array(13)?;
            ensure!(
                f[0].uint()? == 200
                    && f[1].uint()? == 1
                    && f[2].text()? == "PageContentProgress"
                    && f[3].fixed::<32>()? == context.0
                    && f[4].fixed::<32>()? == context.1
                    && f[5].fixed::<32>()? == context.2,
                "content progress belongs to another network or requester"
            );
            let retained_effect = match f[9].uint()? {
                0 => content::Effect::Upload,
                1 => content::Effect::Read,
                2 => content::Effect::Inspect,
                3 => content::Effect::Repair,
                4 => content::Effect::Purge,
                _ => anyhow::bail!("invalid content progress effect"),
            };
            Self {
                directory,
                _lock: lock,
                context,
                placement_ref: domain::version(&f[6])?,
                host: domain::version(&f[7])?,
                placement: content::Placement::parse(&f[8])?,
                effect: retained_effect,
                offset: f[10].uint()?,
                bytes: f[11].bytes()?.to_vec(),
                receipt: if f[12] == V::Null {
                    None
                } else {
                    Some(content::Copy::parse(f[12].bytes()?, context.0, context.1)?)
                },
            }
        } else {
            let record = state.record(159, placement_ref.id)?;
            ensure!(
                record.reference == *placement_ref,
                "content progress has another placement version"
            );
            let placement = content::Placement::parse(&record.payload)?;
            let host = placement
                .hosts
                .iter()
                .find(|r| r.id == host)
                .context("content host is not in exact content placement")?
                .clone();
            Self {
                directory,
                _lock: lock,
                context,
                placement_ref: placement_ref.clone(),
                host,
                placement,
                effect,
                offset: 0,
                bytes: upload.unwrap_or_default().to_vec(),
                receipt: None,
            }
        };
        ensure!(
            p.placement_ref == *placement_ref
                && p.placement_ref.kind == 159
                && p.placement.identity()? == placement_ref.id
                && p.host.id == host
                && p.placement.hosts.contains(&p.host)
                && p.effect == effect
                && p.offset <= p.placement.bytes.max(1),
            "content progress differs from the requested exact job"
        );
        let certified = state.record(159, placement_ref.id)?;
        ensure!(
            certified.reference == p.placement_ref && certified.payload == p.placement.value(),
            "content progress differs from the retained certified placement"
        );
        if matches!(effect, content::Effect::Upload | content::Effect::Repair) {
            ensure!(
                upload == Some(p.bytes.as_slice()),
                "content upload differs from its retained bytes"
            );
            validate(&p.placement, &p.bytes)?;
        } else if effect != content::Effect::Purge {
            ensure!(
                p.bytes.len() as u64 == p.offset,
                "content progress range has a gap"
            );
        }
        if let Some(receipt) = &p.receipt {
            ensure!(
                receipt.placement == p.placement_ref
                    && receipt.host == p.host
                    && receipt.bytes == p.placement.bytes
                    && receipt.digest == p.placement.digest,
                "content progress receipt differs"
            );
        }
        if effect != content::Effect::Purge && p.offset == p.placement.bytes {
            validate(&p.placement, &p.bytes)?;
            ensure!(
                p.receipt.is_some(),
                "completed content progress lacks a complete-copy receipt"
            );
        }
        ensure!(
            p.placement.bytes <= MAXIMUM_BYTES as u64,
            "content progress exceeds its local bound"
        );
        if !exists {
            p.save()?;
        }
        Ok(p)
    }
    pub fn begin_repair(&mut self, pending_effect: bool) -> Result<()> {
        if self.effect == content::Effect::Repair
            && self.offset == self.placement.bytes
            && !pending_effect
        {
            // A past copy receipt cannot establish that this host still has the bytes.
            // Preserve unfinished ranges until their exact request is acknowledged.
            self.offset = 0;
            self.receipt = None;
            self.save()?;
        }
        Ok(())
    }
    fn save(&mut self) -> Result<()> {
        let r = crate::authority_membership::reference;
        let b = |v: &[u8]| V::Bytes(v.to_vec());
        let value = V::Array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("PageContentProgress".into()),
            b(&self.context.0),
            b(&self.context.1),
            b(&self.context.2),
            r(&self.placement_ref),
            r(&self.host),
            self.placement.value(),
            V::Uint(self.effect.code()),
            V::Uint(self.offset),
            b(&self.bytes),
            self.receipt.as_ref().map_or(V::Null, |r| b(&r.envelope)),
        ]);
        files::atomic_at(
            &self.directory,
            OsStr::new(FILE),
            &wire::encode_state(&value)?,
            true,
        )
    }
    pub fn apply(&mut self, request: &page::MediaRequest, response: &[u8]) -> Result<()> {
        let Action::Content(content::Command::Authorise {
            placement,
            host,
            effect,
            offset,
            bytes,
            ..
        }) = request.command()
        else {
            anyhow::bail!("unexpected content response request")
        };
        ensure!(
            *placement == self.placement_ref
                && *host == self.host
                && *effect == self.effect
                && *offset <= self.offset,
            "content response differs from the retained job"
        );
        let end = offset
            .checked_add(*bytes)
            .context("content extent overflow")?;
        ensure!(
            end <= self.placement.bytes,
            "content response exceeds placement"
        );
        let value = wire::decode(response)?;
        let f = value.array(11)?;
        if self.effect == content::Effect::Purge {
            self.offset = 1;
            return self.save();
        }
        if !matches!(
            self.effect,
            content::Effect::Upload | content::Effect::Repair
        ) {
            let payload = f[9].bytes()?;
            ensure!(
                payload.len() as u64 == *bytes,
                "content response extent differs"
            );
            if *offset < self.offset {
                ensure!(
                    end <= self.offset && self.bytes[*offset as usize..end as usize] == *payload,
                    "content retry changed retained bytes"
                );
            } else {
                self.bytes.extend_from_slice(payload);
            }
        }
        self.offset = self.offset.max(end);
        if f[10] != V::Null {
            let receipt = content::Copy::parse(f[10].bytes()?, self.context.0, self.context.1)?;
            ensure!(
                receipt.placement == self.placement_ref
                    && receipt.host == self.host
                    && receipt.bytes == self.placement.bytes
                    && receipt.digest == self.placement.digest,
                "content complete-copy receipt differs"
            );
            self.receipt = Some(receipt);
        }
        if self.offset == self.placement.bytes {
            validate(&self.placement, &self.bytes)?;
            ensure!(
                self.receipt.is_some(),
                "content completion lacks a validated full-copy receipt"
            );
        }
        self.save()
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Pages/AuthorityPageContentProgressTests.rs"]
mod tests;
