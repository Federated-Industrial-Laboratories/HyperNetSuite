// SPDX-License-Identifier: MIT
// A private durable media job retains exact ranges before requester acknowledgement.
use super::*;
use std::{ffi::OsStr, fs::File};
const FILE: &str = "MediaProgress.cbor";
pub(crate) struct Progress {
    directory: File,
    _lock: files::VaultLock,
    context: (Digest, Digest, Digest),
    pub asset_ref: VersionRef,
    pub host: VersionRef,
    pub asset: page::Asset,
    pub effect: page::MediaEffect,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub receipt: Option<page::CopyReceipt>,
}
impl Progress {
    pub fn open(
        path: &Path,
        context: (Digest, Digest, Digest),
        state: &domain::State,
        asset_ref: &VersionRef,
        host: Digest,
        effect: page::MediaEffect,
        upload: Option<&[u8]>,
    ) -> Result<Self> {
        ensure!(
            state.network == context.0 && state.incarnation == context.1,
            "media progress state belongs to another network"
        );
        let exists = path.exists();
        let directory = if exists {
            files::private_directory(path)?
        } else {
            files::create_directory(path)?
        };
        let lock = files::lock(&directory)?;
        let mut p = if exists {
            let bytes = files::read_at(
                &directory,
                OsStr::new(FILE),
                crate::markup::media::MAX_PAGE_BYTES as usize + 16384,
                true,
            )?;
            let value = wire::decode_state(&bytes)?;
            let f = value.array(13)?;
            ensure!(
                f[0].uint()? == 200
                    && f[1].uint()? == 1
                    && f[2].text()? == "PageMediaProgress"
                    && f[3].fixed::<32>()? == context.0
                    && f[4].fixed::<32>()? == context.1
                    && f[5].fixed::<32>()? == context.2,
                "media progress belongs to another network or requester"
            );
            let retained_effect = match f[9].uint()? {
                0 => page::MediaEffect::Upload,
                1 => page::MediaEffect::Read,
                2 => page::MediaEffect::Inspect,
                3 => page::MediaEffect::Repair,
                _ => anyhow::bail!("invalid media progress effect"),
            };
            Self {
                directory,
                _lock: lock,
                context,
                asset_ref: domain::version(&f[6])?,
                host: domain::version(&f[7])?,
                asset: page::Asset::parse(&f[8])?,
                effect: retained_effect,
                offset: f[10].uint()?,
                bytes: f[11].bytes()?.to_vec(),
                receipt: if f[12] == V::Null {
                    None
                } else {
                    Some(page::CopyReceipt::parse(
                        f[12].bytes()?,
                        context.0,
                        context.1,
                    )?)
                },
            }
        } else {
            let record = state.record(144, asset_ref.id)?;
            ensure!(
                record.reference == *asset_ref,
                "media progress has another asset version"
            );
            let asset = page::Asset::parse(&record.payload)?;
            let host = asset
                .hosts
                .iter()
                .find(|r| r.id == host)
                .context("media host is not in exact asset placement")?
                .clone();
            Self {
                directory,
                _lock: lock,
                context,
                asset_ref: asset_ref.clone(),
                host,
                asset,
                effect,
                offset: 0,
                bytes: upload.unwrap_or_default().to_vec(),
                receipt: None,
            }
        };
        ensure!(
            p.asset_ref == *asset_ref
                && p.asset_ref.kind == 144
                && p.asset.identity()? == asset_ref.id
                && p.host.id == host
                && p.asset.hosts.contains(&p.host)
                && p.effect == effect
                && p.offset <= p.asset.manifest.bytes,
            "media progress differs from the requested exact job"
        );
        let certified = state.record(144, asset_ref.id)?;
        ensure!(
            certified.reference == p.asset_ref && certified.payload == p.asset.value(),
            "media progress differs from the retained certified asset"
        );
        if effect.writes() {
            ensure!(
                upload == Some(p.bytes.as_slice()),
                "media upload differs from its retained bytes"
            );
            crate::markup::media::validate_asset_bytes(&p.asset.manifest, &p.bytes)
                .map_err(anyhow::Error::msg)?;
        } else {
            ensure!(
                p.bytes.len() as u64 == p.offset,
                "media progress range has a gap"
            );
        }
        if let Some(receipt) = &p.receipt {
            ensure!(
                receipt.asset == p.asset_ref
                    && receipt.host == p.host
                    && receipt.bytes == p.asset.manifest.bytes
                    && hex::encode(receipt.digest) == p.asset.manifest.digest,
                "media progress receipt differs"
            );
        }
        if p.offset == p.asset.manifest.bytes {
            crate::markup::media::validate_asset_bytes(&p.asset.manifest, &p.bytes)
                .map_err(anyhow::Error::msg)?;
            ensure!(
                p.receipt.is_some(),
                "completed media progress lacks a complete-copy receipt"
            );
        }
        if !exists {
            p.save()?;
        }
        Ok(p)
    }
    pub fn begin_repair(&mut self, pending_effect: bool) -> Result<()> {
        if self.effect == page::MediaEffect::Repair
            && self.offset == self.asset.manifest.bytes
            && !pending_effect
        {
            // A completed local attempt must obtain another current host exchange.
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
            V::Text("PageMediaProgress".into()),
            b(&self.context.0),
            b(&self.context.1),
            b(&self.context.2),
            r(&self.asset_ref),
            r(&self.host),
            self.asset.value(),
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
        let Action::MediaAuthorise {
            asset,
            host,
            effect,
            offset,
            bytes,
            ..
        } = request.command()
        else {
            anyhow::bail!("unexpected media response request")
        };
        ensure!(
            *asset == self.asset_ref
                && *host == self.host
                && *effect == self.effect
                && *offset <= self.offset,
            "media response differs from the retained job"
        );
        let end = offset
            .checked_add(*bytes)
            .context("media extent overflow")?;
        ensure!(
            end <= self.asset.manifest.bytes,
            "media response exceeds asset"
        );
        let value = wire::decode(response)?;
        let f = value.array(11)?;
        if !self.effect.writes() {
            let payload = f[9].bytes()?;
            ensure!(
                payload.len() as u64 == *bytes,
                "media response extent differs"
            );
            if *offset < self.offset {
                ensure!(
                    end <= self.offset && self.bytes[*offset as usize..end as usize] == *payload,
                    "media retry changed retained bytes"
                );
            } else {
                self.bytes.extend_from_slice(payload);
            }
        }
        self.offset = self.offset.max(end);
        if f[10] != V::Null {
            let receipt = page::CopyReceipt::parse(f[10].bytes()?, self.context.0, self.context.1)?;
            ensure!(
                receipt.asset == self.asset_ref
                    && receipt.host == self.host
                    && receipt.bytes == self.asset.manifest.bytes
                    && hex::encode(receipt.digest) == self.asset.manifest.digest,
                "media complete-copy receipt differs"
            );
            self.receipt = Some(receipt);
        }
        if self.offset == self.asset.manifest.bytes {
            crate::markup::media::validate_asset_bytes(&self.asset.manifest, &self.bytes)
                .map_err(anyhow::Error::msg)?;
            ensure!(
                self.receipt.is_some(),
                "media completion lacks a validated full-copy receipt"
            );
        }
        self.save()
    }
}

#[cfg(test)]
#[path = "AuthorityPageMediaProgressTests.rs"]
mod tests;
