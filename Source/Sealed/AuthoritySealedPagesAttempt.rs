// SPDX-License-Identifier: MIT
// One encrypted immutable attempt preserves the exact ciphertext and signed staging request across retries.
use super::*;
use serde::{Deserialize, Serialize};
use std::{ffi::OsStr, fs::File};
const FILE: &str = "SealedPublication.age";
const LIMIT: usize = 32 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Data {
    version: u64,
    network: Digest,
    incarnation: Digest,
    bootstrap: Digest,
    reviewer: Digest,
    device: Digest,
    inspected: Digest,
    clock_floor_ms: u64,
    grant: Vec<u8>,
    command: Vec<u8>,
    ciphertext: Vec<u8>,
}
pub(super) struct Attempt {
    data: Data,
    _directory: File,
    _lock: files::VaultLock,
}
impl Attempt {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        path: &Path,
        c: &Client,
        device: Digest,
        key: &age::x25519::Identity,
        inspected: Digest,
        grant: &VersionRef,
        command: &publication::Command,
        ciphertext: Vec<u8>,
    ) -> Result<Self> {
        let directory = files::create_directory(path)?;
        let lock = files::lock(&directory)?;
        let s = c.bootstrap.descriptor().scope();
        let data = Data {
            version: 1,
            network: s.network,
            incarnation: s.incarnation,
            bootstrap: c.bootstrap.file_digest(),
            reviewer: c.key.verifying_key().to_bytes(),
            device,
            inspected,
            clock_floor_ms: now(c)?,
            grant: wire::encode(&reference(grant))?,
            command: wire::encode(&command.value())?,
            ciphertext,
        };
        let out = Self {
            data,
            _directory: directory,
            _lock: lock,
        };
        out.validate(c, device)?;
        let plain = Zeroizing::new(serde_json::to_vec(&out.data)?);
        let encrypted = crypto::encrypt_bounded(&[key.to_public()], &plain, LIMIT)?;
        files::atomic_at(&out._directory, OsStr::new(FILE), &encrypted, false)?;
        Ok(out)
    }
    pub fn open(
        path: &Path,
        c: &Client,
        device: Digest,
        key: &age::x25519::Identity,
    ) -> Result<Self> {
        let directory = files::private_directory(path)?;
        let lock = files::lock(&directory)?;
        let encrypted = files::read_at(&directory, OsStr::new(FILE), LIMIT + 4096, true)?;
        let plain = crypto::decrypt_bounded(key, &encrypted, LIMIT)?;
        let out = Self {
            data: serde_json::from_slice(&plain)?,
            _directory: directory,
            _lock: lock,
        };
        out.validate(c, device)?;
        Ok(out)
    }
    fn validate(&self, c: &Client, device: Digest) -> Result<()> {
        let s = c.bootstrap.descriptor().scope();
        let d = &self.data;
        ensure!(
            d.version == 1
                && d.network == s.network
                && d.incarnation == s.incarnation
                && d.bootstrap == c.bootstrap.file_digest()
                && d.reviewer == c.key.verifying_key().to_bytes()
                && d.device == device
                && d.inspected != [0; 32]
                && now(c)?.saturating_add(2000) >= d.clock_floor_ms,
            "sealed attempt differs from accepted network, reviewer, device or clock"
        );
        let command = self.command()?;
        let publication::Command::Stage { outer, .. } = command else {
            anyhow::bail!("sealed attempt is not exact staging")
        };
        let outer = publication::Outer::parse(&outer.bytes, d.network, d.incarnation)?;
        ensure!(
            outer.reviewer == d.reviewer
                && outer.ciphertext == crypto::ciphertext_digest(&d.ciphertext)
                && outer.bytes == d.ciphertext.len() as u64
                && self.grant()?.kind == 102,
            "sealed attempt ciphertext or signer differs"
        );
        Ok(())
    }
    pub fn command(&self) -> Result<publication::Command> {
        publication::Command::parse(
            &wire::decode(&self.data.command)?,
            self.data.network,
            self.data.incarnation,
        )
    }
    pub fn grant(&self) -> Result<VersionRef> {
        domain::version(&wire::decode(&self.data.grant)?)
    }
    pub fn ciphertext(&self) -> &[u8] {
        &self.data.ciphertext
    }
    pub fn outer(&self) -> Result<publication::Outer> {
        let publication::Command::Stage { outer, .. } = self.command()? else {
            anyhow::bail!("sealed attempt lacks outer publication")
        };
        publication::Outer::parse(&outer.bytes, self.data.network, self.data.incarnation)
    }
}
