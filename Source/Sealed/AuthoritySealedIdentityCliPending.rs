// SPDX-License-Identifier: MIT
// One issuer directory retains one encrypted challenge and its exact consumption state.
use super::*;
use age::secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::{ffi::OsStr, fs::File};
use zeroize::{Zeroize, Zeroizing};

const LIMIT: usize = 2 * wire::MAXIMUM;
const FILE: &str = "RecipientChallenge.age";
const KEY: &str = "RecipientChallenge.key";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Data {
    pub version: u64,
    pub network: Digest,
    pub incarnation: Digest,
    pub bootstrap: Digest,
    pub endpoint: Key,
    pub binding: Vec<u8>,
    #[serde(default)]
    pub delegate: Option<Vec<u8>>,
    pub challenge: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub issued_ms: u64,
    pub expires_ms: u64,
    pub clock_floor_ms: u64,
    // 0 issued; 1 consuming exact response; 2 exact admission committed.
    pub status: u64,
    pub response: Option<Vec<u8>>,
    pub command: Option<Vec<u8>>,
    pub grant: Option<Vec<u8>>,
    pub committed: Option<Vec<u8>>,
}
impl Drop for Data {
    fn drop(&mut self) {
        self.challenge.zeroize();
    }
}
pub(super) struct Pending {
    pub data: Data,
    directory: File,
    _lock: files::VaultLock,
    key: age::x25519::Identity,
}
impl Pending {
    pub fn create(path: &Path, data: Data) -> Result<Self> {
        let directory = files::create_directory(path)?;
        let lock = files::lock(&directory)?;
        let key = age::x25519::Identity::generate();
        let secret = Zeroizing::new(key.to_string().expose_secret().as_bytes().to_vec());
        files::atomic_at(&directory, OsStr::new(KEY), &secret, false)?;
        let out = Self {
            data,
            directory,
            _lock: lock,
            key,
        };
        out.validate()?;
        out.save(false)?;
        Ok(out)
    }
    pub fn open(path: &Path, bootstrap: &Verified, pin: Digest, endpoint: Key) -> Result<Self> {
        let s = bootstrap.descriptor().scope();
        Self::open_bound(path, s.network, s.incarnation, pin, endpoint)
    }
    fn open_bound(
        path: &Path,
        network: Digest,
        incarnation: Digest,
        pin: Digest,
        endpoint: Key,
    ) -> Result<Self> {
        let directory = files::private_directory(path)?;
        let lock = files::lock(&directory)?;
        let secret = Zeroizing::new(files::read_at(&directory, OsStr::new(KEY), 4096, true)?);
        let key: age::x25519::Identity = std::str::from_utf8(&secret)?
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid private challenge identity"))?;
        let encrypted = files::read_at(&directory, OsStr::new(FILE), LIMIT + 4096, true)?;
        let plain = crypto::decrypt_bounded(&key, &encrypted, LIMIT)?;
        let out = Self {
            data: serde_json::from_slice(&plain)?,
            directory,
            _lock: lock,
            key,
        };
        out.validate()?;
        ensure!(
            out.data.network == network
                && out.data.incarnation == incarnation
                && out.data.bootstrap == pin
                && out.data.endpoint == endpoint,
            "private challenge issuer or accepted network differs"
        );
        ensure!(
            now()?.saturating_add(2000) >= out.data.clock_floor_ms,
            "private challenge clock rollback"
        );
        Ok(out)
    }
    fn validate(&self) -> Result<()> {
        let d = &self.data;
        ensure!(
            d.version == 1
                && d.status <= 2
                && d.expires_ms > d.issued_ms
                && d.expires_ms - d.issued_ms <= 30_000
                && d.clock_floor_ms >= d.issued_ms
                && [d.network, d.incarnation, d.bootstrap, d.endpoint]
                    .iter()
                    .all(|x| *x != [0; 32]),
            "invalid private challenge state"
        );
        ensure!(
            (d.status == 0) == d.response.is_none()
                && d.command.is_some() == d.grant.is_some()
                && (d.status == 2) == d.committed.is_some()
                && (d.command.is_none() || d.response.is_some()),
            "private challenge consumption state differs"
        );
        let record = identity::signed_record(&d.binding, d.network, d.incarnation)?;
        let binding =
            identity::Binding::parse(&identity::payload(&record)?, d.network, d.incarnation)?;
        if let Some(bytes) = &d.delegate {
            let delegated = identity::signed_record(bytes, d.network, d.incarnation)?;
            let delegated = identity::Binding::parse(
                &identity::payload(&delegated)?,
                d.network,
                d.incarnation,
            )?;
            ensure!(
                delegated.root == binding.root && delegated.purposes.contains(&1),
                "private challenge delegate differs from candidate root"
            );
            identity::signer(&record, delegated.signing_key)?;
        }
        let (challenge, signatures) = wire::envelope(&d.challenge, 1)?;
        let challenge = identity::Challenge::parse(&challenge, d.network, d.incarnation)?;
        ensure!(
            signatures[0].0 == d.endpoint
                && challenge.endpoint == d.endpoint
                && challenge.binding == binding.reference.digest
                && challenge.expires_ms == d.expires_ms,
            "private challenge exact binding differs"
        );
        if let Some(response) = &d.response {
            verify_response(d, response)?;
        }
        Ok(())
    }
    fn save(&self, replace: bool) -> Result<()> {
        let plain = Zeroizing::new(serde_json::to_vec(&self.data)?);
        let encrypted = crypto::encrypt_bounded(&[self.key.to_public()], &plain, LIMIT)?;
        files::atomic_at(&self.directory, OsStr::new(FILE), &encrypted, replace)
    }
    pub fn persist(&mut self) -> Result<()> {
        self.data.clock_floor_ms = self.data.clock_floor_ms.max(now()?);
        self.validate()?;
        self.save(true)
    }
    pub fn consume(&mut self, response: &[u8], at: u64) -> Result<()> {
        verify_response(&self.data, response)?;
        if let Some(prior) = &self.data.response {
            ensure!(
                prior == response,
                "private challenge was consumed by another exact response"
            );
            return Ok(());
        }
        ensure!(
            self.data.status == 0 && self.data.expires_ms > at.saturating_add(1250),
            "private challenge expired or already consumed"
        );
        self.data.response = Some(response.to_vec());
        self.data.status = 1;
        self.persist()
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Sealed/AuthoritySealedIdentityCliPendingTests.rs"]
mod tests;
pub(super) fn verify_response(d: &Data, response: &[u8]) -> Result<identity::Possession> {
    let record = identity::signed_record(&d.binding, d.network, d.incarnation)?;
    let binding = identity::Binding::parse(&identity::payload(&record)?, d.network, d.incarnation)?;
    let (challenge, _) = wire::envelope(&d.challenge, 1)?;
    let parsed = identity::Challenge::parse(&challenge, d.network, d.incarnation)?;
    let (bytes, signatures) = wire::envelope(response, 1)?;
    let proof = identity::Possession::parse(&bytes, d.network, d.incarnation)?;
    ensure!(
        signatures[0].0 == binding.signing_key
            && proof.operation == parsed.operation
            && proof.binding == binding.reference.digest
            && proof.endpoint == d.endpoint
            && proof.challenge == wire::digest(&challenge)
            && proof.expires_ms == d.expires_ms,
        "response does not prove exact challenged device possession"
    );
    Ok(proof)
}
