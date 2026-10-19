// SPDX-License-Identifier: MIT
// Explicitly retained publications and their local search leases share one encrypted private corpus.
use crate::{
    authority_challenge::{ClockHealth, DELTA_MS},
    authority_floor::Store,
    authority_proof::{Digest, VersionRef},
    sealed_crypto as crypto, transfer_files as files,
};
use age::secrecy::ExposeSecret;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, ffi::OsStr, fs::File, path::Path};
use zeroize::{Zeroize, Zeroizing};

// This matches the existing bounded age archive decoder; larger collections use another explicit corpus.
pub const MAXIMUM_BYTES: usize = 32 * 1024 * 1024;
pub const MAXIMUM_ITEMS: usize = crate::authority_domains::MAXIMUM_RECORDS;
const FILE: &str = "RetainedSearch.age";
const CIPHERTEXT_OVERHEAD: usize = crypto::MAXIMUM_RECIPIENTS * 192 + 4096;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Lease {
    pub configuration: Digest,
    pub epoch: u64,
    pub height: u64,
    pub policy_state: Digest,
    pub kernel_boot: String,
    pub evaluated_at_ms: u64,
    pub expires_at_ms: u64,
    pub deadline_boot_ms: u64,
    pub versions: Vec<VersionRef>,
    pub receipt: Vec<u8>,
    pub attestation: Vec<u8>,
}
pub fn kernel_boot() -> Result<String> {
    let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let value = value.trim();
    ensure!(
        value.len() == 36 && value.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
        "kernel boot identity is unavailable"
    );
    Ok(value.into())
}
impl Lease {
    fn attested(&self) -> Result<Vec<u8>> {
        use crate::{
            authority_membership::reference,
            trust_wire::{self as wire, Value as V},
        };
        wire::encode(&V::Array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("RetainedSearchLease".into()),
            V::Bytes(self.configuration.to_vec()),
            V::Uint(self.epoch),
            V::Uint(self.height),
            V::Bytes(self.policy_state.to_vec()),
            V::Text(self.kernel_boot.clone()),
            V::Uint(self.evaluated_at_ms),
            V::Uint(self.expires_at_ms),
            V::Uint(self.deadline_boot_ms),
            V::Array(self.versions.iter().map(reference).collect()),
            V::Bytes(wire::digest(&self.receipt).to_vec()),
        ]))
    }
    pub fn sign(&mut self, signer: &ed25519_dalek::SigningKey) -> Result<()> {
        self.attestation = crate::trust_wire::sign_envelope(&self.attested()?, signer)?;
        Ok(())
    }
    fn verify(&self, store: &Store) -> Result<crate::authority_domains::Operation> {
        use crate::{authority_domains as domain, authority_proof as proof, trust_wire as wire};
        let (payload, signers) = wire::envelope(&self.attestation, 1)?;
        ensure!(
            signers.len() == 1
                && signers[0].0 == store.requester()
                && payload == self.attested()?,
            "local search lease attestation differs"
        );
        let value = wire::decode(&self.receipt)?;
        let f = value.array(9)?;
        ensure!(
            f[0].uint()? == 201 && f[1].uint()? == 1 && f[2].text()? == "AuthorityDomainReceipt",
            "local search receipt format differs"
        );
        let ancestry = vec![f[8].bytes()?.to_vec()];
        let verified = proof::verify_response(
            store.descriptor(),
            proof::ProofContext {
                intent: f[3].bytes()?,
                challenge: f[4].bytes()?,
                restrictions: proof::Restrictions::default(),
                minimum_height: self.height,
                maximum_effect: 1,
                expected_stream: None,
            },
            proof::Response {
                ordered_request: f[5].bytes()?,
                operation_result: f[6].bytes()?,
                certificate: f[7].bytes()?,
                ancestry: &ancestry,
            },
            |intent, result, executed| {
                ensure!(
                    intent.requester == store.requester()
                        && result.disposition == proof::Disposition::Permit
                        && executed.maximum_effect == 1
                        && executed.evaluated_at_ms == self.evaluated_at_ms
                        && executed.expires_at_ms == self.expires_at_ms
                        && executed.height == self.height,
                    "local lease execution context differs"
                );
                let value = wire::decode(&result.value)?;
                let fields = value.array(5)?;
                let versions = fields[3]
                    .list(64)?
                    .iter()
                    .map(domain::version)
                    .collect::<Result<Vec<_>>>()?;
                ensure!(
                    fields[0].uint()? == 201
                        && fields[1].uint()? == 1
                        && fields[2].text()? == "AuthorityDomain"
                        && versions == self.versions,
                    "local lease certified dependencies differ"
                );
                proof::ActionValidation::new(versions)
            },
        )?;
        ensure!(
            *verified.point().prefix().policy_state() == self.policy_state
                && verified.point().prefix().scope().configuration == self.configuration,
            "local lease certified prefix differs"
        );
        let intent = proof::Intent::from_signed(f[3].bytes()?)?;
        let operation = domain::Operation::parse(&intent)?;
        ensure!(
            matches!(
                operation.command,
                domain::Command::Page(domain::page::Command::LocalSearchLease { .. })
                    | domain::Command::Federation(
                        domain::federation::Command::LocalSearchRead { .. }
                    )
                    | domain::Command::Federation(domain::federation::Command::SearchRead { .. })
            ),
            "receipt does not authorise current search"
        );
        Ok(operation)
    }
    pub fn authorises(&self, entry: &Entry, store: &Store) -> Result<()> {
        use crate::authority_domains as domain;
        let operation = self.verify(store)?;
        ensure!(
            operation.grant.as_ref() == Some(&entry.grant)
                && self.versions.contains(&entry.publication),
            "local lease belongs to another grant or publication"
        );
        match (&entry.source, operation.command) {
            (
                Source::Native { .. },
                domain::Command::Page(domain::page::Command::LocalSearchLease { items }),
            ) => ensure!(
                items.contains(&(entry.publication.clone(), None)),
                "native retained publication is outside lease"
            ),
            (
                Source::Sealed { binding, .. },
                domain::Command::Page(domain::page::Command::LocalSearchLease { items }),
            ) => {
                let s = store.descriptor().scope();
                let binding = domain::Record::parse(binding, s.network, s.incarnation)?;
                ensure!(
                    items.contains(&(entry.publication.clone(), Some(binding.reference))),
                    "sealed recipient is outside lease"
                );
            }
            (
                Source::Imported { .. },
                domain::Command::Federation(
                    domain::federation::Command::LocalSearchRead { page, .. }
                    | domain::federation::Command::SearchRead { page, .. },
                ),
            ) => ensure!(page == entry.id, "imported publication is outside lease"),
            _ => anyhow::bail!("retained source has another lease kind"),
        }
        Ok(())
    }
    pub fn current(&self, store: &Store, health: ClockHealth) -> Result<()> {
        self.verify(store)?;
        self.current_bounds(store, health)
    }
    pub(super) fn current_bounds(&self, store: &Store, health: ClockHealth) -> Result<()> {
        let now = health.observe()?;
        ensure!(
            self.kernel_boot == kernel_boot()?
                && self.configuration == store.descriptor().scope().configuration
                && self.epoch == store.prefix().scope().epoch
                && self.height <= store.prefix().height()
                && now.boot_ms < self.deadline_boot_ms
                && now
                    .wall_ms
                    .checked_add(DELTA_MS)
                    .is_some_and(|t| t < self.expires_at_ms),
            "retained search authority is stale or locked"
        );
        for expected in &self.versions {
            ensure!(
                store.generations().contains(expected),
                "retained search dependency changed"
            );
            if expected.kind == 102 {
                ensure!(
                    !store
                        .generations()
                        .iter()
                        .any(|r| r.kind == 126 && r.id == expected.id),
                    "retained search grant was revoked"
                );
            }
            if expected.kind == 127 {
                ensure!(
                    !store
                        .generations()
                        .iter()
                        .any(|r| r.kind == 128 && r.id == expected.id),
                    "retained search application was withdrawn"
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum Source {
    Native {
        bundle: Vec<u8>,
        approval: Vec<u8>,
    },
    Imported {
        bundle: Vec<u8>,
        revision: Vec<u8>,
        review: Vec<u8>,
    },
    Sealed {
        ciphertext: Vec<u8>,
        outer: Vec<u8>,
        policy: Vec<u8>,
        binding: Vec<u8>,
        device: Digest,
    },
}
impl Drop for Source {
    fn drop(&mut self) {
        match self {
            Self::Native { bundle, .. } | Self::Imported { bundle, .. } => bundle.zeroize(),
            Self::Sealed { .. } => {}
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Entry {
    pub id: Digest,
    pub namespace: String,
    pub grant: VersionRef,
    pub publication: VersionRef,
    pub retained_at_ms: u64,
    pub source: Source,
    pub lease: Option<Lease>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Data {
    version: u64,
    network: Digest,
    incarnation: Digest,
    requester: Digest,
    bootstrap: Digest,
    generation: u64,
    entries: BTreeMap<String, Entry>,
}
pub struct Library {
    data: Data,
    directory: File,
    _lock: files::VaultLock,
    key: age::x25519::Identity,
    poisoned: bool,
}
impl Library {
    pub fn initialise(
        path: &Path,
        key_path: &Path,
        network: Digest,
        incarnation: Digest,
        requester: Digest,
        bootstrap: Digest,
    ) -> Result<Self> {
        let directory = files::create_directory(path)?;
        let lock = files::lock(&directory)?;
        let key = age::x25519::Identity::generate();
        let secret = Zeroizing::new(key.to_string().expose_secret().as_bytes().to_vec());
        files::write_new(key_path, &secret)?;
        let mut out = Self {
            data: Data {
                version: 1,
                network,
                incarnation,
                requester,
                bootstrap,
                generation: 1,
                entries: BTreeMap::new(),
            },
            directory,
            _lock: lock,
            key,
            poisoned: false,
        };
        out.validate()?;
        out.save()?;
        Ok(out)
    }
    pub fn open(
        path: &Path,
        key_path: &Path,
        network: Digest,
        incarnation: Digest,
        requester: Digest,
        bootstrap: Digest,
    ) -> Result<Self> {
        let directory = files::private_directory(path)?;
        let lock = files::lock(&directory)?;
        let secret = Zeroizing::new(files::read_single(key_path, 4096, true)?);
        let key = std::str::from_utf8(&secret)?
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid retained-search age identity"))?;
        let ciphertext = files::read_at(
            &directory,
            OsStr::new(FILE),
            MAXIMUM_BYTES + CIPHERTEXT_OVERHEAD,
            true,
        )?;
        let plaintext = crypto::decrypt_bounded(&key, &ciphertext, MAXIMUM_BYTES)?;
        let data: Data = serde_json::from_slice(&plaintext)?;
        ensure!(
            data.network == network
                && data.incarnation == incarnation
                && data.requester == requester
                && data.bootstrap == bootstrap,
            "retained search corpus belongs to another network or requester"
        );
        let out = Self {
            data,
            directory,
            _lock: lock,
            key,
            poisoned: false,
        };
        out.validate()?;
        Ok(out)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.poisoned
                && self.data.version == 1
                && self.data.generation > 0
                && self.data.entries.len() <= MAXIMUM_ITEMS
                && [
                    self.data.network,
                    self.data.incarnation,
                    self.data.requester,
                    self.data.bootstrap
                ]
                .iter()
                .all(|v| *v != [0; 32]),
            "invalid retained search corpus"
        );
        for (slot, entry) in &self.data.entries {
            ensure!(
                *slot == hex::encode(entry.id)
                    && entry.id != [0; 32]
                    && crate::markup::namespace(&entry.namespace)
                    && entry.grant.kind == 102
                    && entry.grant.generation > 0
                    && entry.publication.generation > 0,
                "invalid retained search item"
            );
            if let Some(lease) = &entry.lease {
                crate::authority_proof::validate_versions(&lease.versions, 64)?;
                ensure!(
                    lease.evaluated_at_ms < lease.expires_at_ms && lease.deadline_boot_ms > 0,
                    "invalid retained search lease"
                );
            }
        }
        Ok(())
    }
    fn save(&mut self) -> Result<()> {
        self.validate()?;
        let plain = Zeroizing::new(serde_json::to_vec(&self.data)?);
        ensure!(
            plain.len() <= MAXIMUM_BYTES,
            "retained corpus is full; forget content or select another corpus"
        );
        let encrypted = crypto::encrypt_bounded(&[self.key.to_public()], &plain, MAXIMUM_BYTES)?;
        let result = files::atomic_at(&self.directory, OsStr::new(FILE), &encrypted, true);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    #[cfg(test)]
    pub fn retain(&mut self, entry: Entry) -> Result<()> {
        self.retain_many(vec![entry])
    }
    pub fn retain_many(&mut self, entries: Vec<Entry>) -> Result<()> {
        self.data.generation = self
            .data
            .generation
            .checked_add(1)
            .context("retained corpus generation exhausted")?;
        for entry in entries {
            self.data.entries.insert(hex::encode(entry.id), entry);
        }
        self.save()
    }
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.data.entries.values()
    }
    pub fn generation(&self) -> u64 {
        self.data.generation
    }
    pub fn entry(&self, id: Digest) -> Result<&Entry> {
        self.data
            .entries
            .get(&hex::encode(id))
            .context("publication is not explicitly retained")
    }
    pub fn forget(&mut self, id: Digest) -> Result<()> {
        ensure!(
            self.data.entries.remove(&hex::encode(id)).is_some(),
            "publication is not explicitly retained"
        );
        self.data.generation = self
            .data
            .generation
            .checked_add(1)
            .context("retained corpus generation exhausted")?;
        self.save()
    }
}
