// SPDX-License-Identifier: MIT
// Sealed recipient keys and explicit contact acceptance remain in a separate encrypted local vault.
use crate::{
    authority_domains::sealed_identity::{self as identity, Binding, Root},
    authority_proof::{Digest, VersionRef},
    sealed_crypto as crypto, transfer_files as files,
    trust_wire::{self as wire, Value as V},
};
use age::secrecy::ExposeSecret;
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, ffi::OsStr, fs::File, path::Path};
use zeroize::{Zeroize, Zeroizing};

const LIMIT: usize = 8 * 1024 * 1024;
const MAXIMUM_ROOTS: usize = 256;
const MAXIMUM_DEVICES: usize = 1024;
const FILE: &str = "SealedVault.age";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootSecret {
    member: Digest,
    seed: String,
}
impl Drop for RootSecret {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceSecret {
    member: Digest,
    device: Digest,
    signing_seed: String,
    encryption_identity: String,
}
impl Drop for DeviceSecret {
    fn drop(&mut self) {
        self.signing_seed.zeroize();
        self.encryption_identity.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Contact {
    root: Vec<u8>,
    acceptance: Vec<u8>,
    bindings: BTreeMap<String, Vec<u8>>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Data {
    version: u64,
    network: Digest,
    incarnation: Digest,
    bootstrap: Digest,
    clock_floor_ms: u64,
    trust_seed: String,
    roots: BTreeMap<String, RootSecret>,
    devices: BTreeMap<String, DeviceSecret>,
    contacts: BTreeMap<String, Contact>,
}
impl Drop for Data {
    fn drop(&mut self) {
        self.trust_seed.zeroize();
    }
}

pub struct DevicePublic {
    #[cfg(test)]
    pub member: Digest,
    #[cfg(test)]
    pub device: Digest,
    pub signing_key: Digest,
    pub encryption_key: Digest,
}
pub struct Vault {
    data: Data,
    directory: File,
    _lock: files::VaultLock,
    key: age::x25519::Identity,
    poisoned: bool,
}
fn now_ms() -> Result<u64> {
    crate::now()?
        .checked_mul(1000)
        .context("sealed vault clock overflow")
}
fn seed() -> String {
    let mut bytes = Zeroizing::new([0; 32]);
    OsRng.fill_bytes(bytes.as_mut());
    hex::encode(bytes.as_ref())
}
fn signer(secret: &str) -> Result<SigningKey> {
    let bytes = Zeroizing::new(hex::decode(secret)?);
    ensure!(
        bytes.len() == 32 && hex::encode(&*bytes) == secret,
        "invalid sealed signing identity"
    );
    Ok(SigningKey::from_bytes(bytes.as_slice().try_into()?))
}
fn encryption(secret: &str) -> Result<age::x25519::Identity> {
    secret
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid sealed encryption identity"))
}
fn root(envelope: &[u8], n: Digest, i: Digest) -> Result<Root> {
    let (payload, signatures) = wire::envelope(envelope, 4)?;
    let root = Root::parse(&payload, n, i)?;
    ensure!(
        signatures.iter().any(|(key, _)| *key == root.key),
        "sealed root lacks its own possession signature"
    );
    Ok(root)
}
fn reference(value: &VersionRef) -> V {
    V::Array(vec![
        V::Uint(value.kind),
        V::Bytes(value.id.to_vec()),
        V::Uint(value.generation),
        V::Bytes(value.digest.to_vec()),
    ])
}
impl Vault {
    pub fn initialise(
        path: &Path,
        key_path: &Path,
        n: Digest,
        i: Digest,
        pin: Digest,
    ) -> Result<Self> {
        ensure!(
            [n, i, pin].iter().all(|id| *id != [0; 32]),
            "sealed vault network identity is invalid"
        );
        let directory = files::create_directory(path)?;
        let lock = files::lock(&directory)?;
        let key = age::x25519::Identity::generate();
        let secret = Zeroizing::new(key.to_string().expose_secret().as_bytes().to_vec());
        files::write_new(key_path, &secret)?;
        let mut out = Self {
            data: Data {
                version: 1,
                network: n,
                incarnation: i,
                bootstrap: pin,
                clock_floor_ms: now_ms()?,
                trust_seed: seed(),
                roots: BTreeMap::new(),
                devices: BTreeMap::new(),
                contacts: BTreeMap::new(),
            },
            directory,
            _lock: lock,
            key,
            poisoned: false,
        };
        out.save()?;
        Ok(out)
    }
    pub fn open(path: &Path, key_path: &Path, n: Digest, i: Digest, pin: Digest) -> Result<Self> {
        let directory = files::private_directory(path)?;
        let lock = files::lock(&directory)?;
        let secret = Zeroizing::new(files::read(key_path, 4096, true)?);
        let key = encryption(std::str::from_utf8(&secret)?.trim())?;
        let bytes = files::read_at(&directory, OsStr::new(FILE), LIMIT + 200_704, true)?;
        let plain = crypto::decrypt_bounded(&key, &bytes, LIMIT)?;
        let data: Data = serde_json::from_slice(&plain)?;
        ensure!(
            data.version == 1
                && data.network == n
                && data.incarnation == i
                && data.bootstrap == pin,
            "sealed vault differs from independently accepted network"
        );
        let out = Self {
            data,
            directory,
            _lock: lock,
            key,
            poisoned: false,
        };
        out.check()?;
        out.validate()?;
        Ok(out)
    }
    fn check(&self) -> Result<()> {
        ensure!(
            !self.poisoned,
            "sealed vault requires recovery after an uncertain write"
        );
        ensure!(
            now_ms()?.saturating_add(2000) >= self.data.clock_floor_ms,
            "sealed vault clock rollback"
        );
        Ok(())
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.data.roots.len() <= MAXIMUM_ROOTS
                && self.data.contacts.len() <= MAXIMUM_ROOTS
                && self.data.devices.len() <= MAXIMUM_DEVICES,
            "sealed vault record admission exceeded"
        );
        let trust = signer(&self.data.trust_seed)?.verifying_key().to_bytes();
        for (id, secret) in &self.data.roots {
            ensure!(
                *id == hex::encode(secret.member) && secret.member != [0; 32],
                "sealed root slot differs"
            );
            signer(&secret.seed)?;
        }
        for (id, secret) in &self.data.devices {
            ensure!(
                *id == hex::encode(secret.device)
                    && secret.member != [0; 32]
                    && secret.device != [0; 32],
                "sealed device slot differs"
            );
            signer(&secret.signing_seed)?;
            encryption(&secret.encryption_identity)?;
        }
        for (id, contact) in &self.data.contacts {
            let root = root(&contact.root, self.data.network, self.data.incarnation)?;
            ensure!(
                *id == hex::encode(root.member) && contact.bindings.len() <= 16,
                "sealed contact slot differs"
            );
            let (acceptance, signatures) = wire::envelope(&contact.acceptance, 1)?;
            let acceptance =
                identity::Acceptance::parse(&acceptance, self.data.network, self.data.incarnation)?;
            ensure!(
                signatures[0].0 == trust
                    && acceptance.contact == root.member
                    && acceptance.accepted_root == root.reference,
                "sealed local acceptance differs"
            );
            for (device, envelope) in &contact.bindings {
                let binding = self.parse_binding(&root, envelope)?;
                ensure!(
                    *device == hex::encode(binding.device),
                    "sealed binding slot differs"
                );
            }
        }
        Ok(())
    }
    fn save(&mut self) -> Result<()> {
        self.check()?;
        self.poisoned = true;
        self.data.clock_floor_ms = self.data.clock_floor_ms.max(now_ms()?);
        self.validate()?;
        let plain = Zeroizing::new(serde_json::to_vec(&self.data)?);
        ensure!(
            plain.len() <= LIMIT,
            "sealed vault reached its storage admission"
        );
        let bytes = crypto::encrypt_bounded(&[self.key.to_public()], &plain, LIMIT)?;
        files::atomic_at(&self.directory, OsStr::new(FILE), &bytes, true)?;
        self.poisoned = false;
        Ok(())
    }
    pub fn trust_key(&self) -> Result<Digest> {
        self.check()?;
        Ok(signer(&self.data.trust_seed)?.verifying_key().to_bytes())
    }
    pub fn generate_root(&mut self, member: Digest) -> Result<Digest> {
        self.check()?;
        ensure!(
            member != [0; 32]
                && self.data.roots.len() < MAXIMUM_ROOTS
                && !self.data.roots.contains_key(&hex::encode(member)),
            "sealed local root exists or exceeds admission"
        );
        let secret = RootSecret {
            member,
            seed: seed(),
        };
        let key = signer(&secret.seed)?.verifying_key().to_bytes();
        self.data.roots.insert(hex::encode(member), secret);
        self.save()?;
        Ok(key)
    }
    pub fn root_signer(&self, member: Digest) -> Result<SigningKey> {
        self.check()?;
        signer(
            &self
                .data
                .roots
                .get(&hex::encode(member))
                .context("sealed local root is absent")?
                .seed,
        )
    }
    pub fn generate_device(&mut self, member: Digest, device: Digest) -> Result<DevicePublic> {
        self.check()?;
        ensure!(
            member != [0; 32]
                && device != [0; 32]
                && self.data.devices.len() < MAXIMUM_DEVICES
                && self
                    .data
                    .devices
                    .values()
                    .filter(|d| d.member == member)
                    .count()
                    < 16
                && !self.data.devices.contains_key(&hex::encode(device)),
            "sealed local device exists or exceeds admission"
        );
        let key = age::x25519::Identity::generate();
        let secret = DeviceSecret {
            member,
            device,
            signing_seed: seed(),
            encryption_identity: key.to_string().expose_secret().to_owned(),
        };
        let out = DevicePublic {
            #[cfg(test)]
            member,
            #[cfg(test)]
            device,
            signing_key: signer(&secret.signing_seed)?.verifying_key().to_bytes(),
            encryption_key: crypto::recipient_key(&key.to_public())?,
        };
        self.data.devices.insert(hex::encode(device), secret);
        self.save()?;
        Ok(out)
    }
    pub fn device_signer(&self, device: Digest) -> Result<SigningKey> {
        self.check()?;
        signer(
            &self
                .data
                .devices
                .get(&hex::encode(device))
                .context("sealed local device is absent")?
                .signing_seed,
        )
    }
    pub fn device_identity(&self, device: Digest) -> Result<age::x25519::Identity> {
        self.check()?;
        encryption(
            &self
                .data
                .devices
                .get(&hex::encode(device))
                .context("sealed local device is absent")?
                .encryption_identity,
        )
    }
    pub fn contact_root(&self, member: Digest) -> Result<Root> {
        self.check()?;
        root(
            &self
                .data
                .contacts
                .get(&hex::encode(member))
                .context("independently accepted sealed contact is absent")?
                .root,
            self.data.network,
            self.data.incarnation,
        )
    }
    pub fn contact_acceptance(&self, member: Digest) -> Result<Vec<u8>> {
        self.check()?;
        Ok(self
            .data
            .contacts
            .get(&hex::encode(member))
            .context("independently accepted sealed contact is absent")?
            .acceptance
            .clone())
    }
    fn acceptance(
        &self,
        root: &Root,
        previous: Option<&VersionRef>,
        recovery: Option<Digest>,
        trust: Digest,
    ) -> Result<Vec<u8>> {
        ensure!(
            trust != [0; 32],
            "independent sealed trust context is required"
        );
        let mut operation = [0; 32];
        OsRng.fill_bytes(&mut operation);
        let bytes = |v: &[u8]| V::Bytes(v.to_vec());
        let payload = wire::encode(&V::Array(vec![
            V::Uint(121),
            V::Uint(1),
            bytes(&self.data.network),
            bytes(&self.data.incarnation),
            V::Uint(0),
            V::Null,
            bytes(&operation),
            bytes(&root.member),
            previous.map_or(V::Null, reference),
            reference(&root.reference),
            recovery.map_or(V::Null, |id| bytes(&id)),
            bytes(&trust),
        ]))?;
        identity::Acceptance::parse(&payload, self.data.network, self.data.incarnation)?;
        wire::sign_envelope(&payload, &signer(&self.data.trust_seed)?)
    }
    /// The caller obtains the exact root fingerprint and trust context independently of directory lookup.
    pub fn accept_contact(
        &mut self,
        envelope: &[u8],
        independently_verified: Digest,
        trust: Digest,
    ) -> Result<Vec<u8>> {
        self.check()?;
        let root = root(envelope, self.data.network, self.data.incarnation)?;
        ensure!(
            independently_verified == root.reference.digest && trust != [0; 32],
            "sealed contact differs from independently verified root"
        );
        if let Some(old) = self.data.contacts.get(&hex::encode(root.member)) {
            ensure!(
                old.root == envelope,
                "sealed contact root changed; explicit successor acceptance required"
            );
            return Ok(old.acceptance.clone());
        }
        ensure!(
            self.data.contacts.len() < MAXIMUM_ROOTS,
            "sealed contact admission exhausted"
        );
        let acceptance = self.acceptance(&root, None, None, trust)?;
        self.data.contacts.insert(
            hex::encode(root.member),
            Contact {
                root: envelope.to_vec(),
                acceptance: acceptance.clone(),
                bindings: BTreeMap::new(),
            },
        );
        self.save()?;
        Ok(acceptance)
    }
    /// Successor continuity and explicit independent acceptance are both required; old devices are discarded.
    #[allow(clippy::too_many_arguments)]
    pub fn accept_successor(
        &mut self,
        envelope: &[u8],
        expected_previous: &VersionRef,
        independently_verified: Digest,
        trust: Digest,
        recovery: Option<&[u8]>,
        custody: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.check()?;
        let next = root(envelope, self.data.network, self.data.incarnation)?;
        let old = self.contact_root(next.member)?;
        ensure!(
            &old.reference == expected_previous && next.reference.digest == independently_verified,
            "sealed successor differs from exact explicit acceptance"
        );
        identity::verify_successor(
            &old,
            &next,
            envelope,
            recovery,
            custody,
            self.data.network,
            self.data.incarnation,
        )?;
        let declaration = recovery
            .map(|bytes| wire::envelope(bytes, 4).map(|(p, _)| wire::digest(&p)))
            .transpose()?;
        let acceptance = self.acceptance(&next, Some(&old.reference), declaration, trust)?;
        self.data.contacts.insert(
            hex::encode(next.member),
            Contact {
                root: envelope.to_vec(),
                acceptance: acceptance.clone(),
                bindings: BTreeMap::new(),
            },
        );
        self.save()?;
        Ok(acceptance)
    }
    fn parse_binding(&self, root: &Root, envelope: &[u8]) -> Result<Binding> {
        let (payload, signatures) = wire::envelope(envelope, 1)?;
        let binding = Binding::parse(&payload, self.data.network, self.data.incarnation)?;
        ensure!(
            signatures[0].0 == root.key
                && binding.member == root.member
                && binding.root == root.reference,
            "sealed device differs from accepted root signature"
        );
        crypto::validate_recipient_key(binding.encryption_key)?;
        Ok(binding)
    }
    /// Current authority and possession admission must be verified independently by the supplied consumer.
    pub fn observe_binding(
        &mut self,
        member: Digest,
        envelope: &[u8],
        verify_current: impl FnOnce(&Root, &Binding) -> Result<()>,
    ) -> Result<Binding> {
        self.check()?;
        let root = self.contact_root(member)?;
        let binding = self.parse_binding(&root, envelope)?;
        if let Some(local) = self.data.devices.get(&hex::encode(binding.device)) {
            ensure!(
                local.member == member
                    && signer(&local.signing_seed)?.verifying_key().to_bytes()
                        == binding.signing_key
                    && crypto::recipient_key(&encryption(&local.encryption_identity)?.to_public())?
                        == binding.encryption_key,
                "sealed binding substitutes local device keys"
            );
        }
        let now = now_ms()?;
        ensure!(
            binding.purposes.contains(&0) && binding.validity.0 <= now && now < binding.validity.1,
            "sealed device is not currently valid for reading"
        );
        verify_current(&root, &binding)?;
        let contact = self.data.contacts.get(&hex::encode(member)).unwrap();
        if let Some(old) = contact.bindings.get(&hex::encode(binding.device)) {
            ensure!(
                old == envelope,
                "sealed device identity changed; enrol a new device identity"
            );
            return Ok(binding);
        }
        ensure!(
            contact.bindings.len() < 16,
            "sealed contact device admission exhausted"
        );
        self.data
            .contacts
            .get_mut(&hex::encode(member))
            .unwrap()
            .bindings
            .insert(hex::encode(binding.device), envelope.to_vec());
        self.save()?;
        Ok(binding)
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Sealed/SealedVaultTests.rs"]
mod tests;
