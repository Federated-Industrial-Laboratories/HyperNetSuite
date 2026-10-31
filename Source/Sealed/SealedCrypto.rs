// SPDX-License-Identifier: MIT
// Bounded sealed containers use typed age X25519 recipients and exact inner approval checks.
use crate::{
    authority_proof::{Digest, VersionRef},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context as _, Result, ensure};
use bech32::{FromBase32, ToBase32, Variant};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
};
use zeroize::{Zeroize, Zeroizing};

pub const MAXIMUM_RECIPIENTS: usize = 1024;
pub const MAXIMUM_ASSETS: usize = 64;
pub const MAXIMUM_ASSET_BYTES: usize = 4 * 1024 * 1024;
pub const MAXIMUM_ASSET_METADATA: usize = 4096;
pub const MAXIMUM_PLAINTEXT: usize = MAXIMUM_ASSET_BYTES
    + MAXIMUM_ASSETS * MAXIMUM_ASSET_METADATA
    + crate::authority_objects::PAGE_SOURCE_BYTES
    + wire::MAXIMUM * 2
    + 8192;
pub const MAXIMUM_CIPHERTEXT: usize = MAXIMUM_PLAINTEXT + MAXIMUM_RECIPIENTS * 192 + 4096;
const MAXIMUM_ARCHIVE: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    pub network: Digest,
    pub incarnation: Digest,
    pub publication: Digest,
    pub object: Digest,
    pub revision: u64,
    pub encryption_generation: u64,
    pub audience: VersionRef,
    pub roster_digest: Digest,
    pub inner_approval_digest: Digest,
}
impl Context {
    fn value(&self) -> V {
        V::Array(vec![
            bytes(&self.network),
            bytes(&self.incarnation),
            bytes(&self.publication),
            bytes(&self.object),
            V::Uint(self.revision),
            V::Uint(self.encryption_generation),
            V::Array(vec![
                V::Uint(self.audience.kind),
                bytes(&self.audience.id),
                V::Uint(self.audience.generation),
                bytes(&self.audience.digest),
            ]),
            bytes(&self.roster_digest),
            bytes(&self.inner_approval_digest),
        ])
    }
    fn parse(value: &V) -> Result<Self> {
        let f = value.array(9)?;
        let out = Self {
            network: f[0].fixed()?,
            incarnation: f[1].fixed()?,
            publication: f[2].fixed()?,
            object: f[3].fixed()?,
            revision: f[4].uint()?,
            encryption_generation: f[5].uint()?,
            audience: crate::authority_domains::version(&f[6])?,
            roster_digest: f[7].fixed()?,
            inner_approval_digest: f[8].fixed()?,
        };
        out.validate()?;
        Ok(out)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            [
                self.network,
                self.incarnation,
                self.publication,
                self.object,
                self.roster_digest,
                self.inner_approval_digest,
                self.audience.id,
                self.audience.digest
            ]
            .iter()
            .all(|id| *id != [0; 32])
                && self.revision > 0
                && self.encryption_generation > 0
                && self.audience.kind == 110
                && self.audience.generation > 0,
            "sealed container context is invalid"
        );
        Ok(())
    }
}

pub struct Asset {
    pub id: Digest,
    pub metadata: Zeroizing<Vec<u8>>,
    pub bytes: Zeroizing<Vec<u8>>,
}
pub struct Container {
    pub context: Context,
    pub signed_inner: Zeroizing<Vec<u8>>,
    pub signed_author: Zeroizing<Vec<u8>>,
    pub source: Zeroizing<Vec<u8>>,
    pub assets: Vec<Asset>,
}
impl Container {
    fn validate(&self) -> Result<()> {
        self.context.validate()?;
        ensure!(
            !self.signed_author.is_empty()
                && self.signed_author.len() <= wire::MAXIMUM
                && !self.signed_inner.is_empty()
                && self.signed_inner.len() <= wire::MAXIMUM
                && wire::digest(&self.signed_inner) == self.context.inner_approval_digest
                && !self.source.is_empty()
                && self.source.len() <= crate::authority_objects::PAGE_SOURCE_BYTES
                && self.assets.len() <= MAXIMUM_ASSETS,
            "sealed container exceeds its exact approval or content bounds"
        );
        let mut total = 0usize;
        let mut previous = None;
        for asset in &self.assets {
            ensure!(
                asset.id != [0; 32]
                    && previous.is_none_or(|id| id < asset.id)
                    && !asset.bytes.is_empty()
                    && !asset.metadata.is_empty()
                    && asset.metadata.len() <= MAXIMUM_ASSET_METADATA,
                "sealed asset identities repeat or metadata exceeds admission"
            );
            previous = Some(asset.id);
            total = total
                .checked_add(asset.bytes.len())
                .context("sealed asset extent overflow")?;
            ensure!(
                total <= MAXIMUM_ASSET_BYTES,
                "sealed assets exceed their byte admission"
            );
        }
        Ok(())
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        let value = PrivateValue(V::Array(vec![
            V::Uint(201),
            V::Uint(1),
            V::Text("SealedPageContainer".into()),
            self.context.value(),
            bytes(&self.signed_inner),
            bytes(&self.signed_author),
            bytes(&self.source),
            V::Array(
                self.assets
                    .iter()
                    .map(|a| V::Array(vec![bytes(&a.id), bytes(&a.metadata), bytes(&a.bytes)]))
                    .collect(),
            ),
        ]));
        Ok(Zeroizing::new(wire::encode_bounded(
            &value.0,
            MAXIMUM_PLAINTEXT,
        )?))
    }
    fn parse(plain: &[u8]) -> Result<Self> {
        let value = PrivateValue(wire::decode_bounded(plain, MAXIMUM_PLAINTEXT)?);
        let f = value.0.array(8)?;
        ensure!(
            f[0].uint()? == 201 && f[1].uint()? == 1 && f[2].text()? == "SealedPageContainer",
            "sealed container tag differs"
        );
        let out = Self {
            context: Context::parse(&f[3])?,
            signed_inner: Zeroizing::new(f[4].bytes()?.to_vec()),
            signed_author: Zeroizing::new(f[5].bytes()?.to_vec()),
            source: Zeroizing::new(f[6].bytes()?.to_vec()),
            assets: f[7]
                .list(MAXIMUM_ASSETS)?
                .iter()
                .map(|v| {
                    let a = v.array(3)?;
                    Ok(Asset {
                        id: a[0].fixed()?,
                        metadata: Zeroizing::new(a[1].bytes()?.to_vec()),
                        bytes: Zeroizing::new(a[2].bytes()?.to_vec()),
                    })
                })
                .collect::<Result<_>>()?,
        };
        out.validate()?;
        Ok(out)
    }
}
fn bytes(value: &[u8]) -> V {
    V::Bytes(value.to_vec())
}
struct PrivateValue(V);
impl Drop for PrivateValue {
    fn drop(&mut self) {
        fn erase(v: &mut V) {
            match v {
                V::Bytes(bytes) => bytes.zeroize(),
                V::Text(text) => text.zeroize(),
                V::Array(values) => values.iter_mut().for_each(erase),
                _ => {}
            }
        }
        erase(&mut self.0);
    }
}

pub fn ciphertext_digest(bytes: &[u8]) -> Digest {
    Sha256::digest(bytes).into()
}

pub fn recipient_from_key(key: [u8; 32]) -> Result<age::x25519::Recipient> {
    validate_recipient_key(key)?;
    let text = bech32::encode("age", key.to_base32(), Variant::Bech32)?;
    text.parse()
        .map_err(|_| anyhow::anyhow!("invalid sealed X25519 recipient"))
}
pub fn recipient_key(recipient: &age::x25519::Recipient) -> Result<[u8; 32]> {
    let (prefix, data, variant) = bech32::decode(&recipient.to_string())?;
    ensure!(
        prefix == "age" && variant == Variant::Bech32,
        "invalid sealed recipient encoding"
    );
    Vec::<u8>::from_base32(&data)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid sealed recipient key extent"))
}
pub fn validate_recipient_key(key: [u8; 32]) -> Result<()> {
    crate::authority_domains::sealed_identity::validate_encryption_key(key)?;
    // Validate before age wraps a file key: its recipient implementation can panic for low-order inputs.
    let ephemeral = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let shared = ephemeral.diffie_hellman(&x25519_dalek::PublicKey::from(key));
    ensure!(
        shared.was_contributory(),
        "non-contributory sealed recipient key"
    );
    Ok(())
}

pub(crate) fn encrypt_bounded(
    recipients: &[age::x25519::Recipient],
    plain: &[u8],
    maximum: usize,
) -> Result<Vec<u8>> {
    ensure!(
        maximum <= MAXIMUM_ARCHIVE
            && plain.len() <= maximum
            && (1..=MAXIMUM_RECIPIENTS).contains(&recipients.len()),
        "sealed encryption admission exceeded"
    );
    let mut keys = BTreeSet::new();
    for recipient in recipients {
        validate_recipient_key(recipient_key(recipient)?)?;
        ensure!(
            keys.insert(recipient_key(recipient)?),
            "sealed recipient key repeats"
        );
    }
    // Each construction generates a new file key and fresh recipient wrapping randomness.
    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))?;
    let mut ciphertext = Vec::new();
    let mut stream = encryptor.wrap_output(&mut ciphertext)?;
    stream.write_all(plain)?;
    stream.finish()?;
    ensure!(
        ciphertext.len() <= maximum + MAXIMUM_RECIPIENTS * 192 + 4096,
        "sealed ciphertext admission exceeded"
    );
    Ok(ciphertext)
}

fn recipient_header(ciphertext: &[u8]) -> Result<()> {
    // This policy gate bounds header work and rejects other stanza types. age parses the format.
    let mut offset = 0usize;
    let mut recipients = 0usize;
    let mut grease = 0usize;
    let mut body = None;
    let mut body_bytes = 0usize;
    loop {
        let rest = ciphertext
            .get(offset..)
            .context("truncated sealed age header")?;
        let length = rest
            .iter()
            .take(129)
            .position(|b| *b == b'\n')
            .context("sealed age header line exceeds its bound")?;
        let line = &rest[..length];
        offset += length + 1;
        ensure!(
            offset <= MAXIMUM_RECIPIENTS * 192 + 1024,
            "sealed age header exceeds admission"
        );
        if offset == length + 1 {
            ensure!(
                line == b"age-encryption.org/v1",
                "sealed ciphertext requires binary age version one"
            );
        } else if line.starts_with(b"-> ") {
            ensure!(body.is_none(), "sealed age recipient body is incomplete");
            let tag = line[3..].split(|b| *b == b' ').next().unwrap_or_default();
            if tag == b"X25519" {
                recipients += 1;
                ensure!(
                    recipients <= MAXIMUM_RECIPIENTS,
                    "sealed recipient count exceeds admission"
                );
                body = Some(true);
            } else {
                // age adds one ignored random stanza to exercise format extensibility.
                grease += 1;
                ensure!(
                    tag.ends_with(b"-grease") && grease <= 1,
                    "sealed ciphertext has an unsupported recipient"
                );
                body = Some(false);
            }
            body_bytes = 0;
        } else if line.starts_with(b"--- ") {
            ensure!(
                body.is_none() && recipients > 0,
                "sealed age recipient body is incomplete"
            );
            return Ok(());
        } else {
            let x25519 = body.context("sealed age recipient body is absent")?;
            body_bytes += line.len();
            ensure!(
                (x25519 && line.len() == 43 && body_bytes == 43)
                    || (!x25519 && line.len() <= 64 && body_bytes <= 134),
                "sealed age recipient body differs"
            );
            if line.len() < 64 {
                body = None;
            }
        }
    }
}
pub(crate) fn decrypt_bounded(
    identity: &age::x25519::Identity,
    ciphertext: &[u8],
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        maximum <= MAXIMUM_ARCHIVE && ciphertext.len() <= maximum + MAXIMUM_RECIPIENTS * 192 + 4096,
        "sealed ciphertext admission exceeded"
    );
    recipient_header(ciphertext)?;
    let decryptor = age::Decryptor::new_buffered(ciphertext)?;
    ensure!(
        !decryptor.is_scrypt(),
        "sealed ciphertext does not accept passphrases"
    );
    let reader = decryptor.decrypt(std::iter::once(identity as &dyn age::Identity))?;
    let mut plain = Zeroizing::new(Vec::new());
    reader.take((maximum + 1) as u64).read_to_end(&mut plain)?;
    ensure!(
        plain.len() <= maximum,
        "sealed plaintext exceeds its admission"
    );
    Ok(plain)
}

/// The verifier must authenticate canonical inner approval, current context and exact content digests.
pub fn seal(
    content: &Container,
    recipients: &[age::x25519::Recipient],
    verify: impl FnOnce(&Container) -> Result<()>,
) -> Result<Vec<u8>> {
    content.validate()?;
    verify(content)?;
    encrypt_bounded(recipients, &content.encode()?, MAXIMUM_PLAINTEXT)
}
/// Expected context and ciphertext digest come from the independently verified outer publication.
pub fn open(
    identity: &age::x25519::Identity,
    ciphertext: &[u8],
    expected_digest: Digest,
    expected: &Context,
    verify: impl FnOnce(&Container) -> Result<()>,
) -> Result<Container> {
    ensure!(
        ciphertext.len() <= MAXIMUM_CIPHERTEXT && ciphertext_digest(ciphertext) == expected_digest,
        "sealed outer ciphertext differs"
    );
    let plain = decrypt_bounded(identity, ciphertext, MAXIMUM_PLAINTEXT)?;
    let content = Container::parse(&plain)?;
    ensure!(
        &content.context == expected,
        "sealed inner and outer contexts differ"
    );
    verify(&content)?;
    Ok(content)
}
pub fn encrypt_challenge(key: &[u8; 32], challenge: &[u8]) -> Result<Vec<u8>> {
    encrypt_bounded(&[recipient_from_key(*key)?], challenge, wire::MAXIMUM)
}
pub fn decrypt_challenge(
    identity: &age::x25519::Identity,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    decrypt_bounded(identity, ciphertext, wire::MAXIMUM)
}

#[cfg(test)]
#[path = "../../Tests/Unit/Sealed/SealedCryptoTests.rs"]
mod tests;

#[cfg(test)]
include!("../../Tests/Support/Sealed/SealedCrypto.rs");
