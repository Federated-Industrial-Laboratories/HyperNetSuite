// SPDX-License-Identifier: MIT
// Private author submissions and reader verification share exact inert source and media validation.
use crate::{
    authority_domains::{
        sealed_identity::Roster,
        sealed_publication::{Author, Inner, ObjectPolicy, Outer},
    },
    authority_membership::{Snapshot, reference},
    authority_proof::{Digest, VersionRef},
    markup,
    sealed_crypto::{self as crypto, Asset, Container},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context as _, Result, ensure};
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
pub fn asset_id(id: &str) -> Result<Digest> {
    ensure!(markup::namespace(id), "invalid sealed asset identity");
    Ok(wire::digest(&wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("SealedAsset".into()),
        V::Text(id.into()),
    ]))?))
}
pub fn source_assets(source: &[u8], files: &BTreeMap<String, Vec<u8>>) -> Result<Vec<Asset>> {
    let document = markup::parse(std::str::from_utf8(source)?).map_err(anyhow::Error::msg)?;
    ensure!(
        files.len() == document.assets.len(),
        "sealed media selection is not exact"
    );
    let mut assets = Vec::new();
    for manifest in &document.assets {
        let bytes = files
            .get(&manifest.id)
            .context("sealed media file is absent")?;
        markup::media::validate_asset_bytes(manifest, bytes).map_err(anyhow::Error::msg)?;
        assets.push(Asset {
            id: asset_id(&manifest.id)?,
            metadata: Zeroizing::new(serde_json::to_vec(manifest)?),
            bytes: Zeroizing::new(bytes.clone()),
        });
    }
    assets.sort_by_key(|a| a.id);
    Ok(assets)
}
fn verify_source(source: &[u8], assets: &[Asset], author: &Author) -> Result<markup::Document> {
    ensure!(
        source.len() <= markup::MAX_BYTES && crypto::ciphertext_digest(source) == author.source,
        "sealed source differs from author declaration"
    );
    let document = markup::parse(std::str::from_utf8(source)?).map_err(anyhow::Error::msg)?;
    ensure!(
        assets.len() == document.assets.len() && assets.len() == author.assets.len(),
        "sealed assets are incomplete or duplicated"
    );
    let actual = assets
        .iter()
        .map(|a| (a.id, crypto::ciphertext_digest(&a.bytes)))
        .collect::<Vec<_>>();
    ensure!(
        actual == author.assets && assets.windows(2).all(|w| w[0].id < w[1].id),
        "sealed asset bytes differ from exact author intent"
    );
    for manifest in &document.assets {
        let id = asset_id(&manifest.id)?;
        let asset = assets
            .iter()
            .find(|a| a.id == id)
            .context("sealed asset absent")?;
        ensure!(
            asset.metadata.as_slice() == serde_json::to_vec(manifest)?,
            "sealed asset metadata differs from approved source"
        );
        markup::media::validate_asset_bytes(manifest, &asset.bytes).map_err(anyhow::Error::msg)?;
    }
    Ok(document)
}
struct PrivateValue(V);
impl Drop for PrivateValue {
    fn drop(&mut self) {
        fn erase(v: &mut V) {
            match v {
                V::Bytes(v) => v.zeroize(),
                V::Text(v) => v.zeroize(),
                V::Array(v) => v.iter_mut().for_each(erase),
                _ => (),
            }
        }
        erase(&mut self.0)
    }
}
pub struct Submission {
    pub network: Digest,
    pub incarnation: Digest,
    pub reviewer: VersionRef,
    pub signed_author: Zeroizing<Vec<u8>>,
    pub source: Zeroizing<Vec<u8>>,
    pub assets: Vec<Asset>,
}
impl Submission {
    pub fn new(
        network: Digest,
        incarnation: Digest,
        reviewer: VersionRef,
        signed_author: Vec<u8>,
        source: Vec<u8>,
        assets: Vec<Asset>,
    ) -> Result<Self> {
        let s = Self {
            network,
            incarnation,
            reviewer,
            signed_author: Zeroizing::new(signed_author),
            source: Zeroizing::new(source),
            assets,
        };
        s.verify()?;
        Ok(s)
    }
    fn verify(&self) -> Result<Author> {
        ensure!(
            self.reviewer.kind == 108
                && self.signed_author.len() <= wire::MAXIMUM
                && self.assets.len() <= crypto::MAXIMUM_ASSETS,
            "sealed review submission exceeds admission"
        );
        let author = Author::parse(&self.signed_author, self.network, self.incarnation)?;
        verify_source(&self.source, &self.assets, &author)?;
        Ok(author)
    }
    pub fn validate(&self, policy: &ObjectPolicy, at: u64) -> Result<Author> {
        let author = self.verify()?;
        ensure!(
            author.policy == policy.reference
                && author.object == policy.object
                && author.audience == policy.audience
                && author.publisher == policy.publisher
                && author.expires_ms > at.saturating_add(1250)
                && policy.modes.contains(&1)
                && !policy.public_audience,
            "sealed author policy or expiry changed"
        );
        Ok(author)
    }
    pub fn document(&self) -> Result<markup::Document> {
        let author = self.verify()?;
        verify_source(&self.source, &self.assets, &author)
    }
    pub fn encrypt(&self, reviewer_key: [u8; 32]) -> Result<Vec<u8>> {
        self.verify()?;
        let value = PrivateValue(a(vec![
            V::Uint(201),
            V::Uint(1),
            V::Text("SealedReviewSubmission".into()),
            b(&self.network),
            b(&self.incarnation),
            reference(&self.reviewer),
            b(&self.signed_author),
            b(&self.source),
            a(self
                .assets
                .iter()
                .map(|asset| a(vec![b(&asset.id), b(&asset.metadata), b(&asset.bytes)]))
                .collect()),
        ]));
        let bytes = Zeroizing::new(wire::encode_bounded(&value.0, crypto::MAXIMUM_PLAINTEXT)?);
        crypto::encrypt_bounded(
            &[crypto::recipient_from_key(reviewer_key)?],
            &bytes,
            crypto::MAXIMUM_PLAINTEXT,
        )
    }
    pub fn open(
        identity: &age::x25519::Identity,
        ciphertext: &[u8],
        expected_device: &VersionRef,
        n: Digest,
        i: Digest,
    ) -> Result<Self> {
        let bytes = crypto::decrypt_bounded(identity, ciphertext, crypto::MAXIMUM_PLAINTEXT)?;
        let value = PrivateValue(wire::decode_bounded(&bytes, crypto::MAXIMUM_PLAINTEXT)?);
        let f = value.0.array(9)?;
        ensure!(
            f[0].uint()? == 201
                && f[1].uint()? == 1
                && f[2].text()? == "SealedReviewSubmission"
                && f[3].fixed::<32>()? == n
                && f[4].fixed::<32>()? == i
                && crate::authority_domains::version(&f[5])? == *expected_device,
            "sealed review endpoint or network differs"
        );
        Self::new(
            n,
            i,
            expected_device.clone(),
            f[6].bytes()?.to_vec(),
            f[7].bytes()?.to_vec(),
            f[8].list(crypto::MAXIMUM_ASSETS)?
                .iter()
                .map(|v| {
                    let f = v.array(3)?;
                    ensure!(
                        f[1].bytes()?.len() <= crypto::MAXIMUM_ASSET_METADATA,
                        "sealed media metadata exceeds admission"
                    );
                    Ok(Asset {
                        id: f[0].fixed()?,
                        metadata: Zeroizing::new(f[1].bytes()?.to_vec()),
                        bytes: Zeroizing::new(f[2].bytes()?.to_vec()),
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        )
    }
    pub fn into_container(self, signed_inner: Vec<u8>) -> Result<Container> {
        let inner = Inner::parse(&signed_inner, self.network, self.incarnation)?;
        self.verify()?.verify_inner(&inner)?;
        Ok(Container {
            context: crypto::Context {
                network: self.network,
                incarnation: self.incarnation,
                publication: inner.publication,
                object: inner.object,
                revision: inner.revision,
                encryption_generation: inner.encryption_generation,
                audience: inner.audience,
                roster_digest: inner.roster,
                inner_approval_digest: wire::digest(&signed_inner),
            },
            signed_inner: Zeroizing::new(signed_inner),
            signed_author: self.signed_author,
            source: self.source,
            assets: self.assets,
        })
    }
}
pub fn inner(
    submission: &Submission,
    roster: &Roster,
    snapshot: &Snapshot,
    reviewer: &SigningKey,
) -> Result<Vec<u8>> {
    let author = submission.verify()?;
    ensure!(
        roster.audience == author.audience && roster.revision == author.revision,
        "sealed frozen audience or revision differs from author"
    );
    let fields = a(vec![
        V::Uint(112),
        V::Uint(1),
        b(&submission.network),
        b(&submission.incarnation),
        V::Uint(1),
        V::Null,
        b(&roster.publication),
        b(&author.object),
        V::Uint(author.revision),
        V::Uint(roster.encryption_generation),
        reference(&author.audience),
        b(&roster.reference.digest),
        b(&author.source),
        a(author
            .assets
            .iter()
            .map(|(id, d)| a(vec![b(id), b(d)]))
            .collect()),
        V::Uint(2),
        b(&author.publisher),
        b(&reviewer.verifying_key().to_bytes()),
        snapshot.value.clone(),
    ]);
    wire::sign_envelope(&wire::encode(&fields)?, reviewer)
}
pub fn context(outer: &Outer, n: Digest, i: Digest) -> crypto::Context {
    crypto::Context {
        network: n,
        incarnation: i,
        publication: outer.publication,
        object: outer.object,
        revision: outer.revision,
        encryption_generation: outer.encryption_generation,
        audience: outer.audience.clone(),
        roster_digest: outer.roster,
        inner_approval_digest: outer.inner_approval,
    }
}
pub fn verify_container(
    content: &Container,
    outer: &Outer,
    policy: &ObjectPolicy,
    at: u64,
) -> Result<markup::Document> {
    ensure!(
        content.context == context(outer, content.context.network, content.context.incarnation),
        "sealed reader context differs"
    );
    let inner = Inner::parse(
        &content.signed_inner,
        content.context.network,
        content.context.incarnation,
    )?;
    outer.verify_inner(&inner)?;
    verify_approval(content, policy, at)
}
pub fn verify_approval(
    content: &Container,
    policy: &ObjectPolicy,
    at: u64,
) -> Result<markup::Document> {
    let inner = Inner::parse(
        &content.signed_inner,
        content.context.network,
        content.context.incarnation,
    )?;
    ensure!(
        inner.publication == content.context.publication
            && inner.object == content.context.object
            && inner.revision == content.context.revision
            && inner.encryption_generation == content.context.encryption_generation
            && inner.audience == content.context.audience
            && inner.roster == content.context.roster_digest
            && wire::digest(&content.signed_inner) == content.context.inner_approval_digest,
        "sealed encrypted context differs from approval"
    );
    let author = Author::parse(
        &content.signed_author,
        content.context.network,
        content.context.incarnation,
    )?;
    author.verify_inner(&inner)?;
    ensure!(
        author.policy == policy.reference
            && policy.object == inner.object
            && author.publisher == policy.publisher
            && author.audience == policy.audience
            && author.expires_ms > at
            && policy.modes.contains(&1)
            && !policy.public_audience,
        "sealed reader policy or author intent differs"
    );
    verify_source(&content.source, &content.assets, &author)
}

#[cfg(test)]
#[path = "SealedPageDataTests.rs"]
mod tests;
