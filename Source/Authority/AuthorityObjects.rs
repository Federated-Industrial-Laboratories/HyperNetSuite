// SPDX-License-Identifier: MIT
// Immutable Page inputs are bound to exact finite references before domain parsing.
use crate::trust_wire::{self as wire, Value as V};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, sync::Arc};

pub type Digest = [u8; 32];
pub const PAGE_SOURCE_BYTES: usize = 16 * 1024;
pub const PAGE_BUNDLE_BYTES: usize = 56 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    PageSource,
    PageBundle,
}
impl Class {
    pub fn name(self) -> &'static str {
        match self {
            Self::PageSource => "PageSource",
            Self::PageBundle => "PageBundle",
        }
    }
    pub fn maximum(self) -> usize {
        match self {
            Self::PageSource => PAGE_SOURCE_BYTES,
            Self::PageBundle => PAGE_BUNDLE_BYTES,
        }
    }
    fn parse(name: &str) -> Result<Self> {
        match name {
            "PageSource" => Ok(Self::PageSource),
            "PageBundle" => Ok(Self::PageBundle),
            _ => anyhow::bail!("unknown immutable Page input class"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(into = "Descriptor", try_from = "Descriptor")]
pub struct Reference {
    class: Class,
    content: Digest,
    length: usize,
}
#[derive(Serialize, Deserialize)]
struct Descriptor(String, String, u64);
impl From<Reference> for Descriptor {
    fn from(value: Reference) -> Self {
        Self(
            value.class.name().into(),
            hex::encode(value.content),
            value.length as u64,
        )
    }
}
impl TryFrom<Descriptor> for Reference {
    type Error = anyhow::Error;
    fn try_from(value: Descriptor) -> Result<Self> {
        let content = hex::decode(&value.1)?;
        ensure!(
            hex::encode(&content) == value.1,
            "noncanonical input content digest"
        );
        Self::parse(&V::Array(vec![
            V::Uint(203),
            V::Uint(1),
            V::Text(value.0),
            V::Bytes(content),
            V::Uint(value.2),
        ]))
    }
}
impl Reference {
    pub fn parse(value: &V) -> Result<Self> {
        let fields = value.array(5)?;
        ensure!(
            fields[0].uint()? == 203 && fields[1].uint()? == 1,
            "invalid staged input reference"
        );
        let class = Class::parse(fields[2].text()?)?;
        let length = usize::try_from(fields[4].uint()?)?;
        ensure!(
            (1..=class.maximum()).contains(&length),
            "immutable input exceeds its class bound"
        );
        Ok(Self {
            class,
            content: fields[3].fixed()?,
            length,
        })
    }
    pub fn for_bytes(class: Class, bytes: &[u8]) -> Result<Self> {
        ensure!(
            (1..=class.maximum()).contains(&bytes.len()),
            "immutable input exceeds its class bound"
        );
        Ok(Self {
            class,
            content: Sha256::digest(bytes).into(),
            length: bytes.len(),
        })
    }
    pub fn value(&self) -> V {
        V::Array(vec![
            V::Uint(203),
            V::Uint(1),
            V::Text(self.class.name().into()),
            V::Bytes(self.content.to_vec()),
            V::Uint(self.length as u64),
        ])
    }
    pub fn canonical(&self) -> Vec<u8> {
        wire::encode(&self.value()).expect("bounded immutable input reference")
    }
    pub fn identity(&self) -> Digest {
        wire::digest(&self.canonical())
    }
    pub fn class(&self) -> Class {
        self.class
    }
    pub fn content_sha256(&self) -> Digest {
        self.content
    }
    pub fn len(&self) -> usize {
        self.length
    }
    pub fn verify(&self, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() == self.length && <Digest>::from(Sha256::digest(bytes)) == self.content,
            "immutable input bytes differ from the exact staged reference"
        );
        Ok(())
    }
}

pub fn validate_references(references: &[Reference]) -> Result<()> {
    ensure!(
        references.windows(2).all(|pair| pair[0] < pair[1]),
        "immutable input references are not sorted and unique"
    );
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Object {
    reference: Reference,
    bytes: Arc<Vec<u8>>,
}
impl Object {
    pub fn verify(reference: Reference, bytes: Vec<u8>) -> Result<Self> {
        Self::verify_shared(reference, Arc::new(bytes))
    }
    pub fn verify_shared(reference: Reference, bytes: Arc<Vec<u8>>) -> Result<Self> {
        reference.verify(&bytes)?;
        Ok(Self { reference, bytes })
    }
    pub fn reference(&self) -> &Reference {
        &self.reference
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Debug, Default)]
pub struct Resolved {
    objects: BTreeMap<Reference, Object>,
}
impl Resolved {
    /// The caller derives expected from a typed operation or verified state, not this sidecar.
    pub fn exact(expected: &[Reference], objects: Vec<Object>) -> Result<Self> {
        validate_references(expected)?;
        ensure!(
            objects.len() == expected.len(),
            "immutable input closure count differs"
        );
        let mut result = BTreeMap::new();
        for object in objects {
            ensure!(
                expected.binary_search(object.reference()).is_ok(),
                "unrequested immutable input"
            );
            ensure!(
                result.insert(object.reference.clone(), object).is_none(),
                "repeated immutable input"
            );
        }
        ensure!(
            expected.iter().all(|r| result.contains_key(r)),
            "immutable input closure is incomplete"
        );
        Ok(Self { objects: result })
    }
    pub fn get(&self, reference: &Reference) -> Result<&[u8]> {
        self.objects
            .get(reference)
            .map(Object::bytes)
            .with_context(|| {
                format!(
                    "undeclared evaluation input {}",
                    hex::encode(reference.identity())
                )
            })
    }
    pub fn objects(&self) -> impl Iterator<Item = &Object> {
        self.objects.values()
    }
    pub fn references(&self) -> Vec<Reference> {
        self.objects.keys().cloned().collect()
    }

    pub fn value(&self) -> V {
        V::Array(
            self.objects
                .values()
                .map(|object| {
                    V::Array(vec![
                        object.reference.value(),
                        V::Bytes(object.bytes().to_vec()),
                    ])
                })
                .collect(),
        )
    }
    pub fn parse(expected: &[Reference], value: &V) -> Result<Self> {
        validate_references(expected)?;
        let entries = value.array(expected.len())?;
        let mut objects = Vec::with_capacity(entries.len());
        for (entry, wanted) in entries.iter().zip(expected) {
            let fields = entry.array(2)?;
            let reference = Reference::parse(&fields[0])?;
            ensure!(
                &reference == wanted,
                "input sidecar order or exact reference differs"
            );
            reference.verify(fields[1].bytes()?)?;
            objects.push(Object::verify(reference, fields[1].bytes()?.to_vec())?);
        }
        Self::exact(expected, objects)
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Authority/AuthorityObjectsUnitTests.rs"]
mod tests;

#[cfg(test)]
include!("../../Tests/Support/Authority/AuthorityObjects.rs");
