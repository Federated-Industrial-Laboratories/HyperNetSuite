// SPDX-License-Identifier: MIT
//! Committee succession has one exact declaration and preserves prior application history.
use crate::{
    authority_membership::{Snapshot, reference, version},
    authority_proof::{Digest, Intent, Key, Scope, VersionRef},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;
pub const MAX_DECLARATION: usize = 16384;
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
fn id(v: &V) -> Result<Digest> {
    let id = v.fixed()?;
    ensure!(id != [0; 32], "zero epoch identifier");
    Ok(id)
}
#[derive(Clone, Debug)]
pub struct Nomination {
    pub voter: Key,
    pub profile: VersionRef,
    pub consent: VersionRef,
}
#[derive(Clone, Debug)]
pub struct Declaration {
    pub bytes: Vec<u8>,
    pub old_scope: Scope,
    pub next_epoch: u64,
    pub requester: Key,
    pub snapshot: Snapshot,
    pub nominations: Vec<Nomination>,
}
impl Declaration {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_DECLARATION,
            "epoch declaration exceeds bound"
        );
        let value = wire::decode(bytes)?;
        let f = value.array(8)?;
        ensure!(
            f[0].uint()? == 49 && f[1].uint()? == 1,
            "epoch declaration kind differs"
        );
        let scope = Scope::parse(&f[2])?;
        let next = f[3].uint()?;
        ensure!(
            scope.epoch.checked_add(1) == Some(next),
            "epoch successor is not consecutive"
        );
        let requester = id(&f[4])?;
        wire::valid_key(&requester)?;
        let snapshot = Snapshot::parse(&f[6])?;
        ensure!(
            snapshot.epoch == scope.epoch,
            "epoch declaration snapshot scope differs"
        );
        let mut previous = None;
        let mut deployments = BTreeSet::new();
        let mut nominations = Vec::new();
        for row in f[7].array(4)? {
            let n = row.array(3)?;
            let voter = id(&n[0])?;
            wire::valid_key(&voter)?;
            let profile = version(&n[1])?;
            let consent = version(&n[2])?;
            ensure!(
                previous.is_none_or(|p| p < voter)
                    && profile.kind == 117
                    && consent.kind == 105
                    && profile.id == consent.id
                    && deployments.insert(profile.id),
                "committee nomination is repeated or has inconsistent consent"
            );
            previous = Some(voter);
            nominations.push(Nomination {
                voter,
                profile,
                consent,
            });
        }
        id(&f[5])?;
        Ok(Self {
            bytes: bytes.to_vec(),
            old_scope: scope,
            next_epoch: next,
            requester,
            snapshot,
            nominations,
        })
    }
    pub fn from_intent(intent: &Intent) -> Result<Self> {
        let decoded = wire::decode(&intent.parameters)?;
        let f = decoded.array(4)?;
        ensure!(
            intent.action == "Reconfigure"
                && f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == "Reconfigure",
            "reconfiguration parameters differ from action"
        );
        let declaration = Self::parse(f[3].bytes()?)?;
        ensure!(
            intent.network == declaration.old_scope.network
                && intent.incarnation == declaration.old_scope.incarnation
                && intent.requester == declaration.requester
                && intent.resource == intent.network
                && intent.profile_generation == 0
                && intent.revision == declaration.snapshot.height
                && intent.minimum_policy_epoch == declaration.snapshot.epoch
                && intent.minimum_policy_height == declaration.snapshot.height
                && intent.expected == declaration.snapshot.references,
            "reconfiguration request differs from the exact declaration"
        );
        Ok(declaration)
    }
    pub fn digest(&self) -> Digest {
        wire::digest(&self.bytes)
    }
    pub fn parameters(&self) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("Reconfigure".into()),
            b(&self.bytes),
        ]))
    }
    pub fn create(
        scope: Scope,
        requester: Key,
        grant: Digest,
        snapshot: Snapshot,
        nominations: Vec<Nomination>,
    ) -> Result<Self> {
        let bytes = wire::encode(&a(vec![
            V::Uint(49),
            V::Uint(1),
            scope.value(),
            V::Uint(scope.epoch.checked_add(1).context("epoch overflow")?),
            b(&requester),
            b(&grant),
            snapshot.value,
            a(nominations
                .iter()
                .map(|n| {
                    a(vec![
                        b(&n.voter),
                        reference(&n.profile),
                        reference(&n.consent),
                    ])
                })
                .collect()),
        ]))?;
        Self::parse(&bytes)
    }
}
#[path = "AuthorityEpochProof.rs"]
mod proof;
pub use proof::{ValidatedActivation, ValidatedTerminal, verify_activation, verify_terminal};

#[path = "AuthorityEpochAssembly.rs"]
mod assembly;

pub use assembly::{assemble_checkpoint, assemble_handoff, assemble_ready};

#[path = "AuthorityEpochArchive.rs"]
pub mod archive;

#[cfg(test)]
#[path = "../../../Tests/Unit/Authority/Epochs/AuthorityEpochTests.rs"]
pub(crate) mod tests;

#[cfg(test)]
include!("../../../Tests/Support/Authority/Epochs/AuthorityEpoch.rs");
