// SPDX-License-Identifier: MIT
// Independent recursive vectors cover asymmetric trees; signed fixtures exercise checkpoint bindings.
use super::*;
use crate::authority_proof::{
    CertifiedPoint,
    tests::{Fixture, signers},
};
use ed25519_dalek::Signer;
use serde::Deserialize;
fn b(value: &[u8]) -> V {
    V::Bytes(value.to_vec())
}
fn a(values: Vec<V>) -> Vec<u8> {
    wire::encode(&V::Array(values)).unwrap()
}
fn signed(payload: &[u8], count: usize) -> Vec<u8> {
    a(vec![
        V::Uint(0),
        V::Uint(1),
        b(payload),
        V::Array(
            signers()[..count]
                .iter()
                .map(|key| {
                    let public = key.verifying_key().to_bytes();
                    V::Array(vec![
                        b(&public),
                        b(&key
                            .sign(&wire::signature_message(payload, &public))
                            .to_bytes()),
                    ])
                })
                .collect(),
        ),
    ])
}
fn digest(text: &str) -> Digest {
    hex::decode(text).unwrap().try_into().unwrap()
}
#[derive(Deserialize)]
struct Inclusion {
    size: u64,
    index: u64,
    node: String,
    root: String,
    path: Vec<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Consistency {
    old_size: u64,
    size: u64,
    old_root: String,
    root: String,
    path: Vec<String>,
}
#[derive(Deserialize)]
struct Vectors {
    inclusion: Vec<Inclusion>,
    consistency: Vec<Consistency>,
}
fn vectors() -> Vectors {
    serde_json::from_str(include_str!("../../Tests/AuthorityHistoryVectors.json")).unwrap()
}
#[test]
fn independent_rfc_vectors_and_short_extra_corrupted_paths() {
    let vectors = vectors();
    for v in vectors.inclusion {
        let node = digest(&v.node);
        let root = digest(&v.root);
        let path = v.path.iter().map(|v| digest(v)).collect::<Vec<_>>();
        verify_inclusion(&node, v.index, v.size, &root, &path).unwrap();
        let mut extra = path.clone();
        extra.push([3; 32]);
        assert!(verify_inclusion(&node, v.index, v.size, &root, &extra).is_err());
        if !path.is_empty() {
            assert!(
                verify_inclusion(&node, v.index, v.size, &root, &path[..path.len() - 1]).is_err()
            );
            let mut wrong = path.clone();
            wrong[0][0] ^= 1;
            assert!(verify_inclusion(&node, v.index, v.size, &root, &wrong).is_err());
        }
        let mut wrong = node;
        wrong[31] ^= 1;
        assert!(verify_inclusion(&wrong, v.index, v.size, &root, &path).is_err());
    }
    for v in vectors.consistency {
        let old = digest(&v.old_root);
        let root = digest(&v.root);
        let path = v.path.iter().map(|v| digest(v)).collect::<Vec<_>>();
        verify_consistency(v.old_size, &old, v.size, &root, &path).unwrap();
        let mut extra = path.clone();
        extra.push([3; 32]);
        assert!(verify_consistency(v.old_size, &old, v.size, &root, &extra).is_err());
        if !path.is_empty() {
            assert!(
                verify_consistency(v.old_size, &old, v.size, &root, &path[..path.len() - 1])
                    .is_err()
            );
            let mut wrong = path.clone();
            wrong[0][0] ^= 1;
            assert!(verify_consistency(v.old_size, &old, v.size, &root, &wrong).is_err());
        }
        let mut wrong = old;
        wrong[31] ^= 1;
        assert!(verify_consistency(v.old_size, &wrong, v.size, &root, &path).is_err());
    }
}
#[test]
fn merkle_positions_bounds_and_same_size_equivocation_refuse() {
    let hash = [2; 32];
    for (index, size) in [
        (0, 0),
        (1, 1),
        (MAX_LEAVES, MAX_LEAVES + 1),
        (u64::MAX, u64::MAX),
    ] {
        assert!(verify_inclusion(&hash, index, size, &hash, &[]).is_err());
    }
    assert!(verify_inclusion(&hash, 0, 1, &leaf(&hash), &[[2; 32]; 65]).is_err());
    for (old, new) in [(0, 1), (2, 1), (1, MAX_LEAVES + 1), (u64::MAX, u64::MAX)] {
        assert!(verify_consistency(old, &hash, new, &hash, &[]).is_err());
    }
    verify_consistency(7, &hash, 7, &hash, &[]).unwrap();
    assert!(verify_consistency(7, &hash, 7, &[3; 32], &[]).is_err());
    assert!(verify_consistency(7, &hash, 7, &hash, &[[2; 32]]).is_err());
    assert!(verify_consistency(1, &hash, 2, &hash, &[[2; 32]; 65]).is_err());
}
fn tree(nodes: &[Digest]) -> Digest {
    if nodes.len() == 1 {
        return leaf(&nodes[0]);
    }
    let split = 1usize << ((nodes.len() - 1).ilog2());
    branch(&tree(&nodes[..split]), &tree(&nodes[split..]))
}
fn inclusion(nodes: &[Digest], index: usize) -> Vec<Digest> {
    if nodes.len() == 1 {
        return vec![];
    }
    let split = 1usize << ((nodes.len() - 1).ilog2());
    if index < split {
        let mut p = inclusion(&nodes[..split], index);
        p.push(tree(&nodes[split..]));
        p
    } else {
        let mut p = inclusion(&nodes[split..], index - split);
        p.push(tree(&nodes[..split]));
        p
    }
}
fn consistency(nodes: &[Digest], old: usize, known: bool) -> Vec<Digest> {
    if old == nodes.len() {
        return if known { vec![] } else { vec![tree(nodes)] };
    }
    let split = 1usize << ((nodes.len() - 1).ilog2());
    if old <= split {
        let mut p = consistency(&nodes[..split], old, known);
        p.push(tree(&nodes[split..]));
        p
    } else {
        let mut p = consistency(&nodes[split..], old - split, false);
        p.push(tree(&nodes[..split]));
        p
    }
}
struct Chain {
    f: Fixture,
    nodes: Vec<Vec<u8>>,
}
impl Chain {
    fn new(size: usize) -> Self {
        Self::with_fixture(Fixture::new(10000), size)
    }
    fn with_fixture(f: Fixture, size: usize) -> Self {
        let mut nodes = f.ancestry.clone();
        while nodes.len() < size {
            let previous = Node::parse(nodes.last().unwrap()).unwrap();
            nodes.push(a(vec![
                V::Uint(14),
                V::Uint(1),
                f.descriptor.scope().value(),
                V::Uint(previous.view() + 1),
                V::Uint(previous.height() + 1),
                b(previous.digest()),
                b(&wire::digest(&f.ordered)),
                V::Uint(previous.evaluated_at_ms() + 1),
                b(&[72; 32]),
            ]));
        }
        Self { f, nodes }
    }
    fn checkpoint_value(&self, height: usize, terminal: bool) -> V {
        let n = Node::parse(&self.nodes[height - 1]).unwrap();
        V::Array(vec![
            V::Uint(45),
            V::Uint(1),
            self.f.descriptor.scope().value(),
            V::Uint(height as u64),
            b(n.digest()),
            V::Uint(n.evaluated_at_ms()),
            b(&[81; 32]),
            V::Uint(height as u64),
            b(&tree(&self.digests()[..height])),
            V::Bool(terminal),
        ])
    }
    fn digests(&self) -> Vec<Digest> {
        self.nodes.iter().map(|v| wire::digest(v)).collect()
    }
    fn proof(&self, height: usize, terminal: bool) -> V {
        V::Array(vec![
            V::Uint(46),
            V::Uint(1),
            b(&signed(
                &wire::encode(&self.checkpoint_value(height, terminal)).unwrap(),
                3,
            )),
            b(&self.nodes[height - 1]),
        ])
    }
    fn checkpoint(&self, height: usize, terminal: bool) -> ValidatedCheckpoint {
        verify_checkpoint(
            &self.f.descriptor,
            &wire::encode(&self.proof(height, terminal)).unwrap(),
        )
        .unwrap()
    }
    fn retained_at(&self, height: usize) -> Prefix {
        let envelope = wire::decode(&self.f.certificate).unwrap();
        let mut payload = wire::decode(envelope.array(4).unwrap()[2].bytes().unwrap()).unwrap();
        let node = wire::decode(&self.nodes[height - 1]).unwrap();
        let node = node.array(9).unwrap();
        let V::Array(fields) = &mut payload else {
            unreachable!()
        };
        fields[3] = V::Uint(height as u64);
        fields[4] = b(&wire::digest(&self.nodes[height - 1]));
        fields[5] = node[6].clone();
        fields[16] = b(&[81; 32]);
        fields[18] = node[7].clone();
        let certificate = signed(&wire::encode(&payload).unwrap(), 3);
        CertifiedPoint::from_evidence(&self.f.descriptor, &certificate, &self.nodes[height - 1])
            .unwrap()
            .prefix()
            .clone()
    }
    fn retained(&self) -> Prefix {
        CertifiedPoint::from_evidence(&self.f.descriptor, &self.f.certificate, &self.nodes[0])
            .unwrap()
            .prefix()
            .clone()
    }
    fn history(
        &self,
        checkpoint: &ValidatedCheckpoint,
        retained: &Prefix,
        prior: Option<&TreeHead>,
    ) -> V {
        let nodes = self.digests();
        V::Array(vec![
            V::Uint(47),
            V::Uint(1),
            self.f.descriptor.scope().value(),
            V::Uint(retained.height()),
            b(retained.node()),
            b(checkpoint.digest()),
            V::Array(if retained.height() == 0 {
                vec![]
            } else {
                inclusion(
                    &nodes[..checkpoint.height() as usize],
                    retained.height() as usize - 1,
                )
                .iter()
                .map(|v| b(v))
                .collect()
            }),
            V::Uint(prior.map_or(0, TreeHead::size)),
            prior.map_or(V::Null, |h| b(h.root())),
            V::Array(
                prior
                    .map_or(vec![], |h| {
                        consistency(
                            &nodes[..checkpoint.height() as usize],
                            h.size as usize,
                            true,
                        )
                    })
                    .iter()
                    .map(|v| b(v))
                    .collect(),
            ),
        ])
    }
}
#[test]
fn checkpoint_accepts_applied_state_quorum_without_phase_certificate() {
    let chain = Chain::new(160);
    for anchor in [32, 64, 160] {
        let checkpoint = chain.checkpoint(anchor, false);
        assert_eq!(checkpoint.height(), anchor as u64);
        assert_eq!(checkpoint.node(), &wire::digest(&chain.nodes[anchor - 1]));
        assert_eq!(checkpoint.head.size(), anchor as u64);
        assert!(!checkpoint.terminal());
        assert_eq!(
            wire::decode(checkpoint.canonical_proof())
                .unwrap()
                .array(4)
                .unwrap()
                .len(),
            4
        );
    }
    let first = chain.checkpoint(32, false);
    let mut proof = chain.proof(32, false);
    let V::Array(fields) = &mut proof else {
        unreachable!()
    };
    fields[2] = b(&signed(first.statement(), 4));
    let second = verify_checkpoint(&chain.f.descriptor, &wire::encode(&proof).unwrap()).unwrap();
    assert_eq!(first.digest(), second.digest());
    assert_ne!(first.canonical_proof(), second.canonical_proof());
}
#[test]
fn checkpoint_rejects_malformed_quorum_anchor_schedule_and_attachment_shape() {
    let chain = Chain::new(64);
    for case in 0..11 {
        let mut package = chain.proof(32, false);
        let V::Array(fields) = &mut package else {
            unreachable!()
        };
        match case {
            0 => {
                let payload = wire::encode(&chain.checkpoint_value(32, false)).unwrap();
                fields[2] = b(&signed(&payload, 2));
            }
            1..=4 => {
                let mut value = chain.checkpoint_value(32, false);
                let V::Array(c) = &mut value else {
                    unreachable!()
                };
                match case {
                    1 => c[4] = b(&[99; 32]),
                    2 => c[5] = V::Uint(99),
                    3 => c[7] = V::Uint(31),
                    _ => c[9] = V::Uint(0),
                }
                fields[2] = b(&signed(&wire::encode(&value).unwrap(), 3));
            }
            5 => fields[3] = b(&chain.nodes[32]),
            6 => {
                fields.pop();
            }
            7 => fields.push(V::Null),
            8 => fields.extend([b(&[0]), V::Array(vec![])]),
            9 => package = chain.proof(31, false),
            _ => fields[3] = V::Null,
        }
        assert!(
            verify_checkpoint(&chain.f.descriptor, &wire::encode(&package).unwrap()).is_err(),
            "case {case}"
        );
    }
}
#[test]
fn checkpoint_rejects_former_shape_even_with_valid_deciding_commit_evidence() {
    let chain = Chain::new(35);
    let node = Node::parse(&chain.nodes[34]).unwrap();
    let vote = a(vec![
        V::Uint(11),
        V::Uint(1),
        chain.f.descriptor.scope().value(),
        V::Uint(node.view()),
        V::Uint(2),
        b(node.digest()),
    ]);
    let envelope = wire::decode(&signed(&vote, 3)).unwrap();
    let qc = a(vec![
        V::Uint(12),
        V::Uint(1),
        chain.f.descriptor.scope().value(),
        b(&vote),
        envelope.array(4).unwrap()[3].clone(),
    ]);
    let mut package = chain.proof(32, false);
    let V::Array(fields) = &mut package else {
        unreachable!()
    };
    fields.extend([
        b(&qc),
        V::Array(chain.nodes[32..35].iter().map(|v| b(v)).collect()),
    ]);
    assert!(verify_checkpoint(&chain.f.descriptor, &wire::encode(&package).unwrap()).is_err());
}
#[test]
fn history_binds_retained_node_genesis_and_requested_checkpoint() {
    let chain = Chain::new(35);
    let checkpoint = chain.checkpoint(32, false);
    let retained = chain.retained();
    let history = chain.history(&checkpoint, &retained, None);
    let bytes = wire::encode(&history).unwrap();
    let verified = verify_history(&checkpoint, &retained, None, &bytes).unwrap();
    assert_eq!(verified.from.node(), retained.node());
    verified.ordinary_checkpoint().unwrap();
    let genesis = chain.f.descriptor.genesis().unwrap();
    let history = chain.history(&checkpoint, &genesis, None);
    verify_history(
        &checkpoint,
        &genesis,
        None,
        &wire::encode(&history).unwrap(),
    )
    .unwrap();
    for case in 0..5 {
        let mut wrong = chain.history(&checkpoint, &retained, None);
        let V::Array(f) = &mut wrong else {
            unreachable!()
        };
        match case {
            0 => f[3] = V::Uint(2),
            1 => f[4] = b(&[8; 32]),
            2 => f[5] = b(&[8; 32]),
            3 => f[6] = V::Array(vec![]),
            _ => {
                f[7] = V::Uint(1);
                f[8] = b(&[8; 32]);
            }
        }
        assert!(
            verify_history(&checkpoint, &retained, None, &wire::encode(&wrong).unwrap()).is_err()
        );
    }
}
#[test]
fn same_position_checkpoint_cannot_replace_retained_applied_state() {
    let chain = Chain::new(32);
    let retained = chain.retained_at(32);
    let checkpoint = chain.checkpoint(32, false);
    let history = wire::encode(&chain.history(&checkpoint, &retained, None)).unwrap();
    verify_history(&checkpoint, &retained, None, &history).unwrap();
    let mut statement = chain.checkpoint_value(32, false);
    let V::Array(fields) = &mut statement else {
        unreachable!()
    };
    fields[6] = b(&[99; 32]);
    let mut package = chain.proof(32, false);
    let V::Array(fields) = &mut package else {
        unreachable!()
    };
    fields[2] = b(&signed(&wire::encode(&statement).unwrap(), 3));
    let conflicting =
        verify_checkpoint(&chain.f.descriptor, &wire::encode(&package).unwrap()).unwrap();
    let history = wire::encode(&chain.history(&conflicting, &retained, None)).unwrap();
    assert!(verify_history(&conflicting, &retained, None, &history).is_err());
}
#[test]
fn terminal_proof_is_visible_but_cannot_authorise_ordinary_old_scope_effects() {
    let chain = Chain::new(8);
    let checkpoint = chain.checkpoint(7, true);
    assert!(checkpoint.terminal());
    let retained = chain.retained();
    let history = chain.history(&checkpoint, &retained, None);
    let verified = verify_history(
        &checkpoint,
        &retained,
        None,
        &wire::encode(&history).unwrap(),
    )
    .unwrap();
    assert!(verified.ordinary_checkpoint().is_err());
}

#[test]
fn retained_tree_head_consistency_is_mandatory_and_cannot_be_selected_by_response() {
    let chain = Chain::new(65);
    let prior = chain.checkpoint(32, false);
    let checkpoint = chain.checkpoint(64, false);
    let retained = chain.retained_at(33);
    let good = chain.history(&checkpoint, &retained, Some(prior.head()));
    let good = wire::encode(&good).unwrap();
    verify_history(&checkpoint, &retained, Some(prior.head()), &good).unwrap();
    assert!(verify_history(&checkpoint, &retained, None, &good).is_err());
    for case in 0..5 {
        let mut bad = chain.history(&checkpoint, &retained, Some(prior.head()));
        let V::Array(fields) = &mut bad else {
            unreachable!()
        };
        match case {
            0 => fields[7] = V::Uint(31),
            1 => fields[8] = b(&[99; 32]),
            2 => fields[9] = V::Array(vec![]),
            3 => {
                let V::Array(path) = &mut fields[9] else {
                    unreachable!()
                };
                path.push(b(&[99; 32]));
            }
            _ => fields[6] = V::Array(vec![]),
        }
        assert!(
            verify_history(
                &checkpoint,
                &retained,
                Some(prior.head()),
                &wire::encode(&bad).unwrap()
            )
            .is_err(),
            "case {case}"
        );
    }
    let retained = chain.retained_at(64);
    let same = chain.history(&checkpoint, &retained, Some(checkpoint.head()));
    verify_history(
        &checkpoint,
        &retained,
        Some(checkpoint.head()),
        &wire::encode(&same).unwrap(),
    )
    .unwrap();
    let mut other = chain.checkpoint_value(64, false);
    let V::Array(fields) = &mut other else {
        unreachable!()
    };
    fields[8] = b(&[99; 32]);
    let mut package = chain.proof(64, false);
    let V::Array(fields) = &mut package else {
        unreachable!()
    };
    fields[2] = b(&signed(&wire::encode(&other).unwrap(), 3));
    let other = verify_checkpoint(&chain.f.descriptor, &wire::encode(&package).unwrap()).unwrap();
    let path = chain.history(&other, &retained, Some(checkpoint.head()));
    assert!(
        verify_history(
            &other,
            &retained,
            Some(checkpoint.head()),
            &wire::encode(&path).unwrap()
        )
        .is_err()
    );
}

#[test]
fn prior_terminal_checkpoint_cannot_be_replaced_or_extended_in_the_old_scope() {
    let chain = Chain::new(65);
    let terminal = chain.checkpoint(32, true);
    let retained = chain.retained_at(32);
    for replacement in [
        chain.checkpoint(32, false),
        chain.checkpoint(64, false),
        chain.checkpoint(64, true),
    ] {
        let proof = chain.history(&replacement, &retained, Some(terminal.head()));
        assert!(
            verify_history(
                &replacement,
                &retained,
                Some(terminal.head()),
                &wire::encode(&proof).unwrap()
            )
            .is_err()
        );
    }
}

#[test]
fn checkpoint_statement_rejects_duplicate_foreign_and_tampered_signers() {
    let chain = Chain::new(35);
    for case in 0..4 {
        let mut package = chain.proof(32, false);
        let V::Array(fields) = &mut package else {
            unreachable!()
        };
        let mut envelope = wire::decode(fields[2].bytes().unwrap()).unwrap();
        let V::Array(q) = &mut envelope else {
            unreachable!()
        };
        let V::Array(signatures) = &mut q[3] else {
            unreachable!()
        };
        match case {
            0 => signatures[1] = signatures[0].clone(),
            1 => signatures.swap(0, 1),
            2 => {
                let V::Array(pair) = &mut signatures[0] else {
                    unreachable!()
                };
                pair[0] = b(&ed25519_dalek::SigningKey::from_bytes(&[99; 32])
                    .verifying_key()
                    .to_bytes());
            }
            _ => {
                let V::Array(pair) = &mut signatures[0] else {
                    unreachable!()
                };
                pair[1] = b(&[99; 64]);
            }
        }
        fields[2] = b(&wire::encode(&envelope).unwrap());
        assert!(verify_checkpoint(&chain.f.descriptor, &wire::encode(&package).unwrap()).is_err());
    }
    let payload = wire::encode(&chain.checkpoint_value(32, false)).unwrap();
    let mut keys = signers();
    keys.truncate(2);
    keys.push(ed25519_dalek::SigningKey::from_bytes(&[99; 32]));
    keys.sort_by_key(|key| key.verifying_key().to_bytes());
    let envelope = a(vec![
        V::Uint(0),
        V::Uint(1),
        b(&payload),
        V::Array(
            keys.iter()
                .map(|key| {
                    let public = key.verifying_key().to_bytes();
                    V::Array(vec![
                        b(&public),
                        b(&key
                            .sign(&wire::signature_message(&payload, &public))
                            .to_bytes()),
                    ])
                })
                .collect(),
        ),
    ]);
    wire::envelope(&envelope, 4).unwrap();
    let mut package = chain.proof(32, false);
    let V::Array(fields) = &mut package else {
        unreachable!()
    };
    fields[2] = b(&envelope);
    assert!(verify_checkpoint(&chain.f.descriptor, &wire::encode(&package).unwrap()).is_err());
}

#[test]
fn valid_signatures_cannot_move_checkpoint_anchor_or_history_to_another_scope() {
    let chain = Chain::new(35);
    let mut other = chain.f.descriptor.scope().clone();
    other.epoch += 1;
    for case in 0..2 {
        let mut package = chain.proof(32, false);
        let V::Array(fields) = &mut package else {
            unreachable!()
        };
        if case == 0 {
            let mut statement = chain.checkpoint_value(32, false);
            let V::Array(value) = &mut statement else {
                unreachable!()
            };
            value[2] = other.value();
            fields[2] = b(&signed(&wire::encode(&statement).unwrap(), 3));
        } else {
            let mut anchor = wire::decode(fields[3].bytes().unwrap()).unwrap();
            let V::Array(value) = &mut anchor else {
                unreachable!()
            };
            value[2] = other.value();
            let anchor = wire::encode(&anchor).unwrap();
            let mut statement = chain.checkpoint_value(32, false);
            let V::Array(value) = &mut statement else {
                unreachable!()
            };
            value[4] = b(&wire::digest(&anchor));
            fields[2] = b(&signed(&wire::encode(&statement).unwrap(), 3));
            fields[3] = b(&anchor);
        }
        assert!(verify_checkpoint(&chain.f.descriptor, &wire::encode(&package).unwrap()).is_err());
    }
    let checkpoint = chain.checkpoint(32, false);
    let retained = chain.retained();
    let mut history = chain.history(&checkpoint, &retained, None);
    let V::Array(value) = &mut history else {
        unreachable!()
    };
    value[2] = other.value();
    assert!(
        verify_history(
            &checkpoint,
            &retained,
            None,
            &wire::encode(&history).unwrap()
        )
        .is_err()
    );
}

#[path = "AuthorityHistoryFloorTests.rs"]
mod durable;
