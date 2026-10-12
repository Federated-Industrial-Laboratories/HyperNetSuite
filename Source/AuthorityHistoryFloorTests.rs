// SPDX-License-Identifier: MIT
// Checkpoint catch-up persists one restrictive authority floor before any effect.
use super::*;
use crate::{
    authority_challenge::{ClockHealth, Session, boot_time_ms},
    authority_floor::Store,
    authority_proof::{ActionValidation, Response, VerifiedResult, VersionRef, verify_response},
};
use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("HyperNetHistoryFloor{}", crate::random_hex::<16>()));
        crate::transfer_files::create_directory(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn health() -> ClockHealth {
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let boot = boot_time_ms().unwrap();
    ClockHealth::new(wall, boot, boot + 30000, 100)
        .unwrap()
        .frozen()
}
fn chain(session: &mut Session, sample: ClockHealth, size: usize) -> Chain {
    let mut f = Fixture::new(sample.observe().unwrap().wall_ms);
    f.challenge = session
        .issue(&f.intent, &f.recipient, [90; 32], 5000, sample)
        .unwrap();
    f.rebuild();
    Chain::with_fixture(f, size)
}
impl Chain {
    fn result_at(&self, height: usize, start: usize, refuse: bool) -> VerifiedResult {
        let node = Node::parse(&self.nodes[height - 1]).unwrap();
        let mut operation = wire::decode(&self.f.operation).unwrap();
        if refuse {
            let V::Array(fields) = &mut operation else {
                unreachable!()
            };
            fields[3] = V::Uint(1);
            fields[4] = V::Uint(7);
        }
        let operation = wire::encode(&operation).unwrap();
        let (payload, _) = wire::envelope(&self.f.certificate, 4).unwrap();
        let V::Array(mut fields) = wire::decode(&payload).unwrap() else {
            unreachable!()
        };
        fields[3] = V::Uint(height as u64);
        fields[4] = b(node.digest());
        fields[14] = V::Uint(if refuse { 0 } else { 64 });
        fields[15] = b(&wire::digest(&operation));
        fields[16] = b(&[81; 32]);
        fields[18] = V::Uint(node.evaluated_at_ms());
        let certificate = signed(&a(fields), 3);
        verify_response(
            &self.f.descriptor,
            self.f.context(),
            Response {
                ordered_request: &self.f.ordered,
                operation_result: &operation,
                certificate: &certificate,
                ancestry: &self.nodes[start..height],
            },
            |intent, result, _| {
                ensure!(result.value == intent.parameters, "test schema mismatch");
                ActionValidation::new(Vec::new())
            },
        )
        .unwrap()
    }
    fn attach(
        &self,
        store: &Store,
        height: usize,
        checkpoint: usize,
        refuse: bool,
    ) -> VerifiedResult {
        let c = self.checkpoint(checkpoint, false);
        let history = wire::encode(&self.history(&c, store.prefix(), store.tree_head())).unwrap();
        store
            .attach_history(
                self.result_at(height, checkpoint, refuse),
                c.canonical_proof(),
                &history,
            )
            .unwrap()
    }
}
fn known() -> VersionRef {
    VersionRef {
        kind: 126,
        id: [91; 32],
        generation: 1,
        digest: [92; 32],
    }
}
fn rewrite(directory: &Directory, edit: impl FnOnce(&mut serde_json::Value)) {
    let path = directory.0.join("AuthorityFloor.json");
    let mut floor: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    edit(&mut floor);
    let bytes = serde_json::to_vec(&floor).unwrap();
    std::fs::write(path, &bytes).unwrap();
    let witness = serde_json::json!({"sequence":floor["sequence"],"digest":hex::encode(Sha256::digest(&bytes))});
    std::fs::write(
        directory.0.join("AuthorityWitness.json"),
        serde_json::to_vec(&witness).unwrap(),
    )
    .unwrap();
}
#[test]
fn history_and_generation_floor_survive_restart_and_contiguous_use() {
    let sample = health();
    let mut session = Session::new().unwrap();
    let c = chain(&mut session, sample, 225);
    let directory = Directory::new();
    let mut store = Store::initialise(
        &directory.0,
        c.f.descriptor.clone(),
        crate::authority_proof::Intent::from_signed(&c.f.intent)
            .unwrap()
            .requester,
        sample,
    )
    .unwrap();
    crate::authority_floor::tests::prepared_fixture(&mut store, &c.f.intent);
    assert!(
        store
            .accept(c.result_at(200, 192, false), &mut session, sample, 0)
            .is_err()
    );
    let mut result = c.attach(&store, 200, 192, false);
    result.generations = vec![known()];
    let permit = store.accept(result, &mut session, sample, 0).unwrap();
    assert_eq!(store.prefix().height(), 200);
    assert_eq!(store.tree_head().unwrap().size(), 192);
    assert_eq!(store.generations(), &[known()]);
    assert_eq!(
        permit
            .perform(
                &mut store,
                &mut session,
                sample,
                1,
                |_| Ok(()),
                |r, _| Ok(r.action.clone())
            )
            .unwrap(),
        "ReadPage"
    );
    drop(store);
    let mut store = Store::open(&directory.0, c.f.descriptor.clone()).unwrap();
    assert_eq!(store.prefix().height(), 200);
    assert_eq!(store.tree_head().unwrap().size(), 192);
    assert_eq!(store.generations(), &[known()]);
    store.observe(c.result_at(201, 200, true)).unwrap();
    assert_eq!(store.tree_head().unwrap().size(), 192);
    let checkpoint = c.checkpoint(224, false);
    let substituted = wire::encode(&c.history(&checkpoint, store.prefix(), None)).unwrap();
    assert!(
        store
            .attach_history(
                c.result_at(225, 224, true),
                checkpoint.canonical_proof(),
                &substituted
            )
            .is_err()
    );
    store.observe(c.attach(&store, 225, 224, true)).unwrap();
    drop(store);
    let store = Store::open(&directory.0, c.f.descriptor).unwrap();
    assert_eq!(store.prefix().height(), 225);
    assert_eq!(store.tree_head().unwrap().size(), 224);
    assert_eq!(store.generations(), &[known()]);
}
#[test]
fn history_refusal_invalidates_pending_permit_and_failed_persistence_grants_nothing() {
    let sample = health();
    let mut session = Session::new().unwrap();
    let c = chain(&mut session, sample, 200);
    let directory = Directory::new();
    let mut store = Store::initialise(
        &directory.0,
        c.f.descriptor.clone(),
        crate::authority_proof::Intent::from_signed(&c.f.intent)
            .unwrap()
            .requester,
        sample,
    )
    .unwrap();
    crate::authority_floor::tests::prepared_fixture(&mut store, &c.f.intent);
    let pending = store
        .accept(c.result_at(1, 0, false), &mut session, sample, 0)
        .unwrap();
    let mut refused = c.attach(&store, 200, 192, true);
    let crate::authority_proof::SignedRequest::Intent(refused_intent) = &mut refused.request else {
        unreachable!()
    };
    refused_intent.expected = vec![known()];
    store.observe(refused).unwrap();
    assert!(store.generations().is_empty());
    assert!(
        pending
            .perform(
                &mut store,
                &mut session,
                sample,
                1,
                |_| Ok(()),
                |_, _| -> Result<()> { panic!("stale effect") }
            )
            .is_err()
    );
    drop(store);
    assert_eq!(
        Store::open(&directory.0, c.f.descriptor.clone())
            .unwrap()
            .tree_head()
            .unwrap()
            .size(),
        192
    );
    let directory = Directory::new();
    let mut store = Store::initialise(
        &directory.0,
        c.f.descriptor.clone(),
        crate::authority_proof::Intent::from_signed(&c.f.intent)
            .unwrap()
            .requester,
        sample,
    )
    .unwrap();
    crate::authority_floor::tests::prepared_fixture(&mut store, &c.f.intent);
    let result = c.attach(&store, 200, 192, false);
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o500)).unwrap();
    assert!(store.accept(result, &mut session, sample, 0).is_err());
    assert_eq!(store.prefix().height(), 0);
    assert!(store.tree_head().is_none());
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(store.observe(c.result_at(1, 0, true)).is_err());
}
#[test]
fn stored_checkpoint_is_required_and_cryptographically_reverified() {
    let sample = health();
    let mut session = Session::new().unwrap();
    let c = chain(&mut session, sample, 200);
    let directory = Directory::new();
    let mut store = Store::initialise(
        &directory.0,
        c.f.descriptor.clone(),
        crate::authority_proof::Intent::from_signed(&c.f.intent)
            .unwrap()
            .requester,
        sample,
    )
    .unwrap();
    crate::authority_floor::tests::prepared_fixture(&mut store, &c.f.intent);
    let bytes = std::fs::read(directory.0.join("AuthorityFloor.json")).unwrap();
    let initial: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(initial.get("checkpointProof").unwrap().is_null());
    store.observe(c.attach(&store, 200, 192, true)).unwrap();
    drop(store);
    rewrite(&directory, |floor| {
        floor.as_object_mut().unwrap().remove("checkpointProof");
    });
    assert!(Store::open(&directory.0, c.f.descriptor.clone()).is_err());
    let mut proof = c.checkpoint(192, false).canonical_proof().to_vec();
    *proof.last_mut().unwrap() ^= 1;
    rewrite(&directory, |floor| {
        floor["checkpointProof"] = hex::encode(&proof).into();
    });
    assert!(Store::open(&directory.0, c.f.descriptor.clone()).is_err());
    let mut old_shape = c.proof(192, false);
    let V::Array(fields) = &mut old_shape else {
        unreachable!()
    };
    fields.extend([b(&[]), V::Array(vec![])]);
    rewrite(&directory, |floor| {
        floor["checkpointProof"] = hex::encode(wire::encode(&old_shape).unwrap()).into();
    });
    assert!(Store::open(&directory.0, c.f.descriptor.clone()).is_err());
    let terminal = c.checkpoint(192, true);
    rewrite(&directory, |floor| {
        floor["checkpointProof"] = hex::encode(terminal.canonical_proof()).into();
    });
    assert!(Store::open(&directory.0, c.f.descriptor.clone()).is_err());
}
#[test]
fn attachment_rejects_terminal_and_other_retained_prefix() {
    let sample = health();
    let mut session = Session::new().unwrap();
    let c = chain(&mut session, sample, 200);
    let directory = Directory::new();
    let mut store = Store::initialise(
        &directory.0,
        c.f.descriptor.clone(),
        crate::authority_proof::Intent::from_signed(&c.f.intent)
            .unwrap()
            .requester,
        sample,
    )
    .unwrap();
    crate::authority_floor::tests::prepared_fixture(&mut store, &c.f.intent);
    let checkpoint = c.checkpoint(192, true);
    let history = wire::encode(&c.history(&checkpoint, store.prefix(), None)).unwrap();
    assert!(
        store
            .attach_history(
                c.result_at(200, 192, false),
                checkpoint.canonical_proof(),
                &history
            )
            .is_err()
    );
    let old = c.attach(&store, 200, 192, true);
    store.observe(c.result_at(1, 0, true)).unwrap();
    assert!(store.observe(old).is_err());
    assert!(store.tree_head().is_none());
}
