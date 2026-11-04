// SPDX-License-Identifier: MIT
// Fresh evidence survives floor recovery without completing or replacing an ordinary operation.
use super::*;
use crate::authority_read::{self as read, Query, Request, Statement, VerifiedRead};

fn later(sample: ClockHealth, elapsed: u64) -> ClockHealth {
    let now = sample.observe().unwrap();
    ClockHealth::new(
        now.wall_ms + elapsed,
        now.boot_ms + elapsed,
        now.boot_ms + elapsed + 30_000,
        100,
    )
    .unwrap()
    .frozen()
}

struct Read {
    request: Vec<u8>,
    challenge: Vec<u8>,
    result: Vec<u8>,
    certificate: Vec<u8>,
    node: Vec<u8>,
    versions: Vec<VersionRef>,
}
impl Read {
    fn with_nonce(
        store: &Store,
        session: &mut Session,
        sample: ClockHealth,
        nonce: Digest,
    ) -> Self {
        let signer = SigningKey::from_bytes(&[1; 32]);
        let scope = store.descriptor().scope();
        let request = Request::sign(
            scope,
            &signer,
            store.requester(),
            nonce,
            store.prefix().height(),
            Query::PolicyContext,
        )
        .unwrap();
        let challenge = session
            .issue_read(&request, &signer, nonce, 5000, sample)
            .unwrap();
        let versions = [100, 114]
            .into_iter()
            .map(|kind| VersionRef {
                kind,
                id: scope.network,
                generation: 1,
                digest: [kind as u8; 32],
            })
            .collect::<Vec<_>>();
        let value = encoded(vec![
            V::Uint(201),
            V::Uint(1),
            V::Text("AuthorityPolicyContext".into()),
            V::Array(
                versions
                    .iter()
                    .map(crate::authority_membership::reference)
                    .collect(),
            ),
            V::Array(vec![]),
        ]);
        let result = encoded(vec![
            V::Uint(24),
            V::Uint(1),
            V::Text("AuthorityPolicyContext".into()),
            V::Uint(0),
            V::Uint(0),
            b(&value),
        ]);
        let request_digest = Request::from_signed(&request).unwrap().digest;
        let parsed = proof::Challenge::from_signed(&challenge).unwrap();
        let evaluated_at_ms = (parsed.created_at_ms + crate::authority_governance::UNCERTAINTY_MS)
            .max(store.prefix().evaluated_at_ms());
        let statement = Statement {
            scope: scope.clone(),
            request: request_digest,
            challenge: parsed.digest,
            requester: store.requester(),
            recipient: store.requester(),
            height: store.prefix().height(),
            node: *store.prefix().node(),
            state: *store.prefix().policy_state(),
            evaluated_at_ms,
            expires_at_ms: parsed
                .evaluation_expiry(evaluated_at_ms, parsed.expires_at_ms)
                .unwrap(),
            result: wire::digest(&result),
        };
        let certificate = quorum(
            wire::decode(&statement.encode().unwrap())
                .unwrap()
                .array(13)
                .unwrap()
                .to_vec(),
        );
        let node = hex::decode(store.stored.node.as_ref().unwrap()).unwrap();
        Self {
            request,
            challenge,
            result,
            certificate,
            node,
            versions,
        }
    }
    fn verify(&self, store: &Store) -> VerifiedRead {
        read::verify_response(
            store.descriptor(),
            &self.request,
            &self.challenge,
            read::Response {
                node: &self.node,
                certificate: &self.certificate,
                result: &self.result,
                ancestry: std::slice::from_ref(&self.node),
            },
            |_, result, _| {
                ensure!(
                    result.value == OperationResult::parse(&self.result)?.value,
                    "floor fixture result changed"
                );
                Ok(self.versions.clone())
            },
        )
        .unwrap()
    }

    fn certify_later_prefix(&mut self, height: u64, branch: u8) {
        let (payload, _) = wire::envelope(&self.certificate, 4).unwrap();
        let mut statement = Statement::parse(&payload).unwrap();
        let value = wire::decode(&self.node).unwrap();
        let mut node = value.array(9).unwrap().to_vec();
        assert!(height > statement.height);
        node[3] = V::Uint(height);
        node[4] = V::Uint(node[4].uint().unwrap() + height - statement.height);
        node[5] = b(&statement.node);
        node[6] = b(&[branch; 32]);
        node[7] = V::Uint(statement.evaluated_at_ms);
        self.node = encoded(node);
        statement.height = height;
        statement.node = wire::digest(&self.node);
        self.certificate = quorum(
            wire::decode(&statement.encode().unwrap())
                .unwrap()
                .array(13)
                .unwrap()
                .to_vec(),
        );
    }
}

#[test]
fn concurrent_lower_bound_reads_accept_same_newer_certified_prefix_once_each() {
    let (directory, sample, mut session, mut store) = setup();
    let sample = later(sample, 500);
    let issued_height = store.prefix().height();
    let tracker = store.stored.tracker.clone();
    let mut first = Read::with_nonce(&store, &mut session, sample, [97; 32]);
    let mut second = Read::with_nonce(&store, &mut session, sample, [98; 32]);
    for query in [&mut first, &mut second] {
        query.certify_later_prefix(issued_height + 1, 83);
        assert_eq!(
            Request::from_signed(&query.request).unwrap().minimum_height,
            issued_height
        );
    }
    let first_result = first.verify(&store);
    let second_result = second.verify(&store);
    let mut effects = 0;
    for result in [second_result, first_result] {
        store
            .accept_read_consumed(result, &mut session, &mut || Ok(sample), 0, |_, _| {
                effects += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(store.prefix().height(), issued_height + 1);
        assert_eq!(store.stored.tracker, tracker);
    }
    assert_eq!(effects, 2);
    for query in [&first, &second] {
        assert!(
            store
                .accept_read_consumed(
                    query.verify(&store),
                    &mut session,
                    &mut || Ok(sample),
                    0,
                    |_, _| -> Result<()> { panic!("completed read was consumed twice") },
                )
                .is_err()
        );
    }
    let prefix = store.prefix().clone();
    let descriptor = store.descriptor().clone();
    drop(store);
    assert_eq!(
        Store::open(&directory.0, descriptor).unwrap().prefix(),
        &prefix
    );
}

#[test]
fn newer_floor_still_rejects_stale_or_conflicting_read_results() {
    let (directory, sample, mut session, mut store) = setup();
    let sample = later(sample, 500);
    let mut accepted = Read::with_nonce(&store, &mut session, sample, [97; 32]);
    let stale = Read::with_nonce(&store, &mut session, sample, [98; 32]);
    let mut conflicting = Read::with_nonce(&store, &mut session, sample, [99; 32]);
    let height = store.prefix().height() + 1;
    accepted.certify_later_prefix(height, 83);
    conflicting.certify_later_prefix(height, 84);
    store
        .accept_read_consumed(
            accepted.verify(&store),
            &mut session,
            &mut || Ok(sample),
            0,
            |_, _| Ok(()),
        )
        .unwrap();
    let prefix = store.prefix().clone();
    let floor = std::fs::read(directory.0.join(FLOOR)).unwrap();
    let witness = std::fs::read(directory.0.join(WITNESS)).unwrap();
    for (query, expected) in [
        (&stale, "below the accepted"),
        (&conflicting, "conflicting result"),
    ] {
        let error = store
            .accept_read_consumed(
                query.verify(&store),
                &mut session,
                &mut || Ok(sample),
                0,
                |_, _| -> Result<()> { panic!("stale or conflicting read published") },
            )
            .err()
            .unwrap();
        assert!(error.to_string().contains(expected), "{error:#}");
        assert_eq!(store.prefix(), &prefix);
        assert_eq!(std::fs::read(directory.0.join(FLOOR)).unwrap(), floor);
        assert_eq!(std::fs::read(directory.0.join(WITNESS)).unwrap(), witness);
    }
}

#[test]
fn history_bound_before_concurrent_publication_is_not_rebased() {
    use sha2::{Digest as _, Sha256};

    let (directory, sample, mut session, mut store) = setup();
    let sample = later(sample, 500);
    assert_eq!(store.prefix().height(), 1);
    let mut first = Read::with_nonce(&store, &mut session, sample, [97; 32]);
    let mut second = Read::with_nonce(&store, &mut session, sample, [98; 32]);
    first.certify_later_prefix(32, 83);
    second.certify_later_prefix(32, 83);
    let (payload, _) = wire::envelope(&first.certificate, 4).unwrap();
    let statement = Statement::parse(&payload).unwrap();
    let mut nodes = [[85; 32]; 32];
    nodes[0] = *store.prefix().node();
    nodes[31] = statement.node;
    let mut hashes = nodes
        .iter()
        .map(|node| Sha256::digest([&[0][..], node].concat()).into())
        .collect::<Vec<Digest>>();
    let mut inclusion = Vec::new();
    while hashes.len() > 1 {
        inclusion.push(hashes[1]);
        hashes = hashes
            .chunks_exact(2)
            .map(|pair| Sha256::digest([&[1][..], &pair[0], &pair[1]].concat()).into())
            .collect();
    }
    let checkpoint = encoded(vec![
        V::Uint(46),
        V::Uint(1),
        b(&quorum(vec![
            V::Uint(45),
            V::Uint(1),
            statement.scope.value(),
            V::Uint(32),
            b(&statement.node),
            V::Uint(statement.evaluated_at_ms),
            b(&statement.state),
            V::Uint(32),
            b(&hashes[0]),
            V::Bool(false),
        ])),
        b(&first.node),
    ]);
    let verified_checkpoint = history::verify_checkpoint(store.descriptor(), &checkpoint).unwrap();
    let proof = encoded(vec![
        V::Uint(47),
        V::Uint(1),
        statement.scope.value(),
        V::Uint(store.prefix().height()),
        b(store.prefix().node()),
        b(verified_checkpoint.digest()),
        V::Array(inclusion.iter().map(|hash| b(hash)).collect()),
        V::Uint(0),
        V::Null,
        V::Array(vec![]),
    ]);
    let first_result = store
        .attach_read_history(first.verify(&store), &checkpoint, &proof)
        .unwrap();
    let second_result = store
        .attach_read_history(second.verify(&store), &checkpoint, &proof)
        .unwrap();
    store
        .accept_read_consumed(first_result, &mut session, &mut || Ok(sample), 0, |_, _| {
            Ok(())
        })
        .unwrap();
    let floor = std::fs::read(directory.0.join(FLOOR)).unwrap();
    let error = store
        .accept_read_consumed(
            second_result,
            &mut session,
            &mut || Ok(sample),
            0,
            |_, _| -> Result<()> { panic!("old history was silently rebased") },
        )
        .err()
        .unwrap();
    assert!(error.to_string().contains("history differs"), "{error:#}");
    assert_eq!(store.prefix().height(), 32);
    assert_eq!(std::fs::read(directory.0.join(FLOOR)).unwrap(), floor);
    assert!(
        store
            .attach_read_history(second.verify(&store), &checkpoint, &proof)
            .is_err()
    );
}
