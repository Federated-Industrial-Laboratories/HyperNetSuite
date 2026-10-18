// SPDX-License-Identifier: MIT
// Retained matching distinguishes query scopes and never extends authority freshness.
use super::*;
use crate::authority_challenge::ClockHealth;
fn query() -> Request {
    Request {
        network: [1; 32],
        incarnation: [2; 32],
        operation: [3; 32],
        scope: 0,
        terms: vec!["books".into()],
        combination: 0,
        namespaces: vec![],
        limit: 1,
        cursor: None,
        historical: false,
        snapshot: V::Array(vec![
            V::Array(vec![V::Uint(1), V::Uint(1), V::Bytes(vec![4; 32])]),
            V::Array(vec![]),
        ]),
    }
}
fn hits() -> Vec<Hit> {
    [([5; 32], 2), ([6; 32], 1)]
        .into_iter()
        .map(|(id, score)| Hit {
            id: hex::encode(id),
            namespace: "Books".into(),
            matched: search_text::Match {
                title: "Books".into(),
                snippet: "A book".into(),
                tags: vec![],
                score,
            },
            uri: None,
            provenance: json!({"kind":"Native"}),
        })
        .collect()
}
#[test]
fn cursor_cannot_cross_query_scope_or_changed_result_extent() {
    let mut request = query();
    let binding = request.digest().unwrap();
    let (first, next, total) = page(hits(), &request, binding).unwrap();
    assert_eq!(total, 2);
    assert_eq!(first[0].matched.score, 2);
    request.cursor = Some(id(&next.unwrap()).unwrap());
    assert_eq!(
        page(hits(), &request, binding).unwrap().0[0].matched.score,
        1
    );
    assert!(page(hits(), &request, [9; 32]).is_err());
    let mut missing = hits();
    missing.remove(0);
    assert!(page(missing, &request, binding).is_err());
    let mut duplicate = hits();
    duplicate[1].id = duplicate[0].id.clone();
    assert!(page(duplicate, &query(), binding).is_err());
}
#[test]
fn encrypted_corpus_reopens_without_plaintext_and_rejects_another_requester() {
    let root = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join(format!("SearchState{}", crate::random_hex::<16>()));
    crate::transfer_files::create_directory(&root).unwrap();
    let corpus = root.join("Corpus");
    let key = root.join("Corpus.key");
    let mut library =
        library::Library::initialise(&corpus, &key, [1; 32], [2; 32], [3; 32], [4; 32]).unwrap();
    let publication = VersionRef {
        kind: 142,
        id: [5; 32],
        generation: 1,
        digest: [6; 32],
    };
    let secret = b"Private retained terms not suitable for disk indexing".to_vec();
    library
        .retain(library::Entry {
            id: [7; 32],
            namespace: "Books".into(),
            grant: VersionRef {
                kind: 102,
                id: [8; 32],
                generation: 1,
                digest: [9; 32],
            },
            publication,
            retained_at_ms: 1000,
            source: library::Source::Native {
                bundle: secret.clone(),
                approval: vec![],
            },
            lease: None,
        })
        .unwrap();
    let encrypted = std::fs::read(corpus.join("RetainedSearch.age")).unwrap();
    assert!(!encrypted.windows(secret.len()).any(|w| w == secret));
    assert_eq!(
        std::fs::read_dir(&corpus)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains("Plain"))
            .count(),
        0
    );
    drop(library);
    assert!(library::Library::open(&corpus, &key, [1; 32], [2; 32], [8; 32], [4; 32]).is_err());
    let library =
        library::Library::open(&corpus, &key, [1; 32], [2; 32], [3; 32], [4; 32]).unwrap();
    assert!(
        matches!(&library.entry([7;32]).unwrap().source, library::Source::Native {bundle,..} if *bundle == secret)
    );
    drop(library);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn lease_rejects_reboot_expiry_and_unknown_policy_dependencies() {
    let root = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join(format!("SearchLease{}", crate::random_hex::<16>()));
    crate::transfer_files::create_directory(&root).unwrap();
    let fixture = crate::authority_proof::tests::Fixture::new(10000);
    let health = ClockHealth::new(10000, 100, 10000, 0).unwrap().frozen();
    let requester = crate::authority_proof::Intent::from_signed(&fixture.intent)
        .unwrap()
        .requester;
    let store = Store::initialise(&root, fixture.descriptor, requester, health).unwrap();
    let mut network = query();
    network.scope = 1;
    let publication = VersionRef {
        kind: 155,
        id: [31; 32],
        generation: 1,
        digest: [32; 32],
    };
    let floor = VersionRef {
        kind: 157,
        id: [33; 32],
        generation: 1,
        digest: [34; 32],
    };
    let mut refreshed = floor.clone();
    refreshed.generation = 2;
    refreshed.digest = [35; 32];
    let original = binding(&store, &network, 0, &[publication.clone(), floor.clone()]).unwrap();
    assert_eq!(
        original,
        binding(
            &store,
            &network,
            0,
            &[publication.clone(), refreshed.clone()]
        )
        .unwrap()
    );
    let mut replaced = publication.clone();
    replaced.generation = 2;
    replaced.digest = [36; 32];
    assert_ne!(
        original,
        binding(&store, &network, 0, &[replaced, refreshed.clone()]).unwrap()
    );
    network.scope = 0;
    assert_ne!(
        binding(&store, &network, 1, &[publication.clone(), floor]).unwrap(),
        binding(&store, &network, 1, &[publication, refreshed]).unwrap()
    );
    let mut lease = library::Lease {
        configuration: store.descriptor().scope().configuration,
        epoch: store.prefix().scope().epoch,
        height: store.prefix().height(),
        policy_state: *store.prefix().policy_state(),
        kernel_boot: library::kernel_boot().unwrap(),
        evaluated_at_ms: 10000,
        expires_at_ms: 15000,
        deadline_boot_ms: 5100,
        versions: vec![],
        receipt: vec![],
        attestation: vec![],
    };
    assert!(lease.current_bounds(&store, health).is_ok());
    assert!(lease.current(&store, health).is_err());
    lease
        .sign(&ed25519_dalek::SigningKey::from_bytes(&[1; 32]))
        .unwrap();
    assert!(lease.current(&store, health).is_err());
    assert!(
        lease
            .current_bounds(
                &store,
                ClockHealth::new(14750, 4850, 10000, 0).unwrap().frozen()
            )
            .is_err()
    );
    assert!(
        lease
            .current_bounds(
                &store,
                ClockHealth::new(14000, 5100, 10000, 0).unwrap().frozen()
            )
            .is_err()
    );
    lease.kernel_boot = "another-boot".into();
    assert!(lease.current_bounds(&store, health).is_err());
    lease.kernel_boot = library::kernel_boot().unwrap();
    lease.versions.push(VersionRef {
        kind: 102,
        id: [8; 32],
        generation: 1,
        digest: [9; 32],
    });
    assert!(lease.current(&store, health).is_err());
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}
