// SPDX-License-Identifier: MIT
// A failed domain cache publication retains the exact pending request and durable quorum evidence.
use super::super::tests::{Fixture, certified_request};
use super::*;
fn domain_request(f: &Fixture) -> Request {
    Request {
        command: domains::ssh::Command::Context {
            action: 20,
            scope_kind: 0,
            resource: [20; 32],
        }
        .into(),
        grant: Some(
            references(f.bootstrap.governance_records(), [20; 32], [21; 32])
                .unwrap()
                .into_iter()
                .find(|v| v.kind == 102)
                .unwrap(),
        ),
    }
}
fn reply(p: &Prepared, f: &Fixture) -> (CertifiedReply, AncestryEvidence) {
    let intent = Intent::from_signed(&p.intent).unwrap();
    let result = Operation::parse(&intent)
        .unwrap()
        .prepare(
            &p.prior.state,
            f.bootstrap.governance_records(),
            &Reservations(f.bootstrap.reservations().to_vec()),
            &intent,
            f.current.observe().unwrap().wall_ms,
            false,
            true,
        )
        .unwrap();
    assert_eq!(result.code, 0);
    let (packet, node) = certified_request(
        &p.descriptor,
        &p.intent,
        &p.challenge,
        &p.ordered,
        result.value,
        f.current.observe().unwrap().wall_ms,
        *f.store.prefix().node(),
        f.store.prefix().height() + 1,
        0,
    );
    let value = wire::decode(&packet).unwrap();
    let fields = value.array(10).unwrap();
    (
        CertifiedReply {
            node: node.clone(),
            certificate: fields[7].bytes().unwrap().to_vec(),
            result: fields[8].bytes().unwrap().to_vec(),
        },
        AncestryEvidence::direct(vec![node]),
    )
}

#[test]
fn domain_challenge_refreshes_clock_after_durable_intent_preparation() {
    let mut f = Fixture::with_actions(vec![0, 20]);
    let now = f.issued.observe().unwrap();
    let preflight = ClockHealth::new(now.wall_ms, now.boot_ms, now.boot_ms + 1000, 100)
        .unwrap()
        .frozen();
    let issued = ClockHealth::new(
        now.wall_ms + 1500,
        now.boot_ms + 1500,
        now.boot_ms + 2500,
        100,
    )
    .unwrap()
    .frozen();
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    let request = domain_request(&f);
    let mut calls = 0;
    let prepared = Prepared::new_with_objects(
        &f.bootstrap,
        request,
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        vec![],
        &mut || {
            calls += 1;
            Ok(if calls == 1 { preflight } else { issued })
        },
    )
    .unwrap();
    assert_eq!(calls, 2);
    let challenge = Challenge::from_signed(&prepared.challenge).unwrap();
    assert_eq!(challenge.created_at_ms, now.wall_ms + 1500);
    assert_eq!(challenge.expires_at_ms, now.wall_ms + 1500 + DURATION);
    assert_eq!(prepared.deadline, now.boot_ms + 1500 + DURATION);
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        prepared.intent
    );
}

#[test]
fn unavailable_issuance_clock_keeps_exact_pending_domain_intent() {
    let mut f = Fixture::with_actions(vec![0, 20]);
    let now = f.issued.observe().unwrap();
    let invalid = ClockHealth::new(
        now.wall_ms + 1500,
        now.boot_ms + 1500,
        now.boot_ms + 1500,
        100,
    )
    .unwrap()
    .frozen();
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    let request = domain_request(&f);
    let mut calls = 0;
    let result = Prepared::new_with_objects(
        &f.bootstrap,
        request,
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        vec![],
        &mut || {
            calls += 1;
            Ok(if calls == 1 { f.issued } else { invalid })
        },
    );
    let error = result.err().unwrap();
    assert!(format!("{error:#}").contains("clock health is stale or invalid"));
    assert_eq!(calls, 2);
    let original = f
        .store
        .resume_ordinary()
        .unwrap()
        .unwrap()
        .signed()
        .to_vec();
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    let request = domain_request(&f);
    let prepared = Prepared::new(
        &f.bootstrap,
        request,
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.current,
    )
    .unwrap();
    assert_eq!(prepared.intent, original);
}
#[test]
fn cache_failure_reopens_and_retries_the_exact_original_domain_request() {
    let mut f = Fixture::with_actions(vec![0, 20]);
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    assert!(cache.records.is_empty());
    let request = domain_request(&f);
    let prepared = Prepared::new(
        &f.bootstrap,
        request,
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let original = prepared.intent.clone();
    let (certified, evidence) = reply(&prepared, &f);
    let path = f.directory.0.join(CACHE);
    std::fs::create_dir(&path).unwrap();
    assert!(
        prepared
            .finish(
                certified,
                evidence,
                &mut f.store,
                &mut f.session,
                &mut || Ok(f.current)
            )
            .is_err()
    );
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        original
    );
    assert!(Cache::load(&f.bootstrap, &f.store).is_err());
    std::fs::remove_dir(&path).unwrap();
    drop(f.store);
    f.store = Store::open(&f.directory.0, f.bootstrap.descriptor().clone()).unwrap();
    f.session = Session::new().unwrap();
    let now = f.current.observe().unwrap();
    f.issued = f.current;
    f.current = ClockHealth::new(
        now.wall_ms + 2000,
        now.boot_ms + 2000,
        now.boot_ms + 30000,
        100,
    )
    .unwrap()
    .frozen();
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    let mut changed = domain_request(&f);
    changed.command = domains::ssh::Command::Services {
        network: [20; 32],
        after: None,
    }
    .into();
    assert!(
        Prepared::new(
            &f.bootstrap,
            changed,
            cache.clone(),
            &f.signer,
            &mut f.store,
            &mut f.session,
            f.issued
        )
        .is_err()
    );
    let request = domain_request(&f);
    let prepared = Prepared::new(
        &f.bootstrap,
        request,
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    assert_eq!(prepared.intent, original);
    let (certified, evidence) = reply(&prepared, &f);
    prepared
        .finish(
            certified,
            evidence,
            &mut f.store,
            &mut f.session,
            &mut || Ok(f.current),
        )
        .unwrap();
    assert!(f.store.resume_ordinary().unwrap().is_none());
    let cached = Cache::load(&f.bootstrap, &f.store).unwrap();
    assert!(!cached.records.is_empty());
    drop(f.store);
    f.store = Store::open(&f.directory.0, f.bootstrap.descriptor().clone()).unwrap();
    assert_eq!(
        Cache::load(&f.bootstrap, &f.store).unwrap().records,
        cached.records
    );
}
