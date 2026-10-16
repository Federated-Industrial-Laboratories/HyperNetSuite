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
    reply_at(p, f.current.observe().unwrap().wall_ms, f.store.prefix())
}
fn reply_at(p: &Prepared, at: u64, prefix: &Prefix) -> (CertifiedReply, AncestryEvidence) {
    let intent = Intent::from_signed(&p.intent).unwrap();
    let result = Operation::parse(&intent)
        .unwrap()
        .prepare(
            &p.prior.state,
            p.bootstrap.governance_records(),
            &Reservations(p.bootstrap.reservations().to_vec()),
            &intent,
            at,
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
        at,
        *prefix.node(),
        prefix.height() + 1,
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

fn page_query(f: &Fixture) -> Request {
    let mut request = domain_request(f);
    request.command = domains::page::Command::Context {
        action: 0,
        scope_kind: 0,
        resource: [20; 32],
        namespace: None,
    }
    .into();
    request
}
fn elapsed_health(health: ClockHealth, elapsed: u64) -> ClockHealth {
    let now = health.observe().unwrap();
    ClockHealth::new(
        now.wall_ms + elapsed,
        now.boot_ms + elapsed,
        now.boot_ms + elapsed + 1000,
        100,
    )
    .unwrap()
    .frozen()
}

#[test]
fn own_backup_metadata_finishes_without_inventing_a_discretionary_policy_dependency() {
    let mut f = Fixture::with_actions(vec![0, 20]);
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    let prepared = Prepared::new(
        &f.bootstrap,
        Request {
            command: domains::backup::Command::List { after: None }.into(),
            grant: None,
        },
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    assert!(
        Intent::from_signed(&prepared.intent)
            .unwrap()
            .expected
            .is_empty()
    );
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

    let expected = policy::current_reference(&f.bootstrap, &f.store).unwrap();
    let request = page_query(&f);
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    f.issued = f.current;
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
    assert_eq!(
        Intent::from_signed(&prepared.intent).unwrap().expected,
        vec![expected]
    );
}

#[test]
fn page_history_refresh_keeps_exact_intent_and_original_deadline() {
    let mut f = Fixture::with_actions(vec![0, 20]);
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    let request = page_query(&f);
    let mut prepared = Prepared::new(
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
    let deadline = prepared.deadline;
    let prefix = f.store.prefix().clone();
    let elapsed = std::cell::Cell::new(0);
    let mut attempts = Vec::new();
    let (certified, evidence) = prepared
        .exchange_with_history(
            &f.signer,
            &mut f.session,
            &mut || Ok(elapsed_health(f.issued, elapsed.get())),
            &mut |attempt, _| {
                assert_eq!(attempt.intent, original);
                assert_eq!(attempt.deadline, deadline);
                let value = wire::decode(&attempt.ordered)?;
                let fields = value.array(6)?;
                assert_eq!(fields[3].bytes()?, original);
                attempts.push(Challenge::from_signed(fields[4].bytes()?)?);
                if attempts.len() == 1 {
                    elapsed.set(1000);
                    Err(crate::authority_local_transport::HistoryOvertaken.into())
                } else {
                    Ok(reply_at(
                        attempt,
                        f.current.observe().unwrap().wall_ms,
                        &prefix,
                    ))
                }
            },
        )
        .unwrap();
    assert_eq!(attempts.len(), 2);
    assert_ne!(attempts[0].nonce, attempts[1].nonce);
    assert_eq!(attempts[0].intent, attempts[1].intent);
    assert_eq!(attempts[0].maximum_duration_ms, DURATION);
    assert_eq!(attempts[1].maximum_duration_ms, DURATION - 1000);
    assert_eq!(attempts[0].expires_at_ms, attempts[1].expires_at_ms);
    assert_eq!(f.store.prefix().node(), prefix.node());
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        original
    );
    assert!(
        Cache::load(&f.bootstrap, &f.store)
            .unwrap()
            .records
            .is_empty()
    );
    let result = prepared
        .finish(
            certified,
            evidence,
            &mut f.store,
            &mut f.session,
            &mut || Ok(f.current),
        )
        .unwrap();
    assert_eq!(result.deadline_boot_ms, deadline);
    assert_eq!(result.prefix.height(), prefix.height() + 1);
    assert!(f.store.resume_ordinary().unwrap().is_none());
}

#[test]
fn page_history_refresh_stops_on_repeated_overtaking_at_original_deadline() {
    let mut f = Fixture::with_actions(vec![0, 20]);
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    let request = page_query(&f);
    let mut prepared = Prepared::new(
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
    let prefix = f.store.prefix().clone();
    let deadline = prepared.deadline;
    let elapsed = std::cell::Cell::new(0);
    let mut calls = 0;
    let error = prepared
        .exchange_with_history::<(), _>(
            &f.signer,
            &mut f.session,
            &mut || Ok(elapsed_health(f.issued, elapsed.get())),
            &mut |attempt, _| {
                calls += 1;
                assert_eq!(attempt.intent, original);
                assert_eq!(attempt.deadline, deadline);
                assert_eq!(
                    Challenge::from_signed(&attempt.challenge)?.maximum_duration_ms,
                    DURATION - elapsed.get()
                );
                elapsed.set(elapsed.get() + 1000);
                Err(crate::authority_local_transport::HistoryOvertaken.into())
            },
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("original domain query deadline expired")
    );
    assert_eq!(calls, 5);
    assert_eq!(f.store.prefix().node(), prefix.node());
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        original
    );
    assert!(
        Cache::load(&f.bootstrap, &f.store)
            .unwrap()
            .records
            .is_empty()
    );
}

#[test]
fn page_history_refresh_does_not_retry_malformed_proofs_or_other_domains() {
    for permitted in [true, false] {
        let mut f = Fixture::with_actions(vec![0, 20]);
        let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
        let request = if permitted {
            page_query(&f)
        } else {
            domain_request(&f)
        };
        let mut prepared = Prepared::new(
            &f.bootstrap,
            request,
            cache,
            &f.signer,
            &mut f.store,
            &mut f.session,
            f.issued,
        )
        .unwrap();
        let original = prepared.challenge.clone();
        let mut calls = 0;
        let mut clock_calls = 0;
        let error = prepared
            .exchange_with_history::<(), _>(
                &f.signer,
                &mut f.session,
                &mut || {
                    clock_calls += 1;
                    Ok(f.current)
                },
                &mut |_, _| {
                    calls += 1;
                    if permitted {
                        anyhow::bail!("malformed checkpoint proof");
                    }
                    Err(crate::authority_local_transport::HistoryOvertaken.into())
                },
            )
            .unwrap_err();
        assert_eq!(calls, 1);
        assert_eq!(clock_calls, 0);
        assert_eq!(prepared.challenge, original);
        if permitted {
            assert_eq!(error.to_string(), "malformed checkpoint proof");
        } else {
            assert!(error.is::<crate::authority_local_transport::HistoryOvertaken>());
        }
    }
}

#[test]
fn page_history_refresh_excludes_mutations_and_serving_authorisations() {
    use domains::page::{Command as Page, content::Command as Content};
    let reference = |kind| VersionRef {
        kind,
        id: [30; 32],
        generation: 1,
        digest: [31; 32],
    };
    let queries = vec![
        Page::Read { page: [1; 16] },
        Page::List {
            namespace: "Books".into(),
            after: None,
        },
        Page::SearchList {
            namespace: "Books".into(),
            after: None,
        },
        Page::LocalSearchLease {
            items: vec![(reference(142), None)],
        },
        Page::Content(Content::Get {
            placement: reference(159),
        }),
    ];
    for query in queries {
        assert!(refreshable_page_query(&query.into()));
    }
    let excluded = vec![
        Page::HostWithdraw {
            role: 1,
            host: [30; 32],
            generation: 1,
        }
        .into(),
        Page::Withdraw {
            page: [1; 16],
            as_reviewer: false,
        }
        .into(),
        Page::Content(Content::Withdraw {
            placement: reference(159),
        })
        .into(),
        Page::Content(Content::Authorise {
            placement: reference(159),
            host: reference(147),
            effect: domains::page::content::Effect::Search,
            offset: 0,
            bytes: 32,
            digest: None,
        })
        .into(),
        Page::MediaAuthorise {
            asset: reference(149),
            host: reference(147),
            effect: domains::page::MediaEffect::Read,
            offset: 0,
            bytes: 32,
            digest: None,
        }
        .into(),
        domains::ssh::Command::Authorise {
            service: [30; 32],
            id: [31; 32],
        }
        .into(),
    ];
    for command in excluded {
        assert!(!refreshable_page_query(&command));
    }
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
