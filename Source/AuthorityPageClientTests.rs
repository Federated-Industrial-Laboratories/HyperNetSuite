// SPDX-License-Identifier: MIT
// Interrupted multi-record Page publication retains the original request and exact source identity.
use super::super::tests::{Fixture, certified_request, voters};
use super::*;
use crate::{
    authority_domains::page::{self, Command as PageCommand, objects::Author},
    authority_objects::Resolved,
};
use ed25519_dalek::Signer;

fn current_clocks() -> (ClockHealth, ClockHealth) {
    let boot = boot_time_ms().unwrap();
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    let issued = ClockHealth::new(wall, boot, boot + 30000, 100)
        .unwrap()
        .frozen();
    // Exercise the effect strictly inside its conservative absolute interval.
    let elapsed = crate::authority_challenge::DELTA_MS + 1;
    assert!(elapsed + crate::authority_challenge::DELTA_MS < DURATION);
    let current = ClockHealth::new(wall + elapsed, boot + elapsed, boot + 30000, 100)
        .unwrap()
        .frozen();
    (issued, current)
}

#[test]
fn page_host_withdrawal_resumes_retained_signed_mutation_without_a_context_read() {
    let signer = crate::authority_deployment_tests::key(90);
    let mut f = Fixture::with_actions_and_signer(vec![0], signer);
    let host = crate::authority_deployment_tests::key(100)
        .verifying_key()
        .to_bytes();
    let request = || Request {
        command: PageCommand::HostWithdraw {
            role: 1,
            host,
            generation: 1,
        }
        .into(),
        grant: None,
    };
    // Retain the already-issued mutation, then lose its transient context and
    // session. A retry must not insert another ordinary read before this slot.
    let expected = vec![VersionRef {
        kind: 147,
        id: host,
        generation: 1,
        digest: [77; 32],
    }];
    let operation = request().operation(&f.store, &expected).unwrap();
    let descriptor = f.store.descriptor().clone();
    let signed = prepare_ordinary(
        &descriptor,
        &f.signer,
        &mut f.store,
        "AuthorityDomain",
        host,
        1,
        &expected,
        &operation.parameters().unwrap(),
    )
    .unwrap();
    drop(f.store);
    f.store = Store::open(&f.directory.0, f.bootstrap.descriptor().clone()).unwrap();
    f.session = Session::new().unwrap();
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    assert!(cache.state.records.is_empty() && cache.records.is_empty());
    (f.issued, f.current) = current_clocks();
    let context = Request {
        command: PageCommand::HostGet { role: 1, host }.into(),
        grant: None,
    };
    assert!(
        Prepared::new(
            &f.bootstrap,
            context,
            cache.clone(),
            &f.signer,
            &mut f.store,
            &mut f.session,
            f.issued
        )
        .is_err()
    );
    let resumed = Prepared::new(
        &f.bootstrap,
        request(),
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    assert_eq!(resumed.intent, signed);
    assert_eq!(f.store.resume_ordinary().unwrap().unwrap().signed(), signed);
}

fn reply(
    p: &Prepared,
    f: &Fixture,
    state: &State,
    replay: bool,
) -> (CertifiedReply, AncestryEvidence, State) {
    reply_at(
        p,
        state,
        replay,
        f.current.observe().unwrap().wall_ms,
        *f.store.prefix().node(),
        f.store.prefix().height() + 1,
    )
}

fn reply_at(
    p: &Prepared,
    state: &State,
    replay: bool,
    at: u64,
    parent: [u8; 32],
    height: u64,
) -> (CertifiedReply, AncestryEvidence, State) {
    let intent = Intent::from_signed(&p.intent).unwrap();
    let operation = Operation::parse(&intent).unwrap();
    let inputs = evaluation_inputs(&operation.command, state, &p.objects).unwrap();
    let result = operation
        .prepare_with_inputs(
            state,
            p.bootstrap.governance_records(),
            &Reservations(p.bootstrap.reservations().to_vec()),
            &intent,
            at,
            replay,
            true,
            &inputs,
        )
        .unwrap();
    assert_eq!(result.code, 0);
    let next = result.state.clone().unwrap_or_else(|| state.clone());
    let (packet, node) = certified_request(
        &p.descriptor,
        &p.intent,
        &p.challenge,
        &p.ordered,
        result.value,
        at,
        parent,
        height,
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
        next,
    )
}

#[test]
fn page_submit_recovers_expired_lost_response_without_a_second_mutation() {
    page_submit_expiry(false);
}

#[test]
fn page_submit_second_expiry_retains_exact_pending_intent_without_publication() {
    page_submit_expiry(true);
}

fn page_submit_expiry(second_expiry: bool) {
    use crate::authority_local_transport::RequestDeadlineExpired;
    use std::{
        cell::Cell,
        os::unix::{fs::PermissionsExt, net::UnixListener},
    };
    let mut f = Fixture::with_actions(vec![0, 2, 3]);
    let scope = f.bootstrap.descriptor().scope();
    let grant = references(
        f.bootstrap.governance_records(),
        scope.network,
        scope.incarnation,
    )
    .unwrap()
    .into_iter()
    .find(|r| r.kind == 102)
    .unwrap();
    let parameters = Author::parameters(
        [71; 16],
        "Books",
        b"HyperNetPage/2\n# Bookshop\n: Opening hours.\n",
        &grant,
        None,
        f.current.observe().unwrap().wall_ms + 600000,
    )
    .unwrap();
    let signed = crate::authority_deployment_tests::signed(
        &f.signer,
        "PageAuthorStatement",
        page::page_id(&[71; 16]).unwrap(),
        1,
        wire::decode(&parameters).unwrap(),
        vec![],
    );
    let request = Request {
        command: PageCommand::Submit {
            author: Author::parse(&signed, scope.network, scope.incarnation).unwrap(),
        }
        .into(),
        grant: Some(grant),
    };
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    (f.issued, f.current) = current_clocks();
    let base = f.issued.observe().unwrap();
    let offset = Cell::new(0);
    let health = || {
        ClockHealth::new(
            base.wall_ms + offset.get(),
            base.boot_ms + offset.get(),
            base.boot_ms + 30000,
            100,
        )
        .unwrap()
        .frozen()
    };
    let mut prepared = Prepared::new_with_objects(
        &f.bootstrap,
        request,
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        vec![],
        &mut || Ok(health()),
    )
    .unwrap();
    let original = prepared.intent.clone();
    let first_challenge = prepared.challenge.clone();
    let first_deadline = prepared.deadline;
    let parent = *f.store.prefix().node();
    let height = f.store.prefix().height() + 1;
    let mut authority = State::empty(scope.network, scope.incarnation);
    let mut authority_parent = parent;
    let mut authority_height = height;
    let mut authority_nodes = Vec::new();
    let socket = f.directory.0.join("Recovery.sock");
    let _listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut attempts = 0;
    let mut preparations = 0;
    let result = prepared.exchange_with_recovery(
        LocalControl::open(&socket).unwrap(),
        &f.store,
        &f.signer,
        &mut f.session,
        &mut || Ok(health()),
        || {
            preparations += 1;
            offset.set(offset.get() + 2000);
            LocalControl::open(&socket)
        },
        &mut |attempt, _, _| {
            attempts += 1;
            assert_eq!(attempt.intent, original);
            assert_eq!(
                f.store.resume_ordinary().unwrap().unwrap().signed(),
                original
            );
            assert!(!f.directory.0.join(CACHE).exists());
            let at = Challenge::from_signed(&attempt.challenge)
                .unwrap()
                .created_at_ms
                + crate::authority_challenge::DELTA_MS
                + 1;
            let (reply, _, next) = reply_at(
                attempt,
                &authority,
                attempts > 1,
                at,
                authority_parent,
                authority_height,
            );
            authority_parent = wire::digest(&reply.node);
            authority_height += 1;
            authority_nodes.push(reply.node.clone());
            if attempts == 1 {
                assert_ne!(next.value(), authority.value());
                authority = next;
                // The authority committed the mutation, but its response was lost until expiry.
                offset.set(DURATION + 100);
                return Err(RequestDeadlineExpired {
                    deadline: attempt.deadline,
                }
                .into());
            }
            assert_eq!(attempts, 2);
            assert_ne!(attempt.challenge, first_challenge);
            assert!(attempt.deadline > first_deadline);
            assert_eq!(attempt.deadline, base.boot_ms + offset.get() + DURATION);
            assert_eq!(
                Challenge::from_signed(&attempt.challenge)
                    .unwrap()
                    .created_at_ms,
                base.wall_ms + offset.get()
            );
            assert_eq!(
                next.value(),
                authority.value(),
                "exact replay must not mutate again"
            );
            if second_expiry {
                Err(RequestDeadlineExpired {
                    deadline: attempt.deadline,
                }
                .into())
            } else {
                Ok((reply, AncestryEvidence::direct(authority_nodes.clone())))
            }
        },
    );
    assert_eq!(attempts, 2);
    assert_eq!(preparations, 1);
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        original
    );
    assert_eq!(*f.store.prefix().node(), parent);
    assert!(!f.directory.0.join(CACHE).exists());
    if second_expiry {
        assert_eq!(
            result
                .err()
                .unwrap()
                .downcast_ref::<RequestDeadlineExpired>()
                .unwrap()
                .deadline,
            prepared.deadline
        );
        return;
    }
    let ((reply, evidence), _control) = result.unwrap();
    offset.set(offset.get() + crate::authority_challenge::DELTA_MS + 1);
    let (published, _) = prepared
        .finish_with_objects(
            reply,
            evidence,
            Resolved::default(),
            &mut f.store,
            &mut f.session,
            &mut || Ok(health()),
        )
        .unwrap();
    assert!(f.store.resume_ordinary().unwrap().is_none());
    assert_eq!(f.store.prefix().height(), height + 1);
    assert_eq!(published.cache.state.value(), authority.value());
    assert_eq!(
        Cache::load(&f.bootstrap, &f.store).unwrap().state.value(),
        authority.value()
    );
}

#[test]
fn exchange_recovery_requires_its_exact_typed_deadline() {
    use crate::authority_local_transport::{RequestDeadlineExpired, retry_expired_exchange};
    for error in [
        anyhow::Error::from(RequestDeadlineExpired { deadline: 9 }),
        std::io::Error::from(std::io::ErrorKind::TimedOut).into(),
        std::io::Error::from(std::io::ErrorKind::ConnectionAborted).into(),
        anyhow::anyhow!("original inspection deadline expired"),
    ] {
        let mut error = Some(error);
        let mut calls = 0;
        let result: Result<()> = retry_expired_exchange(|| {
            calls += 1;
            Ok((
                10,
                Err(error.take().expect("ineligible error must not retry")),
            ))
        });
        assert!(result.is_err());
        assert_eq!(calls, 1);
    }
}

#[test]
fn page_history_expiry_uses_one_fresh_prepared_attempt() {
    use crate::authority_local_transport::{HistoryOvertaken, RequestDeadlineExpired};
    use std::{
        cell::Cell,
        os::unix::{fs::PermissionsExt, net::UnixListener},
    };
    for second_expiry in [false, true] {
        let mut f = Fixture::with_actions(vec![0, 20]);
        let scope = f.bootstrap.descriptor().scope();
        let request = Request {
            command: PageCommand::Context {
                action: 0,
                scope_kind: 0,
                resource: scope.network,
                namespace: None,
            }
            .into(),
            grant: references(
                f.bootstrap.governance_records(),
                scope.network,
                scope.incarnation,
            )
            .unwrap()
            .into_iter()
            .find(|r| r.kind == 102),
        };
        let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
        (f.issued, f.current) = current_clocks();
        let base = f.issued.observe().unwrap();
        let elapsed = Cell::new(0);
        let health = || {
            ClockHealth::new(
                base.wall_ms + elapsed.get(),
                base.boot_ms + elapsed.get(),
                base.boot_ms + 30000,
                100,
            )
            .unwrap()
            .frozen()
        };
        let mut prepared = Prepared::new_with_objects(
            &f.bootstrap,
            request,
            cache,
            &f.signer,
            &mut f.store,
            &mut f.session,
            vec![],
            &mut || Ok(health()),
        )
        .unwrap();
        let original = prepared.intent.clone();
        let old_challenge = prepared.challenge.clone();
        let old_deadline = prepared.deadline;
        let prefix = f.store.prefix().clone();
        let socket = f.directory.0.join("HistoryRecovery.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut preparations = 0;
        let mut calls = 0;
        let result = prepared.exchange_with_recovery(
            LocalControl::open(&socket).unwrap(),
            &f.store,
            &f.signer,
            &mut f.session,
            &mut || Ok(health()),
            || {
                preparations += 1;
                LocalControl::open(&socket)
            },
            &mut |attempt, _, _| {
                calls += 1;
                assert_eq!(attempt.intent, original);
                if calls == 1 || second_expiry {
                    elapsed.set(elapsed.get() + DURATION);
                    return Err(HistoryOvertaken.into());
                }
                assert_ne!(attempt.challenge, old_challenge);
                assert_eq!(attempt.deadline, old_deadline + DURATION);
                let at = base.wall_ms + elapsed.get() + crate::authority_challenge::DELTA_MS + 1;
                let (reply, evidence, _) = reply_at(
                    attempt,
                    &State::empty(scope.network, scope.incarnation),
                    false,
                    at,
                    *prefix.node(),
                    prefix.height() + 1,
                );
                Ok((reply, evidence))
            },
        );
        assert_eq!(calls, 2);
        assert_eq!(preparations, 1);
        assert_eq!(
            f.store.resume_ordinary().unwrap().unwrap().signed(),
            original
        );
        assert_eq!(f.store.prefix(), &prefix);
        if second_expiry {
            assert_eq!(
                result
                    .err()
                    .unwrap()
                    .downcast_ref::<RequestDeadlineExpired>()
                    .unwrap()
                    .deadline,
                prepared.deadline
            );
        } else {
            let ((reply, evidence), _control) = result.unwrap();
            elapsed.set(elapsed.get() + crate::authority_challenge::DELTA_MS + 1);
            prepared
                .finish_with_objects(
                    reply,
                    evidence,
                    Resolved::default(),
                    &mut f.store,
                    &mut f.session,
                    &mut || Ok(health()),
                )
                .unwrap();
            assert!(f.store.resume_ordinary().unwrap().is_none());
        }
    }
}

#[test]
fn page_source_metadata_survives_floor_before_cache_interruption() {
    let mut f = Fixture::with_actions(vec![0, 2, 3]);
    let scope = f.bootstrap.descriptor().scope();
    let source = b"HyperNetPage/2\n# Bookshop\n: Opening hours.\n";
    let grant = references(
        f.bootstrap.governance_records(),
        scope.network,
        scope.incarnation,
    )
    .unwrap()
    .into_iter()
    .find(|r| r.kind == 102)
    .unwrap();
    let parameters = Author::parameters(
        [71; 16],
        "Books",
        source,
        &grant,
        None,
        f.current.observe().unwrap().wall_ms + 600000,
    )
    .unwrap();
    let signed = crate::authority_deployment_tests::signed(
        &f.signer,
        "PageAuthorStatement",
        page::page_id(&[71; 16]).unwrap(),
        1,
        wire::decode(&parameters).unwrap(),
        vec![],
    );
    let author = Author::parse(&signed, scope.network, scope.incarnation).unwrap();
    let request = || Request {
        command: PageCommand::Submit {
            author: author.clone(),
        }
        .into(),
        grant: Some(grant.clone()),
    };
    let objects = Vec::new;
    let authority = State::empty(scope.network, scope.incarnation);
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    // Bootstrap verification and durable fixture setup precede this request's live deadline.
    (f.issued, f.current) = current_clocks();
    let prepared = Prepared::new_with_objects(
        &f.bootstrap,
        request(),
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        objects(),
        &mut || Ok(f.issued),
    )
    .unwrap();
    let original = prepared.intent.clone();
    let (certified, evidence, authority) = reply(&prepared, &f, &authority, false);
    let path = f.directory.0.join(CACHE);
    std::fs::create_dir(&path).unwrap();
    let interruption = prepared
        .finish_with_objects(
            certified,
            evidence,
            Resolved::default(),
            &mut f.store,
            &mut f.session,
            &mut || Ok(f.current),
        )
        .err()
        .expect("a directory at the cache path must prevent cache publication");
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        original
    );
    assert!(
        f.store.generations().iter().any(|r| r.kind == 140),
        "result failed before the intended cache interruption: {interruption:#}"
    );
    assert!(
        f.store.generations().iter().any(|r| r.kind == 141),
        "result failed before retaining the source revision: {interruption:#}"
    );
    std::fs::remove_dir(&path).unwrap();
    drop(f.store);
    f.store = Store::open(&f.directory.0, f.bootstrap.descriptor().clone()).unwrap();
    f.session = Session::new().unwrap();
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    (f.issued, f.current) = current_clocks();
    let prepared = Prepared::new_with_objects(
        &f.bootstrap,
        request(),
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        objects(),
        &mut || Ok(f.issued),
    )
    .unwrap();
    assert_eq!(prepared.intent, original);
    let (certified, evidence, _) = reply(&prepared, &f, &authority, true);
    let (result, output) = prepared
        .finish_with_objects(
            certified,
            evidence,
            Resolved::default(),
            &mut f.store,
            &mut f.session,
            &mut || Ok(f.current),
        )
        .unwrap();
    assert!(output.is_empty());
    assert!(f.store.resume_ordinary().unwrap().is_none());
    assert_eq!(result.cache.state.value(), authority.value());
    let reopened = Cache::load(&f.bootstrap, &f.store).unwrap();
    assert_eq!(reopened.state.value(), authority.value());
}

#[test]
fn certified_page_view_reads_exact_retained_source_and_rejects_advanced_catalogue_floor() {
    let (bootstrap, mut authority, records, grant, placement, source) =
        page::tests::view_tests::consumer_fixture();
    let mut f = Fixture::with_bootstrap(bootstrap, crate::authority_deployment_tests::key(5), 6000);
    let request = |command: PageCommand| Request {
        command: command.into(),
        grant: Some(grant.clone()),
    };
    let certify = |p: &Prepared, state: &State, at: u64, prefix: &Prefix| {
        let intent = Intent::from_signed(&p.intent).unwrap();
        let decision = Operation::parse(&intent)
            .unwrap()
            .prepare_with_inputs(
                state,
                &records,
                &Reservations(p.bootstrap.reservations().to_vec()),
                &intent,
                at,
                false,
                true,
                &Resolved::default(),
            )
            .unwrap();
        assert_eq!(decision.code, 0);
        let next = decision.state.clone().unwrap_or_else(|| state.clone());
        let (packet, node) = certified_request(
            &p.descriptor,
            &p.intent,
            &p.challenge,
            &p.ordered,
            decision.value,
            at,
            *prefix.node(),
            prefix.height() + 1,
            0,
        );
        let packet = wire::decode(&packet).unwrap();
        let fields = packet.array(10).unwrap();
        // The generic certificate fixture knows only challenge expiry. A domain
        // evaluation must also clip it to the actual publication/placement/grant bound.
        let envelope = wire::decode(fields[7].bytes().unwrap()).unwrap();
        let mut executed = wire::decode(envelope.array(4).unwrap()[2].bytes().unwrap())
            .unwrap()
            .array(23)
            .unwrap()
            .to_vec();
        let expiry = executed[19].uint().unwrap().min(decision.expires_ms);
        assert!(at + crate::authority_governance::UNCERTAINTY_MS < expiry);
        assert!(
            Challenge::from_signed(&p.challenge)
                .unwrap()
                .completion_within_interval(at, expiry)
        );
        executed[19] = V::Uint(expiry);
        let payload = wire::encode(&a(executed)).unwrap();
        let signatures = voters()[..3]
            .iter()
            .map(|key| {
                let public = key.verifying_key().to_bytes();
                a(vec![
                    b(&public),
                    b(&key
                        .sign(&wire::signature_message(&payload, &public))
                        .to_bytes()),
                ])
            })
            .collect();
        let certificate =
            wire::encode(&a(vec![V::Uint(0), V::Uint(1), b(&payload), a(signatures)])).unwrap();
        (
            CertifiedReply {
                node: node.clone(),
                certificate,
                result: fields[8].bytes().unwrap().to_vec(),
            },
            AncestryEvidence::direct(vec![node]),
            next,
        )
    };
    // The normal fresh challenge, independent domain proof verification, durable
    // floor and cache publication produce the result consumed by the reader.
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    // Anchor after durable setup, then advance one virtual clock across this recipient session.
    let boot = boot_time_ms().unwrap();
    let delta = crate::authority_challenge::DELTA_MS + 1;
    let advance = |health: ClockHealth| {
        let last = health.observe().unwrap();
        ClockHealth::new(
            last.wall_ms + delta,
            last.boot_ms + delta,
            boot + 30000,
            100,
        )
        .unwrap()
        .frozen()
    };
    f.issued = ClockHealth::new(6000 - delta, boot, boot + 30000, 100)
        .unwrap()
        .frozen();
    f.current = advance(f.issued);
    let prepared = Prepared::new(
        &f.bootstrap,
        request(PageCommand::View { page: [71; 16] }),
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let (reply, evidence, _) = certify(&prepared, &authority, 6000, f.store.prefix());
    let mut view = prepared
        .finish(reply, evidence, &mut f.store, &mut f.session, &mut || {
            Ok(f.current)
        })
        .unwrap();
    assert!(
        crate::search::current_view_for_test(&f.store, &view, f.current.observe().unwrap())
            .unwrap()
    );
    let mut client = crate::authority_pages::Client {
        bootstrap: f.bootstrap,
        directory: f.directory.0.clone(),
        key: f.signer.clone(),
        store: f.store,
        session: f.session,
        clock: crate::authority_clock::Source::Private {
            path: f.directory.0.join("UnavailableClock.json"),
        },
        socket: f.directory.0.join("UnavailableAuthority.sock"),
        content: Default::default(),
    };
    crate::authority_pages::content_cli::view_tests::policy_view(
        &mut client,
        &placement,
        &mut view,
        f.current,
    );
    crate::authority_pages::content_cli::view_tests::consume(
        &mut client,
        &grant,
        &placement,
        &view,
        &source,
    );
    f.bootstrap = client.bootstrap;
    f.store = client.store;
    f.session = client.session;
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    f.issued = f.current;
    f.current = advance(f.issued);
    let prepared = Prepared::new(
        &f.bootstrap,
        request(PageCommand::Content(page::content::Command::Withdraw {
            placement: placement.clone(),
        })),
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let host = page::content::Placement::parse(
        &view.cache.state.record(159, placement.id).unwrap().payload,
    )
    .unwrap()
    .hosts[0]
        .clone();
    assert!(
        !crate::authority_inspection::page_media_client::current_read_view(
            &f.bootstrap,
            &f.store,
            &view,
            &placement,
            &host,
            || panic!("pending recovery must not request a new clock observation"),
        )
        .unwrap()
    );
    crate::authority_inspection::page_media_client::ensure_content_read(
        &f.bootstrap,
        &mut f.store,
        &f.directory.0.join("UnavailableAuthority.sock"),
        &f.signer,
        &mut f.session,
        || panic!("the exact pending operation must follow its existing recovery path"),
        Some((&view, &placement, &host)),
    )
    .unwrap();
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        prepared.intent
    );
    let (reply, evidence, next) = certify(
        &prepared,
        &authority,
        f.current.observe().unwrap().wall_ms,
        f.store.prefix(),
    );
    authority = next;
    prepared
        .finish(reply, evidence, &mut f.store, &mut f.session, &mut || {
            Ok(f.current)
        })
        .unwrap();
    assert!(
        authority
            .records
            .contains_key(&(page::content::TOMBSTONE_KIND, placement.id))
    );
    assert!(
        f.store
            .generations()
            .iter()
            .any(|r| r.kind == page::content::TOMBSTONE_KIND)
    );
    let now = f.current.observe().unwrap();
    assert!(now.boot_ms < view.deadline_boot_ms);
    assert!(now.wall_ms + crate::authority_challenge::DELTA_MS < view.expires_at_ms);
    assert!(
        !crate::search::current_view_for_test(&f.store, &view, now).unwrap(),
        "an earlier catalogue cannot omit a newly retained content withdrawal"
    );
    let authority = f.directory.0.join("UnavailableAuthority.sock");
    let error = crate::authority_inspection::page_media_client::ensure_content_read(
        &f.bootstrap,
        &mut f.store,
        &authority,
        &f.signer,
        &mut f.session,
        || Ok(f.current),
        Some((&view, &placement, &host)),
    )
    .unwrap_err();
    assert!(
        error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound),
        "an advanced floor must prepare normal discovery on the unavailable authority socket"
    );
    assert!(f.store.resume_ordinary().unwrap().is_none());
}
