// SPDX-License-Identifier: MIT
// Private-socket reads preserve nonce binding, independent stream state and durable anchor provenance.
use super::*;
use crate::authority_inspection::tests::{Fixture, receive_control, send_control, voters};
use ed25519_dalek::Signer;
use std::os::unix::{fs::PermissionsExt, net::UnixListener};

pub(crate) fn submitted(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let value = wire::decode(bytes).unwrap();
    let fields = value.array(5).unwrap();
    assert_eq!(fields[0], V::Uint(41));
    assert_eq!(fields[3], V::Uint(6));
    let value = wire::decode(fields[4].bytes().unwrap()).unwrap();
    let fields = value.array(2).unwrap();
    (
        fields[0].bytes().unwrap().to_vec(),
        fields[1].bytes().unwrap().to_vec(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn response(
    request: &[u8],
    challenge: &[u8],
    node: &[u8],
    state: [u8; 32],
    value: V,
    evaluated: u64,
    expiry: u64,
    code: u64,
) -> Vec<u8> {
    let parsed = read::Request::from_signed(request).unwrap();
    let challenge_parsed = Challenge::from_signed(challenge).unwrap();
    let result = wire::encode(&a(vec![
        V::Uint(24),
        V::Uint(1),
        V::Text(parsed.query.action().into()),
        V::Uint(u64::from(code != 0)),
        V::Uint(code),
        b(&wire::encode(&value).unwrap()),
    ]))
    .unwrap();
    let anchor = proof::Node::parse(node).unwrap();
    let statement = read::Statement {
        scope: parsed.scope.clone(),
        request: parsed.digest,
        challenge: challenge_parsed.digest,
        requester: parsed.requester,
        recipient: parsed.recipient,
        height: anchor.height(),
        node: *anchor.digest(),
        state,
        evaluated_at_ms: evaluated,
        expires_at_ms: challenge_parsed
            .evaluation_expiry(evaluated, expiry.min(challenge_parsed.expires_at_ms))
            .unwrap(),
        result: wire::digest(&result),
    }
    .encode()
    .unwrap();
    let signatures = voters()[..3]
        .iter()
        .map(|key| {
            let public = key.verifying_key().to_bytes();
            a(vec![
                b(&public),
                b(&key
                    .sign(&wire::signature_message(&statement, &public))
                    .to_bytes()),
            ])
        })
        .collect();
    let certificate = wire::encode(&a(vec![
        V::Uint(0),
        V::Uint(1),
        b(&statement),
        a(signatures),
    ]))
    .unwrap();
    wire::encode(&a(vec![
        V::Uint(62),
        V::Uint(1),
        parsed.scope.value(),
        V::Uint(1),
        V::Uint(0),
        b(&read::read_id(request, challenge).unwrap()),
        b(node),
        b(&certificate),
        b(&result),
        a(vec![]),
    ]))
    .unwrap()
}

#[test]
fn fresh_policy_roundtrip_preserves_stream_and_anchor_on_reopen() {
    consumed_roundtrip(false, false);
}

#[test]
fn consumed_policy_read_sends_exact_cleanup_without_waiting_for_a_receipt() {
    consumed_roundtrip(true, false);
}

#[test]
fn consumed_domain_refusal_sends_exact_cleanup_without_changing_ordinary_state() {
    consumed_roundtrip(true, true);
}

fn assert_cleanup(listener: &UnixListener, request: &[u8], challenge: &[u8], reply: &[u8]) {
    let (_stream, bytes) = receive_control(listener);
    let packet = wire::decode(&bytes).unwrap();
    let packet = packet.array(5).unwrap();
    assert_eq!(packet[3], V::Uint(8));
    let parsed = read::Request::from_signed(request).unwrap();
    let (payload, signatures) = wire::envelope(packet[4].bytes().unwrap(), 1).unwrap();
    let value = wire::decode(&payload).unwrap();
    let fields = value.array(7).unwrap();
    let reply = wire::decode(reply).unwrap();
    let reply = reply.array(10).unwrap();
    let (statement, _) = wire::envelope(reply[7].bytes().unwrap(), 3).unwrap();
    let parsed_statement = read::Statement::parse(&statement).unwrap();
    assert_eq!(signatures[0].0, parsed.requester);
    assert_eq!(packet[2], parsed.scope.value());
    assert_eq!(fields[0], V::Uint(63));
    assert_eq!(fields[1], V::Uint(1));
    assert_eq!(fields[2], parsed.scope.value());
    assert_eq!(fields[3], b(&read::read_id(request, challenge).unwrap()));
    assert_eq!(fields[4], b(&wire::digest(&statement)));
    assert_eq!(fields[5], b(&wire::digest(reply[8].bytes().unwrap())));
    assert!(fields[6].uint().unwrap() <= parsed_statement.expires_at_ms);
    // Closing without a receipt cannot change the consumed result.
}

fn consumed_roundtrip(cleanup: bool, domain: bool) {
    let mut f = Fixture::new();
    let socket = f.directory.0.join("Read.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    if cleanup {
        std::fs::hard_link(&socket, f.directory.0.join("ReadAcknowledgements.sock")).unwrap();
    }
    let prefix = f.store.prefix().clone();
    let metadata = f
        .store
        .stream_metadata()
        .unwrap()
        .unwrap()
        .canonical()
        .to_vec();
    let status_needed = f.store.needs_stream_status().unwrap();
    let (p, r) = policy::current(&f.bootstrap, &f.store).unwrap();
    let scope = f.store.descriptor().scope();
    let refs = [100, 114]
        .into_iter()
        .zip([&p, &r])
        .map(|(kind, bytes)| {
            crate::authority_policies::record_reference(
                bytes,
                scope.network,
                scope.incarnation,
                kind,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityPolicyContext".into()),
        a(refs.iter().map(version_value).collect()),
        a(vec![b(&p), b(&r)]),
    ]);
    let node = f.status_node.clone();
    let state = *prefix.policy_state();
    let evaluated = f.current.observe().unwrap().wall_ms;
    let server = std::thread::spawn(move || {
        let (stream, bytes) = receive_control(&listener);
        let (request, challenge) = submitted(&bytes);
        assert!(matches!(
            read::Request::from_signed(&request).unwrap().query,
            Query::PolicyContext
        ));
        let reply = response(
            &request,
            &challenge,
            &node,
            state,
            value,
            evaluated,
            u64::MAX,
            0,
        );
        send_control(stream, &reply);
        if cleanup {
            assert_cleanup(&listener, &request, &challenge, &reply);
        }
        if domain {
            let (stream, bytes) = receive_control(&listener);
            let (request, challenge) = submitted(&bytes);
            assert!(matches!(
                read::Request::from_signed(&request).unwrap().query,
                Query::Domain(_)
            ));
            let reply = response(
                &request,
                &challenge,
                &node,
                state,
                a(vec![]),
                evaluated,
                u64::MAX,
                3,
            );
            send_control(stream, &reply);
            assert_cleanup(&listener, &request, &challenge, &reply);
        }
    });
    let mut first = true;
    let clock = || {
        let health = if first { f.issued } else { f.current };
        first = false;
        Ok(health)
    };
    if domain {
        let error = crate::authority_inspection::domain_client::local(
            &f.bootstrap,
            crate::authority_inspection::domain_client::Request {
                command: crate::authority_domains::routes::Command::Lookup { service: [88; 32] }
                    .into(),
                grant: None,
            },
            &socket,
            &f.signer,
            &mut f.store,
            &mut f.session,
            clock,
        )
        .err()
        .expect("verified domain refusal required");
        assert!(
            error
                .downcast_ref::<crate::authority_inspection::domain_client::Refusal>()
                .is_some_and(|refusal| refusal.code == 3),
            "{error:#}"
        );
    } else {
        policy::discover(
            &f.bootstrap,
            &socket,
            &f.signer,
            &mut f.store,
            &mut f.session,
            clock,
        )
        .unwrap();
    }
    server.join().unwrap();
    assert_eq!(f.store.prefix(), &prefix);
    assert_eq!(
        f.store.stream_metadata().unwrap().unwrap().canonical(),
        metadata
    );
    assert_eq!(f.store.needs_stream_status().unwrap(), status_needed);
    assert!(f.store.resume_ordinary().unwrap().is_none());
    assert!(refs.iter().all(|r| f.store.generations().contains(r)));
    let descriptor = f.store.descriptor().clone();
    drop(f.store);
    let reopened = Store::open(&f.directory.0, descriptor).unwrap();
    assert_eq!(reopened.prefix(), &prefix);
    assert_eq!(
        reopened.stream_metadata().unwrap().unwrap().canonical(),
        metadata
    );
    assert!(refs.iter().all(|r| reopened.generations().contains(r)));
}

#[test]
fn unavailable_fresh_read_leaves_no_ordinary_operation_or_floor_change() {
    let mut f = Fixture::new();
    let socket = f.directory.0.join("UnavailableRead.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let prefix = f.store.prefix().clone();
    let server = std::thread::spawn(move || {
        let (stream, bytes) = receive_control(&listener);
        let (request, challenge) = submitted(&bytes);
        let parsed = read::Request::from_signed(&request).unwrap();
        let reply = wire::encode(&a(vec![
            V::Uint(62),
            V::Uint(1),
            parsed.scope.value(),
            V::Uint(2),
            V::Uint(1),
            b(&read::read_id(&request, &challenge).unwrap()),
            V::Null,
            V::Null,
            V::Null,
            a(vec![]),
        ]))
        .unwrap();
        send_control(stream, &reply);
    });
    let error = policy::discover(
        &f.bootstrap,
        &socket,
        &f.signer,
        &mut f.store,
        &mut f.session,
        || Ok(f.issued),
    )
    .unwrap_err();
    server.join().unwrap();
    assert!(error.is::<crate::authority_local_transport::ReadUnavailable>());
    assert_eq!(f.store.prefix(), &prefix);
    assert!(f.store.resume_ordinary().unwrap().is_none());
}

#[test]
fn replayed_read_certificate_cannot_satisfy_a_new_query_nonce() {
    let mut f = Fixture::new();
    let socket = f.directory.0.join("ReplayRead.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (p, r) = policy::current(&f.bootstrap, &f.store).unwrap();
    let scope = f.store.descriptor().scope();
    let refs = [100, 114]
        .into_iter()
        .zip([&p, &r])
        .map(|(kind, bytes)| {
            crate::authority_policies::record_reference(
                bytes,
                scope.network,
                scope.incarnation,
                kind,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityPolicyContext".into()),
        a(refs.iter().map(version_value).collect()),
        a(vec![b(&p), b(&r)]),
    ]);
    let node = f.status_node.clone();
    let state = *f.store.prefix().policy_state();
    let evaluated = f.current.observe().unwrap().wall_ms;
    let server = std::thread::spawn(move || {
        let (stream, bytes) = receive_control(&listener);
        let (first_request, first_challenge) = submitted(&bytes);
        let first = response(
            &first_request,
            &first_challenge,
            &node,
            state,
            value,
            evaluated,
            u64::MAX,
            0,
        );
        send_control(stream, &first);
        let (stream, bytes) = receive_control(&listener);
        let (request, challenge) = submitted(&bytes);
        assert_ne!(request, first_request);
        assert_ne!(challenge, first_challenge);
        let mut fields = wire::decode(&first).unwrap().array(10).unwrap().to_vec();
        // Transport correlation is not the quorum certificate's cryptographic request binding.
        fields[5] = b(&read::read_id(&request, &challenge).unwrap());
        send_control(stream, &wire::encode(&a(fields)).unwrap());
    });
    let mut first = true;
    policy::discover(
        &f.bootstrap,
        &socket,
        &f.signer,
        &mut f.store,
        &mut f.session,
        || {
            let health = if first { f.issued } else { f.current };
            first = false;
            Ok(health)
        },
    )
    .unwrap();
    let retained = std::fs::read(f.directory.0.join("AuthorityFloor.json")).unwrap();
    let error = policy::discover(
        &f.bootstrap,
        &socket,
        &f.signer,
        &mut f.store,
        &mut f.session,
        || Ok(f.current),
    )
    .unwrap_err();
    server.join().unwrap();
    assert!(
        error.to_string().contains("fresh response binding differs"),
        "{error:#}"
    );
    assert_eq!(
        std::fs::read(f.directory.0.join("AuthorityFloor.json")).unwrap(),
        retained
    );
    assert!(f.store.resume_ordinary().unwrap().is_none());
}

#[test]
fn fresh_read_resamples_signed_health_after_persistence_without_extending_authority() {
    use crate::authority_clock;
    use std::cell::Cell;

    for (invalid_clock, short_authority) in [(false, false), (true, false), (false, true)] {
        let mut f = Fixture::new();
        let monitor = SigningKey::from_bytes(&[93; 32]);
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .unwrap()
            .trim()
            .to_owned();
        let path = f.directory.0.join("ClockHealth.cbor");
        let source = authority_clock::Source::select(
            &path,
            Some(&hex::encode(monitor.verifying_key().to_bytes())),
            Some(&boot),
        )
        .unwrap();
        let publish_health = |invalid: bool| {
            let wall_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            let boot_ms = crate::authority_challenge::boot_time_ms().unwrap();
            let bytes = wire::sign_envelope(
                &wire::encode(&a(vec![
                    V::Uint(44),
                    V::Uint(1),
                    V::Text(boot.clone()),
                    V::Uint(wall_ms.saturating_sub(if invalid { 1000 } else { 0 })),
                    V::Uint(boot_ms),
                    V::Uint(boot_ms + 1000),
                    V::Uint(20),
                    V::Text("192.0.2.1".into()),
                ]))
                .unwrap(),
                &monitor,
            )
            .unwrap();
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        publish_health(false);
        let issued = source.health().unwrap();
        let at = issued.observe().unwrap();
        let descriptor = f.store.descriptor().clone();
        let requester = f.signer.verifying_key().to_bytes();
        let request = read::Request::sign(
            descriptor.scope(),
            &f.signer,
            requester,
            [94; 32],
            f.store.prefix().height(),
            Query::PolicyContext,
        )
        .unwrap();
        let challenge = f
            .session
            .issue_read(&request, &f.signer, [94; 32], DURATION, issued)
            .unwrap();
        let (p, r) = policy::current(&f.bootstrap, &f.store).unwrap();
        let scope = descriptor.scope();
        let refs = [100, 114]
            .into_iter()
            .zip([&p, &r])
            .map(|(kind, bytes)| {
                crate::authority_policies::record_reference(
                    bytes,
                    scope.network,
                    scope.incarnation,
                    kind,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let reply = response(
            &request,
            &challenge,
            &f.status_node,
            *f.store.prefix().policy_state(),
            a(vec![
                V::Uint(201),
                V::Uint(1),
                V::Text("AuthorityPolicyContext".into()),
                a(refs.iter().map(version_value).collect()),
                a(vec![b(&p), b(&r)]),
            ]),
            at.wall_ms,
            if short_authority {
                at.wall_ms + 1400
            } else {
                u64::MAX
            },
            0,
        );
        let decoded = wire::decode(&reply).unwrap();
        let fields = decoded.array(10).unwrap();
        let verified = read::verify_response(
            &descriptor,
            &request,
            &challenge,
            read::Response {
                node: fields[6].bytes().unwrap(),
                certificate: fields[7].bytes().unwrap(),
                result: fields[8].bytes().unwrap(),
                ancestry: std::slice::from_ref(&f.status_node),
            },
            |_, _, _| Ok(refs.clone()),
        )
        .unwrap();
        let calls = Cell::new(0);
        let published = Cell::new(false);
        let previous = Cell::<Option<ClockHealth>>::new(None);
        let result = f.store.accept_read(
            verified,
            &mut f.session,
            &mut || {
                calls.set(calls.get() + 1);
                if published.get() {
                    // The callback completed after the preceding signed sample expired.
                    assert!(previous.get().unwrap().observe().is_err());
                }
                publish_health(invalid_clock && published.get());
                let health = source.health()?;
                previous.set(Some(health));
                Ok(health)
            },
            0,
            |_, _| {
                files::write_new(&f.directory.0.join("ReadOutput"), b"Verified")?;
                std::thread::sleep(Duration::from_millis(1500));
                published.set(true);
                Ok("Verified")
            },
        );
        assert!(published.get());
        assert_eq!(calls.get(), 3);
        if invalid_clock {
            assert!(format!("{:#}", result.unwrap_err()).contains("clock error exceeds"));
        } else if short_authority {
            assert!(format!("{:#}", result.unwrap_err()).contains("absolute validity interval"));
        } else {
            assert_eq!(result.unwrap(), "Verified");
        }
        assert!(f.store.resume_ordinary().unwrap().is_none());
    }
}

#[test]
fn preparation_reacquires_only_the_expired_policy_read_after_persisting_its_floor() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let mut f = Fixture::new();
    let socket = f.directory.0.join("ExpiredPolicy.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let floor_path = f.directory.0.join("AuthorityFloor.json");
    let initial: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&floor_path).unwrap()).unwrap();
    let sequence = initial["sequence"].as_u64().unwrap();
    let metadata = f
        .store
        .stream_metadata()
        .unwrap()
        .unwrap()
        .canonical()
        .to_vec();
    let (p, r) = policy::current(&f.bootstrap, &f.store).unwrap();
    let scope = f.store.descriptor().scope();
    let refs = [100, 114]
        .into_iter()
        .zip([&p, &r])
        .map(|(kind, bytes)| {
            crate::authority_policies::record_reference(
                bytes,
                scope.network,
                scope.incarnation,
                kind,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityPolicyContext".into()),
        a(refs.iter().map(version_value).collect()),
        a(vec![b(&p), b(&r)]),
    ]);
    let node = f.status_node.clone();
    let state = *f.store.prefix().policy_state();
    let at = f.current.observe().unwrap();
    let later = ClockHealth::new(
        at.wall_ms + 2900,
        at.boot_ms + 2900,
        at.boot_ms + 30000,
        100,
    )
    .unwrap()
    .frozen();
    let count = Arc::new(AtomicUsize::new(0));
    let requests = count.clone();
    let server_floor = floor_path.clone();
    let server = std::thread::spawn(move || {
        let mut first = None;
        for attempt in 0..2 {
            let (stream, bytes) = receive_control(&listener);
            let (request, challenge) = submitted(&bytes);
            assert!(matches!(
                read::Request::from_signed(&request).unwrap().query,
                Query::PolicyContext
            ));
            if attempt == 0 {
                first = Some((request.clone(), challenge.clone()));
            } else {
                let (old_request, old_challenge) = first.as_ref().unwrap();
                assert_ne!(&request, old_request);
                assert_ne!(&challenge, old_challenge);
                let retained: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&server_floor).unwrap()).unwrap();
                assert!(retained["sequence"].as_u64().unwrap() > sequence);
                assert!(
                    retained["tracker"]["ordinary"].is_null()
                        || retained["tracker"]["ordinary"]["complete"].as_bool() == Some(true)
                );
            }
            requests.fetch_add(1, Ordering::SeqCst);
            send_control(
                stream,
                &response(
                    &request,
                    &challenge,
                    &node,
                    state,
                    value.clone(),
                    at.wall_ms + if attempt == 0 { 0 } else { 2900 },
                    u64::MAX,
                    0,
                ),
            );
        }
    });
    let mut first = true;
    let mut expired_observation = false;
    let mut budget = RetryBudget::new(
        crate::authority_challenge::boot_time_ms().unwrap() + 30000,
        || false,
    );
    policy::refresh_before_request_with_budget(
        &f.bootstrap,
        &socket,
        &f.signer,
        &mut f.store,
        &mut f.session,
        || {
            if first {
                first = false;
                return Ok(f.issued);
            }
            let retained: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&floor_path)?).unwrap();
            if retained["sequence"].as_u64().unwrap() > sequence && !expired_observation {
                expired_observation = true;
                return Err(crate::authority_clock::ObservationExpired.into());
            }
            Ok(if retained["sequence"].as_u64().unwrap() > sequence {
                later
            } else {
                f.current
            })
        },
        &mut budget,
    )
    .unwrap();
    server.join().unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 2);
    assert!(expired_observation);
    assert!(budget.reissued);
    assert!(f.store.resume_ordinary().unwrap().is_none());
    assert_eq!(
        f.store.stream_metadata().unwrap().unwrap().canonical(),
        metadata
    );
    let retained: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&floor_path).unwrap()).unwrap();
    assert_eq!(retained["sequence"].as_u64().unwrap(), sequence + 2);
}

#[test]
fn preparation_read_reissue_is_single_bounded_and_never_accepts_other_failures() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let deadline = crate::authority_challenge::boot_time_ms().unwrap() + 30000;
    let mut budget = RetryBudget::new(deadline, || false);
    let mut calls = 0;
    let result: Result<()> = budget.run(|_| {
        calls += 1;
        Err(crate::authority_floor::ReadExpired.into())
    });
    assert!(
        result
            .unwrap_err()
            .is::<crate::authority_floor::ReadExpired>()
    );
    assert_eq!(calls, 2);
    let result: Result<()> = budget.run(|_| {
        calls += 1;
        Err(crate::authority_floor::ReadExpired.into())
    });
    assert!(result.is_err());
    assert_eq!(calls, 3);
    for message in [
        "clock moved backwards",
        "challenge context invalid",
        "authority refused",
    ] {
        let mut budget = RetryBudget::new(deadline, || false);
        let mut calls = 0;
        let result: Result<()> = budget.run(|_| {
            calls += 1;
            anyhow::bail!(message)
        });
        assert!(result.is_err());
        assert_eq!(calls, 1);
        assert!(!budget.reissued);
    }
    let mut budget = RetryBudget::new(
        crate::authority_challenge::boot_time_ms().unwrap() + 1000,
        || false,
    );
    let mut calls = 0;
    let result: Result<()> = budget.run(|_| {
        calls += 1;
        Err(crate::authority_floor::ReadExpired.into())
    });
    assert!(result.is_err());
    assert_eq!(calls, 1);
    assert!(!budget.reissued);
    let cancelled = Arc::new(AtomicBool::new(false));
    let observed = cancelled.clone();
    let mut budget = RetryBudget::new(deadline, move || observed.load(Ordering::SeqCst));
    let mut calls = 0;
    let result: Result<()> = budget.run(|_| {
        calls += 1;
        cancelled.store(true, Ordering::SeqCst);
        Err(crate::authority_floor::ReadExpired.into())
    });
    assert!(result.is_err());
    assert_eq!(calls, 1);
    assert!(!budget.reissued);
}

#[test]
fn preparation_budget_stops_blocked_policy_reply_without_reissuing() {
    use std::{
        io::Read,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };
    for cancelled in [false, true] {
        let mut f = Fixture::new();
        let path = f.directory.0.join("BoundedPolicy.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let signal = Arc::new(AtomicBool::new(false));
        let observed = signal.clone();
        let server = std::thread::spawn(move || {
            let (mut stream, bytes) = receive_control(&listener);
            let (request, _) = submitted(&bytes);
            assert!(matches!(
                read::Request::from_signed(&request).unwrap().query,
                Query::PolicyContext
            ));
            if cancelled {
                signal.store(true, Ordering::Release);
            }
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            assert_eq!(stream.read(&mut [0; 1]).unwrap(), 0);
            listener.set_nonblocking(true).unwrap();
            assert!(
                matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
            );
        });
        let end = crate::authority_challenge::boot_time_ms().unwrap()
            + if cancelled { 5000 } else { 250 };
        let mut budget = RetryBudget::new(end, move || observed.load(Ordering::Acquire));
        let prefix = f.store.prefix().clone();
        let error = policy::refresh_before_request_with_budget(
            &f.bootstrap,
            &path,
            &f.signer,
            &mut f.store,
            &mut f.session,
            || Ok(f.current),
            &mut budget,
        )
        .unwrap_err();
        assert!(!budget.reissued);
        assert!(f.store.resume_ordinary().unwrap().is_none());
        assert_eq!(f.store.prefix(), &prefix);
        assert!(crate::authority_challenge::boot_time_ms().unwrap() < end + 500);
        if cancelled {
            assert!(format!("{error:#}").contains("application preparation cancelled"));
        }
        server.join().unwrap();
    }
}
