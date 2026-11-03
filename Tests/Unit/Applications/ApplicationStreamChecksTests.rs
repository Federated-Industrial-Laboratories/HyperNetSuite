// SPDX-License-Identifier: MIT
use super::*;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
struct Fixture {
    checks: Arc<Checks>,
    key: ed25519_dalek::SigningKey,
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "hrc-checks-{}",
            hex::encode(crate::route_protocol::random().unwrap())
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let clock = path.join("Clock.json");
        let boot = boot_time_ms().unwrap();
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        fs::write(&clock,serde_json::to_vec(&json!({"version":1,"kernelBoot":fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap().trim(),"sampleWallMs":wall,"sampleBootMs":boot,"validUntilBootMs":boot+1000,"maximumErrorMs":1,"source":"192.0.2.1"})).unwrap()).unwrap();
        fs::set_permissions(&clock, fs::Permissions::from_mode(0o600)).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[33; 32]);
        let binding = Binding {
            version: 1,
            id: [1; 32],
            network: [2; 32],
            incarnation: [3; 32],
            service: [4; 32],
            owner: key.verifying_key().to_bytes(),
            endpoint: key.verifying_key().to_bytes(),
            protocol: "example/1".into(),
        };
        let checks = Arc::new(
            Checks::new(
                binding,
                Arc::new(Source::select(&clock, None, None).unwrap()),
            )
            .unwrap(),
        );
        Self { checks, key, path }
    }
    fn attach(
        &self,
    ) -> (
        UnixStream,
        std::thread::JoinHandle<Result<()>>,
        contract::Ready,
    ) {
        let (companion, mut endpoint) = UnixStream::pair().unwrap();
        endpoint
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let checks = self.checks.clone();
        let worker = std::thread::spawn(move || checks.serve(companion));
        let challenge = contract::parse(&ipc::read_frame(&mut endpoint).unwrap()).unwrap();
        let ready = contract::Ready {
            challenge,
            endpoint_instance: [5; 32],
            monotonic_offset_ns: 0,
            boottime_offset_ns: 0,
            capabilities: vec![contract::CAPABILITY.into()],
            privacy: contract::Privacy {
                transport_protection: contract::TransportProtection::Tls13FinalService,
                endpoint_mode: 2,
                incoming_path: contract::IncomingPath::PublicListener,
                attachment: None,
                physical_independence_verified: false,
                profile_currentness_asserted: false,
            },
        };
        ipc::write_frame(
            &mut endpoint,
            &contract::sign(&ready, &self.checks.binding, &self.key).unwrap(),
        )
        .unwrap();
        let limit = Instant::now() + Duration::from_secs(1);
        while !self.checks.ready() {
            assert!(Instant::now() < limit);
            std::thread::yield_now();
        }
        (endpoint, worker, ready)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.checks.stop();
        let _ = fs::remove_dir_all(&self.path);
    }
}
fn reference() -> VersionRef {
    VersionRef {
        kind: 173,
        id: [8; 32],
        generation: 2,
        digest: [9; 32],
    }
}
#[test]
fn exact_signed_receipt_and_certified_denial_remain_distinct() {
    let fixture = Fixture::new();
    let (mut endpoint, worker, ready) = fixture.attach();
    let (caller, peer) = UnixStream::pair().unwrap();
    let checks = fixture.checks.clone();
    let check = std::thread::spawn(move || {
        let started = boot_time_ms().unwrap();
        checks
            .check(
                &Input {
                    id: "connection",
                    nonce: [10; 32],
                    action_digest: [11; 32],
                    started,
                    deadline: started + 500,
                },
                reference(),
                Arc::new(AtomicBool::new(false)),
                &caller,
            )
            .unwrap()
    });
    let request: contract::Request =
        contract::parse(&ipc::read_frame(&mut endpoint).unwrap()).unwrap();
    assert_eq!(request.session, reference());
    let receipt = contract::Receipt {
        not_after_boot_ms: request.caller_deadline_boot_ms,
        request,
        disposition: contract::Disposition::Denied,
        authority: Some(contract::Authority {
            network: [2; 32],
            incarnation: [3; 32],
            configuration: [12; 32],
            epoch: 1,
            height: 9,
            state: [13; 32],
            statement_digest: [14; 32],
            evaluated_at_ms: 10000,
            expires_at_ms: 11000,
            code: 1,
        }),
        privacy: ready.privacy,
    };
    ipc::write_frame(
        &mut endpoint,
        &contract::sign(&receipt, &fixture.checks.binding, &fixture.key).unwrap(),
    )
    .unwrap();
    let result = check.join().unwrap();
    assert_eq!(result["result"]["disposition"], "denied");
    assert_eq!(result["result"]["authority"]["code"], 1);
    assert_eq!(result["result"]["privacy"]["relayPath"], "unknown");
    drop(peer);
    fixture.checks.stop();
    drop(endpoint);
    let _ = worker.join();
}
#[test]
fn replacement_and_misbound_receipts_invalidate_without_reusing_authority() {
    let fixture = Fixture::new();
    let (mut endpoint, worker, ready) = fixture.attach();
    let (replacement, _) = UnixStream::pair().unwrap();
    assert!(fixture.checks.serve(replacement).is_err());
    let (caller, _peer) = UnixStream::pair().unwrap();
    let checks = fixture.checks.clone();
    let check = std::thread::spawn(move || {
        let started = boot_time_ms().unwrap();
        checks
            .check(
                &Input {
                    id: "connection",
                    nonce: [10; 32],
                    action_digest: [11; 32],
                    started,
                    deadline: started + 500,
                },
                reference(),
                Arc::new(AtomicBool::new(false)),
                &caller,
            )
            .unwrap()
    });
    let mut request: contract::Request =
        contract::parse(&ipc::read_frame(&mut endpoint).unwrap()).unwrap();
    request.nonce = [12; 32];
    let receipt = contract::Receipt {
        not_after_boot_ms: request.caller_deadline_boot_ms,
        request,
        disposition: contract::Disposition::NotActive,
        authority: None,
        privacy: ready.privacy,
    };
    ipc::write_frame(
        &mut endpoint,
        &contract::sign(&receipt, &fixture.checks.binding, &fixture.key).unwrap(),
    )
    .unwrap();
    assert_eq!(
        check.join().unwrap()["result"]["disposition"],
        "unavailable"
    );
    assert!(worker.join().unwrap().is_err());
    assert!(!fixture.checks.ready());
}
#[test]
fn deadline_is_absolute_even_when_a_frame_arrives_in_fragments() {
    let (mut caller, mut peer) = UnixStream::pair().unwrap();
    let start = boot_time_ms().unwrap();
    let worker = std::thread::spawn(move || read_bounded(&mut caller, start + 100, &|| false));
    peer.write_all(&[0, 0]).unwrap();
    std::thread::sleep(Duration::from_millis(60));
    peer.write_all(&[0, 4, 1]).unwrap();
    assert!(worker.join().unwrap().is_err());
    assert!(boot_time_ms().unwrap() - start < 400);
}
#[test]
fn cancelling_a_connection_discards_pending_authority() {
    let fixture = Fixture::new();
    let (mut endpoint, worker, _) = fixture.attach();
    let (caller, _peer) = UnixStream::pair().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let control = cancel.clone();
    let checks = fixture.checks.clone();
    let check = std::thread::spawn(move || {
        let started = boot_time_ms().unwrap();
        checks
            .check(
                &Input {
                    id: "connection",
                    nonce: [10; 32],
                    action_digest: [11; 32],
                    started,
                    deadline: started + 500,
                },
                reference(),
                cancel,
                &caller,
            )
            .unwrap()
    });
    let request: contract::Request =
        contract::parse(&ipc::read_frame(&mut endpoint).unwrap()).unwrap();
    control.store(true, Ordering::Release);
    assert_eq!(check.join().unwrap()["result"]["disposition"], "notActive");
    let cancel: contract::Cancel =
        contract::parse(&ipc::read_frame(&mut endpoint).unwrap()).unwrap();
    assert_eq!(cancel.request, request);
    assert!(worker.join().unwrap().is_err());
    assert!(fixture.checks.state.lock().unwrap().pending.is_empty());
}

#[test]
fn pending_budget_is_one_per_connection_and_four_for_the_companion() {
    let fixture = Fixture::new();
    let (mut endpoint, worker, _) = fixture.attach();
    let mut peers = Vec::new();
    let mut callers = Vec::new();
    for index in 0..4 {
        let (caller, peer) = UnixStream::pair().unwrap();
        peers.push(peer);
        let checks = fixture.checks.clone();
        callers.push(std::thread::spawn(move || {
            let started = boot_time_ms().unwrap();
            checks
                .check(
                    &Input {
                        id: &format!("connection-{index}"),
                        nonce: [10; 32],
                        action_digest: [11; 32],
                        started,
                        deadline: started + 500,
                    },
                    reference(),
                    Arc::new(AtomicBool::new(false)),
                    &caller,
                )
                .unwrap()
        }));
    }
    let end = Instant::now() + Duration::from_millis(300);
    while fixture.checks.state.lock().unwrap().pending.len() < 4 {
        assert!(Instant::now() < end);
        std::thread::yield_now();
    }
    let mut received = BTreeSet::new();
    for _ in 0..4 {
        let request: contract::Request =
            contract::parse(&ipc::read_frame(&mut endpoint).unwrap()).unwrap();
        received.insert(request.local_connection_id);
    }
    assert_eq!(received.len(), 4);
    for id in ["connection-0", "connection-5"] {
        let (caller, _peer) = UnixStream::pair().unwrap();
        let started = boot_time_ms().unwrap();
        let result = fixture
            .checks
            .check(
                &Input {
                    id,
                    nonce: [10; 32],
                    action_digest: [11; 32],
                    started,
                    deadline: started + 500,
                },
                reference(),
                Arc::new(AtomicBool::new(false)),
                &caller,
            )
            .unwrap();
        assert_eq!(result["result"]["disposition"], "unavailable");
    }
    drop(peers);
    drop(endpoint);
    for caller in callers {
        assert_ne!(caller.join().unwrap()["result"]["disposition"], "permitted");
    }
    let _ = worker.join();
    assert!(fixture.checks.state.lock().unwrap().pending.is_empty());
}

fn start_check(
    fixture: &Fixture,
    id: &'static str,
    duration: u64,
) -> (std::thread::JoinHandle<Value>, UnixStream, Arc<AtomicBool>) {
    let (caller, peer) = UnixStream::pair().unwrap();
    let checks = fixture.checks.clone();
    let cancel = Arc::new(AtomicBool::new(false));
    let control = cancel.clone();
    let worker = std::thread::spawn(move || {
        let started = boot_time_ms().unwrap();
        checks
            .check(
                &Input {
                    id,
                    nonce: [21; 32],
                    action_digest: [22; 32],
                    started,
                    deadline: started + duration,
                },
                reference(),
                cancel,
                &caller,
            )
            .unwrap()
    });
    (worker, peer, control)
}

fn signed_receipt(
    fixture: &Fixture,
    ready: &contract::Ready,
    request: contract::Request,
) -> Vec<u8> {
    contract::sign(
        &contract::Receipt {
            not_after_boot_ms: request.caller_deadline_boot_ms,
            request,
            disposition: contract::Disposition::NotActive,
            authority: None,
            privacy: ready.privacy.clone(),
        },
        &fixture.checks.binding,
        &fixture.key,
    )
    .unwrap()
}

#[test]
fn two_checks_pipeline_and_signed_out_of_order_receipts_complete_independently() {
    let fixture = Fixture::new();
    let (mut endpoint, worker, ready) = fixture.attach();
    let (slow, _slow_peer, _) = start_check(&fixture, "slow", 900);
    let first: contract::Request =
        contract::parse(&ipc::read_frame(&mut endpoint).unwrap()).unwrap();
    let (fast, _fast_peer, _) = start_check(&fixture, "fast", 700);
    let second: contract::Request =
        contract::parse(&ipc::read_frame(&mut endpoint).unwrap()).unwrap();
    assert_eq!(first.local_connection_id, "slow");
    assert_eq!(second.local_connection_id, "fast");
    ipc::write_frame(&mut endpoint, &signed_receipt(&fixture, &ready, second)).unwrap();
    let result = fast.join().unwrap();
    assert_eq!(result["id"], "fast");
    assert_eq!(result["result"]["disposition"], "notActive");
    assert_eq!(
        result["result"]["controlGeneration"],
        ready.challenge.control_generation
    );
    assert!(!slow.is_finished());
    ipc::write_frame(&mut endpoint, &signed_receipt(&fixture, &ready, first)).unwrap();
    assert_eq!(slow.join().unwrap()["id"], "slow");
    fixture.checks.stop();
    drop(endpoint);
    let _ = worker.join();
}

#[test]
fn fragmented_receipt_does_not_block_writing_another_check_and_ordered_endpoint_works() {
    let fixture = Fixture::new();
    let (mut endpoint, worker, ready) = fixture.attach();
    let (first, _peer, _) = start_check(&fixture, "first", 900);
    let request: contract::Request =
        contract::parse(&ipc::read_frame(&mut endpoint).unwrap()).unwrap();
    let encoded = frame(&signed_receipt(&fixture, &ready, request)).unwrap();
    endpoint.write_all(&encoded[..2]).unwrap();
    let (second, _peer2, _) = start_check(&fixture, "second", 700);
    let next: contract::Request =
        contract::parse(&ipc::read_frame(&mut endpoint).unwrap()).unwrap();
    assert_eq!(next.local_connection_id, "second");
    endpoint.write_all(&encoded[2..]).unwrap();
    assert_eq!(first.join().unwrap()["id"], "first");
    ipc::write_frame(&mut endpoint, &signed_receipt(&fixture, &ready, next)).unwrap();
    assert_eq!(second.join().unwrap()["id"], "second");
    fixture.checks.stop();
    drop(endpoint);
    let _ = worker.join();
}

#[test]
fn wrong_full_correlation_invalidates_all_inflight_checks() {
    let fixture = Fixture::new();
    let (mut endpoint, worker, ready) = fixture.attach();
    let (first, _peer, _) = start_check(&fixture, "first", 900);
    let _request: contract::Request =
        contract::parse(&ipc::read_frame(&mut endpoint).unwrap()).unwrap();
    let (second, _peer2, _) = start_check(&fixture, "second", 700);
    let mut wrong: contract::Request =
        contract::parse(&ipc::read_frame(&mut endpoint).unwrap()).unwrap();
    wrong.action_digest = [23; 32];
    ipc::write_frame(&mut endpoint, &signed_receipt(&fixture, &ready, wrong)).unwrap();
    for check in [first, second] {
        assert_eq!(
            check.join().unwrap()["result"]["disposition"],
            "unavailable"
        );
    }
    assert!(worker.join().unwrap().is_err());
    assert!(!fixture.checks.ready());
    assert!(fixture.checks.state.lock().unwrap().pending.is_empty());
}

#[test]
fn expired_sent_check_discards_generation_without_extending_other_deadlines() {
    let fixture = Fixture::new();
    let (mut endpoint, worker, _) = fixture.attach();
    let (first, _peer, _) = start_check(&fixture, "first", 150);
    let original: contract::Request =
        contract::parse(&ipc::read_frame(&mut endpoint).unwrap()).unwrap();
    let (second, _peer2, _) = start_check(&fixture, "second", 700);
    let _other: contract::Request =
        contract::parse(&ipc::read_frame(&mut endpoint).unwrap()).unwrap();
    assert_eq!(first.join().unwrap()["result"]["disposition"], "expired");
    assert!(boot_time_ms().unwrap() >= original.caller_deadline_boot_ms);
    assert_eq!(
        second.join().unwrap()["result"]["disposition"],
        "unavailable"
    );
    assert!(worker.join().unwrap().is_err());
    assert!(!fixture.checks.ready());
}

#[test]
fn cancellation_invalidates_other_work_and_old_receipt_cannot_cross_reconnection() {
    let fixture = Fixture::new();
    let (mut endpoint, worker, ready) = fixture.attach();
    let (first, _peer, cancel) = start_check(&fixture, "first", 900);
    let old: contract::Request = contract::parse(&ipc::read_frame(&mut endpoint).unwrap()).unwrap();
    let (second, _peer2, _) = start_check(&fixture, "second", 700);
    let _other: contract::Request =
        contract::parse(&ipc::read_frame(&mut endpoint).unwrap()).unwrap();
    cancel.store(true, Ordering::Release);
    assert_eq!(first.join().unwrap()["result"]["disposition"], "notActive");
    assert_eq!(
        second.join().unwrap()["result"]["disposition"],
        "unavailable"
    );
    let cancellation: contract::Cancel =
        contract::parse(&ipc::read_frame(&mut endpoint).unwrap()).unwrap();
    assert_eq!(cancellation.request, old);
    assert!(worker.join().unwrap().is_err());
    assert!(fixture.checks.state.lock().unwrap().pending.is_empty());
    drop(endpoint);
    let (mut endpoint, worker, next_ready) = fixture.attach();
    assert!(next_ready.challenge.control_generation > ready.challenge.control_generation);
    let (replacement, _peer3, _) = start_check(&fixture, "first", 700);
    let current: contract::Request =
        contract::parse(&ipc::read_frame(&mut endpoint).unwrap()).unwrap();
    assert_ne!(current, old);
    ipc::write_frame(&mut endpoint, &signed_receipt(&fixture, &ready, old)).unwrap();
    assert_eq!(
        replacement.join().unwrap()["result"]["disposition"],
        "unavailable"
    );
    assert!(worker.join().unwrap().is_err());
    assert!(!fixture.checks.ready());
}

#[test]
fn caller_disconnection_remains_not_active_when_control_also_closes() {
    let fixture = Fixture::new();
    let (mut endpoint, worker, _) = fixture.attach();
    let (check, peer, cancel) = start_check(&fixture, "first", 900);
    let _request: contract::Request =
        contract::parse(&ipc::read_frame(&mut endpoint).unwrap()).unwrap();
    // The IPC caller has gone without setting the stream cancellation flag.
    // Control loss may wake the blocked reply receiver before its next poll.
    drop(peer);
    drop(endpoint);
    assert!(!cancel.load(Ordering::Acquire));
    assert_eq!(check.join().unwrap()["result"]["disposition"], "notActive");
    assert!(worker.join().unwrap().is_err());
    assert!(fixture.checks.state.lock().unwrap().pending.is_empty());
}

#[test]
fn control_loss_releases_all_pending_reservations_without_authority() {
    let fixture = Fixture::new();
    let (mut endpoint, worker, _) = fixture.attach();
    let (first, _peer, _) = start_check(&fixture, "first", 900);
    let _request: contract::Request =
        contract::parse(&ipc::read_frame(&mut endpoint).unwrap()).unwrap();
    let (second, _peer2, _) = start_check(&fixture, "second", 700);
    let _request: contract::Request =
        contract::parse(&ipc::read_frame(&mut endpoint).unwrap()).unwrap();
    drop(endpoint);
    for check in [first, second] {
        assert_eq!(
            check.join().unwrap()["result"]["disposition"],
            "unavailable"
        );
    }
    assert!(worker.join().unwrap().is_err());
    assert!(fixture.checks.state.lock().unwrap().pending.is_empty());
}
