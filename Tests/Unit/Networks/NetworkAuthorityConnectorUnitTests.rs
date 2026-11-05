// SPDX-License-Identifier: MIT
// Unit tests for NetworkAuthorityConnector.
use super::*;
use crate::{authority_proof::Scope, trust_wire::Value as V};

#[test]
fn blocked_status_persistence_does_not_block_exchange_state_updates() {
    let binding = Binding {
        format: "HyperNetAuthorityConnector/1".into(),
        network: "01".repeat(32),
        incarnation: "02".repeat(32),
        bootstrap_digest: "03".repeat(32),
        target_digest: "04".repeat(32),
    };
    let state = Mutex::new(Status {
        running: true,
        active: true,
        active_exchanges: MAXIMUM_EXCHANGES,
        completed: 7,
        ..Status::default()
    });
    let (entered, snapshot) = mpsc::sync_channel(1);
    let (release, blocked) = mpsc::sync_channel(1);
    thread::scope(|scope| {
        let state_ref = &state;
        let binding_ref = &binding;
        let writer = scope.spawn(move || {
            save_status(state_ref, binding_ref, |bytes| {
                entered.send(bytes.to_vec()).unwrap();
                // The persistence boundary stays blocked until all worker-style
                // updates finish. The timeout also bounds cleanup after a panic.
                blocked.recv_timeout(Duration::from_secs(2))?;
                anyhow::bail!("test persistence failure")
            })
        });
        let bytes = snapshot.recv_timeout(Duration::from_secs(2)).unwrap();
        for _ in 0..MAXIMUM_EXCHANGES {
            let mut current = state.try_lock().expect("persistence retained status lock");
            current.active_exchanges -= 1;
            current.active = current.active_exchanges != 0;
            current.completed += 1;
        }
        let saved: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(saved["status"]["activeExchanges"], MAXIMUM_EXCHANGES);
        assert_eq!(saved["status"]["completed"], 7);
        assert_eq!(saved["binding"], serde_json::to_value(&binding).unwrap());
        assert_eq!(saved["maximumQueuedConnections"], MAXIMUM_QUEUED);
        assert_eq!(saved["maximumConcurrentExchanges"], MAXIMUM_EXCHANGES);
        assert_eq!(saved["maximumDurationMs"], DURATION_MS);
        assert!(saved["sampleBootMs"].as_u64().is_some());
        release.send(()).unwrap();
        assert_eq!(
            writer.join().unwrap().unwrap_err().to_string(),
            "test persistence failure"
        );
    });
    let current = state.lock().unwrap();
    assert_eq!(current.active_exchanges, 0);
    assert!(!current.active);
    assert_eq!(current.completed, 7 + MAXIMUM_EXCHANGES as u64);
}

#[test]
fn blocked_exchange_releases_shared_intake_and_preserves_one_queue_bound() {
    let (sender, receiver) = mpsc::sync_channel(MAXIMUM_QUEUED);
    let receiver = Arc::new(Mutex::new(receiver));
    let (started, observed) = mpsc::channel();
    let (release, waiting) = mpsc::channel();
    let waiting = Arc::new(Mutex::new(waiting));
    let mut peers = Vec::new();
    for deadline in 1..=MAXIMUM_EXCHANGES as u64 {
        let (stream, peer) = UnixStream::pair().unwrap();
        peers.push(peer);
        sender.send(Job { stream, deadline }).unwrap();
    }
    let workers: Vec<_> = (0..MAXIMUM_EXCHANGES)
        .map(|_| {
            let receiver = Arc::clone(&receiver);
            let started = started.clone();
            let waiting = Arc::clone(&waiting);
            thread::spawn(move || {
                let job = next_job(&receiver).unwrap();
                started.send(job.deadline).unwrap();
                // All four exchanges must enter before any can complete.
                waiting
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap();
                let cancelled = ipc::disconnected(&job.stream)
                    .unwrap()
                    .then_some(job.deadline);
                let mut deadlines = vec![job.deadline];
                while let Some(job) = next_job(&receiver) {
                    deadlines.push(job.deadline);
                }
                (deadlines, cancelled)
            })
        })
        .collect();
    drop(started);
    let mut active = Vec::new();
    for _ in 0..MAXIMUM_EXCHANGES {
        active.push(observed.recv_timeout(Duration::from_secs(2)).unwrap());
    }
    active.sort_unstable();
    assert_eq!(active, vec![1, 2, 3, 4]);
    for index in 0..MAXIMUM_QUEUED {
        let (stream, peer) = UnixStream::pair().unwrap();
        peers.push(peer);
        sender
            .try_send(Job {
                stream,
                deadline: 100 + index as u64,
            })
            .unwrap();
    }
    let (stream, _peer) = UnixStream::pair().unwrap();
    assert!(matches!(
        sender.try_send(Job {
            stream,
            deadline: 0
        }),
        Err(mpsc::TrySendError::Full(_))
    ));
    // Cancellation belongs to this worker's caller, not the shared receiver or
    // another worker's independently owned exchange.
    drop(peers.remove(0));
    drop(sender);
    for _ in 0..MAXIMUM_EXCHANGES {
        release.send(()).unwrap();
    }
    let completed: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(completed.len(), MAXIMUM_EXCHANGES);
    let cancelled: Vec<_> = completed
        .iter()
        .filter_map(|(_, cancelled)| *cancelled)
        .collect();
    assert_eq!(cancelled, vec![1]);
    let mut deadlines: Vec<_> = completed
        .into_iter()
        .flat_map(|(deadlines, _)| deadlines)
        .collect();
    deadlines.sort_unstable();
    let mut expected = vec![1, 2, 3, 4];
    expected.extend(100..100 + MAXIMUM_QUEUED as u64);
    assert_eq!(deadlines, expected);
    assert!(next_job(&receiver).is_none());
}

#[test]
fn authority_connector_binding_and_packet_limits_are_exact() {
    let binding = Binding {
        format: "HyperNetAuthorityConnector/1".into(),
        network: "01".repeat(32),
        incarnation: "02".repeat(32),
        bootstrap_digest: "03".repeat(32),
        target_digest: "04".repeat(32),
    };
    let bytes = binding.encode().unwrap();
    assert_eq!(Binding::parse(&bytes).unwrap(), binding);
    let mut wrong = binding.clone();
    wrong.target_digest = "AB".repeat(32);
    assert!(wrong.encode().is_err());
    let mut extra: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    extra["fallback"] = json!("127.0.0.1:1");
    assert!(Binding::parse(&serde_json::to_vec(&extra).unwrap()).is_err());
    let scope = Scope {
        network: [1; 32],
        incarnation: [2; 32],
        configuration: [3; 32],
        epoch: 0,
    };
    let frame = |operation| {
        wire::encode(&V::Array(vec![
            V::Uint(41),
            V::Uint(1),
            scope.value(),
            V::Uint(operation),
            V::Bytes(wire::encode(&V::Array(vec![])).unwrap()),
        ]))
        .unwrap()
    };
    packet::validate([1; 32], [2; 32], &frame(2)).unwrap();
    assert!(packet::validate([1; 32], [9; 32], &frame(2)).is_err());
    assert!(packet::validate([1; 32], [2; 32], &frame(5)).is_err());
}

fn cleanup_fields(kind: u64) -> Vec<V> {
    vec![
        V::Uint(kind),
        V::Uint(1),
        Scope {
            network: [1; 32],
            incarnation: [2; 32],
            configuration: [3; 32],
            epoch: 0,
        }
        .value(),
        V::Bytes(vec![4; 32]),
        V::Bytes(vec![5; 32]),
        V::Bytes(vec![6; 32]),
        if kind == 63 {
            V::Uint(14000)
        } else {
            V::Bool(true)
        },
    ]
}
fn cleanup_packet(fields: Vec<V>) -> Vec<u8> {
    let scope = cleanup_fields(63)[2].clone();
    let signed = wire::sign_envelope(
        &wire::encode(&V::Array(fields)).unwrap(),
        &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
    )
    .unwrap();
    wire::encode(&V::Array(vec![
        V::Uint(41),
        V::Uint(1),
        scope,
        V::Uint(8),
        V::Bytes(signed),
    ]))
    .unwrap()
}
#[test]
fn authority_connector_cleanup_authenticates_exact_scope_and_original_deadline() {
    use crate::authority_challenge::Observation;
    let frame = cleanup_packet(cleanup_fields(63));
    let cleanup = packet::validate([1; 32], [2; 32], &frame).unwrap().unwrap();
    let observed = Observation {
        wall_ms: 10000,
        boot_ms: 1000,
    };
    assert_eq!(cleanup.deadline(observed, 30000).unwrap(), 4750);
    assert_eq!(cleanup.deadline(observed, 3000).unwrap(), 3000);
    assert!(
        cleanup
            .deadline(
                Observation {
                    wall_ms: 13750,
                    boot_ms: 4750
                },
                30000
            )
            .is_err()
    );
    assert!(
        cleanup
            .deadline(
                Observation {
                    wall_ms: 8999,
                    boot_ms: 1
                },
                30000
            )
            .is_err()
    );
    assert!(packet::validate([1; 32], [9; 32], &frame).is_err());
    for (index, invalid) in [
        (0, V::Uint(64)),
        (1, V::Uint(2)),
        (
            2,
            Scope {
                network: [9; 32],
                incarnation: [2; 32],
                configuration: [3; 32],
                epoch: 0,
            }
            .value(),
        ),
        (3, V::Bytes(vec![0; 32])),
        (4, V::Bytes(vec![0; 32])),
        (5, V::Bytes(vec![0; 32])),
        (6, V::Uint(0)),
    ] {
        let mut fields = cleanup_fields(63);
        fields[index] = invalid;
        assert!(packet::validate([1; 32], [2; 32], &cleanup_packet(fields)).is_err());
    }
    let value = wire::decode(&frame).unwrap();
    let mut outer = value.array(5).unwrap().to_vec();
    let mut signed = outer[4].bytes().unwrap().to_vec();
    *signed.last_mut().unwrap() ^= 1;
    outer[4] = V::Bytes(signed);
    assert!(packet::validate([1; 32], [2; 32], &wire::encode(&V::Array(outer)).unwrap()).is_err());
}
#[test]
fn authority_connector_cleanup_drains_bound_receipt_without_a_local_response_waiter() {
    let frame = cleanup_packet(cleanup_fields(63));
    let cleanup = packet::validate([1; 32], [2; 32], &frame).unwrap().unwrap();
    let (mut waiting, mut local) = UnixStream::pair().unwrap();
    let not_released =
        exchange_cleanup(None, &frame, boot_time_ms().unwrap() + 1000, &cleanup).unwrap();
    deliver_reply(
        &mut local,
        &not_released,
        boot_time_ms().unwrap() + 1000,
        Some(&cleanup),
    )
    .unwrap();
    assert_eq!(ipc::read_frame(&mut waiting).unwrap(), not_released);
    let (caller, mut accepted) = UnixStream::pair().unwrap();
    drop(caller);
    let deadline = boot_time_ms().unwrap() + 1000;
    for released in [true, false] {
        let mut fields = cleanup_fields(64);
        fields[6] = V::Bool(released);
        let reply = wire::encode(&V::Array(fields)).unwrap();
        deliver_reply(&mut accepted, &reply, deadline, Some(&cleanup)).unwrap();
        assert!(deliver_reply(&mut accepted, &reply, deadline, None).is_err());
    }
    for (index, invalid) in [
        (0, V::Uint(42)),
        (1, V::Uint(2)),
        (
            2,
            Scope {
                network: [9; 32],
                incarnation: [2; 32],
                configuration: [3; 32],
                epoch: 0,
            }
            .value(),
        ),
        (3, V::Bytes(vec![9; 32])),
        (4, V::Bytes(vec![9; 32])),
        (5, V::Bytes(vec![9; 32])),
        (6, V::Uint(1)),
    ] {
        let mut fields = cleanup_fields(64);
        fields[index] = invalid;
        assert!(
            deliver_reply(
                &mut accepted,
                &wire::encode(&V::Array(fields)).unwrap(),
                deadline,
                Some(&cleanup)
            )
            .is_err()
        );
    }
}
