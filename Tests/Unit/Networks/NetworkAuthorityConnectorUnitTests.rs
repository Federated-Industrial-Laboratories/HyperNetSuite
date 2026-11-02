// SPDX-License-Identifier: MIT
// Unit tests for NetworkAuthorityConnector.
use super::*;
use crate::{authority_proof::Scope, trust_wire::Value as V};

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
