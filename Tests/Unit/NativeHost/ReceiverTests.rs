// SPDX-License-Identifier: Apache-2.0
// Receiver maintenance preserves exact expired requests and live allowances.
use super::*;
#[test]
fn exhausted_receiver_waits_for_original_expiry_before_recovery() {
    let mut route = json!({"state":"quotaExhausted","expiresAtMs":5000,"recoveryAfterMs":5000});
    assert!(!expired_route(&route, 4999).unwrap());
    assert!(expired_route(&route, 5000).unwrap());
    route["recoveryAfterMs"] = json!(1000);
    assert!(expired_route(&route, 5000).is_err());
    route["state"] = json!("current");
    route["recoveryAfterMs"] = Value::Null;
    assert!(expired_route(&route, 5000).unwrap());
}
#[test]
fn interrupted_recovery_replays_discovery_but_never_advances_waiting_or_uncertain_work() {
    use std::cell::Cell;
    let calls = Cell::new(0);
    let replayed = Cell::new(false);
    resolve_expired(
        None,
        || {
            calls.set(calls.get() + 1);
            if !replayed.get() {
                anyhow::bail!("pending RouteContext")
            }
            Ok(json!({"state":"RouteIssueRecovery","status":"Recovered"}))
        },
        || {
            replayed.set(true);
            anyhow::bail!("exact old issuance is expired")
        },
    )
    .unwrap();
    assert_eq!(calls.get(), 2);
    assert_eq!(
        unrecorded_expiry(
            &json!({"state":"RouteIssueRecovery","status":"Waiting","expiresAtMs":5000}),
            10000
        )
        .unwrap(),
        5000
    );
    resolve_expired(
        Some(5000),
        || Ok(json!({"state":"RouteIssueRecovery","status":"Waiting","expiresAtMs":5000})),
        || panic!("current exact command resumes outside recovery"),
    )
    .unwrap();
    for status in ["Waiting", "RecoveryPending"] {
        assert!(
            resolve_expired(
                None,
                || Ok(json!({"state":"RouteIssueRecovery","status":status})),
                || panic!("live/uncertain request must not be replayed")
            )
            .is_err()
        );
    }
    assert!(resolve_expired(None, || anyhow::bail!("unavailable"), || Ok(())).is_err());
    let old = json!({"generation":7,"expires":5000,"complete":false,"previous":{"generation":6,"expires":1000}});
    assert!(new_cycle(&old, 10000, 4999).is_err());
    assert!(new_cycle(&old, 5000, 5000).is_err());
    let next = new_cycle(&old, 10000, 5000).unwrap();
    assert_eq!(next["previous"], json!({"generation":7,"expires":5000}));
    assert_eq!(old["complete"], false);
}

#[test]
fn live_certificate_refresh_cannot_extend_expiry_or_reset_usage_baseline() {
    use crate::{
        authority_domains::{Record, routes::Voucher},
        authority_proof::VersionRef,
        trust_wire::{self, Value as V},
    };
    let reference = |kind, id| VersionRef {
        kind,
        id: [id; 32],
        generation: 1,
        digest: [id; 32],
    };
    let voucher = Voucher {
        relay: reference(165, 3),
        destination: reference(165, 4),
        grant: reference(102, 5),
        sponsor: crate::authority_deployment_tests::key(6)
            .verifying_key()
            .to_bytes(),
        possession: crate::authority_deployment_tests::key(7)
            .verifying_key()
            .to_bytes(),
        action: 0,
        scope: (0, [1; 32]),
        connections: 64,
        bytes: 65536,
        expires: 50000,
        creation: [8; 32],
        baseline: Some((4, 262144)),
    };
    let record = |v: &Voucher, generation| {
        Record::parse(
            &trust_wire::encode(&V::Array(vec![
                V::Uint(166),
                V::Uint(1),
                V::Bytes(vec![1; 32]),
                V::Bytes(vec![2; 32]),
                V::Uint(generation),
                if generation == 1 {
                    V::Null
                } else {
                    V::Bytes(vec![9; 32])
                },
                V::Bytes(vec![10; 32]),
                v.value(),
            ]))
            .unwrap(),
            [1; 32],
            [2; 32],
        )
        .unwrap()
    };
    let old = record(&voucher, 1);
    let mut changed = voucher.clone();
    changed.relay.generation = 2;
    changed.relay.digest = [11; 32];
    same_allowance(&old, &record(&changed, 2)).unwrap();
    for mutation in 0..7 {
        let mut other = changed.clone();
        match mutation {
            0 => other.expires += 1,
            1 => other.baseline = Some((5, 262144)),
            2 => other.baseline = Some((4, 327680)),
            3 => other.connections += 1,
            4 => other.bytes += 1,
            5 => other.grant.generation += 1,
            _ => {
                other.possession = crate::authority_deployment_tests::key(9)
                    .verifying_key()
                    .to_bytes()
            }
        }
        assert!(
            same_allowance(&old, &record(&other, 2)).is_err(),
            "mutation {mutation}"
        );
    }
    let args = exact_voucher_args(
        &old,
        Path::new("/Private/Template.json"),
        Path::new("/Private/Output.json"),
    )
    .unwrap();
    for (name, value) in [
        ("--id", hex::encode(old.reference.id)),
        ("--expires-ms", voucher.expires.to_string()),
        ("--connections", voucher.connections.to_string()),
        ("--bytes", voucher.bytes.to_string()),
    ] {
        assert_eq!(
            args[args.iter().position(|v| v == name).unwrap() + 1],
            value
        );
    }
}
