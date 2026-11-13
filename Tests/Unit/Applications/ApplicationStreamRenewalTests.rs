// SPDX-License-Identifier: MIT
// Early authority renewal carries live-session counters and refuses changed pinned authority.
use super::*;

fn voucher() -> domain::routes::Voucher {
    let reference = |kind, id| VersionRef {
        kind,
        id: [id; 32],
        generation: 1,
        digest: [id + 1; 32],
    };
    let key = |id| SigningKey::from_bytes(&[id; 32]).verifying_key().to_bytes();
    domain::routes::Voucher {
        relay: reference(165, 11),
        destination: reference(165, 13),
        sponsor: key(15),
        grant: reference(102, 16),
        possession: key(18),
        action: 0,
        scope: (0, [25; 32]),
        connections: 64,
        bytes: 1048576,
        expires: 90000,
        creation: [19; 32],
        baseline: Some((1000, 4194304)),
    }
}
fn record(voucher: &domain::routes::Voucher, generation: u64) -> domain::Record {
    domain::Record {
        reference: VersionRef {
            kind: 166,
            id: [20; 32],
            generation,
            digest: [21; 32],
        },
        predecessor: (generation > 1).then_some([22; 32]),
        payload: voucher.value(),
        bytes: vec![],
    }
}

#[test]
fn authority_handover_keeps_allowances_when_cumulative_baseline_exceeds_them() {
    let old = voucher();
    let expires = 150000;
    let mut renewed = old.clone();
    renewed.expires = expires;
    renewed.creation = [23; 32];
    assert!(successor(&record(&old, 2), &record(&renewed, 3)).unwrap());
    assert!(!successor(&record(&old, 2), &record(&old, 2)).unwrap());
}

#[test]
fn cached_successor_cannot_reset_budget_or_replace_pinned_authority() {
    let old = voucher();
    for change in 0..9 {
        let mut next = old.clone();
        next.expires += 60000;
        match change {
            0 => next.baseline = Some((1001, 4194304)),
            1 => next.connections += 1,
            2 => next.bytes += 1,
            3 => next.grant.generation += 1,
            4 => next.relay.generation += 1,
            5 => next.destination.id = [29; 32],
            6 => next.possession = SigningKey::from_bytes(&[30; 32]).verifying_key().to_bytes(),
            7 => next.expires = old.expires - 1,
            _ => next.sponsor = SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes(),
        }
        assert!(
            successor(&record(&old, 2), &record(&next, 3)).is_err(),
            "change {change}"
        );
    }
}
