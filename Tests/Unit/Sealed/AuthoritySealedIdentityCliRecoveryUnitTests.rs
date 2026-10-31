// SPDX-License-Identifier: MIT
// Unit tests for AuthoritySealedIdentityCliRecovery.
use super::*;
#[test]
fn recipient_recovery_shares_require_exact_distinct_accepted_custody() {
    let keys = (1..=4)
        .map(|n| SigningKey::from_bytes(&[n; 32]))
        .collect::<Vec<_>>();
    let payload = wire::encode(&a(vec![V::Uint(120), b(&[11; 32])])).unwrap();
    let policy = identity::Custody {
        member: [12; 32],
        threshold: 2,
        keys: keys[..3]
            .iter()
            .enumerate()
            .map(|(n, k)| ([n as u8 + 1; 32], k.verifying_key().to_bytes()))
            .collect(),
        digest: [13; 32],
    };
    let shares = keys
        .iter()
        .map(|k| wire::sign_envelope(&payload, k).unwrap())
        .collect::<Vec<_>>();
    assert!(assemble(&payload, &shares[..2], &policy).is_ok());
    assert!(assemble(&payload, &shares[..1], &policy).is_err());
    assert!(assemble(&payload, &[shares[0].clone(), shares[0].clone()], &policy).is_err());
    assert!(assemble(&payload, &[shares[0].clone(), shares[3].clone()], &policy).is_err());
    assert!(assemble(&[0], &shares[..2], &policy).is_err());
}
