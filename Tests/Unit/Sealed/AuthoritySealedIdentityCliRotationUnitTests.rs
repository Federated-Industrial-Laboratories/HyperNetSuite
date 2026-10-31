// SPDX-License-Identifier: MIT
// Unit tests for AuthoritySealedIdentityCliRotation.
use super::*;
#[test]
fn root_rotation_keeps_distinct_exact_owner_signatures() {
    let old = SigningKey::from_bytes(&[71; 32]);
    let new = SigningKey::from_bytes(&[72; 32]);
    let payload = wire::encode(&a(vec![V::Uint(200), b(&[73; 32])])).unwrap();
    let signed = countersign(&payload, &[&old, &new]).unwrap();
    let (decoded, signatures) = wire::envelope(&signed, 2).unwrap();
    assert_eq!(decoded, payload);
    assert_eq!(signatures.len(), 2);
    assert!(countersign(&payload, &[&old, &old]).is_err());
    let mut changed = signed;
    *changed.last_mut().unwrap() ^= 1;
    assert!(wire::envelope(&changed, 2).is_err());
}
