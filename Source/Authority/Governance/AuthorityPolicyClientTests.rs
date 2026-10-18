// SPDX-License-Identifier: MIT
// A certified successor cannot silently replace a reader's accepted trust contract.
use super::*;
use crate::authority_inspection::tests::Fixture;
#[test]
fn weaker_candidate_is_refused_before_use_and_non_policy_records_do_not_change_trust() {
    let f = Fixture::new();
    let (p, r) = current(&f.bootstrap, &f.store).unwrap();
    let mut fields = wire::decode(&p).unwrap().array(17).unwrap().to_vec();
    fields[4] = V::Uint(2);
    fields[5] = b(&wire::digest(&p));
    fields[8] = V::Uint(0);
    let weaker = wire::encode(&a(fields)).unwrap();
    let candidate = vec![weaker, r];
    assert!(require_records_accepted(&f.bootstrap, &f.store, &candidate).is_err());
    assert!(retain_records(&f.bootstrap, &f.store, &candidate).is_err());
    assert_eq!(current(&f.bootstrap, &f.store).unwrap().0, p);
    let unrelated = wire::encode(&a(vec![V::Uint(169), V::Uint(1)])).unwrap();
    require_records_accepted(&f.bootstrap, &f.store, &[unrelated]).unwrap();
}
#[test]
fn discovery_requires_exact_linked_custody_and_current_candidate_references() {
    let f = Fixture::new();
    let (p, r) = current(&f.bootstrap, &f.store).unwrap();
    let scope = f.store.descriptor().scope();
    let refs = [100, 114]
        .into_iter()
        .zip([&p, &r])
        .map(|(kind, bytes)| {
            policies::record_reference(bytes, scope.network, scope.incarnation, kind).unwrap()
        })
        .collect::<Vec<_>>();
    let mut value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityPolicyContext".into()),
        a(refs.iter().map(version_value).collect()),
        a(vec![b(&p), b(&r)]),
    ]);
    discovery::pair_from_value(&value, scope.network, scope.incarnation).unwrap();
    let V::Array(fields) = &mut value else {
        unreachable!()
    };
    fields[3] = a(vec![version_value(&refs[0]), version_value(&refs[0])]);
    assert!(discovery::pair_from_value(&value, scope.network, scope.incarnation).is_err());
}

#[test]
fn policy_discovery_prepares_transport_before_sampling_challenge_clock() {
    let mut f = Fixture::new();
    let socket = f.directory.0.join("Unavailable.sock");
    let prefix = f.store.prefix().clone();
    let mut sampled = false;
    let error = discover(
        &f.bootstrap,
        &socket,
        &f.signer,
        &mut f.store,
        &mut f.session,
        || {
            sampled = true;
            Ok(f.issued)
        },
    )
    .unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
    assert!(
        !sampled,
        "transport preparation consumed challenge freshness"
    );
    assert!(f.store.resume_ordinary().unwrap().is_none());
    assert_eq!(f.store.prefix(), &prefix);
}

#[test]
fn fresh_discovery_does_not_replace_or_resolve_pending_domain_intent() {
    let mut f = Fixture::new();
    let descriptor = f.store.descriptor().clone();
    let original = prepare_ordinary(
        &descriptor,
        &f.signer,
        &mut f.store,
        "AuthorityDomain",
        [9; 32],
        0,
        &[],
        &wire::encode(&a(vec![])).unwrap(),
    )
    .unwrap();
    let prefix = f.store.prefix().clone();
    discover(
        &f.bootstrap,
        &f.directory.0.join("Absent.sock"),
        &f.signer,
        &mut f.store,
        &mut f.session,
        || panic!("pending recovery must not issue a fresh challenge"),
    )
    .unwrap();
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        original
    );
    assert_eq!(f.store.prefix(), &prefix);
}
