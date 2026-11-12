// SPDX-License-Identifier: MIT
use super::*;
use crate::authority_inspection::{read_client::tests::response, tests::Fixture};

#[test]
fn expired_discovery_requires_fresh_exact_quorum_policy_and_preserves_original_bootstrap() {
    let (bootstrap_bytes, _) = crate::authority_recovery::tests::fixture(20, 10000);
    let bootstrap = crate::trust_bootstrap::inspect(&bootstrap_bytes, true).unwrap();
    let original_digest = bootstrap.file_digest();
    let now = 4_000_000;
    assert!(crate::trust_bootstrap::check(&bootstrap_bytes, true, now).is_err());
    let mut f = Fixture::with_bootstrap(bootstrap, SigningKey::from_bytes(&[5; 32]), now);
    let scope = f.bootstrap.descriptor().scope();
    let (_, op, _, _) = crate::authority_policies::tests::fixture();
    let governance = Governance::parse(
        scope.network,
        scope.incarnation,
        f.bootstrap.governance_records(),
    )
    .unwrap();
    let root = governance
        .versions()
        .into_iter()
        .find(|v| v.kind == 102)
        .unwrap();
    let mut fields = wire::decode(&op.policy)
        .unwrap()
        .array(17)
        .unwrap()
        .to_vec();
    fields[1] = V::Uint(2);
    fields[15] = a(vec![a(vec![
        crate::authority_membership::reference(&root),
        crate::trust_validity::End::UntilWithdrawn.value(),
    ])]);
    let policy = wire::encode(&a(fields)).unwrap();
    let references = [
        policies::record_reference(&policy, scope.network, scope.incarnation, 100).unwrap(),
        policies::record_reference(&op.recovery, scope.network, scope.incarnation, 114).unwrap(),
    ];
    let value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityPolicyContext".into()),
        a(references
            .iter()
            .map(crate::authority_membership::reference)
            .collect()),
        a(vec![b(&policy), b(&op.recovery)]),
    ]);
    let request = crate::authority_read::Request::sign(
        scope,
        &f.signer,
        f.signer.verifying_key().to_bytes(),
        [91; 32],
        1,
        crate::authority_read::Query::PolicyContext,
    )
    .unwrap();
    let challenge = f
        .session
        .issue_read(&request, &f.signer, [91; 32], 5000, f.current)
        .unwrap();
    let reply = response(
        &request,
        &challenge,
        &f.status_node,
        *f.store.prefix().policy_state(),
        value,
        now,
        now + 5000,
        0,
    );
    let decoded = wire::decode(&reply).unwrap();
    let reply = decoded.array(10).unwrap();
    let mut certificate = Certificate {
        schema: "HyperNetDiscoveryPolicy/1".into(),
        bootstrap: hex::encode(f.bootstrap.file_digest()),
        epochs: vec![],
        request: hex::encode(&request),
        challenge: hex::encode(&challenge),
        node: hex::encode(reply[6].bytes().unwrap()),
        certificate: hex::encode(reply[7].bytes().unwrap()),
        result: hex::encode(reply[8].bytes().unwrap()),
        ancestry: vec![hex::encode(&f.status_node)],
    };
    let bytes = serde_json::to_vec(&certificate).unwrap();
    assert_eq!(verify(&f.bootstrap, &bytes, now).unwrap(), 2);
    assert!(verify(&f.bootstrap, &bytes, now + 5000).is_err());
    assert!(verify(&f.bootstrap, &bytes, now - 2000).is_err());
    certificate.bootstrap = "00".repeat(32);
    assert!(
        verify(
            &f.bootstrap,
            &serde_json::to_vec(&certificate).unwrap(),
            now
        )
        .is_err()
    );
    certificate.bootstrap = hex::encode(f.bootstrap.file_digest());
    certificate.result = "00".into();
    assert!(
        verify(
            &f.bootstrap,
            &serde_json::to_vec(&certificate).unwrap(),
            now
        )
        .is_err()
    );
    assert_eq!(f.bootstrap.file_digest(), original_digest);
    assert_eq!(f.store.prefix().height(), 1);
    assert!(crate::trust_bootstrap::check(&bootstrap_bytes, true, now).is_err());
}
