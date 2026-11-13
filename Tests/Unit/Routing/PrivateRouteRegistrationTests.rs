// SPDX-License-Identifier: MIT
// Exact route predictions change with their predecessor and cannot revive withdrawn or foreign service ownership.
use super::*;
#[test]
fn prediction_binds_predecessor_manager_and_withdrawal() {
    let (before, after) = routes::tests::certificate_profiles();
    let mut state = domain::State::empty(before.manifest.network, before.manifest.incarnation);
    let manager = crate::authority_deployment_tests::key(5)
        .verifying_key()
        .to_bytes();
    let grant = VersionRef {
        kind: 102,
        id: [24; 32],
        generation: 1,
        digest: [91; 32],
    };
    let initial = next(&state, before, manager, grant.clone()).unwrap();
    state.put(initial.clone()).unwrap();
    let predicted = next(&state, after.clone(), manager, grant.clone()).unwrap();
    assert_eq!(predicted.reference.generation, 2);
    assert_eq!(predicted.predecessor, Some(initial.reference.digest));
    assert_eq!(
        domain::Record::parse(&predicted.bytes, state.network, state.incarnation)
            .unwrap()
            .reference,
        predicted.reference
    );
    assert!(
        next(
            &state,
            after.clone(),
            crate::authority_deployment_tests::key(6)
                .verifying_key()
                .to_bytes(),
            grant.clone()
        )
        .is_err()
    );
    let mut withdrawn =
        routes::Service::parse(&initial.payload, state.network, state.incarnation).unwrap();
    withdrawn.withdrawn = true;
    state
        .put(domain::Record::next(&state, 165, initial.reference.id, withdrawn.value()).unwrap())
        .unwrap();
    assert!(next(&state, after, manager, grant).is_err());
}
#[test]
fn expired_registration_subject_binds_signed_profile_and_rejects_other_actions() {
    let fixture = crate::authority_deployment_tests::Fixture::new();
    let manifest = crate::authority_deployment_tests::manifest();
    let offer = crate::authority_deployment_tests::offer(manifest.clone());
    let (_, mut intent, _) = fixture.register(&offer);
    let (deployment, profile, deadline) = subject(&intent, None, None).unwrap();
    assert_eq!(deployment, manifest.deployment);
    assert_eq!(profile, wire::digest(&manifest.desired().unwrap()));
    assert_eq!(deadline, 20_000);
    intent.action = "AuthorityDeploymentWithdraw".into();
    assert!(subject(&intent, None, None).is_err());
}

#[test]
fn endpoint_free_pagestore_recovers_only_expired_signed_possession() {
    use crate::authority_deployment_tests::{self as fixture, Fixture};
    use crate::authority_deployments::{Offer, Operation};
    let f = Fixture::persistent();
    let mut manifest = fixture::manifest();
    manifest.roles.retain(|r| r.role == 1);
    manifest.roles[0].bind_endpoint_ids.clear();
    manifest.roles[0].outbound_endpoint_ids.clear();
    manifest.endpoints.clear();
    manifest.authority_config = None;
    manifest
        .volumes
        .retain(|v| manifest.roles[0].volume_ids.contains(&v.volume_id));
    manifest.placement.volumes = manifest.volumes.iter().map(|v| v.volume_id).collect();
    manifest.validity =
        crate::trust_validity::Validity(1000, crate::trust_validity::End::UntilWithdrawn);
    manifest.validate().unwrap();
    let consent =
        wire::sign_envelope(&manifest.unsigned_consent(0).unwrap(), &fixture::key(90)).unwrap();
    let create = |start, end| {
        let proofs = [(0, 100), (2, 91)].map(|(class, seed)| {
            wire::Value::Bytes(
                wire::sign_envelope(
                    &Offer::possession(
                        &manifest,
                        class,
                        fixture::key(seed).verifying_key().to_bytes(),
                        [seed; 32],
                        (start, end),
                    )
                    .unwrap(),
                    &fixture::key(seed),
                )
                .unwrap(),
            )
        });
        Offer::parse(
            &manifest.encode().unwrap(),
            &consent,
            &wire::Value::Array(proofs.to_vec()),
        )
        .unwrap()
    };
    let old = create(1000, 20000);
    let fresh = create(18000, 29000);
    let (_, intent, operation) = f.register(&old);
    assert_eq!(subject(&intent, None, None).unwrap().2, 20000);
    assert_eq!(
        operation
            .authorise(&f.records, &f.reservations, &intent, 20000, false, None)
            .unwrap()
            .code,
        7
    );
    assert_eq!(fresh.manifest_bytes, old.manifest_bytes);
    assert_eq!(fresh.consent, old.consent);
    let signed = fixture::signed(
        &fixture::key(5),
        "AuthorityDeploymentRegister",
        manifest.deployment,
        1,
        f.parameters(&fresh, &intent.expected),
        intent.expected.clone(),
    );
    let renewed = crate::authority_proof::Intent::from_signed(&signed).unwrap();
    assert_eq!(subject(&renewed, None, None).unwrap().2, 29000);
    assert_eq!(
        Operation::parse(&renewed)
            .unwrap()
            .authorise(&f.records, &f.reservations, &renewed, 20000, false, None)
            .unwrap()
            .code,
        0
    );
}
