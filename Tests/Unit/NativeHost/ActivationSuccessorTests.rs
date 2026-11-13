// SPDX-License-Identifier: Apache-2.0
// Persistent succession binds a stopped approved profile to the exact retained dedicated manager request.
use super::*;
use crate::{
    authority_deployment_tests as fixture,
    authority_membership::{Snapshot, reference},
    authority_proof::Intent,
    trust_wire::{self as wire, Value as V},
};

fn request() -> (Vec<u8>, Manifest) {
    let (f, records, registration, grant) = fixture::persistent_activation_manager();
    let recipient = fixture::key(107).verifying_key().to_bytes();
    let operation = activation::Operation {
        grant,
        admission: registration.reference,
        role: 8,
        recipient,
        local_generation: 1,
        snapshot: Snapshot::parse(&fixture::snapshot(&[])).unwrap(),
    };
    let sign = |expected: Vec<crate::authority_proof::VersionRef>| {
        let parameters = V::Array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text(activation::ACTION.into()),
            reference(&operation.grant),
            reference(&operation.admission),
            V::Uint(8),
            V::Bytes(recipient.to_vec()),
            V::Uint(1),
            fixture::snapshot(&expected),
        ]);
        let signed = fixture::signed(
            &fixture::key(80),
            activation::ACTION,
            [60; 32],
            1,
            parameters,
            expected,
        );
        let (payload, _) = wire::envelope(&signed, 1).unwrap();
        let mut fields = wire::decode(&payload).unwrap().array(17).unwrap().to_vec();
        fields[12] = V::Uint(1);
        wire::sign_envelope(&wire::encode(&V::Array(fields)).unwrap(), &fixture::key(80)).unwrap()
    };
    let intent = Intent::from_signed(&sign(vec![])).unwrap();
    let decision = operation
        .prepare(&records, &f.reservations, &intent, recipient, 5000, false)
        .unwrap();
    assert_eq!(decision.code, 0);
    let request = activation::Request::new(sign(decision.versions), records.clone())
        .unwrap()
        .until_withdrawn()
        .unwrap();
    assert_eq!(
        request
            .operation()
            .authorise(
                &records,
                &f.reservations,
                request.intent(),
                recipient,
                5000,
                false
            )
            .unwrap()
            .code,
        0
    );
    (request.encode().unwrap(), registration.manifest)
}
fn successor(previous: &Manifest) -> Manifest {
    let mut next = previous.clone();
    next.generation += 1;
    next.previous_profile = Some(wire::digest(&previous.desired().unwrap()));
    next.previous_consent = Some(wire::digest(&previous.unsigned_consent(0).unwrap()));
    next.software_digest = [244; 32];
    next.validate().unwrap();
    next
}
fn plan(request: &[u8], manifest: &Manifest) -> Result<Plan> {
    Plan::new(
        "ManagerSsh",
        &hex::encode([60; 32]),
        &hex::encode([179; 32]),
        8,
        Attempt {
            generation: 1,
            attempt: 0,
        },
        request,
        &hex::encode(fixture::key(80).verifying_key().to_bytes()),
        manifest,
    )
}
fn status(manifest: &Manifest) -> Value {
    json!({"running":false,"cleanupComplete":true,"status":"Consented",
        "localGeneration":manifest.generation,"manifest":manifest})
}
fn context(manifest: &Manifest) -> Value {
    json!({"registeredProfile":{"withdrawn":false,"manifest":manifest,
        "profileDigest":hex::encode(wire::digest(&manifest.desired().unwrap())),
        "consentDigest":hex::encode(wire::digest(&manifest.unsigned_consent(0).unwrap()))}})
}
#[test]
fn activation_successor_requires_stopped_exact_certified_profile_and_retained_manager() {
    let (request, old) = request();
    let next = successor(&old);
    let selected = plan(&request, &next).unwrap();
    assert_eq!(selected.stream_generation, 1);
    assert_eq!(selected.generation, 2);
    assert_eq!(
        selected.intent,
        hex::encode(
            activation::Request::parse(&request)
                .unwrap()
                .intent()
                .digest
        )
    );
    assert_eq!(stopped(&status(&next), 2).unwrap(), next);
    certified(&context(&next), &next).unwrap();
    assert!(plan(&request, &old).is_err());
    // Several certified non-serving successors can precede the next activation after a long interruption.
    plan(&request, &successor(&next)).unwrap();
    let mut changed = next.clone();
    changed.roles[0].memory_bytes += 4096;
    assert!(plan(&request, &changed).is_err());
    for (field, value) in [
        ("running", json!(true)),
        ("cleanupComplete", json!(false)),
        ("status", json!("Withdrawn")),
        ("localGeneration", json!(1)),
    ] {
        let mut changed = status(&next);
        changed[field] = value;
        assert!(stopped(&changed, 2).is_err());
    }
    assert!(certified(&context(&old), &next).is_err());
    for (field, value) in [
        ("withdrawn", json!(true)),
        ("profileDigest", json!("00".repeat(32))),
        ("consentDigest", json!("00".repeat(32))),
    ] {
        let mut changed = context(&next);
        changed["registeredProfile"][field] = value;
        assert!(certified(&changed, &next).is_err());
    }
    for (grant, role, generation, attempt, requester) in [
        ([178; 32], 8, 1, 0, 80),
        ([179; 32], 7, 1, 0, 80),
        ([179; 32], 8, 2, 0, 80),
        ([179; 32], 8, 1, 1, 80),
        ([179; 32], 8, 1, 0, 81),
    ] {
        assert!(
            Plan::new(
                "ManagerSsh",
                &hex::encode([60; 32]),
                &hex::encode(grant),
                role,
                Attempt {
                    generation,
                    attempt
                },
                &request,
                &hex::encode(fixture::key(requester).verifying_key().to_bytes()),
                &next
            )
            .is_err()
        );
    }
}
#[test]
fn activation_successor_plan_is_immutable_until_its_exact_successor_was_launched() {
    let (request, old) = request();
    let plan = plan(&request, &successor(&old)).unwrap();
    plan.retain(None).unwrap();
    let retained = serde_json::to_value(&plan).unwrap();
    plan.retain(Some(retained.clone())).unwrap();
    for field in [
        "manager",
        "deployment",
        "grant",
        "requestSha256",
        "intent",
        "streamGenerationId",
        "profileDigest",
        "consentDigest",
    ] {
        let mut changed = retained.clone();
        changed[field] = json!("changed");
        assert!(plan.retain(Some(changed)).is_err());
    }
    let mut later = plan.clone();
    later.prior.generation = 2;
    later.generation = 3;
    later.stream_generation = 2;
    later.retain(Some(retained.clone())).unwrap();
    // Changing the target while the original successor remains unlaunched cannot replace its retained plan.
    later.prior.generation = 1;
    assert!(later.retain(Some(retained)).is_err());
    assert!(
        plan.retain(Some(serde_json::to_value(later).unwrap()))
            .is_err()
    );
}
