// SPDX-License-Identifier: MIT
// Renewal preparation authenticates ownership after expiry and preserves exact pending operations.
use super::*;
use crate::authority_deployment_tests as deployment;
use clap::Parser;

fn registration() -> streams::Registration {
    let owner = deployment::key(5);
    let mut registration = streams::Registration {
        id: [71; 32],
        route: VersionRef {
            kind: 165,
            id: [72; 32],
            generation: 1,
            digest: [73; 32],
        },
        owner: owner.verifying_key().to_bytes(),
        operator: owner.verifying_key().to_bytes(),
        protocol: "example/1".into(),
        binding: [74; 32],
        limits: crate::route_profile::Limits {
            bytes: 65536,
            duration_ms: 30000,
            idle_ms: 5000,
        },
        validity: (1000, 4000).into(),
        envelope: vec![],
    };
    registration.envelope =
        wire::sign_envelope(&registration.payload([20; 32], [21; 32]).unwrap(), &owner).unwrap();
    registration
}
fn operation(request: &Request) -> domain::Operation {
    domain::Operation {
        grant: request.grant.clone(),
        command: request.command.clone(),
        snapshot: crate::authority_membership::Snapshot::parse(&deployment::snapshot(&[])).unwrap(),
    }
}
fn signed(request: &Request, signer: u8) -> Vec<u8> {
    let operation = operation(request);
    deployment::signed(
        &deployment::key(signer),
        "AuthorityDomain",
        request.command.resource(),
        u64::from(request.command.mutation()),
        wire::decode(&operation.parameters().unwrap()).unwrap(),
        vec![],
    )
}
fn evaluate(
    fixture: &deployment::Fixture,
    state: &domain::State,
    request: &Request,
    signer: u8,
) -> domain::Decision {
    operation(request)
        .prepare(
            state,
            &fixture.records,
            &fixture.reservations,
            &Intent::from_signed(&signed(request, signer)).unwrap(),
            5000,
            false,
            false,
        )
        .unwrap()
}

#[test]
fn renewal_preparation_reads_expired_owned_service_without_reusing_its_capability() {
    let mut fixture = deployment::Fixture::with_actions(vec![0, 11, 13, 29, 30]);
    let root = crate::authority_governance::Governance::parse([20; 32], [21; 32], &fixture.records)
        .unwrap()
        .versions()
        .into_iter()
        .find(|r| r.kind == 102 && r.id == [23; 32])
        .unwrap();
    let registration = registration();
    let old = deployment::scoped_grant(
        &mut fixture.records,
        &root,
        [75; 32],
        &[(3, registration.id)],
    );
    let record = fixture
        .records
        .iter_mut()
        .find(|bytes| {
            crate::authority_governance::Governance::record_versions(
                [20; 32],
                [21; 32],
                std::slice::from_ref(*bytes),
            )
            .is_ok_and(|refs| refs == [old.clone()])
        })
        .unwrap();
    let value = wire::decode(record).unwrap();
    let mut fields = value.array(17).unwrap().to_vec();
    fields[12] = V::Array(vec![V::Uint(1000), V::Uint(4000)]);
    *record = wire::encode(&V::Array(fields)).unwrap();
    let old = crate::authority_governance::Governance::parse([20; 32], [21; 32], &fixture.records)
        .unwrap()
        .versions()
        .into_iter()
        .find(|r| r.index() == old.index())
        .unwrap();
    let current = deployment::scoped_grant(
        &mut fixture.records,
        &root,
        [76; 32],
        &[(3, registration.id)],
    );
    let empty = domain::State::empty([20; 32], [21; 32]);
    let mut state = empty.clone();
    let existing = domain::Record::next(
        &state,
        172,
        registration.id,
        streams::Service {
            registration: registration.clone(),
            grant: old,
            withdrawn: false,
        }
        .value(),
    )
    .unwrap();
    state.put(existing.clone()).unwrap();

    let initial = registration_requests(current.clone(), registration.clone(), false);
    assert_eq!(evaluate(&fixture, &empty, &initial[0], 5).code, 0);
    assert_eq!(evaluate(&fixture, &state, &initial[0], 5).code, 3);

    let renewal = registration_requests(current.clone(), registration.clone(), true);
    let selected = evaluate(&fixture, &state, &renewal[0], 5);
    assert_eq!(selected.code, 0);
    assert_eq!(selected.versions, vec![existing.reference]);
    let capability = evaluate(&fixture, &state, &renewal[1], 5);
    assert_eq!(capability.code, 0);
    assert!(capability.versions.contains(&current));
    assert_eq!(evaluate(&fixture, &empty, &renewal[0], 5).code, 3);
    assert_eq!(evaluate(&fixture, &state, &renewal[0], 8).code, 3);
    // Metadata recovery alone cannot authorise an expired registration or absent route.
    assert_eq!(
        evaluate(&fixture, &state, renewal.last().unwrap(), 5).code,
        3
    );
}

#[test]
fn registration_resumes_only_its_exact_selected_preparation_or_mutation() {
    let fixture = deployment::Fixture::new();
    let registration = registration();
    for renew in [false, true] {
        let requests = registration_requests(fixture.grant.clone(), registration.clone(), renew);
        assert_eq!(registration_start(&requests, None).unwrap(), 0);
        for (index, request) in requests.iter().enumerate() {
            let pending = signed(request, 5);
            assert_eq!(
                registration_start(&requests, Some(&pending)).unwrap(),
                index
            );
        }
        let mut other = registration_requests(fixture.grant.clone(), registration.clone(), renew);
        other.last_mut().unwrap().grant.as_mut().unwrap().digest = [90; 32];
        assert!(registration_start(&requests, Some(&signed(other.last().unwrap(), 5))).is_err());
        let unrelated = Request {
            grant: None,
            command: domain::Command::Stream(streams::Command::Lookup {
                service: [91; 32],
                slot: 0,
            }),
        };
        assert!(registration_start(&requests, Some(&signed(&unrelated, 5))).is_err());
    }
    let requests = registration_requests(fixture.grant.clone(), registration.clone(), true);
    let initial = registration_requests(fixture.grant, registration, false);
    assert!(registration_start(&requests, Some(&signed(&initial[0], 5))).is_err());
}

#[test]
fn registration_cli_requires_explicit_renewal_mode() {
    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        command: super::super::Command,
    }
    let mut args = vec![
        "HyperNetSuite",
        "register",
        "--bootstrap",
        "/Private/Bootstrap.cbor",
        "--bootstrap-digest",
        "0101010101010101010101010101010101010101010101010101010101010101",
        "--directory",
        "/Private/Floor",
        "--clock-witness",
        "/Private/Clock.json",
        "--key",
        "/Private/Owner.json",
        "--socket",
        "/Private/Authority.sock",
        "--grant",
        "0202020202020202020202020202020202020202020202020202020202020202",
        "--accepted",
        "/Private/ServiceAccepted.cbor",
    ];
    assert!(matches!(
        Cli::try_parse_from(&args).unwrap().command,
        super::super::Command::Register { renew: false, .. }
    ));
    args.push("--renew");
    assert!(matches!(
        Cli::try_parse_from(&args).unwrap().command,
        super::super::Command::Register { renew: true, .. }
    ));
}

#[test]
fn persistent_registration_still_issues_a_finite_signed_session() {
    let mut registration = registration();
    registration.validity.1 = crate::trust_validity::End::UntilWithdrawn;
    let now = 31_536_000_000;
    let expires = finite_session_expiry(
        registration.validity.1,
        now,
        registration.limits.duration_ms,
    )
    .unwrap();
    assert_eq!(expires, now + 30000);
    let key = deployment::key(80);
    let proof = streams::Proof {
        service: VersionRef {
            kind: 172,
            id: registration.id,
            generation: 1,
            digest: [71; 32],
        },
        principal: key.verifying_key().to_bytes(),
        grant: VersionRef {
            kind: 102,
            id: [72; 32],
            generation: 1,
            digest: [73; 32],
        },
        protocol: registration.protocol,
        slot: 0,
        generation: 1,
        nonce: [74; 32],
        challenge: [75; 32],
        exporter: [76; 32],
        limits: registration.limits,
        expires,
        envelope: vec![],
    };
    let payload = proof.payload([20; 32], [21; 32]).unwrap();
    let signed = wire::sign_envelope(&payload, &key).unwrap();
    assert_eq!(
        streams::Proof::parse(&signed, [20; 32], [21; 32])
            .unwrap()
            .expires,
        expires
    );
    let mut fields = wire::decode(&payload).unwrap().array(16).unwrap().to_vec();
    fields[15] = crate::trust_validity::End::UntilWithdrawn.value();
    let invalid = wire::sign_envelope(&wire::encode(&V::Array(fields)).unwrap(), &key).unwrap();
    assert!(streams::Proof::parse(&invalid, [20; 32], [21; 32]).is_err());
    assert!(
        finite_session_expiry(
            crate::trust_validity::End::UntilWithdrawn,
            u64::MAX - 10,
            30000
        )
        .is_err()
    );
}
