// SPDX-License-Identifier: MIT
// Limited recovery accepts only the exact signed route issuance, not arbitrary pending work.
use super::*;
use crate::{authority_deployment_tests as fixture, authority_proof::Intent};
fn signed(command: routes::Command) -> Intent {
    let operation = domain::Operation {
        command: domain::Command::Route(command),
        grant: None,
        snapshot: domain::snapshot(&fixture::snapshot(&[])).unwrap(),
    };
    Intent::from_signed(&fixture::signed(
        &fixture::key(5),
        "AuthorityDomain",
        operation.command.resource(),
        u64::from(operation.mutation()),
        wire::decode(&operation.parameters().unwrap()).unwrap(),
        vec![],
    ))
    .unwrap()
}
#[test]
fn recovery_accepts_only_exact_signed_issue_or_handover() {
    let identifier = [17; 32];
    let issue = signed(routes::Command::Issue {
        id: identifier,
        relay: [18; 32],
        destination: [19; 32],
        possession: fixture::key(6).verifying_key().to_bytes(),
        action: 0,
        scope: (0, [20; 32]),
        connections: 64,
        bytes: 65536,
        expires: 5000,
    });
    assert_eq!(issue_expiry(&issue, identifier).unwrap(), 5000);
    assert!(issue_expiry(&issue, [21; 32]).is_err());
    let voucher = VersionRef {
        kind: 166,
        id: identifier,
        generation: 1,
        digest: [22; 32],
    };
    assert_eq!(
        issue_expiry(
            &signed(routes::Command::Handover {
                voucher: voucher.clone(),
                expires: 6000
            }),
            identifier
        )
        .unwrap(),
        6000
    );
    for command in [
        routes::Command::RenewContext { voucher },
        routes::Command::Lookup {
            service: identifier,
        },
        routes::Command::Withdraw {
            service: identifier,
            generation: 1,
        },
    ] {
        assert!(issue_expiry(&signed(command), identifier).is_err());
    }
    let mut changed = issue;
    changed.action = "AuthorityRedeemMember".into();
    assert!(issue_expiry(&changed, identifier).is_err());
}

#[test]
fn newer_certified_stream_generation_cannot_be_fenced_for_an_old_issue() {
    use crate::{
        authority_proof::{OwnStreamMetadata, initial_generation_id},
        trust_wire::Value as V,
    };
    let id = [17; 32];
    let mut intent = signed(routes::Command::Handover {
        voucher: VersionRef {
            kind: 166,
            id,
            generation: 1,
            digest: [18; 32],
        },
        expires: 5000,
    });
    intent.generation_id =
        initial_generation_id(intent.network, intent.incarnation, intent.requester).unwrap();
    let bytes = |v: &[u8; 32]| V::Bytes(v.to_vec());
    let scope = V::Array(vec![
        bytes(&intent.network),
        bytes(&intent.incarnation),
        bytes(&[21; 32]),
        V::Uint(0),
    ]);
    let metadata = |generation| {
        let fields = vec![
            V::Uint(56),
            V::Uint(1),
            scope.clone(),
            bytes(&intent.requester),
            V::Bool(true),
            V::Uint(generation),
            bytes(&if generation == 1 {
                intent.generation_id
            } else {
                [19; 32]
            }),
            V::Uint(0),
            V::Null,
            if generation == 1 {
                V::Null
            } else {
                V::Array(vec![
                    bytes(&[19; 32]),
                    bytes(&[20; 32]),
                    V::Uint(1),
                    bytes(&intent.generation_id),
                    V::Uint(0),
                    V::Null,
                ])
            },
        ];
        OwnStreamMetadata::parse(&wire::encode(&V::Array(fields)).unwrap()).unwrap()
    };
    recovery_stream(&intent, &metadata(1)).unwrap();
    assert!(recovery_stream(&intent, &metadata(2)).is_err());
    let mut other = intent.clone();
    other.requester = fixture::key(9).verifying_key().to_bytes();
    assert!(recovery_stream(&other, &metadata(1)).is_err());
}
