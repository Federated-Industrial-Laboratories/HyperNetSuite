// SPDX-License-Identifier: MIT
// Native effects and foreign-floor mutations keep their distinct signed markers across exact retries.
use super::*;
use crate::authority_inspection::tests::Fixture;

fn version(kind: u64, seed: u8) -> VersionRef {
    VersionRef {
        kind,
        id: [seed; 32],
        generation: 1,
        digest: [seed + 1; 32],
    }
}

// This encoding fixture exercises request parsing; execution must still verify its foreign quorum proof.
fn foreign_admission() -> domain::federation::ForeignProof {
    let operation = domain::Operation {
        grant: None,
        command: domain::federation::Command::Admission {
            agreement: version(151, 61),
            bridge: version(152, 63),
            page: Some([65; 16]),
            exchange: [66; 32],
            revision: None,
            after: None,
        }
        .into(),
        snapshot: domain::snapshot(&crate::authority_deployment_tests::snapshot(&[])).unwrap(),
    };
    let signed = crate::authority_deployment_tests::signed(
        &SigningKey::from_bytes(&[5; 32]),
        "AuthorityDomain",
        operation.command.resource(),
        0,
        wire::decode(&operation.parameters().unwrap()).unwrap(),
        vec![],
    );
    let ordered = wire::encode(&a(vec![
        V::Uint(22),
        V::Uint(1),
        V::Null,
        b(&signed),
        V::Null,
        V::Uint(10000),
    ]))
    .unwrap();
    let bytes = wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("FederationProof".into()),
        version_value(&version(150, 67)),
        version_value(&version(157, 67)),
        b(&[]),
        b(&ordered),
        b(&[]),
        b(&[]),
        a(vec![b(&[68; 32])]),
        V::Null,
        V::Null,
        a(vec![]),
    ]))
    .unwrap();
    domain::federation::ForeignProof::parse(&bytes).unwrap()
}

#[test]
fn media_request_preparation_preserves_native_and_foreign_mutation_markers_on_retry() {
    for foreign in [false, true] {
        let mut f = Fixture::with_actions(vec![0, 3]);
        let grant = Governance::record_versions(
            f.store.descriptor().scope().network,
            f.store.descriptor().scope().incarnation,
            f.bootstrap.governance_records(),
        )
        .unwrap()
        .into_iter()
        .find(|r| r.kind == 102)
        .unwrap();
        let command: domain::Command = if foreign {
            domain::federation::Command::MediaAuthorise {
                asset: version(144, 71),
                host: version(143, 73),
                effect: page::MediaEffect::Inspect,
                offset: 0,
                bytes: 16,
                digest: None,
                proof: foreign_admission(),
            }
            .into()
        } else {
            Command::MediaAuthorise {
                asset: version(144, 71),
                host: version(143, 73),
                effect: page::MediaEffect::Inspect,
                offset: 0,
                bytes: 16,
                digest: None,
            }
            .into()
        };
        let mut operation = domain::Operation {
            command: command.clone(),
            grant: Some(grant.clone()),
            snapshot: domain::snapshot(&a(vec![
                a(vec![
                    V::Uint(f.store.prefix().scope().epoch),
                    V::Uint(f.store.prefix().height()),
                    b(f.store.prefix().policy_state()),
                ]),
                a(vec![]),
            ]))
            .unwrap(),
        };
        let mut probe = request_probe(&f.store, &operation).unwrap();
        assert_eq!(probe.revision, u64::from(foreign));
        assert_eq!(
            domain::Operation::parse(&probe).unwrap().mutation(),
            foreign
        );
        if foreign {
            probe.expected = vec![version(157, 67)];
            operation.snapshot = domain::snapshot(&a(vec![
                a(vec![
                    V::Uint(f.store.prefix().scope().epoch),
                    V::Uint(f.store.prefix().height()),
                    b(f.store.prefix().policy_state()),
                ]),
                a(probe.expected.iter().map(version_value).collect()),
            ]))
            .unwrap();
            probe.parameters = operation.parameters().unwrap();
        }
        let mut invalid = probe.clone();
        invalid.revision = u64::from(!foreign);
        assert!(retain_request(&mut f.store, &f.signer, &invalid).is_err());
        assert!(f.store.resume_ordinary().unwrap().is_none());
        let request = retain_request(&mut f.store, &f.signer, &probe).unwrap();
        assert_eq!(request.intent().revision, u64::from(foreign));
        assert_eq!(request.intent().expected, probe.expected);
        assert_eq!(request.domain_command().value(), command.value());
        let signed = request.signed().to_vec();
        drop(f.store);
        f.store = Store::open(&f.directory.0, f.bootstrap.descriptor().clone()).unwrap();
        let retried = prepare_domain(
            &f.bootstrap,
            &f.signer,
            &mut f.store,
            command.clone(),
            Some(grant.clone()),
            f.current,
        )
        .unwrap();
        assert_eq!(retried.signed(), signed);
        assert_eq!(pending(&f.store).unwrap().unwrap().signed(), signed);
        let mut changed = command.clone();
        match &mut changed {
            domain::Command::Page(Command::MediaAuthorise { offset, .. })
            | domain::Command::Federation(domain::federation::Command::MediaAuthorise {
                offset,
                ..
            }) => *offset = 1,
            _ => unreachable!(),
        }
        assert!(
            prepare_domain(
                &f.bootstrap,
                &f.signer,
                &mut f.store,
                changed,
                Some(grant),
                f.current
            )
            .is_err()
        );
        assert!(
            prepare_domain(
                &f.bootstrap,
                &f.signer,
                &mut f.store,
                command,
                None,
                f.current
            )
            .is_err()
        );
        assert_eq!(pending(&f.store).unwrap().unwrap().signed(), signed);
    }
}
