// SPDX-License-Identifier: MIT
// Reviewer delivery checks current recipient authority before encrypted output, independently of the audience.
use super::*;
use crate::{authority_deployment_tests as deployment, authority_governance::Governance};
use std::time::{SystemTime, UNIX_EPOCH};

const MEMBER: Digest = [92; 32];
const DEVICE: Digest = [93; 32];
const OBJECT: Digest = [94; 32];

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn record(kind: u64, fields: Vec<V>, signer: &SigningKey) -> domain::Record {
    let mut values = vec![
        V::Uint(kind),
        V::Uint(1),
        b(&[20; 32]),
        b(&[21; 32]),
        V::Uint(1),
        V::Null,
    ];
    values.extend(fields);
    identity::signed_record(
        &wire::sign_envelope(&wire::encode(&a(values)).unwrap(), signer).unwrap(),
        [20; 32],
        [21; 32],
    )
    .unwrap()
}

#[test]
fn sealed_reviewer_outside_audience_requires_current_membership_and_object_admission() {
    let directory = Directory(std::env::temp_dir().join(format!(
        "HyperNetSealedReviewer{}",
        crate::random_hex::<16>()
    )));
    files::create_directory(&directory.0).unwrap();
    let mut vault = Vault::initialise(
        &directory.0.join("Vault"),
        &directory.0.join("Identity.age"),
        [20; 32],
        [21; 32],
        [22; 32],
    )
    .unwrap();
    let at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let lifetime = a(vec![V::Uint(at - 10000), V::Uint(at + 60000)]);
    let author_key = deployment::key(5);
    let root_key = deployment::key(70);
    let decryptor = age::x25519::Identity::generate();
    let root = record(
        107,
        vec![
            b(&MEMBER),
            b(&root_key.verifying_key().to_bytes()),
            b(&[95; 32]),
            a(vec![V::Uint(0), V::Uint(0), b(&[96; 32])]),
        ],
        &root_key,
    );
    vault
        .accept_contact(&root.bytes, root.reference.digest, [97; 32])
        .unwrap();
    let binding = record(
        108,
        vec![
            b(&MEMBER),
            reference(&root.reference),
            b(&DEVICE),
            b(&deployment::key(71).verifying_key().to_bytes()),
            b(&crypto::recipient_key(&decryptor.to_public()).unwrap()),
            a(vec![V::Uint(0)]),
            lifetime.clone(),
        ],
        &root_key,
    );
    let admission = |scope: (u64, Digest)| {
        record(
            109,
            vec![
                b(&MEMBER),
                reference(&binding.reference),
                a(vec![a(vec![V::Uint(scope.0), b(&scope.1)])]),
                lifetime.clone(),
                b(&[98; 32]),
                deployment::snapshot(&[]),
            ],
            &author_key,
        )
    };
    let mut state = domain::State::empty([20; 32], [21; 32]);
    state.put(root.clone()).unwrap();
    state.put(binding.clone()).unwrap();
    let admitted = admission((2, OBJECT));
    state.put(admitted.clone()).unwrap();
    let mut other_root = root.reference.clone();
    other_root.id = [99; 32];
    other_root.digest = [100; 32];
    let audience = record(
        110,
        vec![
            b(&[101; 32]),
            b(&author_key.verifying_key().to_bytes()),
            a(vec![reference(&other_root)]),
            a(vec![]),
            V::Null,
            V::Bool(false),
            deployment::snapshot(&[]),
        ],
        &author_key,
    );
    let audience_value =
        identity::Audience::parse(&identity::payload(&audience).unwrap(), [20; 32], [21; 32])
            .unwrap();
    assert!(!audience_value.allowed_roots.contains(&root.reference));
    state.put(audience.clone()).unwrap();
    let source = b"HyperNetPage/2\n# Private review\n: Only the reviewer sees this draft.\n".to_vec();
    let intent = publication::Author {
        object: OBJECT,
        policy: VersionRef {
            kind: 104,
            id: OBJECT,
            generation: 1,
            digest: [102; 32],
        },
        grant: VersionRef {
            kind: 102,
            id: [23; 32],
            generation: 1,
            digest: [103; 32],
        },
        revision: 1,
        audience: audience.reference,
        publisher: author_key.verifying_key().to_bytes(),
        source: crypto::ciphertext_digest(&source),
        assets: vec![],
        expires_ms: at + 30000,
    };
    let submission = data::Submission::new(
        [20; 32],
        [21; 32],
        binding.reference.clone(),
        wire::sign_envelope(&intent.payload([20; 32], [21; 32]).unwrap(), &author_key).unwrap(),
        source.clone(),
        vec![],
    )
    .unwrap();
    let mut f = deployment::Fixture::with_actions(vec![0, 4]);
    let governance = Governance::parse([20; 32], [21; 32], &f.records).unwrap();
    let grant = wire::decode(governance.record_bytes(102, [23; 32]).unwrap()).unwrap();
    let mut grant = grant.array(17).unwrap().to_vec();
    let parent = governance
        .versions()
        .into_iter()
        .find(|r| r.kind == 102 && r.id == [23; 32])
        .unwrap();
    grant[6] = b(&[105; 32]);
    grant[8] = b(&deployment::key(75).verifying_key().to_bytes());
    grant[10] = a(vec![V::Uint(4)]);
    grant[11] = a(vec![a(vec![V::Uint(4), b(&MEMBER)])]);
    grant[12] = lifetime.clone();
    grant[13] = reference(&parent);
    grant[14] = V::Uint(0);
    grant[16] = deployment::snapshot(&[]);
    f.records.push(wire::encode(&a(grant)).unwrap());
    crate::authority_membership::sort_records(&mut f.records).unwrap();
    let reader = Governance::parse([20; 32], [21; 32], &f.records)
        .unwrap()
        .versions()
        .into_iter()
        .find(|r| r.kind == 102 && r.id == [105; 32])
        .unwrap();
    let records = |revoked: bool, expires: u64| {
        let mut records = f.records.clone();
        records.push(
            wire::encode(&a(vec![
                V::Uint(125),
                V::Uint(1),
                b(&[20; 32]),
                b(&[21; 32]),
                V::Uint(1),
                V::Null,
                b(&MEMBER),
                b(&deployment::key(75).verifying_key().to_bytes()),
                a(vec![V::Uint(at - 10000), V::Uint(expires)]),
                V::Bool(revoked),
                reference(&reader),
                deployment::snapshot(&[]),
            ]))
            .unwrap(),
        );
        crate::authority_membership::sort_records(&mut records).unwrap();
        records
    };
    let active = Governance::parse([20; 32], [21; 32], &records(false, at + 60000)).unwrap();
    let mut deliver =
        |state: &domain::State, governance: &Governance, output: &Path| -> Result<()> {
            let recipient = reviewer(&mut vault, state, governance, OBJECT, at, &binding.bytes)?;
            let ciphertext = submission.encrypt(recipient.encryption_key)?;
            files::write_new(output, &ciphertext)
        };
    // Pins and valid recipient records cannot override current member withdrawal or expiry.
    for (revoked, expires) in [(true, at + 60000), (false, at - 1)] {
        let governance = Governance::parse([20; 32], [21; 32], &records(revoked, expires)).unwrap();
        let output = directory.0.join("Refused.age");
        let error = deliver(&state, &governance, &output).unwrap_err();
        assert!(error.to_string().contains("recipient member is not active"));
        assert!(!output.exists());
        for record in [&root, &binding, &admitted] {
            assert_eq!(
                state
                    .record(record.reference.kind, record.reference.id)
                    .unwrap()
                    .reference,
                record.reference
            );
        }
    }
    let wrong_scope = admission((2, [104; 32]));
    state
        .records
        .insert(wrong_scope.reference.index(), wrong_scope);
    let output = directory.0.join("WrongObject.age");
    let error = deliver(&state, &active, &output).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("reviewer device admission is not current for this object")
    );
    assert!(!output.exists());
    // Either the exact object or network scope permits delivery without audience inclusion.
    for (name, scope) in [("Object.age", (2, OBJECT)), ("Network.age", (0, [20; 32]))] {
        let admitted = admission(scope);
        state.records.insert(admitted.reference.index(), admitted);
        let output = directory.0.join(name);
        deliver(&state, &active, &output).unwrap();
        let ciphertext = std::fs::read(output).unwrap();
        assert!(!ciphertext.windows(source.len()).any(|part| part == source));
        let opened = data::Submission::open(
            &decryptor,
            &ciphertext,
            &binding.reference,
            [20; 32],
            [21; 32],
        )
        .unwrap();
        assert_eq!(opened.source.as_slice(), source);
    }
}
