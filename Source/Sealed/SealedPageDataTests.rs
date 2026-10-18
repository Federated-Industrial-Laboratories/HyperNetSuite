// SPDX-License-Identifier: MIT
// Private review and publication reject endpoint, author, media and approval substitution before display.
use super::*;
use crate::authority_domains::{self as domains, sealed_publication::Placement};
fn r(kind: u64, id: u8) -> VersionRef {
    VersionRef {
        kind,
        id: [id; 32],
        generation: 1,
        digest: [id + 1; 32],
    }
}
fn fixture() -> (
    Submission,
    ObjectPolicy,
    Roster,
    SigningKey,
    age::x25519::Identity,
) {
    let author_key = SigningKey::from_bytes(&[5; 32]);
    let reviewer = SigningKey::from_bytes(&[6; 32]);
    let identity = age::x25519::Identity::generate();
    let bytes = vec![255, 0, 0];
    let source=format!("HyperNetPage/2\n# Private red square\n@Asset {{\"id\":\"Icon\",\"profile\":\"HyperNetRaster/1\",\"width\":1,\"height\":1,\"bytes\":3,\"digest\":\"{}\",\"hosts\":[\"{}\"],\"copies\":1}}\n@Image {{\"id\":\"Picture\",\"asset\":\"Icon\",\"alt\":\"Private image\",\"rows\":3}}\n",hex::encode(crypto::ciphertext_digest(&bytes)),hex::encode([21;32])).into_bytes();
    let files = BTreeMap::from([("Icon".into(), bytes)]);
    let assets = source_assets(&source, &files).unwrap();
    let snapshot = domains::snapshot(&a(vec![
        a(vec![V::Uint(0), V::Uint(0), b(&[30; 32])]),
        a(vec![]),
    ]))
    .unwrap();
    let policy = ObjectPolicy {
        reference: r(104, 10),
        object: [10; 32],
        namespace: [13; 32],
        publisher: author_key.verifying_key().to_bytes(),
        audience: r(110, 11),
        modes: vec![1],
        public_audience: false,
        placement: Placement {
            hosts: vec![[21; 32]],
            volumes: vec![[22; 32]],
            backups: vec![],
            copies: 1,
        },
        minimum_state: (0, 0, [30; 32]),
        disclosure: None,
        snapshot: snapshot.clone(),
    };
    let author = Author {
        object: policy.object,
        policy: policy.reference.clone(),
        grant: r(102, 12),
        revision: 1,
        audience: policy.audience.clone(),
        publisher: policy.publisher,
        source: crypto::ciphertext_digest(&source),
        assets: assets
            .iter()
            .map(|a| (a.id, crypto::ciphertext_digest(&a.bytes)))
            .collect(),
        expires_ms: 20000,
    };
    let statement =
        wire::sign_envelope(&author.payload([1; 32], [2; 32]).unwrap(), &author_key).unwrap();
    let submission =
        Submission::new([1; 32], [2; 32], r(108, 14), statement, source, assets).unwrap();
    let roster = Roster {
        reference: r(111, 15),
        publication: [15; 32],
        revision: 1,
        encryption_generation: 1,
        audience: policy.audience.clone(),
        roots: vec![[17; 32]],
        devices: vec![([17; 32], [18; 32], [19; 32])],
        snapshot,
    };
    (submission, policy, roster, reviewer, identity)
}
#[test]
fn sealed_submission_stays_encrypted_and_binds_reviewer_device_and_exact_author_media() {
    let (submission, policy, _, _, identity) = fixture();
    let cipher = submission
        .encrypt(crypto::recipient_key(&identity.to_public()).unwrap())
        .unwrap();
    assert!(
        !cipher
            .windows(submission.source.len())
            .any(|b| b == submission.source.as_slice())
    );
    let mut opened =
        Submission::open(&identity, &cipher, &submission.reviewer, [1; 32], [2; 32]).unwrap();
    opened.validate(&policy, 5000).unwrap();
    assert!(Submission::open(&identity, &cipher, &r(108, 31), [1; 32], [2; 32]).is_err());
    opened.assets[0].bytes[0] ^= 1;
    assert!(opened.validate(&policy, 5000).is_err());
    opened.assets[0].bytes[0] ^= 1;
    opened.assets[0].metadata[0] ^= 1;
    assert!(opened.validate(&policy, 5000).is_err());
}
#[test]
fn sealed_reader_verifies_author_and_reviewer_before_rendering_source_or_assets() {
    let (submission, policy, roster, reviewer, identity) = fixture();
    let signed_inner = inner(&submission, &roster, &roster.snapshot, &reviewer).unwrap();
    let mut content = submission.into_container(signed_inner).unwrap();
    let cipher = crypto::seal(&content, &[identity.to_public()], |c| {
        verify_approval(c, &policy, 5000).map(|_| ())
    })
    .unwrap();
    let fields = a(vec![
        V::Uint(113),
        V::Uint(1),
        b(&[1; 32]),
        b(&[2; 32]),
        V::Uint(1),
        V::Null,
        b(&roster.publication),
        b(&policy.object),
        V::Uint(1),
        V::Uint(1),
        reference(&roster.audience),
        b(&roster.reference.digest),
        b(&crypto::ciphertext_digest(&cipher)),
        V::Uint(cipher.len() as u64),
        policy.placement.value(),
        a(vec![b(&[33; 32])]),
        a(vec![V::Uint(0), V::Uint(0), b(&[30; 32])]),
        b(&content.context.inner_approval_digest),
        roster.snapshot.value.clone(),
    ]);
    let outer = Outer::parse(
        &wire::sign_envelope(&wire::encode(&fields).unwrap(), &reviewer).unwrap(),
        [1; 32],
        [2; 32],
    )
    .unwrap();
    let opened = crypto::open(
        &identity,
        &cipher,
        outer.ciphertext,
        &context(&outer, [1; 32], [2; 32]),
        |c| verify_container(c, &outer, &policy, 5000).map(|_| ()),
    )
    .unwrap();
    assert_eq!(
        verify_container(&opened, &outer, &policy, 5000)
            .unwrap()
            .assets
            .len(),
        1
    );
    content.source[17] ^= 1;
    assert!(verify_container(&content, &outer, &policy, 5000).is_err());
    content.source[17] ^= 1;
    let mut substituted = policy.clone();
    substituted.publisher = reviewer.verifying_key().to_bytes();
    assert!(verify_container(&content, &outer, &substituted, 5000).is_err());
    assert!(verify_container(&content, &outer, &policy, 20000).is_err());
    content.signed_author[10] ^= 1;
    assert!(verify_container(&content, &outer, &policy, 5000).is_err());
}
