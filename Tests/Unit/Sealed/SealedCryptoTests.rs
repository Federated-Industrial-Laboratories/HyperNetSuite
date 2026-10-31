// SPDX-License-Identifier: MIT
// Sealed encryption authenticates exact inspected content, recipient sets and the complete age stream.
use super::*;
use ed25519_dalek::SigningKey;

fn approval(content: &Container) -> V {
    let (page, assets) = content.content_digests();
    V::Array(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("SealedApprovalTest".into()),
        bytes(&page),
        V::Array(
            assets
                .iter()
                .zip(&content.assets)
                .map(|((id, digest), asset)| {
                    V::Array(vec![
                        bytes(id),
                        bytes(digest),
                        bytes(&ciphertext_digest(&asset.metadata)),
                    ])
                })
                .collect(),
        ),
    ])
}
fn fixture() -> (Container, SigningKey) {
    let signer = SigningKey::from_bytes(&[17; 32]);
    let mut content = Container {
        context: Context {
            network: [1; 32],
            incarnation: [2; 32],
            publication: [3; 32],
            object: [4; 32],
            revision: 1,
            encryption_generation: 1,
            audience: VersionRef {
                kind: 110,
                id: [5; 32],
                generation: 1,
                digest: [6; 32],
            },
            roster_digest: [7; 32],
            inner_approval_digest: [8; 32],
        },
        signed_inner: Zeroizing::new(vec![]),
        signed_author: Zeroizing::new(vec![1]),
        source: Zeroizing::new(b"private sealed page title and body".to_vec()),
        assets: vec![Asset {
            id: [10; 32],
            metadata: Zeroizing::new(b"private image caption".to_vec()),
            bytes: Zeroizing::new(vec![21; 8192]),
        }],
    };
    content.signed_inner = Zeroizing::new(
        wire::sign_envelope(&wire::encode(&approval(&content)).unwrap(), &signer).unwrap(),
    );
    content.context.inner_approval_digest = wire::digest(&content.signed_inner);
    (content, signer)
}
fn verify(content: &Container, signer: &SigningKey) -> Result<()> {
    let (payload, signatures) = wire::envelope(&content.signed_inner, 1)?;
    ensure!(
        signatures[0].0 == signer.verifying_key().to_bytes()
            && payload == wire::encode(&approval(content))?,
        "exact inspected material differs"
    );
    Ok(())
}
#[test]
fn sealed_multi_recipient_round_trip_uses_fresh_ciphertext_and_no_plaintext_metadata() {
    let (content, signer) = fixture();
    let first = age::x25519::Identity::generate();
    let second = age::x25519::Identity::generate();
    let recipients = [first.to_public(), second.to_public()];
    let a = seal(&content, &recipients, |c| verify(c, &signer)).unwrap();
    let b = seal(&content, &recipients, |c| verify(c, &signer)).unwrap();
    assert_ne!(a, b);
    assert!(
        !a.windows(content.source.len())
            .any(|w| w == content.source.as_slice())
    );
    assert!(
        !a.windows(content.assets[0].metadata.len())
            .any(|w| w == content.assets[0].metadata.as_slice())
    );
    for identity in [&first, &second] {
        let opened = open(identity, &a, ciphertext_digest(&a), &content.context, |c| {
            verify(c, &signer)
        })
        .unwrap();
        assert_eq!(opened.source.as_slice(), content.source.as_slice());
        assert_eq!(
            opened.assets[0].bytes.as_slice(),
            content.assets[0].bytes.as_slice()
        );
        assert_eq!(
            opened.assets[0].metadata.as_slice(),
            content.assets[0].metadata.as_slice()
        );
    }
    assert!(
        open(
            &age::x25519::Identity::generate(),
            &a,
            ciphertext_digest(&a),
            &content.context,
            |c| verify(c, &signer)
        )
        .is_err()
    );
}
#[test]
fn sealed_exact_approval_and_outer_context_prevent_sample_substitution() {
    let (mut content, signer) = fixture();
    let identity = age::x25519::Identity::generate();
    let cipher = seal(&content, &[identity.to_public()], |c| verify(c, &signer)).unwrap();
    content.source[0] ^= 1;
    assert!(seal(&content, &[identity.to_public()], |c| verify(c, &signer)).is_err());
    content.source[0] ^= 1;
    content.assets[0].metadata[0] ^= 1;
    assert!(seal(&content, &[identity.to_public()], |c| verify(c, &signer)).is_err());
    let mut context = content.context.clone();
    context.encryption_generation += 1;
    assert!(
        open(
            &identity,
            &cipher,
            ciphertext_digest(&cipher),
            &context,
            |c| verify(c, &signer)
        )
        .is_err()
    );
    assert!(
        open(&identity, &cipher, [90; 32], &content.context, |c| verify(
            c, &signer
        ))
        .is_err()
    );
    let other = SigningKey::from_bytes(&[18; 32]);
    assert!(
        open(
            &identity,
            &cipher,
            ciphertext_digest(&cipher),
            &content.context,
            |c| verify(c, &other)
        )
        .is_err()
    );
}
#[test]
fn sealed_stream_refuses_corruption_truncation_trailing_bytes_and_oversized_plaintext() {
    let identity = age::x25519::Identity::generate();
    let cipher = encrypt_bounded(&[identity.to_public()], &vec![3; 131072], 131072).unwrap();
    for mut altered in [cipher[..cipher.len() - 1].to_vec(), cipher.clone()] {
        if altered.len() == cipher.len() {
            altered[0] ^= 1;
        }
        assert!(decrypt_bounded(&identity, &altered, 131072).is_err());
    }
    let mut corrupted = cipher.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    assert!(decrypt_bounded(&identity, &corrupted, 131072).is_err());
    let mut appended = cipher.clone();
    appended.push(1);
    assert!(decrypt_bounded(&identity, &appended, 131072).is_err());
    assert!(decrypt_bounded(&identity, &cipher, 131071).is_err());
}
#[test]
fn sealed_recipient_bounds_and_key_possession_use_only_typed_contributory_x25519() {
    let identity = age::x25519::Identity::generate();
    let mut alias = recipient_key(&identity.to_public()).unwrap();
    alias[31] |= 0x80;
    assert!(validate_recipient_key(alias).is_err());
    let key = recipient_key(&identity.to_public()).unwrap();
    validate_recipient_key(key).unwrap();
    assert_eq!(recipient_from_key(key).unwrap(), identity.to_public());
    assert!(validate_recipient_key([0; 32]).is_err());
    let mut identity_element = [0u8; 32];
    identity_element[0] = 1;
    assert!(validate_recipient_key(identity_element).is_err());
    let encoded = bech32::encode("age", [0u8; 32].to_base32(), Variant::Bech32).unwrap();
    let invalid_typed: age::x25519::Recipient = encoded.parse().unwrap();
    assert!(encrypt_bounded(&[invalid_typed], b"private", 7).is_err());
    assert!(encrypt_bounded(&[], b"a", 1).is_err());
    assert!(encrypt_bounded(&[identity.to_public(), identity.to_public()], b"a", 1).is_err());
    assert!(encrypt_bounded(&vec![identity.to_public(); MAXIMUM_RECIPIENTS + 1], b"a", 1).is_err());
    let cipher = encrypt_challenge(&key, b"exact one-use encrypted challenge").unwrap();
    assert_eq!(
        decrypt_challenge(&identity, &cipher).unwrap().as_slice(),
        b"exact one-use encrypted challenge"
    );
    assert!(decrypt_challenge(&age::x25519::Identity::generate(), &cipher).is_err());
    let unsupported = b"age-encryption.org/v1\n-> scrypt ignored\n";
    assert!(decrypt_bounded(&identity, unsupported, 64).is_err());
}
#[test]
fn sealed_container_rejects_duplicate_assets_and_source_admission_before_encryption() {
    let (mut content, signer) = fixture();
    let identity = age::x25519::Identity::generate();
    content.assets.push(Asset {
        id: content.assets[0].id,
        metadata: Zeroizing::new(vec![1]),
        bytes: Zeroizing::new(vec![2]),
    });
    assert!(seal(&content, &[identity.to_public()], |c| verify(c, &signer)).is_err());
    content.assets.pop();
    content
        .source
        .resize(crate::authority_objects::PAGE_SOURCE_BYTES + 1, 1);
    assert!(seal(&content, &[identity.to_public()], |c| verify(c, &signer)).is_err());
}
