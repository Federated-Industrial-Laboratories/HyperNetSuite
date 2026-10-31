// SPDX-License-Identifier: MIT
// Persisted issuer state rejects expiry, endpoint substitution and changed consumption evidence.
use super::*;
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "HyperNetRecipientChallenge{}",
            crate::random_hex::<16>()
        )))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn envelope(kind: u64, generation: u64, body: Vec<V>, key: &SigningKey) -> Vec<u8> {
    let mut fields = vec![
        V::Uint(kind),
        V::Uint(1),
        b(&[1; 32]),
        b(&[2; 32]),
        V::Uint(generation),
        V::Null,
    ];
    fields.extend(body);
    wire::sign_envelope(&wire::encode(&a(fields)).unwrap(), key).unwrap()
}
fn fixture() -> (Data, Vec<u8>, age::x25519::Identity) {
    let root = SigningKey::from_bytes(&[3; 32]);
    let device = SigningKey::from_bytes(&[4; 32]);
    let endpoint = SigningKey::from_bytes(&[5; 32]);
    let encryption = age::x25519::Identity::generate();
    let at = now().unwrap();
    let root_ref = VersionRef {
        kind: 107,
        id: [6; 32],
        generation: 1,
        digest: [7; 32],
    };
    let binding = envelope(
        108,
        1,
        vec![
            b(&[6; 32]),
            reference(&root_ref),
            b(&[8; 32]),
            b(&device.verifying_key().to_bytes()),
            b(&crypto::recipient_key(&encryption.to_public()).unwrap()),
            a(vec![V::Uint(0)]),
            a(vec![V::Uint(at), V::Uint(at + 60_000)]),
        ],
        &root,
    );
    let bound = identity::signed_record(&binding, [1; 32], [2; 32]).unwrap();
    let challenge = envelope(
        123,
        0,
        vec![
            b(&[9; 32]),
            b(&bound.reference.digest),
            b(&endpoint.verifying_key().to_bytes()),
            b(&[10; 32]),
            V::Uint(at + 30_000),
        ],
        &endpoint,
    );
    let ciphertext = crypto::encrypt_challenge(
        &crypto::recipient_key(&encryption.to_public()).unwrap(),
        &challenge,
    )
    .unwrap();
    let digest = wire::digest(&wire::envelope(&challenge, 1).unwrap().0);
    let response = envelope(
        122,
        0,
        vec![
            b(&[9; 32]),
            b(&bound.reference.digest),
            b(&endpoint.verifying_key().to_bytes()),
            b(&digest),
            V::Uint(at + 30_000),
        ],
        &device,
    );
    (
        Data {
            version: 1,
            network: [1; 32],
            incarnation: [2; 32],
            bootstrap: [11; 32],
            endpoint: endpoint.verifying_key().to_bytes(),
            binding,
            delegate: None,
            challenge,
            ciphertext,
            issued_ms: at,
            expires_ms: at + 30_000,
            clock_floor_ms: at,
            status: 0,
            response: None,
            command: None,
            grant: None,
            committed: None,
        },
        response,
        encryption,
    )
}
#[test]
fn challenge_is_encrypted_and_exact_consumption_survives_reopen() {
    let directory = Directory::new();
    let (data, response, key) = fixture();
    let endpoint = data.endpoint;
    assert_eq!(
        crypto::decrypt_challenge(&key, &data.ciphertext)
            .unwrap()
            .as_slice(),
        data.challenge.as_slice()
    );
    assert!(
        crypto::decrypt_challenge(&age::x25519::Identity::generate(), &data.ciphertext).is_err()
    );
    let mut pending = Pending::create(&directory.0, data).unwrap();
    let disk = std::fs::read(directory.0.join(FILE)).unwrap();
    assert!(!disk.windows(32).any(|v| v == [10; 32]));
    let at = pending.data.issued_ms;
    pending.consume(&response, at).unwrap();
    drop(pending);
    let mut reopened =
        Pending::open_bound(&directory.0, [1; 32], [2; 32], [11; 32], endpoint).unwrap();
    assert_eq!(reopened.data.status, 1);
    assert_eq!(reopened.data.response.as_ref(), Some(&response));
    reopened.consume(&response, at + 60_000).unwrap(); // Same retained proof may only resume the same command.
    let mut changed = response.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(reopened.consume(&changed, at).is_err());
    drop(reopened);
    assert!(Pending::open_bound(&directory.0, [1; 32], [2; 32], [12; 32], endpoint).is_err());
    assert!(
        Pending::open_bound(
            &directory.0,
            [1; 32],
            [2; 32],
            [11; 32],
            SigningKey::from_bytes(&[12; 32]).verifying_key().to_bytes()
        )
        .is_err()
    );
}
#[test]
fn expired_or_mismatched_possession_cannot_consume_challenge() {
    let directory = Directory::new();
    let (data, response, _) = fixture();
    let expiry = data.expires_ms;
    let mut pending = Pending::create(&directory.0, data).unwrap();
    assert!(pending.consume(&response, expiry).is_err());
    assert_eq!(pending.data.status, 0);
    let (bytes, _) = wire::envelope(&response, 1).unwrap();
    let mut fields = wire::decode(&bytes).unwrap().array(11).unwrap().to_vec();
    fields[9] = b(&[31; 32]);
    let wrong = wire::sign_envelope(
        &wire::encode(&a(fields)).unwrap(),
        &SigningKey::from_bytes(&[4; 32]),
    )
    .unwrap();
    assert!(pending.consume(&wrong, pending.data.issued_ms).is_err());
    assert_eq!(pending.data.status, 0);
}
