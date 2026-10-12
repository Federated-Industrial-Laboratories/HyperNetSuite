// SPDX-License-Identifier: MIT
// Separate encrypted trust state preserves key possession and rejects silent root or device replacement.
use super::*;
use ed25519_dalek::Signer;
use std::path::PathBuf;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("HyperNetSealedVault{}", crate::random_hex::<16>()));
        files::create_directory(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn bytes(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
fn signed(payload: &[u8], keys: &[&SigningKey]) -> Vec<u8> {
    let mut signatures = keys
        .iter()
        .map(|key| {
            let public = key.verifying_key().to_bytes();
            (
                public,
                key.sign(&wire::signature_message(payload, &public))
                    .to_bytes(),
            )
        })
        .collect::<Vec<_>>();
    signatures.sort_by_key(|(key, _)| *key);
    wire::encode(&V::Array(vec![
        V::Uint(0),
        V::Uint(1),
        bytes(payload),
        V::Array(
            signatures
                .iter()
                .map(|(key, signature)| V::Array(vec![bytes(key), bytes(signature)]))
                .collect(),
        ),
    ]))
    .unwrap()
}
fn root_record(member: Digest, key: &SigningKey, previous: Option<&Root>) -> (Root, Vec<u8>) {
    let payload = wire::encode(&V::Array(vec![
        V::Uint(107),
        V::Uint(1),
        bytes(&[1; 32]),
        bytes(&[2; 32]),
        V::Uint(previous.map_or(1, |r| r.reference.generation + 1)),
        previous.map_or(V::Null, |r| bytes(&r.reference.digest)),
        bytes(&member),
        bytes(&key.verifying_key().to_bytes()),
        bytes(&[19; 32]),
        V::Array(vec![
            V::Uint(1),
            V::Uint(previous.map_or(1, |_| 2)),
            bytes(&[20; 32]),
        ]),
    ]))
    .unwrap();
    (Root::parse(&payload, [1; 32], [2; 32]).unwrap(), payload)
}
fn binding_record(root: &Root, key: &SigningKey, public: &DevicePublic) -> Vec<u8> {
    let now = now_ms().unwrap();
    let payload = wire::encode(&V::Array(vec![
        V::Uint(108),
        V::Uint(1),
        bytes(&[1; 32]),
        bytes(&[2; 32]),
        V::Uint(1),
        V::Null,
        bytes(&root.member),
        reference(&root.reference),
        bytes(&public.device),
        bytes(&public.signing_key),
        bytes(&public.encryption_key),
        V::Array(vec![V::Uint(0)]),
        V::Array(vec![V::Uint(now - 1000), V::Uint(now + 60000)]),
    ]))
    .unwrap();
    wire::sign_envelope(&payload, key).unwrap()
}
fn vault(directory: &Directory) -> Vault {
    Vault::initialise(
        &directory.0.join("Sealed"),
        &directory.0.join("Sealed.key"),
        [1; 32],
        [2; 32],
        [3; 32],
    )
    .unwrap()
}
#[test]
fn sealed_vault_reopens_separate_encrypted_keys_and_rejects_foreign_network_and_lock() {
    let directory = Directory::new();
    let mut vault = vault(&directory);
    let member = [4; 32];
    let root_key = vault.generate_root(member).unwrap();
    let device = vault.generate_device(member, [5; 32]).unwrap();
    let cipher =
        crypto::encrypt_challenge(&device.encryption_key, b"private possession challenge").unwrap();
    let secret = vault
        .data
        .devices
        .values()
        .next()
        .unwrap()
        .encryption_identity
        .as_bytes();
    let disk = files::read(&directory.0.join("Sealed").join(FILE), LIMIT + 200704, true).unwrap();
    assert!(!disk.windows(secret.len()).any(|part| part == secret));
    assert!(
        Vault::open(
            &directory.0.join("Sealed"),
            &directory.0.join("Sealed.key"),
            [1; 32],
            [2; 32],
            [3; 32]
        )
        .is_err()
    );
    drop(vault);
    assert!(
        Vault::open(
            &directory.0.join("Sealed"),
            &directory.0.join("Sealed.key"),
            [1; 32],
            [2; 32],
            [9; 32]
        )
        .is_err()
    );
    let vault = Vault::open(
        &directory.0.join("Sealed"),
        &directory.0.join("Sealed.key"),
        [1; 32],
        [2; 32],
        [3; 32],
    )
    .unwrap();
    assert_eq!(
        vault
            .root_signer(member)
            .unwrap()
            .verifying_key()
            .to_bytes(),
        root_key
    );
    assert_eq!(
        vault
            .device_signer(device.device)
            .unwrap()
            .verifying_key()
            .to_bytes(),
        device.signing_key
    );
    assert_eq!(
        crypto::decrypt_challenge(&vault.device_identity(device.device).unwrap(), &cipher)
            .unwrap()
            .as_slice(),
        b"private possession challenge"
    );
    assert!(vault.device_identity([6; 32]).is_err());
}
#[test]
fn sealed_contacts_require_explicit_fingerprint_and_signed_successor_acceptance() {
    let directory = Directory::new();
    let mut vault = vault(&directory);
    let key = SigningKey::from_bytes(&[7; 32]);
    let (root, payload) = root_record([8; 32], &key, None);
    let envelope = signed(&payload, &[&key]);
    assert!(vault.accept_contact(&envelope, [10; 32], [11; 32]).is_err());
    assert!(
        vault
            .accept_contact(&envelope, root.reference.digest, [0; 32])
            .is_err()
    );
    let acceptance = vault
        .accept_contact(&envelope, root.reference.digest, [11; 32])
        .unwrap();
    assert_eq!(
        acceptance,
        vault
            .accept_contact(&envelope, root.reference.digest, [11; 32])
            .unwrap()
    );
    let successor_key = SigningKey::from_bytes(&[12; 32]);
    let (next, payload) = root_record(root.member, &successor_key, Some(&root));
    let attacker = signed(&payload, &[&successor_key]);
    assert!(
        vault
            .accept_contact(&attacker, next.reference.digest, [13; 32])
            .is_err()
    );
    assert!(
        vault
            .accept_successor(
                &attacker,
                &root.reference,
                next.reference.digest,
                [13; 32],
                None,
                None
            )
            .is_err()
    );
    let valid = signed(&payload, &[&key, &successor_key]);
    assert!(
        vault
            .accept_successor(
                &valid,
                &next.reference,
                next.reference.digest,
                [13; 32],
                None,
                None
            )
            .is_err()
    );
    vault
        .accept_successor(
            &valid,
            &root.reference,
            next.reference.digest,
            [13; 32],
            None,
            None,
        )
        .unwrap();
    assert!(
        vault
            .accept_contact(&envelope, root.reference.digest, [11; 32])
            .is_err()
    );
    drop(vault);
    let vault = Vault::open(
        &directory.0.join("Sealed"),
        &directory.0.join("Sealed.key"),
        [1; 32],
        [2; 32],
        [3; 32],
    )
    .unwrap();
    assert_eq!(
        vault.contact_root(root.member).unwrap().reference,
        next.reference
    );
}
#[test]
fn sealed_binding_requires_pinned_root_current_admission_and_exact_local_device_keys() {
    let directory = Directory::new();
    let mut vault = vault(&directory);
    let key = SigningKey::from_bytes(&[14; 32]);
    let (root, payload) = root_record([15; 32], &key, None);
    vault
        .accept_contact(&signed(&payload, &[&key]), root.reference.digest, [16; 32])
        .unwrap();
    let local = vault.generate_device(root.member, [17; 32]).unwrap();
    let envelope = binding_record(&root, &key, &local);
    assert!(
        vault
            .observe_binding(root.member, &envelope, |_, _| anyhow::bail!(
                "revoked current admission"
            ))
            .is_err()
    );
    assert!(
        vault
            .data
            .contacts
            .values()
            .next()
            .unwrap()
            .bindings
            .is_empty()
    );
    vault
        .observe_binding(root.member, &envelope, |_, _| Ok(()))
        .unwrap();
    let replaced = DevicePublic {
        member: local.member,
        device: local.device,
        signing_key: local.signing_key,
        encryption_key: crypto::recipient_key(&age::x25519::Identity::generate().to_public())
            .unwrap(),
    };
    assert!(
        vault
            .observe_binding(
                root.member,
                &binding_record(&root, &key, &replaced),
                |_, _| Ok(())
            )
            .is_err()
    );
    let other = SigningKey::from_bytes(&[18; 32]);
    assert!(
        vault
            .observe_binding(
                root.member,
                &binding_record(&root, &other, &local),
                |_, _| Ok(())
            )
            .is_err()
    );
    drop(vault);
    let mut vault = Vault::open(
        &directory.0.join("Sealed"),
        &directory.0.join("Sealed.key"),
        [1; 32],
        [2; 32],
        [3; 32],
    )
    .unwrap();
    vault
        .observe_binding(root.member, &envelope, |_, _| Ok(()))
        .unwrap();
}
#[test]
fn sealed_vault_refuses_corrupt_ciphertext_and_symlinked_state() {
    let directory = Directory::new();
    let vault = vault(&directory);
    drop(vault);
    let path = directory.0.join("Sealed").join(FILE);
    let mut bytes = files::read(&path, LIMIT + 200704, true).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    let parent = files::private_directory(&directory.0.join("Sealed")).unwrap();
    files::atomic_at(&parent, OsStr::new(FILE), &bytes, true).unwrap();
    assert!(
        Vault::open(
            &directory.0.join("Sealed"),
            &directory.0.join("Sealed.key"),
            [1; 32],
            [2; 32],
            [3; 32]
        )
        .is_err()
    );
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(directory.0.join("Sealed.key"), &path).unwrap();
    assert!(
        Vault::open(
            &directory.0.join("Sealed"),
            &directory.0.join("Sealed.key"),
            [1; 32],
            [2; 32],
            [3; 32]
        )
        .is_err()
    );
}
