// SPDX-License-Identifier: MIT
// Unit tests for AuthorityTransferVault.
use super::*;
#[test]
fn transfer_receive_replay_preserves_exact_ciphertext_and_recipient() {
    let root = std::env::temp_dir().join(format!(
        "HyperNetTransferVault{}",
        hex::encode(rand::random::<[u8; 16]>())
    ));
    let _parent = files::create_directory(&root).unwrap();
    let path = root.join("Vault");
    let key = root.join("Identity.key");
    let sender = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let recipient = ed25519_dalek::SigningKey::from_bytes(&[4; 32])
        .verifying_key()
        .to_bytes();
    let mut vault = Vault::initialise(&path, &key, [1; 32], [2; 32], [3; 32], recipient).unwrap();
    let mut offer = Offer {
        network: [1; 32],
        incarnation: [2; 32],
        id: [5; 32],
        sender: sender.verifying_key().to_bytes(),
        recipient,
        encryption_key: vault.recipient(),
        payload_bytes: 0,
        payload_digest: [0; 32],
        file_bytes: 12,
        label: "Receipt".into(),
        expires: 10000,
        envelope: vec![],
    };
    let cipher = seal(&offer, "Receipt.txt", b"Private file").unwrap();
    offer.payload_bytes = cipher.len() as u64;
    offer.payload_digest = wire::digest(&cipher);
    offer.envelope = wire::sign_envelope(&offer.payload().unwrap(), &sender).unwrap();
    let offer = Offer::parse(&offer.envelope, [1; 32], [2; 32]).unwrap();
    let split = cipher.len() / 2;
    vault.receive(&offer, 0, &cipher[..split]).unwrap();
    drop(vault);
    let mut vault = Vault::open(&path, &key, [1; 32], [2; 32], [3; 32], recipient).unwrap();
    vault.receive(&offer, 0, &cipher[..split]).unwrap();
    let mut changed = cipher[..split].to_vec();
    changed[0] ^= 1;
    assert!(vault.receive(&offer, 0, &changed).is_err());
    assert!(
        vault
            .receive(&offer, (split + 1) as u64, &cipher[split + 1..])
            .is_err()
    );
    vault
        .receive(&offer, split as u64, &cipher[split..])
        .unwrap();
    let (_, plain) = vault.open_file(&offer).unwrap();
    assert_eq!(&*plain, b"Private file");
    drop(vault);
    assert!(Vault::open(&path, &key, [1; 32], [2; 32], [3; 32], [6; 32]).is_err());
    std::fs::remove_dir_all(root).unwrap();
}
