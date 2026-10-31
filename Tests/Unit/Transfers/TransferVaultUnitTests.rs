// SPDX-License-Identifier: MIT
// Unit tests for TransferVault.
use super::*;
#[test]
fn encrypted_file_binds_recipient_offer_and_all_plain_bytes() {
    let key = age::x25519::Identity::generate();
    let mut offer = wire::Offer {
        version: 1,
        network: "11".repeat(32),
        transfer_id: "22".repeat(16),
        sender_key: "33".repeat(32),
        recipient_key: "44".repeat(32),
        recipient_encryption_key: key.to_public().to_string(),
        payload_bytes: 0,
        payload_digest: String::new(),
        file_bytes: 5,
        label: "Opaque".into(),
        expires: 1,
    };
    let mut cipher = seal(&offer, "Private.txt", b"hello").unwrap();
    offer.payload_bytes = cipher.len() as u64;
    offer.payload_digest = signed::digest(&cipher);
    assert!(!cipher.windows(11).any(|s| s == b"Private.txt"));
    assert_eq!(&*unseal(&offer, &key, &cipher).unwrap().1, b"hello");
    offer.transfer_id = "55".repeat(16);
    assert!(unseal(&offer, &key, &cipher).is_err());
    offer.transfer_id = "22".repeat(16);
    assert!(unseal(&offer, &age::x25519::Identity::generate(), &cipher).is_err());
    cipher[80] ^= 1;
    offer.payload_digest = signed::digest(&cipher);
    assert!(unseal(&offer, &key, &cipher).is_err());
}
