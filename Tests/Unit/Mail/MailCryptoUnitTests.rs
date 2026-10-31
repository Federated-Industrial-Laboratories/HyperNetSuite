// SPDX-License-Identifier: MIT
// Unit tests for MailCrypto.
use super::*;
fn mailbox(
    network: &str,
    expires: u64,
    devices: usize,
) -> (wire::Signed, Vec<(wire::Device, String)>) {
    let owner = wire::new_identity();
    let address = wire::address_id(network, &owner.public_key).unwrap();
    let keys = (0..devices)
        .map(|_| {
            let request = wire::new_identity();
            let (secret, public) = signer().unwrap();
            (
                wire::Device {
                    device_id: wire::device_id(&address, &request.public_key).unwrap(),
                    request_key: request.public_key.clone(),
                    mls_signature_key: public,
                    permissions: vec!["Read".into(), "Send".into()],
                    expires,
                },
                secret,
            )
        })
        .collect::<Vec<_>>();
    let m = wire::Manifest {
        version: 1,
        network: network.into(),
        address_id: address,
        owner_key: owner.public_key.clone(),
        generation: 1,
        previous_digest: None,
        expires,
        devices: keys.iter().map(|(d, _)| d.clone()).collect(),
        storage_hosts: vec!["33".repeat(32)],
        required_copies: 1,
        retention_seconds: 3600,
        deleted: false,
    };
    (
        wire::sign(wire::MANIFEST, network, &owner, &m).unwrap(),
        keys,
    )
}
#[test]
fn offline_letter_checks_every_device_and_restores_only_its_prekey() {
    let network = "11".repeat(32);
    let expires = crate::now().unwrap() + 300;
    let (sender, skeys) = mailbox(&network, expires, 1);
    let (recipient, rkeys) = mailbox(&network, expires, 2);
    let a = wire::manifest(&network, &sender).unwrap();
    let b = wire::manifest(&network, &recipient).unwrap();
    let route = wire::Route {
        version: 1,
        profile: wire::PROFILE.into(),
        network: network.clone(),
        message_id: "22".repeat(16),
        replacement: 0,
        sender_address: a.address_id.clone(),
        sender_device: skeys[0].0.device_id.clone(),
        recipient_address: b.address_id.clone(),
        recipient_generation: 1,
        recipient_manifest_digest: wire::object_digest(&recipient).unwrap(),
        claim_id: "44".repeat(16),
        expires,
    };
    let mut claim = wire::Claim {
        version: 1,
        network: network.clone(),
        sender_address: route.sender_address.clone(),
        sender_device: route.sender_device.clone(),
        claim_id: route.claim_id.clone(),
        recipient_address: route.recipient_address.clone(),
        recipient_generation: 1,
        recipient_manifest_digest: route.recipient_manifest_digest.clone(),
        expires,
        packages: vec![],
    };
    let mut private = Vec::new();
    for (device, secret) in &rkeys {
        let (mut own, public) =
            make_packages(&network, &b.address_id, device, secret, 1, expires).unwrap();
        private.push(own.remove(0));
        claim.packages.extend(public);
    }
    let letter = Letter {
        route,
        subject: "Subject\u{1b}[2J".into(),
        body: "Private canary content".into(),
    };
    let cipher = seal(&skeys[0].1, &claim, &sender, &recipient, &letter).unwrap();
    for (i, p) in private.iter().enumerate() {
        let recovered: PrivatePackage =
            serde_json::from_slice(&serde_json::to_vec(p).unwrap()).unwrap();
        let got = open(
            &cipher,
            &recovered,
            &rkeys[i].0.device_id,
            crate::now().unwrap(),
        )
        .unwrap();
        assert_eq!(got.body, letter.body);
        assert!(got.route == letter.route);
    }
    let mut short = claim.clone();
    short.packages.pop();
    assert!(seal(&skeys[0].1, &short, &sender, &recipient, &letter).is_err());
    let mut wrong = claim.clone();
    wrong.packages[0].expires -= 1;
    assert!(seal(&skeys[0].1, &wrong, &sender, &recipient, &letter).is_err());
    let mut trailing = claim.clone();
    let mut raw = wire::decode(&trailing.packages[0].package, 4096).unwrap();
    raw.push(0);
    trailing.packages[0].package = wire::encode(&raw);
    assert!(seal(&skeys[0].1, &trailing, &sender, &recipient, &letter).is_err());
    let mut altered = cipher.clone();
    altered.route.message_id = "55".repeat(16);
    assert!(
        open(
            &altered,
            &private[0],
            &rkeys[0].0.device_id,
            crate::now().unwrap()
        )
        .is_err()
    );
}
#[test]
fn standard_age_rejects_another_key_and_modified_ciphertext() {
    let identity = age::x25519::Identity::generate();
    let bytes = encrypt_age(&identity.to_public().to_string(), b"mail-private-canary").unwrap();
    assert!(!bytes.windows(19).any(|w| w == b"mail-private-canary"));
    assert_eq!(
        decrypt_age(&identity, &bytes, 64).unwrap().as_slice(),
        b"mail-private-canary"
    );
    assert!(decrypt_age(&age::x25519::Identity::generate(), &bytes, 64).is_err());
    let mut corrupt = bytes;
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(decrypt_age(&identity, &corrupt, 64).is_err());
}
