// SPDX-License-Identifier: MIT
// Actual MLS letters survive encrypted vault reopening without consuming a private package twice.
use super::*;
use crate::authority_mail::{mail, workflow};
struct Directory(std::path::PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn mailbox(network: Digest, service: Digest, expires: u64) -> Mailbox {
    let n = hex::encode(network);
    let owner = wire::new_identity();
    let address = wire::address_id(&n, &owner.public_key).unwrap();
    let mut b = workflow::local_device(
        &address,
        expires,
        vec!["Read".into(), "Send".into(), "Delete".into()],
    )
    .unwrap();
    let manifest = wire::Manifest {
        version: 1,
        network: n.clone(),
        address_id: address,
        owner_key: owner.public_key.clone(),
        generation: 1,
        previous_digest: None,
        expires,
        devices: vec![b.device.clone()],
        storage_hosts: vec![hex::encode(service)],
        required_copies: 1,
        retention_seconds: 600,
        deleted: false,
    };
    let signed = wire::sign(wire::MANIFEST, &n, &owner, &manifest).unwrap();
    let parsed =
        mail::objects::Publication::parse(&serde_json::to_vec(&signed).unwrap(), network).unwrap();
    assert_eq!(
        hex::encode(parsed.digest),
        wire::object_digest(&signed).unwrap()
    );
    b.owner = Some(owner);
    b.manifest = Some(signed);
    b.private = true;
    b
}
#[test]
fn mail_vault_mls_archive_is_durable_and_consumes_the_exact_private_package_once() {
    let root = std::env::temp_dir().join(format!("HyperNetMailVault{}", crate::random_hex::<16>()));
    std::fs::create_dir(&root).unwrap();
    let _cleanup = Directory(root.clone());
    let path = root.join("Vault");
    let key = root.join("Mail.key");
    let n = [17; 32];
    let i = [18; 32];
    let pin = [19; 32];
    let now = crate::now().unwrap();
    let expires = now + 600;
    let service = ed25519_dalek::SigningKey::from_bytes(&[88; 32])
        .verifying_key()
        .to_bytes();
    let sender = mailbox(n, service, expires);
    let mut recipient = mailbox(n, service, expires);
    let (private, packages) = mail_crypto::make_packages(
        &hex::encode(n),
        &recipient.address,
        &recipient.device,
        &recipient.signer,
        1,
        expires,
    )
    .unwrap();
    recipient.packages = private;
    let claim = wire::Claim {
        version: 1,
        network: hex::encode(n),
        sender_address: sender.address.clone(),
        sender_device: sender.device.device_id.clone(),
        claim_id: hex::encode([44; 32]),
        recipient_address: recipient.address.clone(),
        recipient_generation: 1,
        recipient_manifest_digest: wire::object_digest(recipient.manifest.as_ref().unwrap())
            .unwrap(),
        expires,
        packages,
    };
    let letter = Letter {
        route: wire::Route {
            version: 1,
            profile: wire::PROFILE.into(),
            network: claim.network.clone(),
            message_id: claim.claim_id.clone(),
            replacement: 0,
            sender_address: claim.sender_address.clone(),
            sender_device: claim.sender_device.clone(),
            recipient_address: claim.recipient_address.clone(),
            recipient_generation: 1,
            recipient_manifest_digest: claim.recipient_manifest_digest.clone(),
            claim_id: claim.claim_id.clone(),
            expires,
        },
        subject: "Protected letter".into(),
        body: "Ciphertext is stored; private packages stay with their device.".into(),
    };
    let cipher = mail_crypto::seal(
        &sender.signer,
        &claim,
        sender.manifest.as_ref().unwrap(),
        recipient.manifest.as_ref().unwrap(),
        &letter,
    )
    .unwrap();
    let reference = claim.packages[0].reference.clone();
    let signed = recipient.manifest.as_ref().unwrap().clone();
    let mut v = Vault::initialise(&path, &key, n, i, pin).unwrap();
    assert!(v.contact(&signed, Some(&hex::encode([77; 32]))).is_err());
    v.contact(&signed, Some(&signed.public_key)).unwrap();
    v.data.mailboxes.insert("Recipient".into(), recipient);
    v.save().unwrap();
    assert_eq!(
        v.archive("Recipient", &cipher, &reference, now, b"verified receipt")
            .unwrap()
            .body,
        letter.body
    );
    assert!(v.mailbox("Recipient").unwrap().packages.is_empty());
    drop(v);
    let mut v = Vault::open(&path, &key, n, i, pin).unwrap();
    assert_eq!(
        v.archive(
            "Recipient",
            &cipher,
            &reference,
            now,
            b"repeated verified receipt"
        )
        .unwrap()
        .body,
        letter.body
    );
    assert!(v.mailbox("Recipient").unwrap().packages.is_empty());
    let mut different = cipher.clone();
    different.message.push('A');
    assert!(
        v.archive(
            "Recipient",
            &different,
            &reference,
            now,
            b"verified receipt"
        )
        .is_err()
    );
    different.route.message_id = hex::encode([45; 32]);
    assert!(
        v.archive(
            "Recipient",
            &different,
            &reference,
            now,
            b"verified receipt"
        )
        .is_err()
    );
    drop(v);
    assert!(Vault::open(&path, &key, n, [99; 32], pin).is_err());
}
