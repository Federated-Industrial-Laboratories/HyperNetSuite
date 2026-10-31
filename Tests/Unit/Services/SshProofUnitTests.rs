// SPDX-License-Identifier: MIT
// Unit tests for SshProof.
use super::*;
use ed25519_dalek::{Signer, SigningKey};
#[test]
fn standard_ssh_signature_binds_network_member_and_native_key() {
    let signing = SigningKey::from_bytes(&[7; 32]);
    let mut public = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
    public.extend(signing.verifying_key().to_bytes());
    let key = format!("ssh-ed25519 {}", STANDARD.encode(&public));
    let network = "11".repeat(32);
    let member = "22".repeat(32);
    let mut signed = b"SSHSIG".to_vec();
    append(&mut signed, NAMESPACE);
    append(&mut signed, b"");
    append(&mut signed, b"sha512");
    append(
        &mut signed,
        &Sha512::digest(message(&network, &member, &public).unwrap()),
    );
    let mut signature = Vec::new();
    append(&mut signature, b"ssh-ed25519");
    append(&mut signature, &signing.sign(&signed).to_bytes());
    let mut blob = b"SSHSIG\0\0\0\x01".to_vec();
    append(&mut blob, &public);
    append(&mut blob, NAMESPACE);
    append(&mut blob, b"");
    append(&mut blob, b"sha512");
    append(&mut blob, &signature);
    verify_blob(&blob, &network, &member, &key).unwrap();
    assert!(verify_blob(&blob, &"33".repeat(32), &member, &key).is_err());
    assert!(verify_blob(&blob, &network, &"33".repeat(32), &key).is_err());
    let last = blob.len() - 1;
    blob[last] ^= 1;
    assert!(verify_blob(&blob, &network, &member, &key).is_err());
}
