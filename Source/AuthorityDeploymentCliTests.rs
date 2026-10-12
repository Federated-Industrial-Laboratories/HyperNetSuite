// SPDX-License-Identifier: MIT
use super::*;
use ed25519_dalek::pkcs8::EncodePrivateKey;

#[test]
fn possession_import_preserves_exact_key_class_and_approved_manifest() {
    let manifest = crate::authority_deployment_tests::manifest();
    let transport = crate::authority_deployment_tests::key(31);
    let public = transport.verifying_key().to_bytes();
    let bytes = sign_possession(
        &manifest,
        Class::Transport,
        &transport,
        manifest.validity.0,
        manifest.validity.1,
    )
    .unwrap();
    let (payload, signatures) = wire::envelope(&bytes, 1).unwrap();
    assert_eq!(signatures[0].0, public);
    assert_eq!(
        wire::decode(&payload).unwrap().array(12).unwrap()[6],
        V::Uint(1)
    );
    assert!(
        sign_possession(
            &manifest,
            Class::Service,
            &transport,
            manifest.validity.0,
            manifest.validity.1
        )
        .is_err()
    );
    assert!(
        sign_possession(
            &manifest,
            Class::Transport,
            &transport,
            0,
            manifest.validity.1
        )
        .is_err()
    );
    let pem = transport.to_pkcs8_pem(Default::default()).unwrap();
    let root = std::env::temp_dir().join(format!(
        "HyperNetPossession{}",
        hex::encode(rand::random::<[u8; 16]>())
    ));
    files::create_directory(&root).unwrap();
    let path = root.join("Transport.pem");
    files::write_new(&path, pem.as_bytes()).unwrap();
    assert_eq!(
        possession_key(Class::Transport, None, Some(&path))
            .unwrap()
            .verifying_key()
            .to_bytes(),
        public
    );
    assert!(possession_key(Class::Service, None, Some(&path)).is_err());
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn assembled_offer_rejects_partial_possession_and_consent_rebinding() {
    let m = crate::authority_deployment_tests::manifest();
    let original = crate::authority_deployment_tests::offer(m);
    let canonical = offer_bytes(&original).unwrap();
    assert_eq!(
        offer(&canonical).unwrap().manifest_bytes,
        original.manifest_bytes
    );
    let mut values = wire::decode(&canonical).unwrap().array(6).unwrap().to_vec();
    let mut proofs = original.possessions_value().list(19).unwrap().to_vec();
    proofs.pop();
    values[5] = a(proofs);
    assert!(offer(&wire::encode(&a(values.clone())).unwrap()).is_err());
    values[5] = original.possessions_value();
    let mut changed = original.manifest.clone();
    changed.software_digest = [254; 32];
    values[3] = b(&changed.encode().unwrap());
    assert!(offer(&wire::encode(&a(values)).unwrap()).is_err());
}

#[test]
fn installed_raw_operator_key_and_public_artifacts_keep_distinct_file_permissions() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let root = std::env::temp_dir().join(format!(
        "HyperNetOperatorImport{}",
        hex::encode(rand::random::<[u8; 16]>())
    ));
    files::create_directory(&root).unwrap();
    let private = root.join("Operator.key");
    files::write_new(&private, &[90; 32]).unwrap();
    assert_eq!(
        deployment_signer(&private).unwrap().verifying_key(),
        crate::authority_deployment_tests::key(90).verifying_key()
    );
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o444)).unwrap();
    assert!(deployment_signer(&private).is_err());
    let public = root.join("Consent.cbor");
    files::write_new(&public, b"public").unwrap();
    std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o444)).unwrap();
    assert_eq!(files::read_public_single(&public, 64).unwrap(), b"public");
    symlink(&public, root.join("Link.cbor")).unwrap();
    assert!(files::read_public_single(&root.join("Link.cbor"), 64).is_err());
    std::fs::hard_link(&public, root.join("Hard.cbor")).unwrap();
    assert!(files::read_public_single(&public, 64).is_err());
    std::fs::remove_file(root.join("Hard.cbor")).unwrap();
    std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o664)).unwrap();
    assert!(files::read_public_single(&public, 64).is_err());
    std::fs::remove_dir_all(root).unwrap();
}
