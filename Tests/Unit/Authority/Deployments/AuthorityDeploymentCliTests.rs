// SPDX-License-Identifier: MIT
use super::*;
use clap::Parser;
use ed25519_dalek::pkcs8::EncodePrivateKey;

#[test]
fn assemble_cli_accepts_successor_without_repeating_initial_possessions() {
    let parsed = crate::Options::try_parse_from([
        "HyperNetSuite",
        "authority-inspection",
        "deployments",
        "assemble",
        "--bootstrap",
        "Bootstrap.cbor",
        "--bootstrap-digest",
        &"12".repeat(32),
        "--manifest",
        "Manifest.cbor",
        "--consent",
        "Consent.cbor",
        "--output",
        "Offer.cbor",
    ])
    .unwrap();
    let crate::Command::AuthorityInspection(
        crate::authority_inspection_cli::Command::Deployments {
            command: Command::Assemble { possession, .. },
        },
    ) = parsed.command
    else {
        panic!("deployment assembly command changed");
    };
    assert!(possession.is_empty());

    let initial = crate::authority_deployment_tests::manifest();
    let signer = crate::authority_deployment_tests::key(90);
    let consent = wire::sign_envelope(&initial.unsigned_consent(0).unwrap(), &signer).unwrap();
    assert!(Offer::parse(&initial.encode().unwrap(), &consent, &a(vec![])).is_err());

    let mut next = initial.clone();
    next.generation = 2;
    next.previous_profile = Some(wire::digest(&initial.desired().unwrap()));
    next.previous_consent = Some(wire::digest(&initial.unsigned_consent(0).unwrap()));
    let next_consent = wire::sign_envelope(&next.unsigned_consent(0).unwrap(), &signer).unwrap();
    let successor = Offer::parse(&next.encode().unwrap(), &next_consent, &a(vec![])).unwrap();
    assert_eq!(
        offer(&offer_bytes(&successor).unwrap())
            .unwrap()
            .manifest_bytes,
        next.encode().unwrap()
    );
    assert!(Offer::parse(&next.encode().unwrap(), &consent, &a(vec![])).is_err());

    let complete = crate::authority_deployment_tests::offer(next.clone());
    let partial = a(vec![b(&complete.possessions[0])]);
    assert!(Offer::parse(&next.encode().unwrap(), &next_consent, &partial).is_err());
}

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
        manifest.validity.1.finite().unwrap(),
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
            manifest.validity.1.finite().unwrap()
        )
        .is_err()
    );
    assert!(
        sign_possession(
            &manifest,
            Class::Transport,
            &transport,
            0,
            manifest.validity.1.finite().unwrap()
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
