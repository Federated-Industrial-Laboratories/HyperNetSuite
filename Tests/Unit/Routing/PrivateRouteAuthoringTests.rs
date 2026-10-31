// SPDX-License-Identifier: MIT
// Operator authoring rejects identity, reviewed-consent and local-output substitutions.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{fs, os::unix::fs::PermissionsExt};

#[test]
fn route_authoring_binds_operator_manifest_and_private_output() {
    let fixture = crate::authority_deployment_tests::Fixture::new();
    let mut manifest = crate::authority_deployment_tests::manifest();
    manifest.bootstrap_digest = trust_bootstrap::inspect(&fixture.bootstrap, true)
        .unwrap()
        .file_digest();
    let root = std::env::temp_dir().join(format!(
        "HyperNetRouteAuthoring{}",
        crate::random_hex::<16>()
    ));
    files::create_directory(&root).unwrap();
    files::write_new(&root.join("Bootstrap.cbor"), &fixture.bootstrap).unwrap();
    files::write_new(&root.join("Manifest.cbor"), &manifest.encode().unwrap()).unwrap();
    files::write_new(&root.join("Operator.key"), &[90; 32]).unwrap();
    files::write_new(&root.join("Other.key"), &[91; 32]).unwrap();
    let endpoint = manifest
        .endpoints
        .iter()
        .find(|endpoint| endpoint.endpoint_id == [85; 32])
        .unwrap();
    let certificate = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        STANDARD.encode(&endpoint.leaf_der)
    );
    files::write_new(&root.join("Authority.pem"), certificate.as_bytes()).unwrap();
    let arguments = || Profile {
        trust: Trust {
            bootstrap: root.join("Bootstrap.cbor"),
            bootstrap_digest: hex::encode(manifest.bootstrap_digest),
        },
        manifest: root.join("Manifest.cbor"),
        profile_digest: hex::encode(wire::digest(&manifest.desired().unwrap())),
        key: root.join("Operator.key"),
        service: hex::encode([201; 32]),
        endpoint: hex::encode(endpoint.endpoint_id),
        domain: hex::encode([202; 32]),
        mode: Mode::Public,
        protocol: Protocol::Content,
        server_name: "Route.Example".into(),
        certificate_authority: root.join("Authority.pem"),
        relay: None,
        assurance: "Independent".into(),
        maximum_bytes: 1048576,
        maximum_duration_ms: 30000,
        maximum_idle_ms: 5000,
        maximum_connections: 8,
        output: root.join("RouteProfile.cbor"),
    };
    let mut wrong_operator = arguments();
    wrong_operator.key = root.join("Other.key");
    assert!(profile(wrong_operator).is_err());
    assert!(!root.join("RouteProfile.cbor").exists());
    let mut wrong_consent = arguments();
    wrong_consent.profile_digest = hex::encode([203; 32]);
    assert!(profile(wrong_consent).is_err());
    assert!(!root.join("RouteProfile.cbor").exists());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(profile(arguments()).is_err());
    assert!(!root.join("RouteProfile.cbor").exists());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    profile(arguments()).unwrap();
    let output = fs::read(root.join("RouteProfile.cbor")).unwrap();
    let signed =
        routes::RegisteredProfile::parse(&output, manifest.network, manifest.incarnation).unwrap();
    assert_eq!(signed.operator, manifest.operator);
    assert_eq!(signed.service, endpoint.service_key);
    assert_eq!(signed.endpoint, endpoint.endpoint_id);
    assert_eq!(signed.identity.transport_key, endpoint.transport_key);
    assert_eq!(signed.identity.leaf_der, endpoint.leaf_der);
    assert_eq!(
        signed.deployment_profile,
        authority_deployment_records::reference(&manifest.desired().unwrap()).unwrap()
    );
    assert_eq!(
        signed.consent,
        authority_deployment_records::reference(&manifest.unsigned_consent(0).unwrap()).unwrap()
    );
    assert_eq!(
        signed.address,
        Some(SocketAddr::new(endpoint.address, endpoint.port))
    );
    assert!(profile(arguments()).is_err());
    assert_eq!(fs::read(root.join("RouteProfile.cbor")).unwrap(), output);
    let mut attached = arguments();
    attached.mode = Mode::Attached;
    attached.relay = Some(hex::encode([204; 32]));
    attached.output = root.join("AttachedRoute.cbor");
    profile(attached).unwrap();
    let attached = routes::RegisteredProfile::parse(
        &fs::read(root.join("AttachedRoute.cbor")).unwrap(),
        manifest.network,
        manifest.incarnation,
    )
    .unwrap();
    assert_eq!(attached.address, None);
    assert_eq!(attached.relay, Some([204; 32]));
    assert_eq!(attached.endpoint, endpoint.endpoint_id);
    fs::remove_dir_all(root).unwrap();
}
