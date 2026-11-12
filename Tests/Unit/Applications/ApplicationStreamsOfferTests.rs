// SPDX-License-Identifier: MIT
// Renewal keeps an accepted endpoint binding and requires fresh consent for the new validity.
use super::*;
use crate::authority_deployment_tests::key;

struct Fixture {
    directory: PathBuf,
    bootstrap: trust_bootstrap::Verified,
    previous: Artifact,
}
impl Fixture {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("HyperNetStreamOffer{}", crate::random_hex::<8>()));
        files::create_directory(&directory).unwrap();
        let fixture = crate::authority_deployment_tests::Fixture::new();
        files::write_new(&directory.join("Bootstrap.cbor"), &fixture.bootstrap).unwrap();
        for (name, seed) in [("Owner.json", 5), ("Other.json", 8)] {
            files::write_new(
                &directory.join(name),
                &serde_json::to_vec(&json!({
                    "secretKey": hex::encode(key(seed).to_bytes()),
                    "publicKey": hex::encode(key(seed).verifying_key().to_bytes()),
                }))
                .unwrap(),
            )
            .unwrap();
        }
        let bootstrap = trust_bootstrap::inspect(&fixture.bootstrap, true).unwrap();
        let scope = bootstrap.descriptor().scope();
        let binding = streams::local::Binding {
            version: 1,
            id: [60; 32],
            network: scope.network,
            incarnation: scope.incarnation,
            service: [61; 32],
            owner: key(5).verifying_key().to_bytes(),
            endpoint: key(9).verifying_key().to_bytes(),
            protocol: "example/1".into(),
        };
        let mut registration = streams::Registration {
            id: binding.service,
            route: VersionRef {
                kind: 165,
                id: [62; 32],
                generation: 2,
                digest: [63; 32],
            },
            owner: binding.owner,
            operator: key(7).verifying_key().to_bytes(),
            protocol: binding.protocol.clone(),
            binding: binding.digest().unwrap(),
            limits: crate::route_profile::Limits {
                bytes: 1048576,
                duration_ms: 60000,
                idle_ms: 15000,
            },
            validity: (1000, 50000).into(),
            envelope: Vec::new(),
        };
        let payload = registration
            .payload(scope.network, scope.incarnation)
            .unwrap();
        let mut signatures = [5, 7]
            .into_iter()
            .map(|seed| {
                let envelope = wire::sign_envelope(&payload, &key(seed)).unwrap();
                wire::envelope(&envelope, 1).unwrap().1[0]
            })
            .collect::<Vec<_>>();
        signatures.sort_by_key(|(key, _)| *key);
        registration.envelope = wire::encode(&V::Array(vec![
            V::Uint(0),
            V::Uint(1),
            V::Bytes(payload),
            V::Array(
                signatures
                    .into_iter()
                    .map(|(key, signature)| {
                        V::Array(vec![V::Bytes(key.to_vec()), V::Bytes(signature.to_vec())])
                    })
                    .collect(),
            ),
        ]))
        .unwrap();
        let previous = Artifact {
            registration,
            binding,
        };
        files::write_new(&directory.join("Accepted.cbor"), &previous.bytes().unwrap()).unwrap();
        Self {
            directory,
            bootstrap,
            previous,
        }
    }
    fn arguments(&self) -> Arguments {
        let old = &self.previous.registration;
        Arguments {
            trust: Trust {
                bootstrap: self.directory.join("Bootstrap.cbor"),
                bootstrap_digest: hex::encode(self.bootstrap.file_digest()),
            },
            key: self.directory.join("Owner.json"),
            renew_from: Some(self.directory.join("Accepted.cbor")),
            service: hex::encode(old.id),
            route: format!("{}:3:{}", hex::encode(old.route.id), hex::encode([64; 32])),
            operator: hex::encode(old.operator),
            endpoint: hex::encode(self.previous.binding.endpoint),
            protocol: old.protocol.clone(),
            not_before_ms: 2000,
            expires_ms: Some(60000),
            until_withdrawn: false,
            maximum_bytes: old.limits.bytes,
            duration_ms: old.limits.duration_ms,
            idle_ms: old.limits.idle_ms,
            output: self.directory.join("Renewed.cbor"),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn renewal_preserves_exact_binding_and_requires_new_operator_consent() {
    let f = Fixture::new();
    create(f.arguments()).unwrap();
    let bytes = std::fs::read(f.directory.join("Renewed.cbor")).unwrap();
    let renewed = Artifact::parse(&f.bootstrap, &bytes, false).unwrap();
    assert_eq!(renewed.binding, f.previous.binding);
    assert_eq!(
        renewed.registration.binding,
        f.previous.registration.binding
    );
    assert_eq!(renewed.registration.validity, (2000, 60000).into());
    assert_eq!(renewed.registration.route.generation, 3);
    assert_eq!(renewed.registration.route.digest, [64; 32]);
    assert!(Artifact::parse(&f.bootstrap, &bytes, true).is_err());

    let mut same_route = f.arguments();
    same_route.route = format!("{}:2:{}", hex::encode([62; 32]), hex::encode([63; 32]));
    same_route.output = f.directory.join("SameRoute.cbor");
    create(same_route).unwrap();
}

#[test]
fn renewal_rejects_identity_rights_route_and_validity_changes_without_output() {
    let f = Fixture::new();
    for change in 0..15 {
        let mut a = f.arguments();
        match change {
            0 => a.key = f.directory.join("Other.json"),
            1 => a.service = hex::encode([65; 32]),
            2 => a.operator = hex::encode(key(8).verifying_key().to_bytes()),
            3 => a.endpoint = hex::encode(key(8).verifying_key().to_bytes()),
            4 => a.protocol = "example/2".into(),
            5 => a.maximum_bytes += 1,
            6 => a.duration_ms += 1,
            7 => a.idle_ms += 1,
            8 => a.route = format!("{}:3:{}", hex::encode([65; 32]), hex::encode([64; 32])),
            9 => a.route = format!("{}:1:{}", hex::encode([62; 32]), hex::encode([63; 32])),
            10 => a.route = format!("{}:2:{}", hex::encode([62; 32]), hex::encode([64; 32])),
            11 => a.not_before_ms = 999,
            12 => a.expires_ms = Some(50000),
            13 => a.expires_ms = Some(49999),
            _ => a.not_before_ms = a.expires_ms.unwrap(),
        }
        let output = a.output.clone();
        assert!(create(a).is_err(), "accepted changed field {change}");
        assert!(!output.exists(), "wrote refused renewal {change}");
    }
}

#[test]
fn renewal_rejects_unsigned_or_substituted_prior_consent() {
    let f = Fixture::new();
    for change in 0..4 {
        let mut previous = Artifact {
            registration: f.previous.registration.clone(),
            binding: f.previous.binding.clone(),
        };
        let scope = f.bootstrap.descriptor().scope();
        match change {
            0 => {
                previous.registration.envelope = wire::sign_envelope(
                    &previous
                        .registration
                        .payload(scope.network, scope.incarnation)
                        .unwrap(),
                    &key(5),
                )
                .unwrap()
            }
            1 => previous.binding.id = [65; 32],
            2 => *previous.registration.envelope.last_mut().unwrap() ^= 1,
            _ => previous.binding.network = [65; 32],
        }
        let path = f.directory.join(format!("Invalid{change}.cbor"));
        files::write_new(&path, &previous.bytes().unwrap()).unwrap();
        let mut a = f.arguments();
        a.renew_from = Some(path);
        let output = a.output.clone();
        assert!(
            create(a).is_err(),
            "accepted invalid prior artifact {change}"
        );
        assert!(!output.exists());
    }
}

#[test]
fn new_services_still_receive_fresh_binding_ids() {
    let f = Fixture::new();
    let mut bindings = Vec::new();
    for index in 0..2 {
        let mut a = f.arguments();
        a.renew_from = None;
        a.output = f.directory.join(format!("New{index}.cbor"));
        let output = a.output.clone();
        create(a).unwrap();
        let bytes = std::fs::read(output).unwrap();
        bindings.push(
            Artifact::parse(&f.bootstrap, &bytes, false)
                .unwrap()
                .binding,
        );
    }
    assert_ne!(bindings[0].id, bindings[1].id);
    assert_ne!(bindings[0].id, f.previous.binding.id);
}
