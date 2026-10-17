// SPDX-License-Identifier: MIT
// Wrapper arguments preserve the consumer's file pin while retaining the network's distinct fingerprint.
use super::*;

#[test]
fn retained_subject_pins_complete_route_before_connection_preparation() {
    use crate::{
        authority_local_transport::LocalControl,
        route_profile::{Assurance, Identity, Limits},
    };
    let identity = |service, transport| Identity {
        service: [service; 32],
        server_name: "Search.invalid".into(),
        transport_key: [transport; 32],
        leaf_der: vec![transport],
        certificate_authority_pem: "Pinned authority".into(),
    };
    for protocol in [2, 6] {
        let route = crate::route_profile::Profile {
            version: 1,
            network: [1; 32],
            incarnation: [2; 32],
            relay_address: "127.0.0.1:1".parse().unwrap(),
            relay: identity(3, 4),
            destination: identity(5, 6),
            domain: "Destination".into(),
            relay_domain: "Relay".into(),
            protocol,
            assurance: Assurance::Independent,
            minimum_assurance: Assurance::Independent,
            limits: Limits {
                bytes: 16384,
                duration_ms: 1000,
                idle_ms: 1000,
            },
            voucher: vec![8],
        };
        let pinned = SavedRoute {
            service: hex::encode(route.destination.service),
            subject: hex::encode([7; 32]),
            protocol,
            route_digest: SavedRoute::digest(&route).unwrap(),
        };
        assert_ne!(route.destination.service, [7; 32]);
        assert_eq!(pinned.checked_subject(&route).unwrap(), [7; 32]);
        let mut unpinned = serde_json::to_value(&pinned).unwrap();
        unpinned.as_object_mut().unwrap().remove("routeDigest");
        assert!(serde_json::from_value::<SavedRoute>(unpinned).is_err());
        let original = Endpoint {
            format: "HyperNetRelayEndpoint/1".into(),
            profile: PathBuf::from("/AbsentSearchRouteProfile.json"),
            route: route.clone(),
        };
        assert!(original.same_identity(&original).unwrap());
        let mut other_profile = original.clone();
        other_profile.profile = PathBuf::from("/OtherProfile.json");
        assert!(!original.same_identity(&other_profile).unwrap());
        for changed in 0..8 {
            let mut selected = route.clone();
            match changed {
                0 => selected.destination.service = [9; 32],
                1 => selected.destination.transport_key = [9; 32],
                2 => selected.destination.leaf_der.push(9),
                3 => selected.destination.certificate_authority_pem.push('9'),
                4 => selected.destination.server_name = "Other.invalid".into(),
                5 => selected.voucher.push(9),
                6 => selected.limits.bytes += 1,
                _ => selected.relay.transport_key = [9; 32],
            }
            let endpoint = Endpoint {
                format: "HyperNetRelayEndpoint/1".into(),
                profile: PathBuf::from("/AbsentSearchRouteProfile.json"),
                route: selected,
            };
            assert!(!original.same_identity(&endpoint).unwrap());
            let result = LocalControl::from_relay_checked(endpoint, |loaded| {
                assert_eq!(
                    loaded.unwrap().profile,
                    PathBuf::from("/AbsentSearchRouteProfile.json")
                );
                pinned.checked_subject(&loaded.unwrap().route)?;
                Ok(())
            });
            let error = result.err().unwrap().to_string();
            assert!(
                error.contains("explicitly retained subject binding"),
                "{error}"
            );
        }
    }
}

#[test]
fn connected_route_command_accepts_the_bootstrap_file_digest() {
    let fixture = crate::authority_deployment_tests::Fixture::new();
    let checked = trust::inspect(&fixture.bootstrap, true).unwrap();
    assert_ne!(checked.file_digest(), checked.fingerprint());
    let root = std::env::temp_dir().join(format!(
        "HyperNetRouteArguments{}",
        crate::random_hex::<16>()
    ));
    files::create_directory(&root).unwrap();
    files::write_new(&root.join("Bootstrap.cbor"), &fixture.bootstrap).unwrap();
    let joined = onboarding::Joined {
        directory: root.clone(),
        clock_witness: root.join("ClockHealth.json"),
        invitation_digest: "01".repeat(32),
        member: "02".repeat(32),
        reader_grant: hex::encode(fixture.grant.id),
        admitted: true,
    };
    let mut argv = vec![
        OsString::from("routes"),
        OsString::from("lookup"),
        OsString::from("--service"),
        OsString::from("03".repeat(32)),
    ];
    let schema = crate::Options::command();
    let available = leaf(&schema, &argv)
        .unwrap()
        .get_arguments()
        .filter_map(|a| a.get_long().map(|s| (s.to_owned(), a.get_id().to_string())))
        .collect();
    online_defaults(&mut argv, &available, &checked, &joined).unwrap();
    argv.insert(0, "HyperNetSuite".into());
    let parsed = crate::Options::try_parse_from(argv).unwrap();
    let crate::Command::Routes(crate::private_route_commands::Command::Lookup {
        online,
        grant,
        ..
    }) = parsed.command
    else {
        panic!("route wrapper selected another command")
    };
    let bootstrap = crate::authority_inspection_cli::bootstrap(&online.location).unwrap();
    assert_eq!(bootstrap.fingerprint(), checked.fingerprint());
    assert_eq!(grant, joined.reader_grant);
    assert_eq!(online.socket, root.join("AuthorityRoute.json"));
    assert_eq!(online.location.directory, root.join("Requester"));
    std::fs::remove_dir_all(root).unwrap();
}
