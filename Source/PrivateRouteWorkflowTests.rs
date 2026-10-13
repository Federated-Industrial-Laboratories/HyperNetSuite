// SPDX-License-Identifier: MIT
// Wrapper arguments preserve the consumer's file pin while retaining the network's distinct fingerprint.
use super::*;

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
