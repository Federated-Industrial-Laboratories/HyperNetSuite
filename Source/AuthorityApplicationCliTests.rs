// SPDX-License-Identifier: MIT
use super::*;
use clap::Parser;
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
fn online(action: &str) -> Vec<String> {
    [
        "HyperNetSuite",
        action,
        "--bootstrap",
        "/Private/Bootstrap.cbor",
        "--bootstrap-digest",
        &"01".repeat(32),
        "--directory",
        "/Private/Floor",
        "--clock-witness",
        "/Private/Clock.json",
        "--key",
        "/Private/Identity.json",
        "--socket",
        "/Private/Control.sock",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
#[test]
fn application_cli_requires_explicit_authority_and_removes_legacy_permission_forms() {
    for action in ["consent", "grant", "revoke"] {
        assert!(Cli::try_parse_from(["HyperNetSuite", action]).is_err());
    }
    let mut args = online("delegate");
    args.extend([
        "--parent".into(),
        "02".repeat(32),
        "--tier".into(),
        "03".repeat(32),
        "--id".into(),
        "04".repeat(32),
        "--subject".into(),
        "05".repeat(32),
        "--not-before-ms".into(),
        "1".into(),
        "--expires-ms".into(),
        "2".into(),
    ]);
    assert!(Cli::try_parse_from(&args).is_ok());
    let mut legacy = args.clone();
    legacy.extend(["--permission", "PagesRead"].map(str::to_owned));
    assert!(Cli::try_parse_from(legacy).is_err());
    args.extend(["--limits", "1", "2", "3", "4"].map(str::to_owned));
    assert!(Cli::try_parse_from(args).is_ok());
    for action in ["get", "withdraw"] {
        let mut args = online(action);
        assert!(Cli::try_parse_from(&args).is_err());
        args.extend(["--application-key".into(), "05".repeat(32)]);
        assert!(Cli::try_parse_from(args).is_ok());
    }
    assert!(Cli::try_parse_from(online("list")).is_ok());
}
#[test]
fn independent_offline_acceptance_never_requires_a_socket_or_owner_floor() {
    let args = [
        "HyperNetSuite",
        "accept",
        "--bootstrap",
        "/Private/Bootstrap.cbor",
        "--bootstrap-digest",
        &"01".repeat(32),
        "--offer",
        "/Private/Offer.cbor",
        "--owner-key",
        &"02".repeat(32),
        "--key",
        "/Private/Application.json",
        "--output",
        "/Private/Accepted.cbor",
    ];
    assert!(Cli::try_parse_from(args).is_ok());
}
