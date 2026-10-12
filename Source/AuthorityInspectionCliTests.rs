// SPDX-License-Identifier: MIT
use super::*;
use clap::Parser;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
fn arguments() -> Vec<String> {
    [
        "HyperNetSuite",
        "initialise",
        "--requester",
        &hex::encode(key()),
        "--bootstrap",
        "/Private/Bootstrap.cbor",
        "--bootstrap-digest",
        &"01".repeat(32),
        "--directory",
        "/Private/Floor",
        "--clock-witness",
        "/Clock/ClockHealth.cbor",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
fn key() -> [u8; 32] {
    SigningKey::from_bytes(&[61; 32]).verifying_key().to_bytes()
}
const BOOT: &str = "12345678-1234-1234-1234-123456789abc";
fn location(args: Vec<String>) -> Location {
    match Cli::try_parse_from(args).unwrap().command {
        Command::Initialise { location, .. } => location,
        _ => panic!("unexpected command"),
    }
}

#[test]
fn clock_cli_selects_only_the_explicit_complete_source() {
    let private = location(arguments());
    assert!(matches!(
        clock(&private, &[]).unwrap(),
        authority_clock::Source::Private { .. }
    ));
    let mut args = arguments();
    args.extend([
        "--clock-monitor-key".into(),
        hex::encode(key()),
        "--host-kernel-boot".into(),
        BOOT.into(),
    ]);
    let signed = location(args);
    assert!(matches!(
        clock(&signed, &[]).unwrap(),
        authority_clock::Source::Signed { .. }
    ));
    assert!(clock(&signed, &[key()]).is_err());
}

#[test]
fn incomplete_or_invalid_signed_clock_options_never_select_private() {
    for pair in [
        ["--clock-monitor-key".into(), hex::encode(key())],
        ["--host-kernel-boot".into(), BOOT.into()],
    ] {
        let mut args = arguments();
        args.extend(pair);
        assert!(Cli::try_parse_from(args).is_err());
    }
    let mut direct = location(arguments());
    direct.clock_monitor_key = Some(hex::encode(key()));
    assert!(clock(&direct, &[]).is_err());
    direct.clock_monitor_key = None;
    direct.host_kernel_boot = Some(BOOT.into());
    assert!(clock(&direct, &[]).is_err());
    direct.clock_monitor_key = Some("00".repeat(32));
    assert!(clock(&direct, &[]).is_err());
    direct.clock_monitor_key = Some(hex::encode(key()));
    direct.host_kernel_boot = Some("00000000-0000-0000-0000-000000000000".into());
    assert!(clock(&direct, &[]).is_err());
}

#[test]
fn governance_cli_separates_discovery_from_exact_mutation() {
    let mut context = arguments();
    context.drain(2..4);
    context[1] = "context".into();
    context.extend([
        "--key".into(),
        "/Client/Administrator.json".into(),
        "--socket".into(),
        "/Client/Control.sock".into(),
        "--grant".into(),
        "01".repeat(32),
    ]);
    assert!(matches!(
        Cli::try_parse_from(context.clone()).unwrap().command,
        Command::Context { .. }
    ));
    let mut restart = context.clone();
    restart.push("--restart-discovery".into());
    assert!(matches!(
        Cli::try_parse_from(restart).unwrap().command,
        Command::Context {
            restart_discovery: true,
            ..
        }
    ));
    context[1] = "revoke-grant".into();
    assert!(Cli::try_parse_from(context.clone()).is_err());
    context.extend([
        "--target".into(),
        "02".repeat(32),
        "--target-generation".into(),
        "1".into(),
        "--target-digest".into(),
        "03".repeat(32),
    ]);
    assert!(matches!(
        Cli::try_parse_from(context).unwrap().command,
        Command::RevokeGrant {
            target_generation: 1,
            ..
        }
    ));
}

#[test]
fn explicit_stream_controls_have_no_domain_grant_or_target() {
    for command in ["stream-status", "stream-fence"] {
        let mut args = arguments();
        args.drain(2..4);
        args[1] = command.into();
        args.extend([
            "--key".into(),
            "/Private/Signer.json".into(),
            "--socket".into(),
            "/Private/Control.sock".into(),
        ]);
        let parsed = Cli::try_parse_from(args.clone()).unwrap();
        assert!(matches!(
            parsed.command,
            Command::StreamStatus { .. } | Command::StreamFence { .. }
        ));
        args.extend(["--grant".into(), "01".repeat(32)]);
        assert!(Cli::try_parse_from(args).is_err());
    }
    let mut missing = arguments();
    missing.drain(2..4);
    assert!(Cli::try_parse_from(missing).is_err());
}

#[test]
fn member_consent_and_confirmation_cli_have_no_network_or_floor_arguments() {
    let common = vec![
        "HyperNetSuite".to_string(),
        "inspect-offer".into(),
        "--bootstrap".into(),
        "/Private/Bootstrap.cbor".into(),
        "--bootstrap-digest".into(),
        "01".repeat(32),
        "--offer".into(),
        "/Private/Offer.cbor".into(),
    ];
    assert!(matches!(
        Cli::try_parse_from(common.clone()).unwrap().command,
        Command::InspectOffer(_)
    ));
    let mut invalid = common.clone();
    invalid.extend(["--socket".into(), "/Private/Control.sock".into()]);
    assert!(Cli::try_parse_from(invalid).is_err());
    let mut accept = common;
    accept[1] = "accept-member".into();
    assert!(Cli::try_parse_from(accept.clone()).is_err());
    accept.extend([
        "--key".into(),
        "/Private/Candidate.json".into(),
        "--output".into(),
        "/Private/Accepted.cbor".into(),
    ]);
    assert!(matches!(
        Cli::try_parse_from(accept).unwrap().command,
        Command::AcceptMember(_)
    ));
    let confirm = vec![
        "HyperNetSuite".to_string(),
        "confirm-member".into(),
        "--bootstrap".into(),
        "/Private/Bootstrap.cbor".into(),
        "--bootstrap-digest".into(),
        "01".repeat(32),
        "--accepted".into(),
        "/Private/Accepted.cbor".into(),
        "--receipt".into(),
        "/Private/Admission.cbor".into(),
    ];
    assert!(matches!(
        Cli::try_parse_from(confirm.clone()).unwrap().command,
        Command::ConfirmMember(_)
    ));
    let mut invalid = confirm;
    invalid.extend(["--directory".into(), "/Private/Floor".into()]);
    assert!(Cli::try_parse_from(invalid).is_err());
}
#[test]
fn delegation_cli_defaults_to_explicit_reader_only_authority() {
    let mut args = arguments();
    args.drain(2..4);
    args[1] = "delegate-grant".into();
    args.extend([
        "--key".into(),
        "/Private/Admin.json".into(),
        "--socket".into(),
        "/Private/Control.sock".into(),
        "--context-grant".into(),
        "01".repeat(32),
        "--parent".into(),
        "02".repeat(32),
        "--id".into(),
        "03".repeat(32),
        "--subject".into(),
        hex::encode(key()),
        "--not-before-ms".into(),
        "1000".into(),
        "--expires-ms".into(),
        "10000".into(),
    ]);
    assert!(matches!(
        Cli::try_parse_from(args).unwrap().command,
        Command::DelegateGrant(_)
    ));
}
