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

#[test]
fn mutation_reports_accept_the_certified_six_field_results() {
    let reference = a(vec![V::Uint(102), b(&[4; 32]), V::Uint(1), b(&[5; 32])]);
    for (action, status, kind) in [
        ("AuthorityDelegateGrant", "ApplicationGrantDelegated", 102),
        ("AuthorityApplicationRegister", "ApplicationRegistered", 127),
        ("AuthorityApplicationRenew", "ApplicationRenewed", 127),
        ("AuthorityApplicationWithdraw", "ApplicationWithdrawn", 128),
    ] {
        let mut record = vec![V::Null; if kind == 102 { 17 } else { 11 }];
        record[0] = V::Uint(kind);
        record[6] = if kind == 128 {
            reference.clone()
        } else {
            b(&[4; 32])
        };
        record[8] = if kind == 127 {
            reference.clone()
        } else {
            b(&[6; 32])
        };
        let bytes = wire::encode(&a(record)).unwrap();
        let fields = vec![
            V::Uint(201),
            V::Uint(1),
            V::Text(action.into()),
            a(vec![]),
            b(&bytes),
            V::Uint(18),
        ];
        let report = mutation_report(status, &a(fields.clone()), 19).unwrap();
        assert_eq!(report["status"], status);
        assert_eq!(report["committedHeight"], 19);
        assert_eq!(report["recordDigest"], hex::encode(wire::digest(&bytes)));
        assert!(mutation_report(status, &a(fields[..5].to_vec()), 19).is_err());
        let mut extra = fields.clone();
        extra.push(V::Null);
        assert!(mutation_report(status, &a(extra), 19).is_err());
        let mut malformed = fields;
        malformed[5] = V::Null;
        assert!(mutation_report(status, &a(malformed), 19).is_err());
    }
}

#[test]
fn interrupted_delegation_context_keeps_its_exact_selection() {
    let parent = [1; 32];
    let tier = [2; 32];
    let grant = [3; 32];
    let selection = || Selection {
        parent,
        tier,
        child: None,
    };
    let mut pending = crate::authority_proof::Intent {
        network: [4; 32],
        incarnation: [5; 32],
        generation: 1,
        generation_id: [6; 32],
        sequence: 19,
        acknowledged_through: 18,
        requester: [7; 32],
        action: "AuthorityDelegationContext".into(),
        resource: parent,
        revision: 0,
        profile_generation: 0,
        minimum_policy_epoch: 0,
        minimum_policy_height: 18,
        expected: vec![],
        parameters: vec![],
        digest: [8; 32],
    };
    for child in [V::Null, b(&grant)] {
        pending.parameters = wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text(pending.action.clone()),
            b(&parent),
            b(&tier),
            child.clone(),
            V::Null,
            a(vec![]),
        ]))
        .unwrap();
        let selected = delegation_selection(selection(), grant, true, Some(&pending)).unwrap();
        assert_eq!(
            selected.child,
            if child == V::Null { None } else { Some(grant) }
        );
        for other in [
            Selection {
                parent: [9; 32],
                ..selection()
            },
            Selection {
                tier: [9; 32],
                ..selection()
            },
        ] {
            assert!(delegation_selection(other, grant, true, Some(&pending)).is_err());
        }
        if child != V::Null {
            assert!(delegation_selection(selection(), [9; 32], true, Some(&pending)).is_err());
        }
    }
    pending.action = "AuthorityDelegateGrant".into();
    assert_eq!(
        delegation_selection(selection(), grant, true, Some(&pending))
            .unwrap()
            .child,
        None
    );
    assert_eq!(
        delegation_selection(selection(), grant, true, None)
            .unwrap()
            .child,
        Some(grant)
    );
    assert_eq!(
        delegation_selection(selection(), grant, false, None)
            .unwrap()
            .child,
        None
    );
}
