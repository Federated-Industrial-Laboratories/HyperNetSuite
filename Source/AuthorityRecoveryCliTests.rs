// SPDX-License-Identifier: MIT
use super::*;
use crate::authority_recovery::tests::{completed, fixture};
use clap::Parser;
use std::os::unix::fs::PermissionsExt;
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("HyperNetRecovery{}", hex::encode(random())));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        output(&path, bytes).unwrap();
        path
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn old_profile(dir: &Directory, bootstrap: &[u8]) -> PathBuf {
    let checked = trust::inspect(bootstrap, true).unwrap();
    let profile = Profile {
        format: "HyperNetOfflineClient/1".into(),
        bootstrap: hex::encode(bootstrap),
        fingerprint: hex::encode(trust_wire::digest(bootstrap)),
        descriptor_digest: checked.summary.descriptor_digest,
        client_id: hex::encode(random()),
        device: identity(),
        relay_identity: identity(),
        minimum_route: trust::Assurance::Independent,
        accepted_relay_domains: vec![checked.summary.route.relay_domain],
        required_publication_modes: vec!["HostReadable".into(), "Sealed".into()],
        permit_network_search: false,
        recovery: None,
        joined: None,
    };
    dir.file("Predecessor.json", &serde_json::to_vec(&profile).unwrap())
}
fn floor(dir: &Directory, bootstrap: &[u8]) -> PathBuf {
    let checked = trust::inspect(bootstrap, true).unwrap();
    let path = dir.0.join("Floor");
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let boot = crate::authority_challenge::boot_time_ms().unwrap();
    let clock = crate::authority_challenge::ClockHealth::new(
        time().unwrap() * 1000,
        boot,
        boot + 30000,
        100,
    )
    .unwrap();
    crate::authority_floor::Store::initialise(
        &path,
        checked.descriptor().clone(),
        SigningKey::from_bytes(&[99; 32]).verifying_key().to_bytes(),
        clock,
    )
    .unwrap();
    path
}
#[test]
fn installed_recovery_resumes_exact_outputs_and_preserves_conflict_after_restart() {
    let dir = Directory::new();
    let now = time().unwrap();
    let (old, keys) = fixture(20, now);
    let (next, _) = fixture(24, now);
    let (other, _) = fixture(28, now);
    let previous = old_profile(&dir, &old);
    let previous_bytes = files::read_single(&previous, PROFILE_LIMIT, true).unwrap();
    let successor = dir.file("Successor.cbor", &next);
    let declared = completed(&old, &next, &keys, 80);
    let declaration = dir.file("Declaration.cbor", declared.envelope());
    let ledger = dir.0.join("Ledger");
    run(Command::Initialise {
        previous_profile: previous.clone(),
        predecessor_directory: floor(&dir, &old),
        directory: ledger.clone(),
    })
    .unwrap();
    let profile = dir.0.join("Successor.json");
    let receipt = dir.0.join("Acceptance.cbor");
    // Interrupt between durable acceptance and its output publication.
    std::fs::create_dir(&receipt).unwrap();
    std::fs::set_permissions(&receipt, std::fs::Permissions::from_mode(0o700)).unwrap();
    let request = || Command::Accept {
        previous_profile: previous.clone(),
        directory: ledger.clone(),
        declaration: declaration.clone(),
        successor_bootstrap: successor.clone(),
        successor_fingerprint: hex::encode(trust_wire::digest(&next)),
        output_profile: profile.clone(),
        output_acceptance: receipt.clone(),
    };
    assert!(run(request()).is_err());
    let retained = Store::open(&ledger).unwrap();
    let saved_profile = retained.state.accepted.as_ref().unwrap().profile.clone();
    drop(retained);
    std::fs::remove_dir(&receipt).unwrap();
    run(request()).unwrap();
    assert_eq!(
        hex::encode(files::read_single(&profile, PROFILE_LIMIT, true).unwrap()),
        saved_profile
    );
    run(request()).unwrap();
    let (fresh, _) = load(&profile).unwrap();
    let (original, _) = load(&previous).unwrap();
    assert_ne!(fresh.device.public_key, original.device.public_key);
    assert_ne!(
        fresh.relay_identity.public_key,
        original.relay_identity.public_key
    );
    assert_eq!(fresh.minimum_route, original.minimum_route);
    assert_eq!(
        fresh.required_publication_modes,
        original.required_publication_modes
    );
    assert_eq!(
        files::read_single(&previous, PROFILE_LIMIT, true).unwrap(),
        previous_bytes
    );
    let conflict = completed(&old, &other, &[keys[0].clone(), keys[2].clone()], 81);
    let conflict_file = dir.file("Conflicting.cbor", conflict.envelope());
    assert!(
        run(Command::Observe {
            directory: ledger.clone(),
            declaration: conflict_file
        })
        .is_err()
    );
    assert!(Store::open(&ledger).unwrap().state.conflicts());
    assert!(load(&profile).is_err());
    assert!(run(request()).is_err());
    assert!(load(&previous).is_ok());
}
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[test]
fn recovery_cli_requires_explicit_independent_successor_binding() {
    let args = [
        "HyperNetSuite",
        "accept",
        "--previous-profile",
        "/Private/Old.json",
        "--directory",
        "/Private/Recovery",
        "--declaration",
        "/Private/Declaration.cbor",
        "--successor-bootstrap",
        "/Private/New.cbor",
        "--output-profile",
        "/Private/New.json",
        "--output-acceptance",
        "/Private/Acceptance.cbor",
    ];
    assert!(Cli::try_parse_from(args).is_err());
    let mut complete = args.to_vec();
    let fingerprint = "01".repeat(32);
    complete.extend(["--successor-fingerprint", &fingerprint]);
    assert!(Cli::try_parse_from(complete).is_ok());
}

#[test]
fn recovery_later_epoch_anchor_requires_the_complete_verified_archive() {
    let dir = Directory::new();
    let (bootstrap, _) = fixture(20, time().unwrap());
    let checked = trust::inspect(&bootstrap, true).unwrap();
    let mut voters = (1..=4)
        .map(|n| SigningKey::from_bytes(&[n; 32]))
        .collect::<Vec<_>>();
    voters.sort_by_key(|k| k.verifying_key().to_bytes());
    let f = crate::authority_epoch::tests::fixture(
        checked.descriptor(),
        &checked.descriptor().genesis().unwrap(),
        None,
        &[],
        &voters,
    );
    let seal = archive::Seal::new(
        &f.terminal,
        archive::Retained {
            certificate: None,
            node: None,
            checkpoint: None,
        },
    )
    .unwrap();
    let epochs = vec![seal.activate(&f.activation).unwrap()];
    let later = predecessor(&bootstrap, None, &epochs).unwrap();
    assert_eq!(later.point().array(3).unwrap()[0].uint().unwrap(), 1);
    assert_ne!(
        later.point(),
        predecessor(&bootstrap, None, &[]).unwrap().point()
    );
    // A genesis-only requester floor cannot claim a later epoch from an unrelated file.
    let retained = retained_predecessor(&bootstrap, &floor(&dir, &bootstrap)).unwrap();
    assert_ne!(retained.point(), later.point());
    let (unrelated, _) = fixture(24, time().unwrap());
    assert!(predecessor(&unrelated, None, &epochs).is_err());
    let mut corrupted = serde_json::to_value(&epochs).unwrap();
    corrupted[0]["ready"] = serde_json::json!("00");
    let corrupted: Vec<Activated> = serde_json::from_value(corrupted).unwrap();
    assert!(predecessor(&bootstrap, None, &corrupted).is_err());
}
