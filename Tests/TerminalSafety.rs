// SPDX-License-Identifier: MIT
// Imported documents and path-bearing diagnostics cannot execute terminal controls.
use serde_json::json;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn command(args: &[&str]) -> Output {
    Command::new(
        std::env::var_os("HYPERNET_SUITE_BIN")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_HyperNetSuite").into()),
    )
    .args(args)
    .output()
    .unwrap()
}

fn private_json(path: &Path, value: &serde_json::Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn safe_failure(output: Output) {
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("\\u"));
    for bytes in [&output.stdout, &output.stderr] {
        let text = std::str::from_utf8(bytes).unwrap();
        assert!(!text.chars().any(|ch| {
            (ch.is_control() && ch != '\n')
                || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}')
                || ('\u{202a}'..='\u{202e}').contains(&ch)
                || ('\u{2066}'..='\u{2069}').contains(&ch)
        }));
    }
}

#[test]
fn imported_documents_and_paths_are_terminal_safe() {
    let root = std::env::temp_dir().join(format!("HyperNetTerminal{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let _fixture = Fixture(root.clone());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let identity = root.join("Identity.json");
    assert!(
        command(&["keygen", "--output", identity.to_str().unwrap()])
            .status
            .success()
    );
    let key: serde_json::Value = serde_json::from_slice(&fs::read(&identity).unwrap()).unwrap();
    let profile = root.join("Profile.json");
    private_json(
        &profile,
        &json!({
            "network":"00".repeat(32), "endpoint":"https://authority.invalid/",
            "caCertificate":root.join("MissingCa.pem"), "identity":identity
        }),
    );
    let control = "\u{001b}]2;InjectedTitle\u{0007}\u{009b}2J\u{202e}\u{2066}\u{061c}";
    let document = root.join("Imported.json");
    private_json(&document, &json!({(control): true}));
    safe_failure(command(&[
        "--config",
        profile.to_str().unwrap(),
        "redeem",
        "--invitation",
        document.to_str().unwrap(),
    ]));
    safe_failure(command(&[
        "--config",
        profile.to_str().unwrap(),
        "host-consent",
        "--spec",
        document.to_str().unwrap(),
        "--output",
        root.join("Consent.json").to_str().unwrap(),
    ]));
    safe_failure(command(&["--config", document.to_str().unwrap(), "status"]));
    safe_failure(command(&[&format!("--{control}")]));
    let expiry = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 60)
        .to_string();
    let invitation = root.join(format!("Invitation{control}.json"));
    let output = command(&[
        "--config",
        profile.to_str().unwrap(),
        "invite",
        "--device-key",
        key["publicKey"].as_str().unwrap(),
        "--grants",
        "1",
        "--expires",
        &expiry,
        "--output",
        invitation.to_str().unwrap(),
    ]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("Invitation material retained"));
    safe_failure(output);
    assert!(invitation.is_file());
    fs::remove_dir_all(root).unwrap();
}
