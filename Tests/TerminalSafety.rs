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
    let control = "\u{001b}]2;InjectedTitle\u{0007}\u{009b}2J\u{202e}\u{2066}\u{061c}";
    let document = root.join("Imported.json");
    private_json(&document, &json!({(control): true}));
    safe_failure(command(&[
        "network",
        "draft",
        "--spec",
        document.to_str().unwrap(),
        "--output",
        root.join("Draft.cbor").to_str().unwrap(),
    ]));
    safe_failure(command(&[
        "network",
        "inspect",
        "--profile",
        document.to_str().unwrap(),
    ]));
    safe_failure(command(&[&format!("--{control}")]));
    let output = command(&[
        "keygen",
        "--output",
        root.join(format!("Identity{control}.json"))
            .to_str()
            .unwrap(),
    ]);
    assert!(output.status.success());
    let text = std::str::from_utf8(&output.stdout).unwrap();
    assert!(text.contains("\\u"));
    assert!(!text.chars().any(|ch| ch.is_control() && ch != '\n'));
    assert!(!text.contains(['\u{202e}', '\u{2066}', '\u{061c}']));
    fs::remove_dir_all(root).unwrap();
}
