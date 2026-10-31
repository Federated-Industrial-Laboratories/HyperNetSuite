// SPDX-License-Identifier: MIT
use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "HyperNetDiagnostics{}",
            hex::encode(crate::networks::random())
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        files::Destination::open(&path)
            .unwrap()
            .publish(bytes)
            .unwrap();
        path
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn malformed_private_input_has_one_fixed_redacted_snapshot() {
    let directory = Directory::new();
    let missing = encode(&collect(&directory.0.join("Absent.json"))).unwrap();
    let marker = "SecretCanary\u{1b}[31mhttps://private.invalid/query?needle=classified";
    let malicious = directory.write(
        "Injected.json",
        &serde_json::to_vec(&json!({"secretKey": marker, "error": marker})).unwrap(),
    );
    assert_eq!(encode(&collect(&malicious)).unwrap(), missing);
    let oversized = directory.write(
        "Oversized.json",
        &vec![b'x'; super::super::PROFILE_LIMIT + 1],
    );
    assert_eq!(encode(&collect(&oversized)).unwrap(), missing);
    let link = directory.0.join("Linked.json");
    symlink(malicious, &link).unwrap();
    assert_eq!(encode(&collect(&link)).unwrap(), missing);
    let value: serde_json::Value = serde_json::from_slice(&missing).unwrap();
    assert_eq!(value["profile"]["state"], "UnavailableOrInvalid");
    assert!(value["profile"]["permitsNetworkSearch"].is_null());
    assert_eq!(value["currentAuthority"], false);
    assert_eq!(value["networkUsed"], false);
    let text = String::from_utf8(missing).unwrap();
    for forbidden in [
        marker,
        "SecretCanary",
        "secretKey",
        "private.invalid",
        directory.0.to_str().unwrap(),
    ] {
        assert!(!text.contains(forbidden));
    }
}

#[test]
fn route_inventory_exports_only_bounded_counts() {
    let directory = Directory::new();
    let retained = [
        workflow::SavedRoute {
            service: "11".repeat(32),
            subject: "22".repeat(32),
            protocol: 2,
            route_digest: "33".repeat(32),
        },
        workflow::SavedRoute {
            service: "44".repeat(32),
            subject: "55".repeat(32),
            protocol: 6,
            route_digest: "66".repeat(32),
        },
    ];
    let path = directory.write("Routes.json", &serde_json::to_vec(&retained).unwrap());
    let summary = serde_json::to_value(routes(&directory.0)).unwrap();
    assert_eq!(
        summary,
        json!({"state":"RetainedInventory", "count":2, "countsByProtocol":[0,1,0,0,0,1]})
    );
    fs::write(
        &path,
        br#"[{"service":"SecretCanary","error":"\u001b[31m"}]"#,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(routes(&directory.0)).unwrap(),
        json!({"state":"UnavailableOrInvalid", "count":null, "countsByProtocol":null})
    );
}

#[test]
fn export_binds_exact_preview_bytes_and_refuses_changed_selection() {
    let directory = Directory::new();
    let mut snapshot = collect(&directory.0.join("Absent.json"));
    let preview = encode(&snapshot).unwrap();
    let expected = digest(&preview);
    snapshot.profile.permits_network_search = Some(true);
    let changed = encode(&snapshot).unwrap();
    let output = directory.0.join("Report.json");
    assert_eq!(
        export(&changed, &expected, &output)
            .unwrap_err()
            .to_string(),
        "DiagnosticSnapshotChanged"
    );
    assert!(!output.exists());
    assert_eq!(
        export(&preview, "Canary\u{1b}", &output)
            .unwrap_err()
            .to_string(),
        "DiagnosticPreviewDigestInvalid"
    );
    assert!(!output.exists());
    export(&preview, &expected, &output).unwrap();
    assert_eq!(fs::read(&output).unwrap(), preview);
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn diagnostic_export_never_overwrites_or_follows_destination_links() {
    let directory = Directory::new();
    let bytes = encode(&collect(&directory.0.join("Absent.json"))).unwrap();
    let expected = digest(&bytes);
    let existing = directory.write("Existing.json", b"KeepMe");
    assert_eq!(
        export(&bytes, &expected, &existing)
            .unwrap_err()
            .to_string(),
        "DiagnosticOutputUnavailable"
    );
    assert_eq!(fs::read(&existing).unwrap(), b"KeepMe");
    let link = directory.0.join("Linked.json");
    symlink(&existing, &link).unwrap();
    assert!(export(&bytes, &expected, &link).is_err());
    assert_eq!(fs::read(existing).unwrap(), b"KeepMe");
    let linked_parent = directory.0.join("LinkedDirectory");
    symlink(&directory.0, &linked_parent).unwrap();
    assert!(export(&bytes, &expected, &linked_parent.join("New.json")).is_err());
    assert!(!directory.0.join("New.json").exists());
}
