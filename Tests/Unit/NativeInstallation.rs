// SPDX-License-Identifier: MIT
// Real signed inert packages exercise retained targets, interrupted pair install and path binding.
use super::*;
use std::process::Command as Process;
struct Fixture {
    path: PathBuf,
    publisher: String,
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("HyperNetPairTest-{}", files::random()));
        files::directory(&path).unwrap();
        let output = Process::new("/usr/bin/python3")
            .arg("-B")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/Tests/NativeInstallationFixture.py"
            ))
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        Self {
            path,
            publisher: value["rootPin"].as_str().unwrap().into(),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
#[test]
fn signed_pair_reuses_exact_prefixes_and_refuses_modified_index_or_files() {
    let f = Fixture::new();
    let root = f.path.join("Installation");
    let packages = f.path.join("Packages");
    let result = install(&root, &packages, &f.publisher).unwrap();
    assert_eq!(result, inspect(&root, &f.publisher).unwrap());
    assert_eq!(result, install(&root, &packages, &f.publisher).unwrap());
    assert_eq!(
        std::fs::read_dir(root.join("Products/Suite/Installed"))
            .unwrap()
            .count(),
        1
    );
    let mut forged = result.clone();
    forged.suite_executable = PathBuf::from("/usr/bin/other");
    files::publish(
        &root.join("Installation.json"),
        &serde_json::to_vec(&forged).unwrap(),
    )
    .unwrap();
    assert!(inspect(&root, &f.publisher).is_err());
    files::publish(
        &root.join("Installation.json"),
        &serde_json::to_vec(&result).unwrap(),
    )
    .unwrap();
    std::fs::write(result.packages.core.prefix.join("ReadMe.md"), b"Changed").unwrap();
    assert!(inspect(&root, &f.publisher).is_err());
}
#[test]
fn refused_second_package_leaves_no_index_and_exact_retry_retains_first_floor() {
    let f = Fixture::new();
    let root = f.path.join("Installation");
    let packages = f.path.join("Packages");
    let signature = packages.join("Suite/HyperNetSuite-0.11.0-linux-x86_64.target.json.sig");
    let original = std::fs::read(&signature).unwrap();
    std::fs::write(&signature, b"Invalid signature").unwrap();
    assert!(install(&root, &packages, &f.publisher).is_err());
    assert!(!root.join("Installation.json").exists());
    let trust = std::fs::read(root.join("Products/Core/Trust/Trust.json")).unwrap();
    std::fs::write(&signature, original).unwrap();
    let installed = install(&root, &packages, &f.publisher).unwrap();
    assert_eq!(
        trust,
        std::fs::read(root.join("Products/Core/Trust/Trust.json")).unwrap()
    );
    assert_eq!(inspect(&root, &f.publisher).unwrap(), installed);
    assert!(inspect(&root, PUBLISHER).is_err());
}
