// SPDX-License-Identifier: MIT
// Transient observations retain their measured validity through publication and replacement.
use super::*;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "HyperNetClockPublication{}",
            crate::random_hex::<16>()
        ));
        files::create_directory(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn sample() -> observation::Witness {
    observation::Witness {
        version: 1,
        kernel_boot: observation::kernel_boot().unwrap(),
        sample_wall_ms: 10000,
        sample_boot_ms: 2000,
        valid_until_boot_ms: 3000,
        maximum_error_ms: 20,
        source: "162.159.200.1".parse().unwrap(),
    }
}
fn at(boot_ms: u64) -> observation::Moment {
    observation::Moment {
        wall_ms: 8000 + boot_ms,
        boot_ms,
    }
}
fn names(directory: &Path) -> Vec<String> {
    std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect()
}

#[test]
fn publication_is_atomic_private_and_preserves_the_original_ttl() {
    let directory = Directory::new();
    let fd = files::private_directory(&directory.0).unwrap();
    let path = directory.0.join("ClockHealth.json");
    let witness = sample();
    publish(&fd, &witness, || Ok(at(2000))).unwrap();
    let mut opened = File::open(&path).unwrap();
    let original_inode = opened.metadata().unwrap().ino();
    let mut replacement = witness.clone();
    replacement.sample_wall_ms += 100;
    replacement.sample_boot_ms += 100;
    replacement.valid_until_boot_ms += 100;
    publish(&fd, &replacement, || Ok(at(2150))).unwrap();
    let metadata = std::fs::metadata(&path).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert_ne!(metadata.ino(), original_inode);
    assert_eq!(opened.metadata().unwrap().nlink(), 0);
    let mut original = Vec::new();
    opened.read_to_end(&mut original).unwrap();
    assert_eq!(original, serde_json::to_vec(&witness).unwrap());
    assert_eq!(
        std::fs::read(path).unwrap(),
        serde_json::to_vec(&replacement).unwrap()
    );
    assert_eq!(names(&directory.0), ["ClockHealth.json"]);
}

#[test]
fn publication_refuses_expired_entry_and_reports_expiry_after_rename() {
    let directory = Directory::new();
    let fd = files::private_directory(&directory.0).unwrap();
    let witness = sample();
    let error = publish(&fd, &witness, || Ok(at(3000))).unwrap_err();
    assert!(error.is::<authority_clock::ObservationExpired>());
    assert!(names(&directory.0).is_empty());
    let mut observations = 0;
    let error = publish(&fd, &witness, || {
        observations += 1;
        Ok(at(if observations == 1 { 2000 } else { 3000 }))
    })
    .unwrap_err();
    assert!(error.is::<authority_clock::ObservationExpired>());
    assert_eq!(observations, 2);
    assert_eq!(
        std::fs::read(directory.0.join("ClockHealth.json")).unwrap(),
        serde_json::to_vec(&witness).unwrap()
    );
    assert_eq!(names(&directory.0), ["ClockHealth.json"]);
}

#[test]
fn failed_rename_removes_exclusive_staging_file() {
    let directory = Directory::new();
    let fd = files::private_directory(&directory.0).unwrap();
    std::fs::create_dir(directory.0.join("ClockHealth.json")).unwrap();
    assert!(publish(&fd, &sample(), || Ok(at(2000))).is_err());
    assert_eq!(names(&directory.0), ["ClockHealth.json"]);
}

#[test]
fn expired_probe_budget_never_launches_chronyc() {
    let directory = Directory::new();
    let marker = directory.0.join("Launched");
    let executable = directory.0.join("Chronyc");
    std::fs::write(
        &executable,
        format!("#!/bin/sh\n: > '{}'\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let options = Options {
        directory: directory.0.clone(),
        chronyc: executable,
        socket: directory.0.join("Unused.sock"),
    };
    assert!(
        query(
            &options,
            "tracking",
            crate::authority_challenge::boot_time_ms().unwrap()
        )
        .is_err()
    );
    assert!(!marker.exists());
}
