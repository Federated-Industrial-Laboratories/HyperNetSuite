// SPDX-License-Identifier: MIT
use super::*;
use crate::trust_wire::Value as V;
use ed25519_dalek::SigningKey;
use std::os::unix::fs::{PermissionsExt, symlink};

const BOOT: &str = "12345678-1234-1234-1234-123456789abc";
fn key() -> SigningKey {
    SigningKey::from_bytes(&[61; 32])
}
fn fields(now: Observation) -> Vec<V> {
    vec![
        V::Uint(44),
        V::Uint(1),
        V::Text(BOOT.into()),
        V::Uint(now.wall_ms),
        V::Uint(now.boot_ms),
        V::Uint(now.boot_ms + 1000),
        V::Uint(20),
        V::Text("162.159.200.1".into()),
    ]
}
fn encoded(fields: Vec<V>) -> Vec<u8> {
    wire::sign_envelope(&wire::encode(&V::Array(fields)).unwrap(), &key()).unwrap()
}
fn sample() -> Observation {
    Observation {
        wall_ms: 10000,
        boot_ms: 2000,
    }
}
fn accepted(bytes: &[u8], now: Observation) -> bool {
    signed(bytes, key().verifying_key().to_bytes(), BOOT, now).is_ok()
}

#[test]
fn signed_observation_requires_the_exact_monitor_host_boot_and_signature() {
    let bytes = encoded(fields(sample()));
    assert!(accepted(&bytes, sample()));
    let other = SigningKey::from_bytes(&[62; 32]).verifying_key().to_bytes();
    assert!(signed(&bytes, other, BOOT, sample()).is_err());
    assert!(
        signed(
            &bytes,
            key().verifying_key().to_bytes(),
            "22345678-1234-1234-1234-123456789abc",
            sample()
        )
        .is_err()
    );
    let mut tampered = bytes.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(!accepted(&tampered, sample()));
    let value = wire::decode(&bytes).unwrap();
    let mut envelope = value.array(4).unwrap().to_vec();
    envelope[3] = V::Array(vec![]);
    assert!(!accepted(
        &wire::encode(&V::Array(envelope.clone())).unwrap(),
        sample()
    ));
    let signer = value.array(4).unwrap()[3].array(1).unwrap()[0].clone();
    envelope[3] = V::Array(vec![signer.clone(), signer]);
    assert!(!accepted(
        &wire::encode(&V::Array(envelope)).unwrap(),
        sample()
    ));
}

#[test]
fn signed_clock_has_one_exact_schema_and_canonical_source_address() {
    for (index, replacement) in [
        (0, V::Uint(43)),
        (1, V::Uint(2)),
        (2, V::Text("00000000-0000-0000-0000-000000000000".into())),
        (3, V::Text("10000".into())),
        (5, V::Uint(3001)),
        (6, V::Uint(251)),
        (7, V::Text("clock.example".into())),
        (7, V::Text("127.0.0.1".into())),
        (7, V::Text("0.0.0.0".into())),
        (7, V::Text("::".into())),
        (7, V::Text("::1".into())),
        (7, V::Text("2001:0db8::1".into())),
    ] {
        let mut value = fields(sample());
        value[index] = replacement;
        assert!(!accepted(&encoded(value), sample()), "field {index}");
    }
    let mut value = fields(sample());
    value[7] = V::Text("2001:db8::1".into());
    assert!(accepted(&encoded(value), sample()));
    let mut short = fields(sample());
    short.pop();
    assert!(!accepted(&encoded(short), sample()));
    let mut long = fields(sample());
    long.push(V::Null);
    assert!(!accepted(&encoded(long), sample()));
    for boot in [
        "",
        "12345678-1234-1234-1234-123456789ABC",
        "12345678123412341234123456789abc",
    ] {
        let mut value = fields(sample());
        value[2] = V::Text(boot.into());
        assert!(
            signed(
                &encoded(value),
                key().verifying_key().to_bytes(),
                boot,
                sample()
            )
            .is_err()
        );
    }
}

#[test]
fn expiry_and_progression_consume_the_single_declared_error_budget() {
    let bytes = encoded(fields(sample()));
    assert!(accepted(
        &bytes,
        Observation {
            wall_ms: 10999,
            boot_ms: 2999
        }
    ));
    for now in [
        Observation {
            wall_ms: 11000,
            boot_ms: 3000,
        },
        Observation {
            wall_ms: 9999,
            boot_ms: 1999,
        },
        Observation {
            wall_ms: 10331,
            boot_ms: 2100,
        },
    ] {
        assert!(!accepted(&bytes, now));
    }
    assert!(accepted(
        &bytes,
        Observation {
            wall_ms: 10330,
            boot_ms: 2100
        }
    ));
    let mut bounded = fields(sample());
    bounded[6] = V::Uint(250);
    let bytes = encoded(bounded);
    assert!(accepted(&bytes, sample()));
    assert!(!accepted(
        &bytes,
        Observation {
            wall_ms: 10001,
            boot_ms: 2000
        }
    ));
    let mut overflow = fields(sample());
    overflow[3] = V::Uint(u64::MAX);
    assert!(!accepted(
        &encoded(overflow),
        Observation {
            wall_ms: 0,
            boot_ms: 2001
        }
    ));
    let mut overflow = fields(sample());
    overflow[4] = V::Uint(u64::MAX);
    assert!(!accepted(&encoded(overflow), sample()));
}

#[test]
fn signed_source_requires_unshifted_monotonic_and_boot_clocks() {
    assert!(
        unshifted_report("monotonic           0         0\nboottime            0         0\n")
            .is_ok()
    );
    for text in [
        "",
        "monotonic 0 0\n",
        "monotonic 0 0\nboottime 0 1\n",
        "monotonic 1 0\nboottime 0 0\n",
        "monotonic -1 0\nboottime 0 0\n",
        "monotonic +0 0\nboottime 0 0\n",
        "boottime 0 0\nmonotonic 0 0\n",
        "monotonic 0 0\nmonotonic 0 0\n",
        "monotonic 0 0\nboottime 0 0\nextra 0 0\n",
    ] {
        assert!(unshifted_report(text).is_err());
    }
    assert!(unshifted_report(&" ".repeat(257)).is_err());
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("HyperNetClock{}", crate::random_hex::<16>()));
        transfer_files::create_directory(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn private_bytes(now: Observation) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "version":1,"kernelBoot":std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap().trim(),
        "sampleWallMs":now.wall_ms,"sampleBootMs":now.boot_ms,
        "validUntilBootMs":now.boot_ms+1000,"maximumErrorMs":20,"source":"162.159.200.1"
    })).unwrap()
}

#[test]
fn atomic_clock_replacement_preserves_opened_observations_without_extending_validity() {
    let directory = Directory::new();
    let parent = transfer_files::directory(&directory.0).unwrap();
    let path = directory.0.join("ClockHealth.cbor");
    let original = encoded(fields(sample()));
    transfer_files::write_new(&path, &original).unwrap();
    let valid = open_observation(&path, false).unwrap();
    let expired = open_observation(&path, false).unwrap();
    let wrong_pin = open_observation(&path, false).unwrap();
    let later = Observation {
        wall_ms: 11000,
        boot_ms: 3000,
    };
    transfer_files::atomic_at(
        &parent,
        path.file_name().unwrap(),
        &encoded(fields(later)),
        true,
    )
    .unwrap();
    for (file, now, pin, expected) in [
        (valid, sample(), key().verifying_key().to_bytes(), true),
        (expired, later, key().verifying_key().to_bytes(), false),
        (
            wrong_pin,
            sample(),
            SigningKey::from_bytes(&[62; 32]).verifying_key().to_bytes(),
            false,
        ),
    ] {
        assert_eq!(file.metadata().unwrap().nlink(), 0);
        let bytes = read_opened_observation(file, false).unwrap();
        assert_eq!(bytes, original);
        assert_eq!(signed(&bytes, pin, BOOT, now).is_ok(), expected);
    }

    let path = directory.0.join("ClockHealth.json");
    transfer_files::write_new(&path, &private_bytes(sample())).unwrap();
    let valid = open_observation(&path, true).unwrap();
    let exposed = open_observation(&path, true).unwrap();
    transfer_files::atomic_at(
        &parent,
        path.file_name().unwrap(),
        &private_bytes(later),
        true,
    )
    .unwrap();
    assert_eq!(valid.metadata().unwrap().nlink(), 0);
    let witness: Witness =
        serde_json::from_slice(&read_opened_observation(valid, true).unwrap()).unwrap();
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    assert!(witness.health(boot.trim(), sample()).is_ok());
    assert!(witness.health(boot.trim(), later).is_err());
    exposed
        .set_permissions(std::fs::Permissions::from_mode(0o644))
        .unwrap();
    assert_eq!(exposed.metadata().unwrap().nlink(), 0);
    assert!(read_opened_observation(exposed, true).is_err());
}

#[test]
fn private_clock_retains_owner_permissions_and_never_falls_back_to_signed() {
    let directory = Directory::new();
    let path = directory.0.join("ClockHealth.json");
    transfer_files::write_new(&path, &private_bytes(moment().unwrap())).unwrap();
    let source = Source::select(&path, None, None).unwrap();
    assert!(source.health().is_ok());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(source.health().is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let signed_source = Source::select(
        &path,
        Some(&hex::encode(key().verifying_key().to_bytes())),
        Some(BOOT),
    )
    .unwrap();
    assert!(signed_source.health().is_err());
    std::fs::write(&path, encoded(fields(moment().unwrap()))).unwrap();
    assert!(source.health().is_err());
}

#[test]
fn public_signed_export_uses_host_pin_and_rejects_replaced_file_shapes() {
    let directory = Directory::new();
    let path = directory.0.join("ClockHealth.cbor");
    transfer_files::write_new(&path, &encoded(fields(moment().unwrap()))).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let public = hex::encode(key().verifying_key().to_bytes());
    let source = Source::select(&path, Some(&public), Some(BOOT)).unwrap();
    assert!(source.health().is_ok());
    let link = directory.0.join("ClockLink.cbor");
    symlink(&path, &link).unwrap();
    assert!(
        Source::select(&link, Some(&public), Some(BOOT))
            .unwrap()
            .health()
            .is_err()
    );
    std::fs::remove_file(&link).unwrap();
    std::fs::hard_link(&path, &link).unwrap();
    assert!(source.health().is_err());
    std::fs::remove_file(&link).unwrap();
    std::fs::write(&path, vec![0; 4097]).unwrap();
    assert!(source.health().is_err());
}
