// SPDX-License-Identifier: MIT
// A certified successor cannot silently replace a reader's accepted trust contract.
use super::*;
use crate::authority_inspection::tests::Fixture;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

fn successor(policy: &[u8]) -> Vec<u8> {
    let mut fields = wire::decode(policy).unwrap().array(17).unwrap().to_vec();
    fields[4] = V::Uint(2);
    fields[5] = b(&wire::digest(policy));
    wire::encode(&a(fields)).unwrap()
}

#[test]
fn identical_policy_cache_keeps_its_durable_inode_and_changed_bytes_replace_it() {
    let f = Fixture::new();
    let (policy, recovery) = current(&f.bootstrap, &f.store).unwrap();
    for name in [PENDING, CURRENT] {
        retain_cached_pair(&f.store, name, &policy, &recovery).unwrap();
        let path = f.directory.0.join(name);
        let before = std::fs::metadata(&path).unwrap();
        retain_cached_pair(&f.store, name, &policy, &recovery).unwrap();
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(
            (after.ino(), after.mtime(), after.mtime_nsec()),
            (before.ino(), before.mtime(), before.mtime_nsec())
        );
        let changed = successor(&policy);
        retain_cached_pair(&f.store, name, &changed, &recovery).unwrap();
        assert_ne!(std::fs::metadata(&path).unwrap().ino(), before.ino());
        assert_eq!(
            read_pair(&f.store, name).unwrap().unwrap(),
            (changed, recovery.clone())
        );
    }
}

#[test]
fn policy_cache_no_op_never_accepts_malformed_or_unprotected_existing_files() {
    let f = Fixture::new();
    let (policy, recovery) = current(&f.bootstrap, &f.store).unwrap();
    let bytes = pair(&policy, &recovery).unwrap();
    for name in [PENDING, CURRENT] {
        let path = f.directory.0.join(name);
        for invalid in [
            "malformed",
            "unlinked-pair",
            "permissions",
            "symlink",
            "hardlink",
        ] {
            if path.exists() {
                std::fs::remove_file(&path).unwrap();
            }
            let other = f.directory.0.join("CacheTarget");
            if other.exists() {
                std::fs::remove_file(&other).unwrap();
            }
            match invalid {
                "malformed" => files::write_new(&path, b"Invalid").unwrap(),
                "unlinked-pair" => {
                    let mut fields = wire::decode(&policy).unwrap().array(17).unwrap().to_vec();
                    fields[12] = V::Null;
                    files::write_new(
                        &path,
                        &pair(&wire::encode(&a(fields)).unwrap(), &recovery).unwrap(),
                    )
                    .unwrap();
                }
                "permissions" => {
                    files::write_new(&path, &bytes).unwrap();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
                        .unwrap();
                }
                "symlink" => {
                    files::write_new(&other, &bytes).unwrap();
                    symlink(&other, &path).unwrap();
                }
                "hardlink" => {
                    files::write_new(&other, &bytes).unwrap();
                    std::fs::hard_link(&other, &path).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                retain_cached_pair(&f.store, name, &policy, &recovery).is_err(),
                "{name}: {invalid}"
            );
        }
        std::fs::remove_file(&path).unwrap();
    }
}

#[test]
fn changed_pending_policy_is_durable_before_floor_and_recovers_after_interruption() {
    use crate::authority_inspection::{
        read_client::tests::{response, submitted},
        tests::{receive_control, send_control},
    };
    use std::os::unix::net::UnixListener;
    let mut f = Fixture::new();
    let (old, recovery) = current(&f.bootstrap, &f.store).unwrap();
    retain_cached_pair(&f.store, CURRENT, &old, &recovery).unwrap();
    let changed = successor(&old);
    let scope = f.store.descriptor().scope();
    let refs = [100, 114]
        .into_iter()
        .zip([&changed, &recovery])
        .map(|(kind, bytes)| {
            policies::record_reference(bytes, scope.network, scope.incarnation, kind).unwrap()
        })
        .collect::<Vec<_>>();
    retain_cached_pair(&f.store, PENDING, &changed, &recovery).unwrap();
    assert_eq!(current(&f.bootstrap, &f.store).unwrap().0, old);
    let pending_path = f.directory.0.join(PENDING);
    let pending_inode = std::fs::metadata(&pending_path).unwrap().ino();
    let floor_path = f.directory.0.join("AuthorityFloor.json");
    let initial: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&floor_path).unwrap()).unwrap();
    let sequence = initial["sequence"].as_u64().unwrap();
    let socket = f.directory.0.join("PolicyRecovery.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityPolicyContext".into()),
        a(refs.iter().map(version_value).collect()),
        a(vec![b(&changed), b(&recovery)]),
    ]);
    let node = f.status_node.clone();
    let state = *f.store.prefix().policy_state();
    let evaluated = f.current.observe().unwrap().wall_ms;
    let server = std::thread::spawn(move || {
        let (stream, packet) = receive_control(&listener);
        let (request, challenge) = submitted(&packet);
        send_control(
            stream,
            &response(
                &request,
                &challenge,
                &node,
                state,
                value,
                evaluated,
                u64::MAX,
                0,
            ),
        );
    });
    let mut first = true;
    let error = discover(
        &f.bootstrap,
        &socket,
        &f.signer,
        &mut f.store,
        &mut f.session,
        || {
            if first {
                first = false;
                return Ok(f.issued);
            }
            let retained: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&floor_path)?).unwrap();
            if retained["sequence"].as_u64().unwrap() > sequence {
                anyhow::bail!("simulated interruption after durable floor");
            }
            Ok(f.current)
        },
    )
    .unwrap_err();
    server.join().unwrap();
    assert!(error.to_string().contains("simulated interruption"));
    assert_eq!(
        std::fs::metadata(&pending_path).unwrap().ino(),
        pending_inode
    );
    assert_eq!(read_pair(&f.store, CURRENT).unwrap().unwrap().0, old);
    let descriptor = f.store.descriptor().clone();
    drop(f.store);
    let reopened = Store::open(&f.directory.0, descriptor).unwrap();
    assert!(
        refs.iter()
            .all(|reference| reopened.generations().contains(reference))
    );
    assert_eq!(current(&f.bootstrap, &reopened).unwrap().0, changed);
    retain_pair(&reopened, &changed, &recovery).unwrap();
    assert_eq!(read_pair(&reopened, CURRENT).unwrap().unwrap().0, changed);
}

#[test]
fn slow_floor_then_cache_publication_keeps_the_original_read_expiry() {
    use crate::authority_inspection::{
        read_client::tests::{response, submitted},
        tests::{receive_control, send_control},
    };
    use std::os::unix::net::UnixListener;
    for changed in [false, true] {
        let mut f = Fixture::new();
        let (old, recovery) = current(&f.bootstrap, &f.store).unwrap();
        for name in [PENDING, CURRENT] {
            retain_cached_pair(&f.store, name, &old, &recovery).unwrap();
        }
        let selected = if changed {
            successor(&old)
        } else {
            old.clone()
        };
        let scope = f.store.descriptor().scope();
        let refs = [100, 114]
            .into_iter()
            .zip([&selected, &recovery])
            .map(|(kind, bytes)| {
                policies::record_reference(bytes, scope.network, scope.incarnation, kind).unwrap()
            })
            .collect::<Vec<_>>();
        let current_path = f.directory.0.join(CURRENT);
        let current_inode = std::fs::metadata(&current_path).unwrap().ino();
        let floor_path = f.directory.0.join("AuthorityFloor.json");
        let initial: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&floor_path).unwrap()).unwrap();
        let sequence = initial["sequence"].as_u64().unwrap();
        let socket = f.directory.0.join("SlowPolicy.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let value = a(vec![
            V::Uint(201),
            V::Uint(1),
            V::Text("AuthorityPolicyContext".into()),
            a(refs.iter().map(version_value).collect()),
            a(vec![b(&selected), b(&recovery)]),
        ]);
        let node = f.status_node.clone();
        let state = *f.store.prefix().policy_state();
        let at = f.current.observe().unwrap();
        let server = std::thread::spawn(move || {
            let (stream, packet) = receive_control(&listener);
            let (request, challenge) = submitted(&packet);
            send_control(
                stream,
                &response(
                    &request,
                    &challenge,
                    &node,
                    state,
                    value,
                    at.wall_ms,
                    u64::MAX,
                    0,
                ),
            );
        });
        let mut first = true;
        let result = discover(
            &f.bootstrap,
            &socket,
            &f.signer,
            &mut f.store,
            &mut f.session,
            || {
                if first {
                    first = false;
                    return Ok(f.issued);
                }
                let retained: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&floor_path)?).unwrap();
                // Model a slow durable floor with150ms conservative validity left.
                // A visible subsequent cache publication consumes another200ms.
                // Inode identity makes this independent of host scheduling/fsync speed.
                let elapsed = if std::fs::metadata(&current_path)?.ino() != current_inode {
                    2800
                } else if retained["sequence"].as_u64().unwrap() > sequence {
                    2600
                } else {
                    1600
                };
                Ok(ClockHealth::new(
                    at.wall_ms + elapsed,
                    at.boot_ms + elapsed,
                    at.boot_ms + 30000,
                    100,
                )?
                .frozen())
            },
        );
        server.join().unwrap();
        if changed {
            assert!(
                result
                    .unwrap_err()
                    .is::<crate::authority_floor::ReadExpired>()
            );
            assert_ne!(
                std::fs::metadata(&current_path).unwrap().ino(),
                current_inode
            );
        } else {
            result.unwrap();
            assert_eq!(
                std::fs::metadata(&current_path).unwrap().ino(),
                current_inode
            );
        }
        assert!(
            refs.iter()
                .all(|reference| f.store.generations().contains(reference))
        );
        assert!(f.store.resume_ordinary().unwrap().is_none());
    }
}
#[test]
fn weaker_candidate_is_refused_before_use_and_non_policy_records_do_not_change_trust() {
    let f = Fixture::new();
    let (p, r) = current(&f.bootstrap, &f.store).unwrap();
    let mut fields = wire::decode(&p).unwrap().array(17).unwrap().to_vec();
    fields[4] = V::Uint(2);
    fields[5] = b(&wire::digest(&p));
    fields[8] = V::Uint(0);
    let weaker = wire::encode(&a(fields)).unwrap();
    let candidate = vec![weaker, r];
    assert!(require_records_accepted(&f.bootstrap, &f.store, &candidate).is_err());
    assert!(retain_records(&f.bootstrap, &f.store, &candidate).is_err());
    assert_eq!(current(&f.bootstrap, &f.store).unwrap().0, p);
    let unrelated = wire::encode(&a(vec![V::Uint(169), V::Uint(1)])).unwrap();
    require_records_accepted(&f.bootstrap, &f.store, &[unrelated]).unwrap();
}
#[test]
fn discovery_requires_exact_linked_custody_and_current_candidate_references() {
    let f = Fixture::new();
    let (p, r) = current(&f.bootstrap, &f.store).unwrap();
    let scope = f.store.descriptor().scope();
    let refs = [100, 114]
        .into_iter()
        .zip([&p, &r])
        .map(|(kind, bytes)| {
            policies::record_reference(bytes, scope.network, scope.incarnation, kind).unwrap()
        })
        .collect::<Vec<_>>();
    let mut value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityPolicyContext".into()),
        a(refs.iter().map(version_value).collect()),
        a(vec![b(&p), b(&r)]),
    ]);
    discovery::pair_from_value(&value, scope.network, scope.incarnation).unwrap();
    let V::Array(fields) = &mut value else {
        unreachable!()
    };
    fields[3] = a(vec![version_value(&refs[0]), version_value(&refs[0])]);
    assert!(discovery::pair_from_value(&value, scope.network, scope.incarnation).is_err());
}

#[test]
fn policy_discovery_prepares_transport_before_sampling_challenge_clock() {
    let mut f = Fixture::new();
    let socket = f.directory.0.join("Unavailable.sock");
    let prefix = f.store.prefix().clone();
    let mut sampled = false;
    let error = discover(
        &f.bootstrap,
        &socket,
        &f.signer,
        &mut f.store,
        &mut f.session,
        || {
            sampled = true;
            Ok(f.issued)
        },
    )
    .unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
    assert!(
        !sampled,
        "transport preparation consumed challenge freshness"
    );
    assert!(f.store.resume_ordinary().unwrap().is_none());
    assert_eq!(f.store.prefix(), &prefix);
}

#[test]
fn fresh_discovery_does_not_replace_or_resolve_pending_domain_intent() {
    let mut f = Fixture::new();
    let descriptor = f.store.descriptor().clone();
    let original = prepare_ordinary(
        &descriptor,
        &f.signer,
        &mut f.store,
        "AuthorityDomain",
        [9; 32],
        0,
        &[],
        &wire::encode(&a(vec![])).unwrap(),
    )
    .unwrap();
    let prefix = f.store.prefix().clone();
    discover(
        &f.bootstrap,
        &f.directory.0.join("Absent.sock"),
        &f.signer,
        &mut f.store,
        &mut f.session,
        || panic!("pending recovery must not issue a fresh challenge"),
    )
    .unwrap();
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        original
    );
    assert_eq!(f.store.prefix(), &prefix);
}
