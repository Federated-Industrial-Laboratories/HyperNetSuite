// SPDX-License-Identifier: MIT
// Exercise unsent-proof cleanup through the real client, requester floor and private transport.
use super::*;
use crate::authority_challenge::{ClockHealth, boot_time_ms};
use std::{
    fs,
    io::ErrorKind,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

struct Fixture {
    client: Client,
    proof: streams::Proof,
    listener: UnixListener,
    directory: PathBuf,
}
fn publish_clock(directory: &Path) -> (u64, u64) {
    let boot = boot_time_ms().unwrap();
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let clock = directory.join("Clock.json");
    fs::write(
        &clock,
        serde_json::to_vec(&json!({
            "version":1,
            "kernelBoot":fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap().trim(),
            "sampleWallMs":wall,
            "sampleBootMs":boot,
            "validUntilBootMs":boot+1000,
            "maximumErrorMs":1,
            "source":"192.0.2.1"
        }))
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&clock, fs::Permissions::from_mode(0o600)).unwrap();
    (boot, wall)
}
impl Fixture {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("ApplicationCleanup{}", crate::random_hex::<8>()));
        files::create_directory(&directory).unwrap();
        let fixture = crate::authority_deployment_tests::Fixture::new();
        let bootstrap = trust_bootstrap::check(&fixture.bootstrap, true, 1000).unwrap();
        let key = crate::authority_deployment_tests::key(5);
        let (boot, wall) = publish_clock(&directory);
        let clock = directory.join("Clock.json");
        let store = Store::initialise(
            &directory,
            bootstrap.descriptor().clone(),
            key.verifying_key().to_bytes(),
            ClockHealth::new(wall, boot, boot + 30000, 1).unwrap(),
        )
        .unwrap();
        let socket = directory.join("Control.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let proof = streams::Proof {
            service: VersionRef {
                kind: 172,
                id: [71; 32],
                generation: 1,
                digest: [72; 32],
            },
            principal: key.verifying_key().to_bytes(),
            grant: fixture.grant,
            protocol: "example/1".into(),
            slot: 0,
            generation: 1,
            nonce: [73; 32],
            challenge: [74; 32],
            exporter: [75; 32],
            limits: crate::route_profile::Limits {
                bytes: 65536,
                duration_ms: 30000,
                idle_ms: 5000,
            },
            expires: wall + 30000,
            envelope: vec![],
        };
        Self {
            client: Client {
                bootstrap,
                store,
                session: Session::new().unwrap(),
                key,
                clock: crate::authority_clock::Source::Private { path: clock },
                socket,
                preparation: None,
            },
            proof,
            listener,
            directory,
        }
    }
    fn no_network(&self) {
        assert_eq!(
            self.listener.accept().unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn unsigned_cleanup_skips_remote_work_after_recovery() {
    let mut fixture = Fixture::new();
    // The unsigned path needs neither authority transport nor a fresh clock observation.
    fs::remove_file(fixture.directory.join("Clock.json")).unwrap();
    fixture
        .client
        .cleanup(&fixture.proof, boot_time_ms().unwrap() + 5000, &[])
        .unwrap();
    fixture.no_network();
    assert!(fixture.client.preparation.is_none());
    assert!(fixture.client.store.resume_ordinary().unwrap().is_none());
}

#[test]
fn signed_cleanup_with_unknown_acceptance_still_enters_fresh_lookup() {
    let mut fixture = Fixture::new();
    let scope = fixture.client.store.descriptor().scope();
    fixture.proof.envelope = wire::sign_envelope(
        &fixture
            .proof
            .payload(scope.network, scope.incarnation)
            .unwrap(),
        &fixture.client.key,
    )
    .unwrap();
    streams::Proof::parse(&fixture.proof.envelope, scope.network, scope.incarnation).unwrap();
    // Private observations have an exact one-second lifetime. Sample again after
    // durable fixture setup, rather than carrying its elapsed I/O into the read.
    publish_clock(&fixture.directory);
    fixture.client.clock.health().unwrap().observe().unwrap();
    // No acceptance is known. Withhold authority replies: cleanup must attempt
    // the existing lookup path and fail within its original caller deadline.
    let cleanup_error = fixture
        .client
        .cleanup(&fixture.proof, boot_time_ms().unwrap() + 500, &[])
        .unwrap_err();
    let (mut peer, _) = fixture.listener.accept().unwrap_or_else(|error| {
        panic!("authority transport was not reached: {cleanup_error:#}; accept: {error}")
    });
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let frame = ipc::read_frame(&mut peer).unwrap();
    let (request, _) = crate::authority_inspection::read_client::tests::submitted(&frame);
    let request = crate::authority_read::Request::from_signed(&request).unwrap();
    // The existing lookup first obtains its required current policy context.
    assert!(matches!(
        request.query,
        crate::authority_read::Query::PolicyContext
    ));
    assert!(fixture.client.preparation.is_none());
    assert!(fixture.client.store.resume_ordinary().unwrap().is_none());
}

#[test]
fn unsigned_cleanup_preserves_requester_recovery_and_deadline_guards() {
    let mut fixture = Fixture::new();
    fixture.client.key = crate::authority_deployment_tests::key(6);
    let error = fixture
        .client
        .cleanup(&fixture.proof, boot_time_ms().unwrap() + 5000, &[])
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("signer differs from durable journal requester")
    );
    fixture.no_network();
    assert!(fixture.client.preparation.is_none());
    fixture.client.key = crate::authority_deployment_tests::key(5);
    assert!(
        fixture
            .client
            .cleanup(&fixture.proof, boot_time_ms().unwrap(), &[])
            .is_err()
    );
    fixture.no_network();
    assert!(fixture.client.preparation.is_none());
}
