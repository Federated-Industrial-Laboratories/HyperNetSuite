// SPDX-License-Identifier: MIT
// Exercise unsent-proof cleanup through the real client, requester floor and private transport.
use super::*;
use crate::authority_challenge::{ClockHealth, boot_time_ms};
use crate::authority_inspection::tests::{
    certified_request, receive_control, send_control, submitted,
};
use crate::authority_proof::{self as proof, Challenge};
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

    fn retained_refusal(&mut self) -> (Vec<u8>, Digest) {
        let scope = self.client.store.descriptor().scope();
        let requester = self.client.store.requester();
        let generation =
            proof::initial_generation_id(scope.network, scope.incarnation, requester).unwrap();
        let command = domain::Command::Stream(streams::Command::Close {
            session: VersionRef {
                kind: 173,
                id: [76; 32],
                generation: 1,
                digest: [77; 32],
            },
        });
        let snapshot = crate::authority_membership::Snapshot::parse(&V::Array(vec![
            V::Array(vec![
                V::Uint(scope.epoch),
                V::Uint(0),
                V::Bytes([78; 32].to_vec()),
            ]),
            V::Array(vec![]),
        ]))
        .unwrap();
        let operation = domain::Operation {
            grant: None,
            command,
            snapshot,
        };
        let signed = wire::sign_envelope(
            &wire::encode(&V::Array(vec![
                V::Uint(20),
                V::Uint(1),
                V::Bytes(scope.network.to_vec()),
                V::Bytes(scope.incarnation.to_vec()),
                V::Uint(1),
                V::Bytes(generation.to_vec()),
                V::Uint(1),
                V::Uint(0),
                V::Bytes(requester.to_vec()),
                V::Text("AuthorityDomain".into()),
                V::Bytes(operation.command.resource().to_vec()),
                V::Uint(1),
                V::Uint(0),
                V::Uint(scope.epoch),
                V::Uint(0),
                V::Array(vec![]),
                V::Bytes(operation.parameters().unwrap()),
            ]))
            .unwrap(),
            &self.client.key,
        )
        .unwrap();
        domain::Operation::parse(&Intent::from_signed(&signed).unwrap()).unwrap();
        crate::authority_floor::tests::prepared_fixture(&mut self.client.store, &signed);
        publish_clock(&self.directory);
        let challenge = self
            .client
            .session
            .issue(
                &signed,
                &self.client.key,
                [79; 32],
                5000,
                self.client.clock.health().unwrap(),
            )
            .unwrap();
        let parsed = Challenge::from_signed(&challenge).unwrap();
        let descriptor = self.client.store.descriptor();
        let ordered = wire::encode(&V::Array(vec![
            V::Uint(22),
            V::Uint(1),
            descriptor.scope().value(),
            V::Bytes(signed.clone()),
            V::Bytes(challenge.clone()),
            V::Uint(parsed.expires_at_ms),
        ]))
        .unwrap();
        let (reply, node) = certified_request(
            descriptor,
            &signed,
            &challenge,
            &ordered,
            V::Array(vec![
                V::Uint(201),
                V::Uint(1),
                V::Text("AuthorityDomain".into()),
                V::Array(vec![]),
            ]),
            parsed.created_at_ms + crate::authority_governance::UNCERTAINTY_MS,
            *self.client.store.prefix().node(),
            1,
            3,
        );
        let value = wire::decode(&reply).unwrap();
        let fields = value.array(10).unwrap();
        let result = fields[8].bytes().unwrap();
        let verified = proof::verify_response(
            descriptor,
            proof::ProofContext {
                intent: &signed,
                challenge: &challenge,
                restrictions: proof::Restrictions::default(),
                minimum_height: 0,
                maximum_effect: 1,
                expected_stream: None,
            },
            proof::Response {
                ordered_request: &ordered,
                operation_result: result,
                certificate: fields[7].bytes().unwrap(),
                ancestry: &[node],
            },
            |_, result, executed| {
                assert_eq!(result.disposition, proof::Disposition::Refuse);
                assert_eq!(executed.maximum_effect, 0);
                proof::ActionValidation::new(vec![])
            },
        )
        .unwrap();
        self.client.store.observe(verified).unwrap();
        self.client.session.discard(&challenge).unwrap();
        assert!(self.client.store.refusal_needs_status().unwrap());
        (signed, wire::digest(result))
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

#[test]
fn retained_refusal_requires_authenticated_original_completion_before_planning() {
    // Reuse the signed own-stream response fixture; only the original outcome varies.
    for original in [Some(1), Some(0), None] {
        let mut f = Fixture::new();
        let (signed, refused_result) = f.retained_refusal();
        let intent = Intent::from_signed(&signed).unwrap();
        let descriptor = f.client.store.descriptor().clone();
        let parent = *f.client.store.prefix().node();
        let completion = original.map_or(V::Null, |disposition| {
            V::Array(vec![
                V::Uint(intent.sequence),
                V::Bytes(intent.digest.to_vec()),
                V::Uint(disposition),
                V::Uint(if disposition == 1 { 3 } else { 0 }),
                V::Bytes(
                    if disposition == 1 {
                        refused_result
                    } else {
                        [80; 32]
                    }
                    .to_vec(),
                ),
            ])
        });
        let metadata = V::Array(vec![
            V::Uint(56),
            V::Uint(1),
            descriptor.scope().value(),
            V::Bytes(intent.requester.to_vec()),
            V::Bool(true),
            V::Uint(intent.generation),
            V::Bytes(intent.generation_id.to_vec()),
            V::Uint(0),
            completion,
            V::Null,
        ]);
        publish_clock(&f.directory);
        let deadline = boot_time_ms().unwrap() + 3000;
        f.client.preparation = Some(crate::authority_inspection::read_client::RetryBudget::new(
            deadline,
            || false,
        ));
        let result = std::thread::scope(|scope| {
            let listener = &f.listener;
            let directory = &f.directory;
            let server = scope.spawn(move || {
                let (stream, packet) = receive_control(listener);
                let (ordered, request, challenge) = submitted(&packet);
                assert!(matches!(
                    proof::SignedRequest::from_signed(&request).unwrap(),
                    proof::SignedRequest::StreamStatus(_)
                ));
                let admitted = Challenge::from_signed(&challenge).unwrap().created_at_ms
                    + crate::authority_governance::UNCERTAINTY_MS;
                while SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
                    < u128::from(admitted)
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                let (_, wall) = publish_clock(directory);
                let (reply, _) = certified_request(
                    &descriptor,
                    &request,
                    &challenge,
                    &ordered,
                    metadata,
                    wall,
                    parent,
                    2,
                    0,
                );
                send_control(stream, &reply);
            });
            let result = f
                .client
                .recover_retained_refusal(&signed, domain_client::Refusal { code: 3 }.into());
            server.join().unwrap();
            result
        });
        assert_eq!(
            f.client.preparation.as_ref().unwrap().transport().deadline,
            deadline
        );
        assert_eq!(result.is_ok(), original == Some(1));
        if original == Some(1) {
            assert!(f.client.store.resume_ordinary().unwrap().is_none());
            assert_eq!(f.client.store.ordinary_slot().unwrap().sequence(), 2);
        } else {
            assert_eq!(
                result
                    .unwrap_err()
                    .downcast_ref::<domain_client::Refusal>()
                    .unwrap()
                    .code,
                3
            );
            assert_eq!(
                f.client.store.resume_ordinary().unwrap().unwrap().signed(),
                signed
            );
            assert!(f.client.store.ordinary_slot().is_err());
        }
        // Exactly one status request; recovery neither replans nor replaces the effect.
        f.no_network();
    }
}

#[test]
fn retained_refusal_recovery_preserves_budget_cancellation_and_other_failures() {
    for (expired, cancelled) in [(true, false), (false, true), (false, false)] {
        let mut f = Fixture::new();
        let (signed, _) = f.retained_refusal();
        let deadline = boot_time_ms().unwrap() + if expired { 0 } else { 3000 };
        f.client.preparation = Some(crate::authority_inspection::read_client::RetryBudget::new(
            deadline,
            move || cancelled,
        ));
        let error = if expired || cancelled {
            domain_client::Refusal { code: 3 }.into()
        } else {
            anyhow::anyhow!("unverified transport failure")
        };
        assert!(f.client.recover_retained_refusal(&signed, error).is_err());
        assert_eq!(
            f.client.store.resume_ordinary().unwrap().unwrap().signed(),
            signed
        );
        assert!(f.client.store.refusal_needs_status().unwrap());
        assert_eq!(
            f.client.preparation.as_ref().unwrap().transport().deadline,
            deadline
        );
        f.no_network();
    }
}

#[test]
fn retained_status_wait_cannot_extend_the_original_preparation_deadline() {
    let mut f = Fixture::new();
    let (signed, _) = f.retained_refusal();
    publish_clock(&f.directory);
    let deadline = boot_time_ms().unwrap() + 300;
    f.client.preparation = Some(crate::authority_inspection::read_client::RetryBudget::new(
        deadline,
        || false,
    ));
    let error = f
        .client
        .recover_retained_refusal(&signed, domain_client::Refusal { code: 3 }.into())
        .unwrap_err();
    assert!(boot_time_ms().unwrap() >= deadline);
    let (mut peer, _) = f.listener.accept().unwrap_or_else(|accept| {
        panic!("status transport was not reached: {error:#}; accept: {accept}")
    });
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let packet = ipc::read_frame(&mut peer).unwrap();
    let (_, request, _) = submitted(&packet);
    assert!(matches!(
        proof::SignedRequest::from_signed(&request).unwrap(),
        proof::SignedRequest::StreamStatus(_)
    ));
    assert_eq!(
        f.client.store.resume_ordinary().unwrap().unwrap().signed(),
        signed
    );
    assert!(f.client.store.refusal_needs_status().unwrap());
    f.no_network();
}
