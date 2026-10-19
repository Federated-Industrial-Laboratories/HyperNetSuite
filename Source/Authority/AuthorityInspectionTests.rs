// SPDX-License-Identifier: MIT
// Inspection binds exact governance, durable floors and the original recipient deadline.
use super::*;
use crate::trust_bootstrap::{self, Assurance, DraftSpec, RecoveryKey, RecoverySpec, RouteSpec};
use ed25519_dalek::Signer;
use std::{
    io::{Read, Write},
    os::unix::{
        fs::{PermissionsExt, symlink},
        net::UnixStream,
    },
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

fn wall() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn public(seed: u8) -> String {
    hex::encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}
pub(super) fn voters() -> Vec<SigningKey> {
    let mut v = (1..=4)
        .map(|n| SigningKey::from_bytes(&[n; 32]))
        .collect::<Vec<_>>();
    v.sort_by_key(|k| k.verifying_key().to_bytes());
    v
}
fn bootstrap(now: u64, complete: bool) -> Verified {
    bootstrap_actions(now, complete, vec![0, 9, 10, 11, 12, 25])
}
fn bootstrap_actions(now: u64, complete: bool, actions: Vec<u64>) -> Verified {
    let mut recovery = (6..=8)
        .map(|n| SigningKey::from_bytes(&[n; 32]))
        .collect::<Vec<_>>();
    recovery.sort_by_key(|k| k.verifying_key().to_bytes());
    let spec = DraftSpec {
        voters: voters()
            .iter()
            .map(|k| hex::encode(k.verifying_key().to_bytes()))
            .collect(),
        authority_transports: voters()
            .iter()
            .enumerate()
            .map(|(index, voter)| {
                (
                    hex::encode(voter.verifying_key().to_bytes()),
                    public(30 + index as u8),
                )
            })
            .collect(),
        clock_monitors: vec![public(40)],
        administrator: public(5),
        administrator_actions: actions,
        enrolment: "InvitationOnly".into(),
        public_reading: false,
        minimum_route: Assurance::Independent,
        publication_modes: vec!["HostReadable".into(), "Sealed".into()],
        default_publication_mode: "HostReadable".into(),
        limits: [100, 100, 10, 10],
        recovery: RecoverySpec {
            custody: "OwnerThreshold".into(),
            keys: recovery
                .iter()
                .map(|k| RecoveryKey {
                    principal: "11".repeat(32),
                    public_key: hex::encode(k.verifying_key().to_bytes()),
                })
                .collect(),
            accepted_keys: recovery[..2]
                .iter()
                .map(|k| hex::encode(k.verifying_key().to_bytes()))
                .collect(),
            immutable_shared: false,
        },
        route: RouteSpec {
            relay_service: "12".repeat(32),
            relay_origin: "https://relay.invalid/".into(),
            relay_transport_key: public(9),
            relay_domain: "13".repeat(32),
            admission_service: "14".repeat(32),
            admission_origin: "https://admission.invalid/".into(),
            admission_transport_key: public(10),
            admission_domain: "15".repeat(32),
            assurance: Assurance::Independent,
            not_before_ms: now - 10000,
            expires_ms: now + 3600000,
        },
    };
    let draft = trust_bootstrap::draft(spec, [[20; 32], [21; 32], [22; 32], [23; 32]], now - 10000)
        .unwrap();
    let bytes = if complete {
        let acceptances = recovery[..2]
            .iter()
            .map(|k| trust_bootstrap::accept(&draft, k, now).unwrap())
            .collect::<Vec<_>>();
        trust_bootstrap::assemble(&draft, &acceptances, now).unwrap()
    } else {
        draft
    };
    trust_bootstrap::check(&bytes, complete, now).unwrap()
}
pub(super) struct Directory(pub(super) PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("I{}", crate::random_hex::<8>()));
        files::create_directory(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
pub(super) struct Fixture {
    pub(super) directory: Directory,
    pub(super) bootstrap: Verified,
    pub(super) context: ContextState,
    pub(super) store: Store,
    pub(super) session: Session,
    pub(super) issued: ClockHealth,
    pub(super) current: ClockHealth,
    pub(super) signer: SigningKey,
    pub(super) status_node: Vec<u8>,
}
impl Fixture {
    pub(super) fn new() -> Self {
        Self::with_actions(vec![0, 9, 10, 11, 12, 25])
    }
    pub(super) fn with_actions(actions: Vec<u64>) -> Self {
        Self::with_actions_and_signer(actions, SigningKey::from_bytes(&[5; 32]))
    }
    pub(super) fn with_actions_and_signer(actions: Vec<u64>, signer: SigningKey) -> Self {
        let current_wall = wall();
        Self::with_bootstrap(
            bootstrap_actions(current_wall, true, actions),
            signer,
            current_wall,
        )
    }
    pub(super) fn with_bootstrap(
        bootstrap: Verified,
        signer: SigningKey,
        current_wall: u64,
    ) -> Self {
        let current_boot = boot_time_ms().unwrap();
        let issued = ClockHealth::new(
            current_wall - 2000,
            current_boot - 2000,
            current_boot + 30000,
            100,
        )
        .unwrap()
        .frozen();
        let current = ClockHealth::new(current_wall, current_boot, current_boot + 30000, 100)
            .unwrap()
            .frozen();
        let directory = Directory::new();
        let status_issued = ClockHealth::new(
            current_wall - 4000,
            current_boot - 4000,
            current_boot + 30000,
            100,
        )
        .unwrap()
        .frozen();
        let mut store = Store::initialise(
            &directory.0,
            bootstrap.descriptor().clone(),
            signer.verifying_key().to_bytes(),
            status_issued,
        )
        .unwrap();
        let mut session = Session::new().unwrap();
        let descriptor = bootstrap.descriptor();
        let scope = descriptor.scope();
        let requester = signer.verifying_key().to_bytes();
        let request = wire::sign_envelope(
            &wire::encode(&a(vec![
                V::Uint(55),
                V::Uint(1),
                b(&scope.network),
                b(&scope.incarnation),
                b(&requester),
                b(&[82; 32]),
                V::Uint(scope.epoch),
                V::Uint(0),
            ]))
            .unwrap(),
            &signer,
        )
        .unwrap();
        let challenge = session
            .issue(&request, &signer, [83; 32], 5000, status_issued)
            .unwrap();
        let parsed = Challenge::from_signed(&challenge).unwrap();
        let ordered = wire::encode(&a(vec![
            V::Uint(22),
            V::Uint(1),
            scope.value(),
            b(&request),
            b(&challenge),
            V::Uint(parsed.expires_at_ms),
        ]))
        .unwrap();
        let initial_id = wire::digest(
            &wire::encode(&a(vec![
                V::Text("HyperNet/StreamInitial".into()),
                V::Uint(1),
                b(&scope.network),
                b(&scope.incarnation),
                b(&requester),
            ]))
            .unwrap(),
        );
        let metadata = a(vec![
            V::Uint(56),
            V::Uint(1),
            scope.value(),
            b(&requester),
            V::Bool(true),
            V::Uint(1),
            b(&initial_id),
            V::Uint(0),
            V::Null,
            V::Null,
        ]);
        let (reply, status_node) = certified_request(
            descriptor,
            &request,
            &challenge,
            &ordered,
            metadata,
            current_wall - 2000,
            *store.prefix().node(),
            1,
            0,
        );
        let decoded = wire::decode(&reply).unwrap();
        let fields = decoded.array(10).unwrap();
        let verified = proof::verify_response(
            descriptor,
            proof::ProofContext {
                intent: &request,
                challenge: &challenge,
                restrictions: Restrictions::default(),
                minimum_height: 0,
                maximum_effect: 1,
                expected_stream: None,
            },
            proof::Response {
                ordered_request: &ordered,
                operation_result: fields[8].bytes().unwrap(),
                certificate: fields[7].bytes().unwrap(),
                ancestry: std::slice::from_ref(&status_node),
            },
            |_, _, _| bail!("status must use the fixed control verifier"),
        )
        .unwrap();
        let permit = store
            .accept(verified, &mut session, issued, parsed.created_at_ms)
            .unwrap();
        permit
            .perform(
                &mut store,
                &mut session,
                issued,
                1,
                |_| Ok(()),
                |_, _| Ok(()),
            )
            .unwrap();
        assert_eq!(store.prefix().height(), 1);
        assert!(store.stream_metadata().unwrap().unwrap().state().is_some());
        let context = ContextState::bootstrap(&bootstrap, &store).unwrap();
        Self {
            directory,
            bootstrap,
            context,
            store,
            session,
            issued,
            current,
            signer,
            status_node,
        }
    }
}
fn request() -> Request {
    Request {
        grant: [23; 32],
        kind: 100,
        lookup: [20; 32],
    }
}
fn result_value(pending: &Prepared) -> V {
    a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text(ACTION.into()),
        a(pending.expected.iter().map(version_value).collect()),
        b(pending
            .context
            .governance
            .record_bytes(pending.target.kind, pending.target.id)
            .unwrap()),
    ])
}
fn certified(
    pending: &Prepared,
    value: V,
    time: u64,
    parent: [u8; 32],
    height: u64,
) -> (Vec<u8>, Vec<u8>) {
    certified_outcome(pending, value, time, parent, height, false)
}
fn certified_outcome(
    pending: &Prepared,
    value: V,
    time: u64,
    parent: [u8; 32],
    height: u64,
    refused: bool,
) -> (Vec<u8>, Vec<u8>) {
    certified_request(
        &pending.context.descriptor,
        &pending.intent,
        &pending.challenge,
        &pending.ordered,
        value,
        time,
        parent,
        height,
        if refused { 7 } else { 0 },
    )
}
#[allow(clippy::too_many_arguments)]
pub(super) fn certified_request(
    descriptor: &TrustDescriptor,
    request: &[u8],
    challenge: &[u8],
    ordered: &[u8],
    value: V,
    time: u64,
    parent: [u8; 32],
    height: u64,
    code: u64,
) -> (Vec<u8>, Vec<u8>) {
    let scope = descriptor.scope();
    let intent = proof::SignedRequest::from_signed(request).unwrap();
    let challenge = Challenge::from_signed(challenge).unwrap();
    let requested_expiry = wire::decode(ordered).unwrap().array(6).unwrap()[5]
        .uint()
        .unwrap();
    let expiry = if code == 0 {
        challenge.evaluation_expiry(time, requested_expiry).unwrap()
    } else {
        requested_expiry
    };
    let result = wire::encode(&a(vec![
        V::Uint(24),
        V::Uint(1),
        V::Text(intent.action().into()),
        V::Uint(u64::from(code != 0)),
        V::Uint(code),
        b(&wire::encode(&value).unwrap()),
    ]))
    .unwrap();
    let node = wire::encode(&a(vec![
        V::Uint(14),
        V::Uint(1),
        scope.value(),
        V::Uint(height),
        V::Uint(height),
        b(&parent),
        b(&wire::digest(ordered)),
        V::Uint(time),
        b(&[80; 32]),
    ]))
    .unwrap();
    let payload = wire::encode(&a(vec![
        V::Uint(23),
        V::Uint(1),
        scope.value(),
        V::Uint(height),
        b(&wire::digest(&node)),
        b(&wire::digest(ordered)),
        b(&intent.digest()),
        b(&challenge.digest),
        b(&intent.requester()),
        b(&challenge.recipient),
        V::Text(intent.action().into()),
        b(&intent.resource()),
        V::Uint(intent.revision()),
        V::Uint(0),
        V::Uint(u64::from(code == 0)),
        b(&wire::digest(&result)),
        b(&[81; 32]),
        V::Uint(intent.minimum_policy_height()),
        V::Uint(time),
        V::Uint(expiry),
        V::Null,
        V::Null,
        V::Null,
    ]))
    .unwrap();
    let signatures = voters()[..3]
        .iter()
        .map(|key| {
            let public = key.verifying_key().to_bytes();
            a(vec![
                b(&public),
                b(&key
                    .sign(&wire::signature_message(&payload, &public))
                    .to_bytes()),
            ])
        })
        .collect();
    let certificate =
        wire::encode(&a(vec![V::Uint(0), V::Uint(1), b(&payload), a(signatures)])).unwrap();
    let reply = wire::encode(&a(vec![
        V::Uint(42),
        V::Uint(1),
        scope.value(),
        V::Uint(1),
        V::Uint(0),
        b(&wire::digest(ordered)),
        b(&node),
        b(&certificate),
        b(&result),
        a(vec![]),
    ]))
    .unwrap();
    (reply, node)
}
fn proof(pending: &Prepared, time: u64, store: &Store) -> (Vec<u8>, Vec<Vec<u8>>) {
    let (reply, node) = certified(
        pending,
        result_value(pending),
        time,
        *store.prefix().node(),
        store.prefix().height() + 1,
    );
    (reply, vec![node])
}

#[test]
fn immutable_verified_bootstrap_not_summary_supplies_operator_context() {
    let f = Fixture::new();
    let mut draft = bootstrap(wall(), false);
    draft.summary.draft = false;
    assert!(ContextState::bootstrap(&draft, &f.store).is_err());
    let mut accepted = f.bootstrap;
    accepted.summary.draft = true;
    accepted.summary.network = "00".repeat(32);
    accepted.summary.genesis_governance.record_digest = "00".repeat(32);
    assert!(ContextState::bootstrap(&accepted, &f.store).is_ok());
}
#[test]
fn signed_inspection_has_exact_target_revision_and_only_required_current_dependencies() {
    let mut f = Fixture::new();
    let pending = f
        .context
        .prepare(request(), &f.signer, &mut f.store, &mut f.session, f.issued)
        .unwrap();
    let intent = Intent::from_signed(&pending.intent).unwrap();
    let challenge = Challenge::from_signed(&pending.challenge).unwrap();
    let params = wire::decode(&intent.parameters).unwrap();
    let p = params.array(6).unwrap();
    assert_eq!(p[2].text().unwrap(), ACTION);
    assert_eq!(p[3].fixed::<32>().unwrap(), [23; 32]);
    assert_eq!(p[4].uint().unwrap(), 100);
    assert_eq!(p[5].fixed::<32>().unwrap(), [20; 32]);
    assert_eq!(intent.revision, 1);
    assert_eq!(intent.profile_generation, 0);
    assert_eq!(
        intent.expected.iter().map(|v| v.kind).collect::<Vec<_>>(),
        vec![100, 101, 102, 114]
    );
    assert_eq!(challenge.recipient, intent.requester);
    assert_eq!(challenge.maximum_duration_ms, 5000);
    assert_eq!(challenge.intent, intent.digest);
    assert!(!pending.ordered_request().is_empty());
    pending.cancel(&mut f.session).unwrap();
}
#[test]
fn valid_record_is_returned_only_after_certified_floor_persistence() {
    let mut f = Fixture::new();
    let pending = f
        .context
        .prepare(request(), &f.signer, &mut f.store, &mut f.session, f.issued)
        .unwrap();
    let (reply, ancestry) = proof(&pending, f.current.observe().unwrap().wall_ms, &f.store);
    assert_eq!(f.store.prefix().height(), 1);
    let result = pending
        .accept(&reply, ancestry, &mut f.store, &mut f.session, || {
            Ok(f.current)
        })
        .unwrap();
    assert_eq!(result.reference().kind, 100);
    assert_eq!(result.reference().generation, 1);
    assert_eq!(wire::digest(result.canonical()), result.reference().digest);
    assert_eq!(result.prefix(), f.store.prefix());
    assert_eq!(result.prefix().height(), 2);
    let descriptor = f.bootstrap.descriptor().clone();
    drop(f.store);
    let reopened = Store::open(&f.directory.0, descriptor).unwrap();
    assert_eq!(reopened.prefix(), result.prefix());
    assert_eq!(
        reopened
            .generations()
            .iter()
            .map(|v| v.kind)
            .collect::<Vec<_>>(),
        vec![100, 101, 102, 114]
    );
}
#[test]
fn complete_used_dependencies_and_exact_record_schema_are_required_even_with_a_quorum() {
    for change in 0..5 {
        let mut f = Fixture::new();
        let pending = f
            .context
            .prepare(request(), &f.signer, &mut f.store, &mut f.session, f.issued)
            .unwrap();
        let mut value = result_value(&pending);
        let V::Array(fields) = &mut value else {
            unreachable!()
        };
        match change {
            0 => fields[3] = a(vec![version_value(&pending.target)]),
            1 => {
                let mut versions = pending.expected.clone();
                versions.push(
                    f.context
                        .governance
                        .versions()
                        .into_iter()
                        .find(|v| v.kind == 114)
                        .unwrap(),
                );
                fields[3] = a(versions.iter().map(version_value).collect());
            }
            2 => fields[4] = b(f.context.governance.record_bytes(101, [22; 32]).unwrap()),
            3 => {
                let mut target = wire::decode(fields[4].bytes().unwrap()).unwrap();
                let V::Array(f) = &mut target else {
                    unreachable!()
                };
                f[4] = V::Uint(2);
                fields[4] = b(&wire::encode(&target).unwrap());
            }
            4 => fields.push(V::Null),
            _ => unreachable!(),
        }
        let (reply, node) = certified(
            &pending,
            value,
            f.current.observe().unwrap().wall_ms,
            *f.store.prefix().node(),
            2,
        );
        assert!(
            pending
                .accept(&reply, vec![node], &mut f.store, &mut f.session, || Ok(
                    f.current
                ))
                .is_err(),
            "case {change}"
        );
        assert_eq!(f.store.prefix().height(), 1);
    }
}
#[test]
fn stale_or_substituted_cached_governance_cannot_establish_context() {
    let f = Fixture::new();
    let mut records = f.bootstrap.governance_records().to_vec();
    let mut target = wire::decode(&records[0]).unwrap();
    let V::Array(fields) = &mut target else {
        unreachable!()
    };
    fields[7] = V::Bool(true);
    records[0] = wire::encode(&target).unwrap();
    assert!(ContextState::retained(&f.bootstrap, &f.store, &records).is_err());
    records = f.bootstrap.governance_records().to_vec();
    records.remove(1);
    assert!(ContextState::retained(&f.bootstrap, &f.store, &records).is_err());
}

#[test]
fn certified_revocation_cannot_be_omitted_from_retained_inspection_context() {
    let mut f = Fixture::new();
    let scope = f.bootstrap.descriptor().scope();
    let mut records = f.bootstrap.governance_records().to_vec();
    let original = wire::decode(f.context.governance.record_bytes(102, [23; 32]).unwrap()).unwrap();
    let mut grant = original.array(17).unwrap().to_vec();
    grant[6] = b(&[24; 32]);
    grant[16] = a(vec![
        a(vec![
            V::Uint(scope.epoch),
            V::Uint(f.store.prefix().height()),
            b(f.store.prefix().node()),
        ]),
        a(vec![]),
    ]);
    let grant = wire::encode(&a(grant)).unwrap();
    let reference = VersionRef {
        kind: 102,
        id: [24; 32],
        generation: 1,
        digest: wire::digest(&grant),
    };
    records.push(grant);
    crate::authority_membership::sort_records(&mut records).unwrap();
    let without_revocation = records.clone();
    records.push(
        wire::encode(&a(vec![
            V::Uint(126),
            V::Uint(1),
            b(&scope.network),
            b(&scope.incarnation),
            V::Uint(1),
            V::Null,
            version_value(&reference),
            b(&f.signer.verifying_key().to_bytes()),
            a(vec![
                a(vec![
                    V::Uint(scope.epoch),
                    V::Uint(0),
                    b(f.store.prefix().node()),
                ]),
                a(vec![version_value(&reference)]),
            ]),
        ]))
        .unwrap(),
    );
    crate::authority_membership::sort_records(&mut records).unwrap();
    // Model the committed records, then independently certify and persist each inspection.
    let context = ContextState {
        descriptor: f.bootstrap.descriptor().clone(),
        governance: Governance::parse(scope.network, scope.incarnation, &records).unwrap(),
    };
    let mut earlier_context = None;
    for (step, kind) in [102, 126].into_iter().enumerate() {
        let issuance = f.issued.observe().unwrap();
        let elapsed = step as u64 * 2000;
        let issued = ClockHealth::new(
            issuance.wall_ms + elapsed,
            issuance.boot_ms + elapsed,
            issuance.boot_ms + 30000,
            100,
        )
        .unwrap()
        .frozen();
        let received = ClockHealth::new(
            issuance.wall_ms + elapsed + 2000,
            issuance.boot_ms + elapsed + 2000,
            issuance.boot_ms + 30000,
            100,
        )
        .unwrap()
        .frozen();
        let pending = context
            .prepare(
                Request {
                    grant: [23; 32],
                    kind,
                    lookup: [24; 32],
                },
                &f.signer,
                &mut f.store,
                &mut f.session,
                issued,
            )
            .unwrap();
        let (reply, node) = certified(
            &pending,
            result_value(&pending),
            received.observe().unwrap().wall_ms,
            *f.store.prefix().node(),
            f.store.prefix().height() + 1,
        );
        let inspected = pending
            .accept(&reply, vec![node], &mut f.store, &mut f.session, || {
                Ok(received)
            })
            .unwrap();
        assert_eq!(inspected.reference().kind, kind);
        if kind == 102 {
            earlier_context =
                Some(ContextState::retained(&f.bootstrap, &f.store, &without_revocation).unwrap());
        }
    }
    assert!(earlier_context.unwrap().current(&f.store).is_err());
    assert!(ContextState::retained(&f.bootstrap, &f.store, &without_revocation).is_err());
    assert!(ContextState::retained(&f.bootstrap, &f.store, &records).is_ok());
}
#[test]
fn original_deadline_and_current_clock_health_are_rechecked_before_output() {
    for expired in [true, false] {
        let mut f = Fixture::new();
        let mut pending = f
            .context
            .prepare(request(), &f.signer, &mut f.store, &mut f.session, f.issued)
            .unwrap();
        let (reply, ancestry) = proof(&pending, f.current.observe().unwrap().wall_ms, &f.store);
        if expired {
            pending.deadline = boot_time_ms().unwrap();
        }
        let sample = if expired {
            f.current
        } else {
            ClockHealth::new(
                wall() - 100000,
                boot_time_ms().unwrap(),
                boot_time_ms().unwrap() + 10000,
                100,
            )
            .unwrap()
        };
        assert!(
            pending
                .accept(&reply, ancestry, &mut f.store, &mut f.session, || Ok(
                    sample
                ))
                .is_err()
        );
        assert_eq!(f.store.prefix().height(), 1);
    }
}
#[test]
fn unhealthy_final_sample_prevents_output_after_floor_advance() {
    let mut f = Fixture::new();
    let pending = f
        .context
        .prepare(request(), &f.signer, &mut f.store, &mut f.session, f.issued)
        .unwrap();
    let (reply, ancestry) = proof(&pending, f.current.observe().unwrap().wall_ms, &f.store);
    let mut calls = 0;
    let result = pending.accept(&reply, ancestry, &mut f.store, &mut f.session, || {
        calls += 1;
        if calls == 1 {
            Ok(f.current)
        } else {
            ClockHealth::new(
                wall() - 100000,
                boot_time_ms()?,
                boot_time_ms()? + 10000,
                100,
            )
        }
    });
    assert!(result.is_err());
    assert_eq!(calls, 2);
    assert_eq!(f.store.prefix().height(), 2);
}
#[test]
fn persistence_failure_cannot_return_an_inspected_record() {
    let mut f = Fixture::new();
    let pending = f
        .context
        .prepare(request(), &f.signer, &mut f.store, &mut f.session, f.issued)
        .unwrap();
    let (reply, ancestry) = proof(&pending, f.current.observe().unwrap().wall_ms, &f.store);
    let witness = f.directory.0.join("AuthorityWitness.json");
    std::fs::remove_file(&witness).unwrap();
    std::fs::create_dir(&witness).unwrap();
    assert!(
        pending
            .accept(&reply, ancestry, &mut f.store, &mut f.session, || Ok(
                f.current
            ))
            .is_err()
    );
    assert_eq!(f.store.prefix().height(), 1);
}
#[test]
fn ancestry_must_reach_the_retained_floor_without_trust_jumps() {
    let mut f = Fixture::new();
    let pending = f
        .context
        .prepare(request(), &f.signer, &mut f.store, &mut f.session, f.issued)
        .unwrap();
    let time = f.current.observe().unwrap().wall_ms;
    let (_, first) = certified(
        &pending,
        result_value(&pending),
        time,
        *f.store.prefix().node(),
        2,
    );
    let (reply, second) = certified(
        &pending,
        result_value(&pending),
        time,
        wire::digest(&first),
        3,
    );
    let encoded = wire::encode(&a(vec![
        V::Uint(43),
        V::Uint(1),
        f.context.descriptor.scope().value(),
        a(vec![b(&first), b(&second)]),
    ]))
    .unwrap();
    assert_eq!(pending.ancestry_reply(&encoded, &second).unwrap().len(), 2);
    assert!(
        pending
            .accept(&reply, vec![second], &mut f.store, &mut f.session, || Ok(
                f.current
            ))
            .is_err()
    );
    assert_eq!(f.store.prefix().height(), 1);
}
#[test]
fn complete_bounded_ancestry_can_advance_over_intermediate_commits() {
    let mut f = Fixture::new();
    let pending = f
        .context
        .prepare(request(), &f.signer, &mut f.store, &mut f.session, f.issued)
        .unwrap();
    let time = f.current.observe().unwrap().wall_ms;
    let (_, first) = certified(
        &pending,
        result_value(&pending),
        time,
        *f.store.prefix().node(),
        2,
    );
    let (reply, second) = certified(
        &pending,
        result_value(&pending),
        time,
        wire::digest(&first),
        3,
    );
    let result = pending
        .accept(
            &reply,
            vec![first, second],
            &mut f.store,
            &mut f.session,
            || Ok(f.current),
        )
        .unwrap();
    assert_eq!(result.prefix().height(), 3);
}
#[test]
fn local_transport_requires_owned_private_socket_and_bounds_framing() {
    let directory = Directory::new();
    let path = directory.0.join("Control.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let control = LocalControl::open(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut size = [0; 4];
        stream.read_exact(&mut size).unwrap();
        let mut body = vec![0; u32::from_be_bytes(size) as usize];
        stream.read_exact(&mut body).unwrap();
        assert_eq!(body, vec![1, 2, 3]);
        stream
            .write_all(&((wire::MAXIMUM as u32) + 1).to_be_bytes())
            .unwrap();
    });
    assert!(
        control
            .exchange(&[1, 2, 3], boot_time_ms().unwrap() + 1000)
            .is_err()
    );
    server.join().unwrap();
    let link = directory.0.join("Link.sock");
    symlink(&path, &link).unwrap();
    assert!(LocalControl::open(&link).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
    assert!(LocalControl::open(&path).is_err());
}

#[test]
fn private_operator_workflow_returns_only_a_durable_verified_record() {
    let mut f = Fixture::new();
    let socket = f.directory.0.join("Operator.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let pending = f
        .context
        .prepare(request(), &f.signer, &mut f.store, &mut f.session, f.issued)
        .unwrap();
    pending.cancel(&mut f.session).unwrap();
    assert!(f.store.resume_ordinary().unwrap().is_some());
    let context = &f.context;
    let parent = *f.store.prefix().node();
    let result = std::thread::scope(|scope| {
        let server = scope.spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut prefix = [0; 4];
            stream.read_exact(&mut prefix).unwrap();
            let count = u32::from_be_bytes(prefix) as usize;
            assert!(count <= wire::MAXIMUM);
            let mut bytes = vec![0; count];
            stream.read_exact(&mut bytes).unwrap();
            let control = wire::decode(&bytes).unwrap();
            let control = record(&control, 41, 5).unwrap();
            assert_eq!(control[3].uint().unwrap(), 0);
            let submission = wire::decode(control[4].bytes().unwrap()).unwrap();
            let submission = submission.array(2).unwrap();
            assert_eq!(submission[1], V::Array(vec![]));
            let ordered = submission[0].bytes().unwrap().to_vec();
            let order = wire::decode(&ordered).unwrap();
            let order = record(&order, 22, 6).unwrap();
            let intent = order[3].bytes().unwrap().to_vec();
            let parsed = Intent::from_signed(&intent).unwrap();
            let challenge = order[4].bytes().unwrap().to_vec();
            let start = Challenge::from_signed(&challenge).unwrap().created_at_ms;
            let target = context
                .governance
                .versions()
                .into_iter()
                .find(|v| v.kind == 100)
                .unwrap();
            let pending = Prepared {
                context,
                request: request(),
                target,
                expected: parsed.expected,
                intent,
                challenge,
                ordered,
                deadline: boot_time_ms().unwrap() + 5000,
            };
            let admission = start + crate::authority_governance::UNCERTAINTY_MS;
            loop {
                let now = wall();
                if now >= admission {
                    break;
                }
                std::thread::sleep(Duration::from_millis((admission - now).min(20)));
            }
            let (reply, _) = certified(&pending, result_value(&pending), wall(), parent, 2);
            stream
                .write_all(&(reply.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(&reply).unwrap();
        });
        let result = context.inspect_local(
            &socket,
            request(),
            &f.signer,
            &mut f.store,
            &mut f.session,
            || {
                let time = wall();
                let boot = boot_time_ms()?;
                ClockHealth::new(time, boot, boot + 30000, 100)
            },
        );
        server.join().unwrap();
        result
    })
    .unwrap();
    assert_eq!(result.reference().kind, 100);
    assert_eq!(result.prefix().height(), 2);
    assert_eq!(f.store.prefix(), result.prefix());
}

#[test]
fn stream_transport_setup_failure_precedes_challenge_and_clock_sample() {
    let mut f = Fixture::new();
    let descriptor = f.bootstrap.descriptor().clone();
    let prefix = f.store.prefix().clone();
    let absent = f.directory.0.join("AbsentRoute.json");
    let result = stream_client::status_local(
        &descriptor,
        &absent,
        &f.signer,
        &mut f.store,
        &mut f.session,
        || panic!("application challenge clock sampled before transport readiness"),
    );
    assert!(result.is_err());
    assert_eq!(*f.store.prefix(), prefix);
    assert!(f.store.resume_ordinary().unwrap().is_none());
    assert!(f.store.resume_fence().unwrap().is_none());
}

#[test]
fn immediate_stream_status_accepts_a_quick_certificate_without_challenge_ageing() {
    let mut f = Fixture::new();
    let socket = f.directory.0.join("Quick.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let descriptor = f.bootstrap.descriptor().clone();
    let server_descriptor = descriptor.clone();
    let metadata = f.store.stream_metadata().unwrap().unwrap();
    let expected = metadata.canonical().to_vec();
    let parent = *f.store.prefix().node();
    let issued = f.current;
    let sample = issued.observe().unwrap();
    let current = ClockHealth::new(
        sample.wall_ms + 100,
        sample.boot_ms + 100,
        sample.boot_ms + 30000,
        100,
    )
    .unwrap()
    .frozen();
    let server = std::thread::spawn(move || {
        let (stream, packet) = receive_control(&listener);
        let (ordered, signed, challenge) = submitted(&packet);
        let start = Challenge::from_signed(&challenge).unwrap().created_at_ms;
        let (reply, _) = certified_request(
            &server_descriptor,
            &signed,
            &challenge,
            &ordered,
            wire::decode(metadata.canonical()).unwrap(),
            start + 100,
            parent,
            2,
            0,
        );
        send_control(stream, &reply);
    });
    let mut first = true;
    let result = stream_client::status_local(
        &descriptor,
        &socket,
        &f.signer,
        &mut f.store,
        &mut f.session,
        || {
            let health = if first { issued } else { current };
            first = false;
            Ok(health)
        },
    );
    server.join().unwrap();
    assert_eq!(result.unwrap().canonical(), expected);
    assert_eq!(f.store.prefix().height(), 2);
}

#[test]
fn completed_ordinary_work_reuses_stream_metadata_without_another_status_query() {
    let mut f = Fixture::new();
    let socket = f.directory.0.join("Control.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let metadata = f.store.stream_metadata().unwrap().unwrap();
    let context = &f.context;
    let mut parent = *f.store.prefix().node();
    let target = context
        .governance
        .versions()
        .into_iter()
        .find(|reference| reference.kind == 100)
        .unwrap();
    let results = std::thread::scope(|scope| {
        let server = scope.spawn(move || {
            let mut challenges = std::collections::BTreeSet::new();
            for index in 0..3 {
                let (stream, packet) = receive_control(&listener);
                let (ordered, signed, challenge) = submitted(&packet);
                assert!(challenges.insert(wire::digest(&challenge)));
                let value = match (index, proof::SignedRequest::from_signed(&signed).unwrap()) {
                    (0, proof::SignedRequest::StreamStatus(_)) => {
                        wire::decode(metadata.canonical()).unwrap()
                    }
                    (1 | 2, proof::SignedRequest::Intent(intent)) => {
                        assert_eq!(intent.sequence, index);
                        assert_eq!(intent.acknowledged_through, index - 1);
                        let pending = Prepared {
                            context,
                            request: request(),
                            target: target.clone(),
                            expected: intent.expected,
                            intent: signed.clone(),
                            challenge: challenge.clone(),
                            ordered: ordered.clone(),
                            deadline: boot_time_ms().unwrap() + DURATION,
                        };
                        result_value(&pending)
                    }
                    _ => panic!("initial status must be followed by two ordinary requests"),
                };
                let (reply, node) = certified_request(
                    &context.descriptor,
                    &signed,
                    &challenge,
                    &ordered,
                    value,
                    mature(&challenge),
                    parent,
                    index + 2,
                    0,
                );
                parent = wire::digest(&node);
                send_control(stream, &reply);
            }
        });
        let first = context.inspect_local(
            &socket,
            request(),
            &f.signer,
            &mut f.store,
            &mut f.session,
            live_clock,
        );
        let second = first.and_then(|first| {
            context
                .inspect_local(
                    &socket,
                    request(),
                    &f.signer,
                    &mut f.store,
                    &mut f.session,
                    live_clock,
                )
                .map(|second| (first, second))
        });
        server.join().unwrap();
        second
    })
    .unwrap();
    assert_eq!(results.0.prefix().height(), 3);
    assert_eq!(results.1.prefix().height(), 4);
    assert_eq!(results.1.reference(), results.0.reference());
    assert!(!f.store.needs_stream_status().unwrap());
    assert_eq!(f.store.ordinary_slot().unwrap().sequence(), 3);
}

#[test]
fn delayed_refusal_advances_the_floor_without_a_live_clock_or_payload_output() {
    let mut f = Fixture::new();
    let mut pending = f
        .context
        .prepare(request(), &f.signer, &mut f.store, &mut f.session, f.issued)
        .unwrap();
    let value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text(ACTION.into()),
        a(vec![]),
    ]);
    let (reply, node) = certified_outcome(
        &pending,
        value,
        f.current.observe().unwrap().wall_ms,
        *f.store.prefix().node(),
        2,
        true,
    );
    pending.deadline = boot_time_ms().unwrap();
    let error = pending
        .accept(&reply, vec![node], &mut f.store, &mut f.session, || {
            bail!("expired refusal must not require an effect clock")
        })
        .err()
        .unwrap();
    assert_eq!(
        error.to_string(),
        "authority inspection refused with code 7"
    );
    assert_eq!(f.store.prefix().height(), 2);
    assert!(f.store.generations().is_empty());
    let descriptor = f.bootstrap.descriptor().clone();
    drop(f.store);
    assert_eq!(
        Store::open(&f.directory.0, descriptor)
            .unwrap()
            .prefix()
            .height(),
        2
    );
}

#[path = "AuthorityHistoryControlTests.rs"]
mod history_control;

pub(super) fn receive_control(
    listener: &std::os::unix::net::UnixListener,
) -> (UnixStream, Vec<u8>) {
    listener.set_nonblocking(true).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "control fixture timed out"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("control fixture refused: {error}"),
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).unwrap();
    let count = u32::from_be_bytes(prefix) as usize;
    assert!(count <= wire::MAXIMUM);
    let mut bytes = vec![0; count];
    stream.read_exact(&mut bytes).unwrap();
    (stream, bytes)
}
pub(super) fn send_control(mut stream: UnixStream, response: &[u8]) {
    stream
        .write_all(&(response.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(response).unwrap();
}
pub(super) fn submitted(bytes: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let value = wire::decode(bytes).unwrap();
    let f = record(&value, 41, 5).unwrap();
    assert_eq!(f[3], V::Uint(0));
    let submission = wire::decode(f[4].bytes().unwrap()).unwrap();
    let submission = submission.array(2).unwrap();
    assert_eq!(submission[1], V::Array(vec![]));
    let ordered = submission[0].bytes().unwrap().to_vec();
    let value = wire::decode(&ordered).unwrap();
    let f = record(&value, 22, 6).unwrap();
    (
        ordered.clone(),
        f[3].bytes().unwrap().to_vec(),
        f[4].bytes().unwrap().to_vec(),
    )
}
pub(super) fn mature(challenge: &[u8]) -> u64 {
    let start = Challenge::from_signed(challenge).unwrap().created_at_ms;
    while wall() < start + crate::authority_governance::UNCERTAINTY_MS {
        std::thread::sleep(Duration::from_millis(5));
    }
    wall()
}
pub(super) fn live_clock() -> Result<ClockHealth> {
    let boot = boot_time_ms()?;
    // Synthetic health spans bounded persistence work; each request still expires after five seconds.
    ClockHealth::new(wall(), boot, boot + 30000, 100)
}

#[test]
fn lost_fence_response_resumes_exact_signed_fence_and_verifies_committed_ancestry() {
    let mut f = Fixture::new();
    let descriptor = f.bootstrap.descriptor().clone();
    let metadata = f
        .store
        .stream_metadata()
        .unwrap()
        .unwrap()
        .canonical()
        .to_vec();
    let original_parent = *f.store.prefix().node();
    let socket = f.directory.0.join("Fence.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let server_descriptor = descriptor.clone();
    let server = std::thread::spawn(move || {
        let (stream, request) = receive_control(&listener);
        let (ordered, request, challenge) = submitted(&request);
        assert!(matches!(
            proof::SignedRequest::from_signed(&request).unwrap(),
            proof::SignedRequest::StreamStatus(_)
        ));
        let (reply, status_node) = certified_request(
            &server_descriptor,
            &request,
            &challenge,
            &ordered,
            wire::decode(&metadata).unwrap(),
            mature(&challenge),
            original_parent,
            2,
            0,
        );
        send_control(stream, &reply);

        let (stream, request) = receive_control(&listener);
        let (ordered, original_fence, challenge) = submitted(&request);
        let proof::SignedRequest::StreamFence(fence) =
            proof::SignedRequest::from_signed(&original_fence).unwrap()
        else {
            panic!("explicit fence required")
        };
        assert_eq!(fence.expected_metadata_digest, wire::digest(&metadata));
        let old = wire::decode(&metadata).unwrap();
        let old = old.array(10).unwrap();
        let scope = server_descriptor.scope();
        let replacement = wire::encode(&a(vec![
            V::Uint(56),
            V::Uint(1),
            scope.value(),
            b(&fence.requester),
            V::Bool(true),
            V::Uint(2),
            b(&fence.digest),
            V::Uint(0),
            V::Null,
            a(vec![
                b(&fence.digest),
                b(&fence.expected_metadata_digest),
                old[5].clone(),
                old[6].clone(),
                old[7].clone(),
                old[8].clone(),
            ]),
        ]))
        .unwrap();
        let fence_value = |outcome| {
            a(vec![
                V::Uint(58),
                V::Uint(1),
                scope.value(),
                b(&fence.requester),
                b(&fence.digest),
                V::Uint(outcome),
                b(&replacement),
            ])
        };
        let (_, lost_node) = certified_request(
            &server_descriptor,
            &original_fence,
            &challenge,
            &ordered,
            fence_value(0),
            mature(&challenge),
            wire::digest(&status_node),
            3,
            0,
        );
        // The authority committed this exact fence, but its result connection was lost.
        drop(stream);

        let (stream, request) = receive_control(&listener);
        let (ordered, retry, challenge) = submitted(&request);
        assert_eq!(retry, original_fence);
        let (reply, retry_node) = certified_request(
            &server_descriptor,
            &retry,
            &challenge,
            &ordered,
            fence_value(1),
            mature(&challenge),
            wire::digest(&lost_node),
            4,
            0,
        );
        send_control(stream, &reply);
        let (stream, request) = receive_control(&listener);
        let request = wire::decode(&request).unwrap();
        let request = record(&request, 41, 5).unwrap();
        assert_eq!(request[3], V::Uint(3));
        let expected = a(vec![
            V::Uint(2),
            b(&wire::digest(&status_node)),
            b(&wire::digest(&retry_node)),
        ]);
        assert_eq!(wire::decode(request[4].bytes().unwrap()).unwrap(), expected);
        let history = wire::encode(&a(vec![
            V::Uint(43),
            V::Uint(1),
            scope.value(),
            a(vec![b(&lost_node), b(&retry_node)]),
        ]))
        .unwrap();
        send_control(stream, &history);
        original_fence
    });
    let failed = stream_client::fence_local(
        &descriptor,
        &socket,
        &f.signer,
        &mut f.store,
        &mut f.session,
        live_clock,
    );
    assert!(failed.is_err());
    assert_eq!(f.store.prefix().height(), 2);
    let pending = f.store.resume_fence().unwrap().unwrap();
    let original = pending.signed().to_vec();
    assert!(f.store.ordinary_slot().is_err());
    let response = stream_client::fence_local(
        &descriptor,
        &socket,
        &f.signer,
        &mut f.store,
        &mut f.session,
        live_clock,
    )
    .unwrap();
    assert_eq!(server.join().unwrap(), original);
    assert!(matches!(
        response,
        proof::StreamResponse::Fence {
            outcome: proof::FenceOutcome::AlreadyApplied,
            ..
        }
    ));
    assert_eq!(response.metadata().state().unwrap().generation, 2);
    assert_eq!(f.store.prefix().height(), 4);
    assert!(f.store.resume_fence().unwrap().is_none());
    let slot = f.store.ordinary_slot().unwrap();
    assert_eq!(slot.generation(), 2);
    assert_eq!(slot.sequence(), 1);
    drop(f.store);
    let reopened = Store::open(&f.directory.0, descriptor).unwrap();
    assert_eq!(reopened.prefix().height(), 4);
    assert_eq!(
        reopened.stream_metadata().unwrap().unwrap(),
        *response.metadata()
    );
}
