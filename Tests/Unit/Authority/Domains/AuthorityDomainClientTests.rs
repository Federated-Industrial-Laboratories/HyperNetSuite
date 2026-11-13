// SPDX-License-Identifier: MIT
// A failed domain cache publication retains the exact pending request and durable quorum evidence.
use super::super::tests::{Fixture, certified_request};
use super::*;
fn domain_request(f: &Fixture) -> Request {
    Request {
        command: domains::ssh::Command::Context {
            action: 20,
            scope_kind: 0,
            resource: [20; 32],
        }
        .into(),
        grant: Some(
            references(f.bootstrap.governance_records(), [20; 32], [21; 32])
                .unwrap()
                .into_iter()
                .find(|v| v.kind == 102)
                .unwrap(),
        ),
    }
}
fn reply(p: &Prepared, f: &Fixture) -> (CertifiedReply, AncestryEvidence) {
    reply_at(p, f.current.observe().unwrap().wall_ms, f.store.prefix())
}
fn reply_at(p: &Prepared, at: u64, prefix: &Prefix) -> (CertifiedReply, AncestryEvidence) {
    reply_with_records(p, at, prefix, p.bootstrap.governance_records())
}
fn reply_with_records(
    p: &Prepared,
    at: u64,
    prefix: &Prefix,
    records: &[Vec<u8>],
) -> (CertifiedReply, AncestryEvidence) {
    let intent = Intent::from_signed(&p.intent).unwrap();
    let result = Operation::parse(&intent)
        .unwrap()
        .prepare(
            &p.prior.state,
            records,
            &Reservations(p.bootstrap.reservations().to_vec()),
            &intent,
            at,
            false,
            true,
        )
        .unwrap();
    assert_eq!(result.code, 0);
    let (packet, node) = certified_request(
        &p.descriptor,
        &p.intent,
        &p.challenge,
        &p.ordered,
        result.value,
        at,
        *prefix.node(),
        prefix.height() + 1,
        0,
    );
    let value = wire::decode(&packet).unwrap();
    let fields = value.array(10).unwrap();
    (
        CertifiedReply {
            node: node.clone(),
            certificate: fields[7].bytes().unwrap().to_vec(),
            result: fields[8].bytes().unwrap().to_vec(),
        },
        AncestryEvidence::direct(vec![node]),
    )
}

#[test]
fn admission_context_reopens_after_domain_discovery_without_replacing_its_floor() {
    use crate::authority_inspection::admission;

    let mut f = Fixture::with_actions(vec![0, 11, 20]);
    f.context.save(&f.store).unwrap();
    let initial = std::fs::read(f.directory.0.join("Governance.cbor")).unwrap();
    let names = [
        "AdmissionRecordsPending.cbor",
        "AdmissionRecords.cbor",
        "Governance.cbor",
    ];
    for name in names {
        files::atomic_at(
            f.store.profile_directory(),
            OsStr::new(name),
            &initial,
            true,
        )
        .unwrap();
    }
    admission::retained(&f.bootstrap, &f.store).unwrap();

    let parent = domain_request(&f).grant.unwrap();
    let mut fields = wire::decode(
        f.context
            .governance
            .record_bytes(parent.kind, parent.id)
            .unwrap(),
    )
    .unwrap()
    .array(17)
    .unwrap()
    .to_vec();
    fields[6] = b(&[24; 32]);
    fields[13] = version_value(&parent);
    fields[14] = V::Uint(7);
    fields[16] = a(vec![
        a(vec![
            V::Uint(f.store.prefix().scope().epoch),
            V::Uint(f.store.prefix().height()),
            b(f.store.prefix().policy_state()),
        ]),
        a(vec![version_value(&parent)]),
    ]);
    let delegated = wire::encode(&a(fields.clone())).unwrap();
    let child = VersionRef {
        kind: 102,
        id: [24; 32],
        generation: 1,
        digest: wire::digest(&delegated),
    };
    let mut authority = f.bootstrap.governance_records().to_vec();
    authority.push(delegated.clone());
    crate::authority_membership::sort_records(&mut authority).unwrap();
    Governance::parse([20; 32], [21; 32], &authority).unwrap();
    let mut request = domain_request(&f);
    request.grant = Some(child.clone());
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    let prepared = Prepared::new_with_objects(
        &f.bootstrap,
        request,
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        vec![],
        &mut attempt_clock(&mut f.issued, &mut f.current),
    )
    .unwrap();
    let (reply, evidence) = reply_with_records(
        &prepared,
        f.current.observe().unwrap().wall_ms,
        f.store.prefix(),
        &authority,
    );
    // The normal typed domain verifier accepts and publishes the newly learned grant.
    prepared
        .finish(reply, evidence, &mut f.store, &mut f.session, &mut || {
            Ok(f.current)
        })
        .unwrap();
    assert!(f.store.generations().contains(&child));
    assert!(f.store.resume_ordinary().unwrap().is_none());
    assert!(ContextState::load(&f.bootstrap, &f.store, &f.directory.0).is_err());
    drop(f.store);
    f.store = Store::open(&f.directory.0, f.bootstrap.descriptor().clone()).unwrap();
    let floor = std::fs::read(f.directory.0.join("AuthorityFloor.json")).unwrap();
    let witness = std::fs::read(f.directory.0.join("AuthorityWitness.json")).unwrap();
    let records = admission::retained(&f.bootstrap, &f.store).unwrap();
    assert!(records.contains(&delegated));
    ContextState::retained(&f.bootstrap, &f.store, &records).unwrap();

    let path = f.directory.0.join(CACHE);
    let retained = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(admission::retained(&f.bootstrap, &f.store).is_err());
    for tamper in [false, true] {
        let mut value = wire::decode_state(&retained)
            .unwrap()
            .array(5)
            .unwrap()
            .to_vec();
        let V::Array(records) = &mut value[4] else {
            unreachable!()
        };
        let index = records.iter().position(|r| *r == b(&delegated)).unwrap();
        if tamper {
            fields[14] = V::Uint(6);
            let changed = wire::encode(&a(fields.clone())).unwrap();
            let mut parsed = authority.clone();
            *parsed.iter_mut().find(|r| **r == delegated).unwrap() = changed.clone();
            Governance::parse([20; 32], [21; 32], &parsed).unwrap();
            records[index] = b(&changed);
        } else {
            records.remove(index);
        }
        files::atomic_at(
            f.store.profile_directory(),
            OsStr::new(CACHE),
            &wire::encode_state(&a(value)).unwrap(),
            true,
        )
        .unwrap();
        assert!(admission::retained(&f.bootstrap, &f.store).is_err());
    }
    files::atomic_at(
        f.store.profile_directory(),
        OsStr::new(CACHE),
        &retained,
        true,
    )
    .unwrap();
    assert_eq!(
        admission::retained(&f.bootstrap, &f.store).unwrap(),
        records
    );
    for name in names {
        assert_eq!(std::fs::read(f.directory.0.join(name)).unwrap(), initial);
    }
    assert_eq!(
        std::fs::read(f.directory.0.join("AuthorityFloor.json")).unwrap(),
        floor
    );
    assert_eq!(
        std::fs::read(f.directory.0.join("AuthorityWitness.json")).unwrap(),
        witness
    );
    assert!(f.store.resume_ordinary().unwrap().is_none());
    assert!(f.store.resume_fence().unwrap().is_none());
}

fn page_query(f: &Fixture) -> Request {
    let mut request = domain_request(f);
    request.command = domains::page::Command::Context {
        action: 0,
        scope_kind: 0,
        resource: [20; 32],
        namespace: None,
    }
    .into();
    request
}
fn elapsed_health(health: ClockHealth, elapsed: u64) -> ClockHealth {
    let now = health.observe().unwrap();
    ClockHealth::new(
        now.wall_ms + elapsed,
        now.boot_ms + elapsed,
        now.boot_ms + elapsed + 1000,
        100,
    )
    .unwrap()
    .frozen()
}

fn admission_snapshot(f: &Fixture, records: &[Vec<u8>]) -> crate::authority_membership::Snapshot {
    crate::authority_membership::Snapshot::parse(&a(vec![
        a(vec![
            V::Uint(f.store.prefix().scope().epoch),
            V::Uint(f.store.prefix().height()),
            b(f.store.prefix().policy_state()),
        ]),
        a(references(records, [20; 32], [21; 32])
            .unwrap()
            .iter()
            .map(version_value)
            .collect()),
    ]))
    .unwrap()
}

fn admission_record(
    kind: u64,
    id: [u8; 32],
    payload: V,
    snapshot: &crate::authority_membership::Snapshot,
    old: Option<&[u8]>,
) -> Vec<u8> {
    wire::encode(&a(vec![
        V::Uint(kind),
        V::Uint(1),
        b(&[20; 32]),
        b(&[21; 32]),
        V::Uint(old.map_or(1, |old| {
            crate::authority_admission::record_reference(old, [20; 32], [21; 32])
                .unwrap()
                .generation
                + 1
        })),
        old.map_or(V::Null, |old| b(&wire::digest(old))),
        b(&id),
        payload,
        snapshot.value.clone(),
    ]))
    .unwrap()
}

fn certified_admission(
    f: &mut Fixture,
    operation: &crate::authority_admission::Operation,
    source: &[Vec<u8>],
    replay_records: Option<&[Vec<u8>]>,
) -> (proof::VerifiedResult, Vec<Vec<u8>>, Vec<u8>) {
    use crate::authority_admission as native;
    let descriptor = f.store.descriptor().clone();
    let next = native::record_reference(&operation.next, [20; 32], [21; 32]).unwrap();
    let intent = if let Some(pending) = f.store.resume_ordinary().unwrap() {
        assert_eq!(
            native::Operation::parse(&Intent::from_signed(pending.signed()).unwrap())
                .unwrap()
                .parameters()
                .unwrap(),
            operation.parameters().unwrap()
        );
        pending.signed().to_vec()
    } else {
        prepare_ordinary(
            &descriptor,
            &f.signer,
            &mut f.store,
            "AuthorityAdmission",
            next.id,
            next.generation,
            &operation.snapshot.references,
            &operation.parameters().unwrap(),
        )
        .unwrap()
    };
    let wall = f.current.observe().unwrap().wall_ms;
    let boot = boot_time_ms().unwrap();
    f.current = ClockHealth::new(wall, boot, boot + 30000, 100)
        .unwrap()
        .frozen();
    let challenge = f
        .session
        .issue(
            &intent,
            &f.signer,
            random_id().unwrap(),
            DURATION,
            f.current,
        )
        .unwrap();
    let ordered = wire::encode(&a(vec![
        V::Uint(22),
        V::Uint(1),
        descriptor.scope().value(),
        b(&intent),
        b(&challenge),
        V::Uint(Challenge::from_signed(&challenge).unwrap().expires_at_ms),
    ]))
    .unwrap();
    let parsed = Intent::from_signed(&intent).unwrap();
    let selected = operation
        .authorise(
            replay_records.unwrap_or(source),
            &Reservations(f.bootstrap.reservations().to_vec()),
            &parsed,
            wall,
            replay_records.is_some(),
        )
        .unwrap();
    let refs = operation
        .result_references(&selected.dependencies, parsed.network, parsed.incarnation)
        .unwrap();
    let value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityAdmission".into()),
        a(refs.iter().map(version_value).collect()),
        b(&operation.next),
    ]);
    let (packet, node) = certified_request(
        &descriptor,
        &intent,
        &challenge,
        &ordered,
        value.clone(),
        wall,
        *f.store.prefix().node(),
        f.store.prefix().height() + 1,
        0,
    );
    let packet = wire::decode(&packet).unwrap();
    let fields = packet.array(10).unwrap();
    let verified = proof::verify_response(
        &descriptor,
        proof::ProofContext {
            intent: &intent,
            challenge: &challenge,
            restrictions: Restrictions::default(),
            minimum_height: f.store.prefix().height(),
            maximum_effect: 1,
            expected_stream: None,
        },
        proof::Response {
            ordered_request: &ordered,
            operation_result: fields[8].bytes().unwrap(),
            certificate: fields[7].bytes().unwrap(),
            ancestry: std::slice::from_ref(&node),
        },
        |request, result, executed| {
            let actual = native::Operation::parse(request)?;
            ensure!(
                actual.parameters()? == operation.parameters()?,
                "admission request differs"
            );
            let (records, validation) = crate::authority_inspection::admission::validate_permit(
                &f.bootstrap,
                &f.store,
                &actual,
                source,
                request,
                result,
                executed,
            )?;
            ensure!(records == selected.records, "admission records differ");
            ensure!(
                wire::decode(&result.value)? == value,
                "admission result differs"
            );
            Ok(validation)
        },
    )
    .unwrap();
    let verified = AncestryEvidence::direct(vec![node])
        .attach(&f.store, verified)
        .unwrap();
    (verified, selected.records, intent)
}

fn learn_admission_completion(f: &mut Fixture, intent: &Intent, result: proof::Digest) {
    use super::super::tests::{receive_control, send_control, submitted};
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};
    let wall = f.current.observe().unwrap().wall_ms;
    let boot = boot_time_ms().unwrap();
    f.current = ClockHealth::new(wall, boot, boot + 30000, 100)
        .unwrap()
        .frozen();
    let socket = f.directory.0.join("AdmissionStatus.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let descriptor = f.store.descriptor().clone();
    let server_descriptor = descriptor.clone();
    let metadata = a(vec![
        V::Uint(56),
        V::Uint(1),
        descriptor.scope().value(),
        b(&intent.requester),
        V::Bool(true),
        V::Uint(intent.generation),
        b(&intent.generation_id),
        V::Uint(intent.acknowledged_through),
        a(vec![
            V::Uint(intent.sequence),
            b(&intent.digest),
            V::Uint(0),
            V::Uint(0),
            b(&result),
        ]),
        V::Null,
    ]);
    let parent = *f.store.prefix().node();
    let height = f.store.prefix().height() + 1;
    let server = std::thread::spawn(move || {
        let (stream, packet) = receive_control(&listener);
        let (ordered, signed, challenge) = submitted(&packet);
        let at = Challenge::from_signed(&challenge).unwrap().created_at_ms;
        let (reply, _) = certified_request(
            &server_descriptor,
            &signed,
            &challenge,
            &ordered,
            metadata,
            at,
            parent,
            height,
            0,
        );
        send_control(stream, &reply);
    });
    let status = stream_client::status_local(
        &descriptor,
        &socket,
        &f.signer,
        &mut f.store,
        &mut f.session,
        || Ok(f.current),
    );
    server.join().unwrap();
    assert_eq!(
        status
            .unwrap()
            .state()
            .unwrap()
            .completion
            .as_ref()
            .unwrap()
            .intent,
        intent.digest
    );
}

#[test]
fn admission_enrolment_replaces_reserved_cache_and_retries_exact_pending_publication() {
    admission_recovery_after_expiry(false);
}

#[test]
fn admission_lost_first_reply_uses_certified_status_before_late_exact_replay() {
    admission_recovery_after_expiry(true);
}

fn complete_admission(
    f: &mut Fixture,
    operation: &crate::authority_admission::Operation,
    source: &[Vec<u8>],
) -> (Vec<Vec<u8>>, Vec<u8>) {
    let (verified, records, intent) = certified_admission(f, operation, source, None);
    let permit = f
        .store
        .accept_with_clock(verified, &mut f.session, &mut || Ok(f.current), 0)
        .unwrap();
    permit
        .perform_with_clock(
            &mut f.store,
            &mut f.session,
            &mut || Ok(f.current),
            1,
            |_| Ok(()),
            |_, store| {
                let context = ContextState::retained(&f.bootstrap, store, &records)?;
                context.save(store)?;
                Cache::retain_context(&f.bootstrap, store, &context)
            },
        )
        .unwrap();
    (records, intent)
}

#[test]
fn admission_reused_slot_snapshot_survives_certified_enrolment_and_reopen() {
    use crate::authority_admission as native;
    let (mut f, policy, candidate, mut records, mut old) = admission_reserved_fixture();
    let operation = admission_enrol(&f, &records, &policy, &old, &candidate);
    (records, _) = complete_admission(&mut f, &operation, &records);
    old = native::Slot::parse(&operation.next, [20; 32], [21; 32]).unwrap();
    let original_material = references(&old.material, [20; 32], [21; 32]).unwrap();
    for transition in [native::Transition::Retire, native::Transition::Reserve] {
        let snapshot = crate::authority_inspection_cli::admission_cli::snapshot(
            &f.store,
            f.current.observe().unwrap().wall_ms,
            &records,
            &policy,
            Some(&old),
            transition != native::Transition::Retire,
        )
        .unwrap();
        let mut next = old.clone();
        if transition == native::Transition::Retire {
            next.state = 3;
            next.challenge_until = 0;
        } else {
            next.state = 0;
            next.assignment += 1;
            next.claim = [8; 32];
            next.nonce = [97; 32];
            next.challenge_until = f.current.observe().unwrap().wall_ms + native::CHALLENGE_MS;
        }
        let operation = native::Operation {
            transition,
            policy: policy.bytes.clone(),
            previous: Some(old.bytes.clone()),
            next: admission_record(
                native::SLOT,
                old.reference.id,
                next.payload(),
                &snapshot,
                Some(&old.bytes),
            ),
            acceptance: vec![],
            legacy: vec![],
            snapshot,
        };
        (records, _) = complete_admission(&mut f, &operation, &records);
        old = native::Slot::parse(&operation.next, [20; 32], [21; 32]).unwrap();
    }
    assert_eq!(old.assignment, 2);
    let operation = admission_enrol(&f, &records, &policy, &old, &candidate);
    let source = records.clone();
    let (records, signed) = complete_admission(&mut f, &operation, &source);
    let intent = Intent::from_signed(&signed).unwrap();
    assert_eq!((intent.sequence, intent.acknowledged_through), (5, 4));
    assert_eq!(
        original_material.iter().filter(|r| r.kind == 102).count(),
        2
    );
    assert_eq!(
        original_material.iter().filter(|r| r.kind == 125).count(),
        1
    );
    for old in &original_material {
        assert!(operation.snapshot.references.contains(old));
        assert!(intent.expected.contains(old));
        let mut missing = intent.clone();
        missing.expected.retain(|r| r != old);
        assert!(
            operation
                .authorise(
                    &source,
                    &Reservations(f.bootstrap.reservations().to_vec()),
                    &missing,
                    f.current.observe().unwrap().wall_ms,
                    false,
                )
                .err()
                .unwrap()
                .to_string()
                .contains("exact signed predecessor")
        );
    }
    let next = native::Slot::parse(&operation.next, [20; 32], [21; 32]).unwrap();
    let next_material = references(&next.material, [20; 32], [21; 32]).unwrap();
    let cached = Cache::load(&f.bootstrap, &f.store).unwrap().records;
    assert!(cached.iter().all(|record| records.contains(record)));
    let cached_versions = references(&cached, [20; 32], [21; 32]).unwrap();
    assert!(cached_versions.contains(&next.reference));
    for old in original_material {
        let current = next_material
            .iter()
            .find(|r| r.index() == old.index())
            .unwrap();
        assert_eq!(current.generation, old.generation + 1);
        assert!(cached_versions.contains(current));
        assert!(f.store.generations().contains(current));
        assert!(!f.store.generations().contains(&old));
    }
    let floor = std::fs::read(f.directory.0.join("AuthorityFloor.json")).unwrap();
    drop(f.store);
    f.store = Store::open(&f.directory.0, f.bootstrap.descriptor().clone()).unwrap();
    assert!(f.store.resume_ordinary().unwrap().is_none());
    assert_eq!(Cache::load(&f.bootstrap, &f.store).unwrap().records, cached);
    assert_eq!(
        std::fs::read(f.directory.0.join("AuthorityFloor.json")).unwrap(),
        floor
    );
}

fn admission_reserved_fixture() -> (
    Fixture,
    crate::authority_admission::Policy,
    SigningKey,
    Vec<Vec<u8>>,
    crate::authority_admission::Slot,
) {
    use crate::authority_admission as native;
    let registrar = SigningKey::from_bytes(&[90; 32]);
    let mut f = Fixture::with_actions_and_signer(vec![0, 10, 11], registrar);
    let mut source = f.bootstrap.governance_records().to_vec();
    let snapshot = admission_snapshot(&f, &source);
    let parent = references(&source, [20; 32], [21; 32])
        .unwrap()
        .into_iter()
        .find(|r| r.kind == 102)
        .unwrap();
    let now = f.current.observe().unwrap().wall_ms;
    let policy = native::Policy::parse(
        &admission_record(
            native::POLICY,
            [201; 32],
            a(vec![
                b(&SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes()),
                version_value(&parent),
                b(&f.signer.verifying_key().to_bytes()),
                b(&SigningKey::from_bytes(&[91; 32]).verifying_key().to_bytes()),
                V::Bool(true),
                V::Uint(1),
                crate::trust_validity::Validity(now - 2000, (now + 600000).into()).value(),
                b(&[202; 32]),
                b(&[203; 32]),
                a(vec![
                    native::Template {
                        role: 0,
                        destination: [204; 32],
                        application: None,
                        page: None,
                        limits: [100, 100, 10, 10],
                        connections: 16,
                        bytes: 65536,
                        voucher_ms: 120000,
                    }
                    .value(),
                ]),
                a(vec![]),
            ]),
            &snapshot,
            None,
        ),
        [20; 32],
        [21; 32],
    )
    .unwrap();
    source.push(policy.bytes.clone());
    crate::authority_membership::sort_records(&mut source).unwrap();
    let candidate = SigningKey::from_bytes(&[92; 32]);
    let member = candidate.verifying_key().to_bytes();
    let relay = SigningKey::from_bytes(&[93; 32]).verifying_key().to_bytes();
    let role = native::Role {
        role: 0,
        member,
        relay,
        request: wire::sign_envelope(
            &wire::encode(&a(vec![
                V::Uint(200),
                V::Uint(1),
                V::Text("HyperNetJoinRequest".into()),
                b(&[20; 32]),
                b(&[21; 32]),
                b(&[90; 32]),
                b(&member),
                b(&member),
                b(&relay),
                V::Uint(1),
            ]))
            .unwrap(),
            &candidate,
        )
        .unwrap(),
    };
    let snapshot = admission_snapshot(&f, &source);
    let reserved = admission_record(
        native::SLOT,
        native::identifier(policy.reference.id, 0, 0, 0).unwrap(),
        a(vec![
            b(&policy.reference.id),
            V::Uint(0),
            V::Uint(1),
            b(&[7; 32]),
            b(&[94; 32]),
            b(&[95; 32]),
            V::Uint(0),
            V::Uint(now + native::CHALLENGE_MS),
            a(vec![role.value()]),
            b(&[96; 32]),
            V::Uint(1),
            a(vec![]),
            a(vec![]),
        ]),
        &snapshot,
        None,
    );
    let reserve = native::Operation {
        transition: native::Transition::Reserve,
        policy: policy.bytes.clone(),
        previous: None,
        next: reserved.clone(),
        acceptance: vec![],
        legacy: vec![],
        snapshot,
    };
    let (reserved_records, reserve_intent) = complete_admission(&mut f, &reserve, &source);
    assert_eq!(Intent::from_signed(&reserve_intent).unwrap().sequence, 1);
    let old = native::Slot::parse(&reserved, [20; 32], [21; 32]).unwrap();
    (f, policy, candidate, reserved_records, old)
}

fn admission_enrol(
    f: &Fixture,
    records: &[Vec<u8>],
    policy: &crate::authority_admission::Policy,
    old: &crate::authority_admission::Slot,
    candidate: &SigningKey,
) -> crate::authority_admission::Operation {
    use crate::authority_admission as native;
    let snapshot = crate::authority_inspection_cli::admission_cli::snapshot(
        &f.store,
        f.current.observe().unwrap().wall_ms,
        records,
        policy,
        Some(old),
        true,
    )
    .unwrap();
    let governance = Governance::parse([20; 32], [21; 32], records).unwrap();
    let grant = wire::decode(governance.record_bytes(102, policy.parent.id).unwrap()).unwrap();
    let tier = crate::authority_membership::version(&grant.array(17).unwrap()[9]).unwrap();
    let mut successor = old.clone();
    successor.state = 1;
    successor.challenge_until = 0;
    successor.material =
        native::enrol_material(policy, old, &tier, &snapshot, [20; 32], [21; 32]).unwrap();
    native::Operation {
        transition: native::Transition::Enrol,
        policy: policy.bytes.clone(),
        previous: Some(old.bytes.clone()),
        next: admission_record(
            native::SLOT,
            old.reference.id,
            successor.payload(),
            &snapshot,
            Some(&old.bytes),
        ),
        acceptance: vec![
            wire::sign_envelope(
                &old.acceptance_payload([20; 32], [21; 32]).unwrap(),
                candidate,
            )
            .unwrap(),
        ],
        legacy: vec![],
        snapshot,
    }
}

fn admission_recovery_after_expiry(lose_first_reply: bool) {
    use crate::authority_admission as native;
    let (mut f, policy, candidate, reserved_records, old) = admission_reserved_fixture();
    let retained = std::fs::read(f.directory.0.join(CACHE)).unwrap();
    let enrol = admission_enrol(&f, &reserved_records, &policy, &old, &candidate);
    let successor = native::Slot::parse(&enrol.next, [20; 32], [21; 32]).unwrap();
    let (mut verified, enrolled_records, exact_intent) =
        certified_admission(&mut f, &enrol, &reserved_records, None);
    let parsed = Intent::from_signed(&exact_intent).unwrap();
    assert_eq!((parsed.sequence, parsed.acknowledged_through), (2, 1));
    let mut expired = verified.executed.clone();
    expired.evaluated_at_ms = old.challenge_until + 2000;
    let error = crate::authority_inspection::admission::validate_permit(
        &f.bootstrap,
        &f.store,
        &enrol,
        &reserved_records,
        &parsed,
        &verified.result,
        &expired,
    )
    .err()
    .expect("uncommitted expired acceptance must remain refused");
    assert!(
        format!("{error:#}").contains("admission acceptance expired"),
        "{error:#}"
    );
    if lose_first_reply {
        let original_digest = verified.executed.result;
        let pending = f
            .store
            .resume_ordinary()
            .unwrap()
            .unwrap()
            .signed()
            .to_vec();
        drop(f.store);
        f.store = Store::open(&f.directory.0, f.bootstrap.descriptor().clone()).unwrap();
        f.session = Session::new().unwrap();
        f.current = elapsed_health(f.current, native::CHALLENGE_MS + 2000);
        let next = native::record_reference(&enrol.next, [20; 32], [21; 32]).unwrap();
        assert!(!f.store.generations().contains(&next));
        learn_admission_completion(&mut f, &parsed, original_digest);
        assert_eq!(
            f.store.resume_ordinary().unwrap().unwrap().signed(),
            pending
        );
        assert!(!f.store.generations().contains(&next));
        let mut changed = expired.clone();
        changed.result = [99; 32];
        assert!(
            crate::authority_inspection::admission::validate_permit(
                &f.bootstrap,
                &f.store,
                &enrol,
                &reserved_records,
                &parsed,
                &verified.result,
                &changed,
            )
            .is_err()
        );
        let (replayed, records, signed) =
            certified_admission(&mut f, &enrol, &reserved_records, Some(&enrolled_records));
        assert_eq!(signed, exact_intent);
        assert_eq!(records, enrolled_records);
        verified = replayed;
    }
    let permit = f
        .store
        .accept_with_clock(verified, &mut f.session, &mut || Ok(f.current), 0)
        .unwrap();
    let failed: Result<()> = permit.perform_with_clock(
        &mut f.store,
        &mut f.session,
        &mut || Ok(f.current),
        1,
        |_| Ok(()),
        |_, store| {
            ContextState::retained(&f.bootstrap, store, &enrolled_records)?.save(store)?;
            anyhow::bail!("interrupted before domain cache publication")
        },
    );
    assert!(
        failed
            .unwrap_err()
            .to_string()
            .contains("interrupted before domain cache")
    );
    assert_eq!(std::fs::read(f.directory.0.join(CACHE)).unwrap(), retained);
    let current = native::record_reference(&enrol.next, [20; 32], [21; 32]).unwrap();
    assert_eq!(current.generation, 2);
    assert!(f.store.generations().contains(&current));
    assert!(!f.store.generations().contains(&old.reference));
    let floor = std::fs::read(f.directory.0.join("AuthorityFloor.json")).unwrap();
    let status: serde_json::Value = serde_json::from_slice(&floor).unwrap();
    assert_eq!(status["tracker"]["ordinary"]["bodySaved"], true);
    assert_eq!(status["tracker"]["ordinary"]["complete"], false);
    assert_eq!(status["tracker"]["ordinary"]["effect"], "unclaimed");
    let body = std::fs::read(f.directory.0.join("AuthorityBody.cbor")).unwrap();
    drop(f.store);
    f.store = Store::open(&f.directory.0, f.bootstrap.descriptor().clone()).unwrap();
    f.session = Session::new().unwrap();
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        exact_intent
    );
    assert!(Cache::load(&f.bootstrap, &f.store).is_err());
    let context = ContextState::retained(&f.bootstrap, &f.store, &enrolled_records).unwrap();
    let forged = admission_record(
        native::SLOT,
        current.id,
        successor.payload(),
        &enrol.snapshot,
        Some(&enrol.next),
    );
    let mut unproven = enrolled_records.clone();
    *unproven.iter_mut().find(|r| **r == enrol.next).unwrap() = forged;
    assert!(ContextState::retained(&f.bootstrap, &f.store, &unproven).is_err());
    let stale = ContextState {
        descriptor: f.store.descriptor().clone(),
        governance: Governance::parse([20; 32], [21; 32], &unproven).unwrap(),
    };
    assert!(Cache::retain_context(&f.bootstrap, &f.store, &stale).is_err());
    assert_eq!(std::fs::read(f.directory.0.join(CACHE)).unwrap(), retained);
    for corrupt in [
        b"not a cache".to_vec(),
        wire::encode_state(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityDomainCache".into()),
            State::empty([19; 32], [21; 32]).value(),
            a(vec![]),
        ]))
        .unwrap(),
        wire::encode_state(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityDomainCache".into()),
            State::empty([20; 32], [21; 32]).value(),
            a(vec![b(b"not a governance record")]),
        ]))
        .unwrap(),
    ] {
        std::fs::write(f.directory.0.join(CACHE), &corrupt).unwrap();
        assert!(Cache::retain_context(&f.bootstrap, &f.store, &context).is_err());
        assert_eq!(std::fs::read(f.directory.0.join(CACHE)).unwrap(), corrupt);
    }
    std::fs::write(f.directory.0.join(CACHE), &retained).unwrap();
    Cache::retain_context(&f.bootstrap, &f.store, &context).unwrap();
    assert_eq!(
        std::fs::read(f.directory.0.join("AuthorityFloor.json")).unwrap(),
        floor
    );
    assert_eq!(
        std::fs::read(f.directory.0.join("AuthorityBody.cbor")).unwrap(),
        body
    );
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        exact_intent
    );
    assert!(
        references(
            &Cache::load(&f.bootstrap, &f.store).unwrap().records,
            [20; 32],
            [21; 32]
        )
        .unwrap()
        .contains(&current)
    );
    f.current = elapsed_health(f.current, native::CHALLENGE_MS + 2000);
    let (verified, retried_records, retried_intent) =
        certified_admission(&mut f, &enrol, &reserved_records, Some(&enrolled_records));
    assert_eq!(retried_intent, exact_intent);
    assert!(verified.executed.evaluated_at_ms > old.challenge_until);
    let mut different = parsed.clone();
    different.digest = [99; 32];
    assert!(
        crate::authority_inspection::admission::validate_permit(
            &f.bootstrap,
            &f.store,
            &enrol,
            &reserved_records,
            &different,
            &verified.result,
            &verified.executed,
        )
        .is_err()
    );
    let changed_result = proof::OperationResult {
        action: verified.result.action.clone(),
        disposition: Disposition::Permit,
        code: 0,
        value: wire::encode(&V::Null).unwrap(),
    };
    assert!(
        crate::authority_inspection::admission::validate_permit(
            &f.bootstrap,
            &f.store,
            &enrol,
            &reserved_records,
            &parsed,
            &changed_result,
            &verified.executed,
        )
        .is_err()
    );
    let permit = f
        .store
        .accept_with_clock(verified, &mut f.session, &mut || Ok(f.current), 0)
        .unwrap();
    permit
        .perform_with_clock(
            &mut f.store,
            &mut f.session,
            &mut || Ok(f.current),
            1,
            |_| Ok(()),
            |_, store| {
                let context = ContextState::retained(&f.bootstrap, store, &retried_records)?;
                context.save(store)?;
                Cache::retain_context(&f.bootstrap, store, &context)
            },
        )
        .unwrap();
    assert!(f.store.resume_ordinary().unwrap().is_none());
    drop(f.store);
    f.store = Store::open(&f.directory.0, f.bootstrap.descriptor().clone()).unwrap();
    assert!(Cache::load(&f.bootstrap, &f.store).is_ok());
    assert!(f.store.resume_ordinary().unwrap().is_none());
}

// Durable setup precedes a new challenge; frozen wall values still model quorum evaluation.
fn attempt_clock<'a>(
    issued: &'a mut ClockHealth,
    current: &'a mut ClockHealth,
) -> impl FnMut() -> Result<ClockHealth> + 'a {
    let before = issued.observe().unwrap();
    let received = current.observe().unwrap();
    let gap = received.wall_ms.checked_sub(before.wall_ms).unwrap();
    move || {
        let boot = boot_time_ms()?;
        *issued = ClockHealth::new(before.wall_ms, boot, boot + 30000, 100)?.frozen();
        *current = ClockHealth::new(received.wall_ms, boot + gap, boot + 30000, 100)?.frozen();
        eprintln!(
            "domain fixture clock: prior_boot={} sampled_boot={} deadline={} evaluation_gap={}",
            before.boot_ms,
            boot,
            boot + DURATION,
            gap
        );
        Ok(*issued)
    }
}

#[test]
fn own_backup_metadata_finishes_without_inventing_a_discretionary_policy_dependency() {
    let mut f = Fixture::with_actions(vec![0, 20]);
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    let prepared = Prepared::new_with_objects(
        &f.bootstrap,
        Request {
            command: domains::backup::Command::List { after: None }.into(),
            grant: None,
        },
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        vec![],
        &mut attempt_clock(&mut f.issued, &mut f.current),
    )
    .unwrap();
    assert_eq!(
        prepared.deadline,
        f.issued.observe().unwrap().boot_ms + DURATION
    );
    assert!(
        Intent::from_signed(&prepared.intent)
            .unwrap()
            .expected
            .is_empty()
    );
    let (certified, evidence) = reply(&prepared, &f);
    prepared
        .finish(
            certified,
            evidence,
            &mut f.store,
            &mut f.session,
            &mut || Ok(f.current),
        )
        .unwrap();
    assert!(f.store.resume_ordinary().unwrap().is_none());

    let expected = policy::current_reference(&f.bootstrap, &f.store).unwrap();
    let request = page_query(&f);
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    f.issued = f.current;
    let prepared = Prepared::new(
        &f.bootstrap,
        request,
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    assert_eq!(
        Intent::from_signed(&prepared.intent).unwrap().expected,
        vec![expected]
    );
}

#[test]
fn page_history_refresh_keeps_exact_intent_and_original_deadline() {
    let mut f = Fixture::with_actions(vec![0, 20]);
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    let request = page_query(&f);
    let mut prepared = Prepared::new_with_objects(
        &f.bootstrap,
        request,
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        vec![],
        &mut attempt_clock(&mut f.issued, &mut f.current),
    )
    .unwrap();
    assert_eq!(
        prepared.deadline,
        f.issued.observe().unwrap().boot_ms + DURATION
    );
    let original = prepared.intent.clone();
    let deadline = prepared.deadline;
    let prefix = f.store.prefix().clone();
    let elapsed = std::cell::Cell::new(0);
    let mut attempts = Vec::new();
    let (certified, evidence) = prepared
        .exchange_with_history(
            &f.signer,
            &mut f.session,
            &mut || Ok(elapsed_health(f.issued, elapsed.get())),
            &mut |attempt, _| {
                assert_eq!(attempt.intent, original);
                assert_eq!(attempt.deadline, deadline);
                let value = wire::decode(&attempt.ordered)?;
                let fields = value.array(6)?;
                assert_eq!(fields[3].bytes()?, original);
                attempts.push(Challenge::from_signed(fields[4].bytes()?)?);
                if attempts.len() == 1 {
                    elapsed.set(1000);
                    Err(crate::authority_local_transport::HistoryOvertaken.into())
                } else {
                    Ok(reply_at(
                        attempt,
                        f.current.observe().unwrap().wall_ms,
                        &prefix,
                    ))
                }
            },
        )
        .unwrap();
    assert_eq!(attempts.len(), 2);
    assert_ne!(attempts[0].nonce, attempts[1].nonce);
    assert_eq!(attempts[0].intent, attempts[1].intent);
    assert_eq!(attempts[0].maximum_duration_ms, DURATION);
    assert_eq!(attempts[1].maximum_duration_ms, DURATION - 1000);
    assert_eq!(attempts[0].expires_at_ms, attempts[1].expires_at_ms);
    assert_eq!(f.store.prefix().node(), prefix.node());
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        original
    );
    assert!(
        Cache::load(&f.bootstrap, &f.store)
            .unwrap()
            .records
            .is_empty()
    );
    let result = prepared
        .finish(
            certified,
            evidence,
            &mut f.store,
            &mut f.session,
            &mut || Ok(f.current),
        )
        .unwrap();
    assert_eq!(result.deadline_boot_ms, deadline);
    assert_eq!(result.prefix.height(), prefix.height() + 1);
    assert!(f.store.resume_ordinary().unwrap().is_none());
}

#[test]
fn page_history_refresh_stops_on_repeated_overtaking_at_original_deadline() {
    let mut f = Fixture::with_actions(vec![0, 20]);
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    let request = page_query(&f);
    let mut prepared = Prepared::new(
        &f.bootstrap,
        request,
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let original = prepared.intent.clone();
    let prefix = f.store.prefix().clone();
    let deadline = prepared.deadline;
    let elapsed = std::cell::Cell::new(0);
    let mut calls = 0;
    let error = prepared
        .exchange_with_history::<(), _>(
            &f.signer,
            &mut f.session,
            &mut || Ok(elapsed_health(f.issued, elapsed.get())),
            &mut |attempt, _| {
                calls += 1;
                assert_eq!(attempt.intent, original);
                assert_eq!(attempt.deadline, deadline);
                assert_eq!(
                    Challenge::from_signed(&attempt.challenge)?.maximum_duration_ms,
                    DURATION - elapsed.get()
                );
                elapsed.set(elapsed.get() + 1000);
                Err(crate::authority_local_transport::HistoryOvertaken.into())
            },
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("original domain query deadline expired")
    );
    assert_eq!(calls, 5);
    assert_eq!(f.store.prefix().node(), prefix.node());
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        original
    );
    assert!(
        Cache::load(&f.bootstrap, &f.store)
            .unwrap()
            .records
            .is_empty()
    );
}

#[test]
fn page_history_refresh_does_not_retry_malformed_proofs_or_other_domains() {
    for permitted in [true, false] {
        let mut f = Fixture::with_actions(vec![0, 20]);
        let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
        let request = if permitted {
            page_query(&f)
        } else {
            domain_request(&f)
        };
        let mut prepared = Prepared::new(
            &f.bootstrap,
            request,
            cache,
            &f.signer,
            &mut f.store,
            &mut f.session,
            f.issued,
        )
        .unwrap();
        let original = prepared.challenge.clone();
        let mut calls = 0;
        let mut clock_calls = 0;
        let error = prepared
            .exchange_with_history::<(), _>(
                &f.signer,
                &mut f.session,
                &mut || {
                    clock_calls += 1;
                    Ok(f.current)
                },
                &mut |_, _| {
                    calls += 1;
                    if permitted {
                        anyhow::bail!("malformed checkpoint proof");
                    }
                    Err(crate::authority_local_transport::HistoryOvertaken.into())
                },
            )
            .unwrap_err();
        assert_eq!(calls, 1);
        assert_eq!(clock_calls, 0);
        assert_eq!(prepared.challenge, original);
        if permitted {
            assert_eq!(error.to_string(), "malformed checkpoint proof");
        } else {
            assert!(error.is::<crate::authority_local_transport::HistoryOvertaken>());
        }
    }
}

#[test]
fn page_history_refresh_excludes_mutations_and_serving_authorisations() {
    use domains::page::{Command as Page, content::Command as Content};
    let reference = |kind| VersionRef {
        kind,
        id: [30; 32],
        generation: 1,
        digest: [31; 32],
    };
    let queries = vec![
        Page::Read { page: [1; 16] },
        Page::View { page: [1; 16] },
        Page::List {
            namespace: "Books".into(),
            after: None,
        },
        Page::SearchList {
            namespace: "Books".into(),
            after: None,
        },
        Page::LocalSearchLease {
            items: vec![(reference(142), None)],
        },
        Page::Content(Content::Get {
            placement: reference(159),
        }),
    ];
    for query in queries {
        assert!(refreshable_page_query(&query.into()));
    }
    let excluded = vec![
        Page::HostWithdraw {
            role: 1,
            host: [30; 32],
            generation: 1,
        }
        .into(),
        Page::Withdraw {
            page: [1; 16],
            as_reviewer: false,
        }
        .into(),
        Page::Content(Content::Withdraw {
            placement: reference(159),
        })
        .into(),
        Page::Content(Content::Authorise {
            placement: reference(159),
            host: reference(147),
            effect: domains::page::content::Effect::Search,
            offset: 0,
            bytes: 32,
            digest: None,
        })
        .into(),
        Page::MediaAuthorise {
            asset: reference(149),
            host: reference(147),
            effect: domains::page::MediaEffect::Read,
            offset: 0,
            bytes: 32,
            digest: None,
        }
        .into(),
        domains::ssh::Command::Authorise {
            service: [30; 32],
            id: [31; 32],
        }
        .into(),
    ];
    for command in excluded {
        assert!(!refreshable_page_query(&command));
    }
}

#[test]
fn domain_challenge_refreshes_clock_after_durable_intent_preparation() {
    let mut f = Fixture::with_actions(vec![0, 20]);
    let now = f.issued.observe().unwrap();
    let preflight = ClockHealth::new(now.wall_ms, now.boot_ms, now.boot_ms + 1000, 100)
        .unwrap()
        .frozen();
    let issued = ClockHealth::new(
        now.wall_ms + 1500,
        now.boot_ms + 1500,
        now.boot_ms + 2500,
        100,
    )
    .unwrap()
    .frozen();
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    let request = domain_request(&f);
    let mut calls = 0;
    let prepared = Prepared::new_with_objects(
        &f.bootstrap,
        request,
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        vec![],
        &mut || {
            calls += 1;
            Ok(if calls == 1 { preflight } else { issued })
        },
    )
    .unwrap();
    assert_eq!(calls, 2);
    let challenge = Challenge::from_signed(&prepared.challenge).unwrap();
    assert_eq!(challenge.created_at_ms, now.wall_ms + 1500);
    assert_eq!(challenge.expires_at_ms, now.wall_ms + 1500 + DURATION);
    assert_eq!(prepared.deadline, now.boot_ms + 1500 + DURATION);
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        prepared.intent
    );
}

#[test]
fn unavailable_issuance_clock_keeps_exact_pending_domain_intent() {
    let mut f = Fixture::with_actions(vec![0, 20]);
    let now = f.issued.observe().unwrap();
    let invalid = ClockHealth::new(
        now.wall_ms + 1500,
        now.boot_ms + 1500,
        now.boot_ms + 1500,
        100,
    )
    .unwrap()
    .frozen();
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    let request = domain_request(&f);
    let mut calls = 0;
    let result = Prepared::new_with_objects(
        &f.bootstrap,
        request,
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        vec![],
        &mut || {
            calls += 1;
            Ok(if calls == 1 { f.issued } else { invalid })
        },
    );
    let error = result.err().unwrap();
    assert!(format!("{error:#}").contains("clock health is stale or invalid"));
    assert_eq!(calls, 2);
    let original = f
        .store
        .resume_ordinary()
        .unwrap()
        .unwrap()
        .signed()
        .to_vec();
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    let request = domain_request(&f);
    let prepared = Prepared::new(
        &f.bootstrap,
        request,
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.current,
    )
    .unwrap();
    assert_eq!(prepared.intent, original);
}
#[test]
fn cache_failure_reopens_and_retries_the_exact_original_domain_request() {
    let mut f = Fixture::with_actions(vec![0, 20]);
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    assert!(cache.records.is_empty());
    let request = domain_request(&f);
    let prepared = Prepared::new_with_objects(
        &f.bootstrap,
        request,
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        vec![],
        &mut attempt_clock(&mut f.issued, &mut f.current),
    )
    .unwrap();
    assert_eq!(
        prepared.deadline,
        f.issued.observe().unwrap().boot_ms + DURATION
    );
    let original = prepared.intent.clone();
    let (certified, evidence) = reply(&prepared, &f);
    let path = f.directory.0.join(CACHE);
    std::fs::create_dir(&path).unwrap();
    assert!(
        prepared
            .finish(
                certified,
                evidence,
                &mut f.store,
                &mut f.session,
                &mut || Ok(f.current)
            )
            .is_err()
    );
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        original
    );
    assert!(Cache::load(&f.bootstrap, &f.store).is_err());
    std::fs::remove_dir(&path).unwrap();
    drop(f.store);
    f.store = Store::open(&f.directory.0, f.bootstrap.descriptor().clone()).unwrap();
    f.session = Session::new().unwrap();
    let now = f.current.observe().unwrap();
    f.issued = f.current;
    f.current = ClockHealth::new(
        now.wall_ms + 2000,
        now.boot_ms + 2000,
        now.boot_ms + 30000,
        100,
    )
    .unwrap()
    .frozen();
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    let mut changed = domain_request(&f);
    changed.command = domains::ssh::Command::Services {
        network: [20; 32],
        after: None,
    }
    .into();
    assert!(
        Prepared::new(
            &f.bootstrap,
            changed,
            cache.clone(),
            &f.signer,
            &mut f.store,
            &mut f.session,
            f.issued
        )
        .is_err()
    );
    let request = domain_request(&f);
    let prepared = Prepared::new_with_objects(
        &f.bootstrap,
        request,
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        vec![],
        &mut attempt_clock(&mut f.issued, &mut f.current),
    )
    .unwrap();
    assert_eq!(
        prepared.deadline,
        f.issued.observe().unwrap().boot_ms + DURATION
    );
    assert_eq!(prepared.intent, original);
    let (certified, evidence) = reply(&prepared, &f);
    prepared
        .finish(
            certified,
            evidence,
            &mut f.store,
            &mut f.session,
            &mut || Ok(f.current),
        )
        .unwrap();
    assert!(f.store.resume_ordinary().unwrap().is_none());
    let cached = Cache::load(&f.bootstrap, &f.store).unwrap();
    assert!(!cached.records.is_empty());
    drop(f.store);
    f.store = Store::open(&f.directory.0, f.bootstrap.descriptor().clone()).unwrap();
    assert_eq!(
        Cache::load(&f.bootstrap, &f.store).unwrap().records,
        cached.records
    );
}

#[test]
fn expired_read_preserves_newer_stream_floor_and_reacquires_superseded_cache() {
    use crate::authority_read::{self as read, Query};
    use std::cell::Cell;

    let mut f = Fixture::with_actions(vec![0, 30]);
    let record = |generation: u64, slot: u64, nonce: u8| {
        let mut proof = domains::streams::Proof {
            service: VersionRef {
                kind: 172,
                id: [71; 32],
                generation: 1,
                digest: [72; 32],
            },
            principal: f.signer.verifying_key().to_bytes(),
            grant: domain_request(&f).grant.unwrap(),
            protocol: "cache-recovery".into(),
            slot,
            generation: generation - 1,
            nonce: [nonce; 32],
            challenge: [73; 32],
            exporter: [74; 32],
            limits: crate::route_profile::Limits {
                bytes: 16384,
                duration_ms: 5000,
                idle_ms: 1000,
            },
            expires: f.current.observe().unwrap().wall_ms + 60000,
            envelope: vec![],
        };
        proof.envelope =
            wire::sign_envelope(&proof.payload([20; 32], [21; 32]).unwrap(), &f.signer).unwrap();
        let id = proof.id().unwrap();
        let session = domains::streams::Session {
            proof,
            closed: true,
            retired: false,
            creation: [75; 32],
        };
        let bytes = wire::encode(&a(vec![
            V::Uint(173),
            V::Uint(1),
            b(&[20; 32]),
            b(&[21; 32]),
            V::Uint(generation),
            b(&[76; 32]),
            b(&id),
            session.value(),
        ]))
        .unwrap();
        domains::Record::parse(&bytes, [20; 32], [21; 32]).unwrap()
    };
    let old = record(62, 0, 77);
    let current = record(64, 0, 78);
    let invalid = [record(64, 0, 79), record(66, 0, 80), record(64, 1, 81)];
    let cache = |record: &domains::Record| {
        let mut state = State::empty([20; 32], [21; 32]);
        state
            .records
            .insert(record.reference.index(), record.clone());
        Cache {
            state,
            records: vec![],
        }
    };
    let certified = |f: &mut Fixture, record: &domains::Record, short: bool| {
        let operation = Request {
            command: domains::streams::Command::Lookup {
                service: [71; 32],
                slot: 0,
            }
            .into(),
            grant: domain_request(f).grant,
        }
        .operation(&f.store, &[])
        .unwrap();
        let request = read::Request::sign(
            f.store.descriptor().scope(),
            &f.signer,
            f.signer.verifying_key().to_bytes(),
            [82; 32],
            f.store.prefix().height(),
            Query::Domain(operation),
        )
        .unwrap();
        let challenge = f
            .session
            .issue_read(&request, &f.signer, [82; 32], 5000, f.current)
            .unwrap();
        let at = f.current.observe().unwrap().wall_ms;
        let packet = crate::authority_inspection::read_client::tests::response(
            &request,
            &challenge,
            &f.status_node,
            *f.store.prefix().policy_state(),
            a(vec![
                V::Uint(201),
                V::Uint(1),
                V::Text("AuthorityDomain".into()),
                a(vec![version_value(&record.reference)]),
                a(vec![
                    V::Text("StreamLookup".into()),
                    a(vec![b(&record.bytes)]),
                    a(vec![]),
                    V::Null,
                ]),
            ]),
            at,
            if short { at + 1400 } else { u64::MAX },
            0,
        );
        let value = wire::decode(&packet).unwrap();
        let fields = value.array(10).unwrap();
        read::verify_response(
            f.store.descriptor(),
            &request,
            &challenge,
            read::Response {
                node: fields[6].bytes().unwrap(),
                certificate: fields[7].bytes().unwrap(),
                result: fields[8].bytes().unwrap(),
                ancestry: std::slice::from_ref(&f.status_node),
            },
            |_, result, _| {
                // This regression exercises certified floor publication and derived-cache recovery.
                // Typed stream authorization is covered by the domain verifier and native integration.
                let value = wire::decode(&result.value)?;
                let body = value.array(5)?[4].array(4)?;
                let actual =
                    domains::Record::parse(body[1].array(1)?[0].bytes()?, [20; 32], [21; 32])?;
                ensure!(actual.bytes == record.bytes, "certified record differs");
                minimum(
                    std::slice::from_ref(&actual.reference),
                    f.store.generations(),
                )?;
                Ok(vec![actual.reference])
            },
        )
        .unwrap()
    };
    let verified = certified(&mut f, &old, false);
    f.store
        .accept_read(
            verified,
            &mut f.session,
            &mut || Ok(f.current),
            0,
            |_, store| cache(&old).save(store),
        )
        .unwrap();
    let retained = std::fs::read(f.directory.0.join(CACHE)).unwrap();
    let verified = certified(&mut f, &current, true);
    let calls = Cell::new(0);
    let published = Cell::new(false);
    let error = f
        .store
        .accept_read(
            verified,
            &mut f.session,
            &mut || {
                calls.set(calls.get() + 1);
                Ok(if calls.get() == 1 {
                    f.current
                } else {
                    elapsed_health(f.current, 2000)
                })
            },
            0,
            |_, store| {
                published.set(true);
                cache(&current).save(store)
            },
        )
        .unwrap_err();
    assert!(
        error.is::<crate::authority_floor::ReadExpired>(),
        "{error:#}"
    );
    assert!(!published.get());
    assert!(f.store.generations().contains(&current.reference));
    assert!(!f.store.generations().contains(&old.reference));
    assert_eq!(std::fs::read(f.directory.0.join(CACHE)).unwrap(), retained);
    let floor = std::fs::read(f.directory.0.join("AuthorityFloor.json")).unwrap();
    drop(f.store);
    f.store = Store::open(&f.directory.0, f.bootstrap.descriptor().clone()).unwrap();
    let recovered = Cache::load(&f.bootstrap, &f.store).unwrap();
    assert!(recovered.state.records.is_empty() && recovered.state.keys.is_empty());
    assert_eq!(
        std::fs::read(f.directory.0.join("AuthorityFloor.json")).unwrap(),
        floor
    );
    assert_eq!(std::fs::read(f.directory.0.join(CACHE)).unwrap(), retained);
    assert!(f.store.resume_ordinary().unwrap().is_none());
    f.current = elapsed_health(f.current, 2000);
    let verified = certified(&mut f, &current, false);
    f.store
        .accept_read(
            verified,
            &mut f.session,
            &mut || Ok(f.current),
            0,
            |_, store| cache(&current).save(store),
        )
        .unwrap();
    assert_eq!(
        Cache::load(&f.bootstrap, &f.store)
            .unwrap()
            .state
            .records
            .values()
            .next()
            .unwrap()
            .reference,
        current.reference
    );
    for record in invalid {
        let candidate = cache(&record);
        let bytes = wire::encode_state(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityDomainCache".into()),
            candidate.state.value(),
            a(vec![]),
        ]))
        .unwrap();
        files::atomic_at(f.store.profile_directory(), OsStr::new(CACHE), &bytes, true).unwrap();
        assert!(Cache::load(&f.bootstrap, &f.store).is_err());
        assert!(f.store.generations().contains(&current.reference));
    }
}

#[test]
fn preparation_cancellation_and_expired_queue_preserve_exact_unknown_ordinary_request() {
    use std::{
        io::Read,
        os::unix::{fs::PermissionsExt, net::UnixListener},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };
    let mut f = Fixture::with_actions(vec![0, 20]);
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    let prepared = Prepared::new(
        &f.bootstrap,
        domain_request(&f),
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.current,
    )
    .unwrap();
    let original = f
        .store
        .resume_ordinary()
        .unwrap()
        .unwrap()
        .signed()
        .to_vec();
    f.session.discard(&prepared.challenge).unwrap();
    let path = f.directory.0.join("BoundedOrdinary.sock");
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let observed = cancel.clone();
    let expected = original.clone();
    let server = std::thread::spawn(move || {
        let (mut stream, bytes) = crate::authority_inspection::tests::receive_control(&listener);
        let packet = wire::decode(&bytes).unwrap();
        let packet = packet.array(5).unwrap();
        assert_eq!(packet[3], V::Uint(0));
        let submission = wire::decode(packet[4].bytes().unwrap()).unwrap();
        let ordered = wire::decode(submission.array(2).unwrap()[0].bytes().unwrap()).unwrap();
        assert_eq!(ordered.array(6).unwrap()[3].bytes().unwrap(), expected);
        cancel.store(true, Ordering::Release);
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        assert_eq!(stream.read(&mut [0; 1]).unwrap(), 0);
    });
    let end = boot_time_ms().unwrap() + 5000;
    let mut budget = crate::authority_inspection::read_client::RetryBudget::new(end, move || {
        observed.load(Ordering::Acquire)
    });
    let error = local_with_read_budget(
        &f.bootstrap,
        domain_request(&f),
        &path,
        &f.signer,
        &mut f.store,
        &mut f.session,
        || Ok(f.current),
        &mut budget,
    )
    .err()
    .expect("cancelled preparation must fail");
    assert!(
        format!("{error:#}").contains("application preparation cancelled"),
        "{error:#}"
    );
    server.join().unwrap();
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        original
    );
    // A queued completion keeps its enqueue deadline; trailing expired work cannot open a new route.
    for _ in 0..8 {
        let mut expired = crate::authority_inspection::read_client::RetryBudget::new(0, || false);
        assert!(
            local_with_read_budget(
                &f.bootstrap,
                domain_request(&f),
                &f.directory.0.join("absent"),
                &f.signer,
                &mut f.store,
                &mut f.session,
                || panic!("expired queue item sampled a new challenge clock"),
                &mut expired
            )
            .is_err()
        );
        assert_eq!(
            f.store.resume_ordinary().unwrap().unwrap().signed(),
            original
        );
    }
}
