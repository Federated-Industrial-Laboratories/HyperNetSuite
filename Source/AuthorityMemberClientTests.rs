// SPDX-License-Identifier: MIT
// Offline consent, exact result consumption and retry evidence remain separate trust contracts.
use super::super::tests::Fixture;
use super::tests::certified;
use super::*;
use crate::authority_membership::{Acceptance, Mutation};
use ed25519_dalek::Signer;

fn epoch_signers(certificate: &[u8], keys: &[SigningKey]) -> Vec<u8> {
    let (payload, _) = wire::envelope(certificate, 4).unwrap();
    wire::encode(&a(vec![
        V::Uint(0),
        V::Uint(1),
        b(&payload),
        a(keys[..3]
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
            .collect()),
    ]))
    .unwrap()
}

#[test]
fn membership_after_epoch_adoption_retains_initial_trust_and_verifies_historical_receipt() {
    let mut f = Fixture::new();
    let candidate = SigningKey::from_bytes(&[42; 32]);
    let delegation_completion = delegate(&mut f, &candidate);
    let (_, offer) = accepted(&f, &candidate);
    let records = f.context.current_records(&f.store).unwrap();
    let old_metadata = f.store.stream_metadata().unwrap().unwrap();
    let leaves = [wire::digest(&f.status_node), *f.store.prefix().node()];
    let epoch = crate::authority_epoch::tests::fixture(
        f.store.descriptor(),
        f.store.prefix(),
        None,
        &leaves,
        &super::super::tests::voters(),
    );
    let seal = crate::authority_epoch::archive::Seal::new(
        &epoch.terminal,
        f.store.epoch_retained().unwrap(),
    )
    .unwrap();
    let archive = vec![seal.activate(&epoch.activation).unwrap()];
    f.store.seal_epoch(&epoch.terminal).unwrap();
    f.store.activate_epoch(&epoch.activation).unwrap();
    assert!(f.store.ordinary_slot().is_err());
    let descriptor = f.store.descriptor().clone();
    let scope = descriptor.scope();
    let previous = f.current.observe().unwrap();
    let at = epoch.terminal.checkpoint().prefix().evaluated_at_ms() + 2000;
    f.issued = ClockHealth::new(at, previous.boot_ms + 20000, previous.boot_ms + 50000, 100)
        .unwrap()
        .frozen();
    f.current = ClockHealth::new(
        at + 2000,
        previous.boot_ms + 22000,
        previous.boot_ms + 50000,
        100,
    )
    .unwrap()
    .frozen();
    let status = wire::sign_envelope(
        &wire::encode(&a(vec![
            V::Uint(55),
            V::Uint(1),
            b(&scope.network),
            b(&scope.incarnation),
            b(&f.signer.verifying_key().to_bytes()),
            b(&[86; 32]),
            V::Uint(1),
            V::Uint(0),
        ]))
        .unwrap(),
        &f.signer,
    )
    .unwrap();
    let challenge = f
        .session
        .issue(&status, &f.signer, [87; 32], 5000, f.issued)
        .unwrap();
    let parsed = Challenge::from_signed(&challenge).unwrap();
    let ordered = wire::encode(&a(vec![
        V::Uint(22),
        V::Uint(1),
        scope.value(),
        b(&status),
        b(&challenge),
        V::Uint(parsed.expires_at_ms),
    ]))
    .unwrap();
    let mut metadata = wire::decode(old_metadata.canonical())
        .unwrap()
        .array(10)
        .unwrap()
        .to_vec();
    metadata[2] = scope.value();
    metadata[8] = delegation_completion;
    let (reply, node) = super::super::tests::certified_request(
        &descriptor,
        &status,
        &challenge,
        &ordered,
        a(metadata),
        at + 2000,
        *f.store.prefix().node(),
        1,
        0,
    );
    let reply = wire::decode(&reply).unwrap();
    let fields = reply.array(10).unwrap();
    let certificate = epoch_signers(fields[7].bytes().unwrap(), &epoch.new_keys);
    let proof = proof::verify_response(
        &descriptor,
        proof::ProofContext {
            intent: &status,
            challenge: &challenge,
            restrictions: Restrictions::default(),
            minimum_height: 0,
            maximum_effect: 1,
            expected_stream: None,
        },
        proof::Response {
            ordered_request: &ordered,
            operation_result: fields[8].bytes().unwrap(),
            certificate: &certificate,
            ancestry: std::slice::from_ref(&node),
        },
        |_, _, _| bail!("status requires its typed verifier"),
    )
    .unwrap();
    f.store
        .accept(proof, &mut f.session, f.current, parsed.created_at_ms)
        .unwrap()
        .perform(
            &mut f.store,
            &mut f.session,
            f.current,
            1,
            |_| Ok(()),
            |_, _| Ok(()),
        )
        .unwrap();
    f.context = ContextState::retained(&f.bootstrap, &f.store, &records).unwrap();
    f.issued = f.current;
    let now = f.current.observe().unwrap();
    f.current = ClockHealth::new(
        now.wall_ms + 2000,
        now.boot_ms + 2000,
        now.boot_ms + 30000,
        100,
    )
    .unwrap()
    .frozen();
    let pending = GovernancePrepared::member(
        &f.context,
        MemberRequest {
            bootstrap: &f.bootstrap,
            mutation: MemberMutation::Admit {
                grant: [23; 32],
                accepted: offer.envelope.clone(),
            },
            receipt: None,
        },
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    assert_eq!(
        Intent::from_signed(&pending.intent)
            .unwrap()
            .minimum_policy_epoch,
        1
    );
    let (mut reply, ancestry) = certified(
        &pending,
        value(&pending),
        now.wall_ms + 2000,
        &f.store,
        false,
    );
    reply.certificate = epoch_signers(&reply.certificate, &epoch.new_keys);
    let receipt = member_offer::receipt(
        &pending.intent,
        &pending.challenge,
        &pending.ordered,
        &reply,
    )
    .unwrap();
    assert!(member_offer::confirm(&f.bootstrap, &offer, &receipt, &[]).is_err());
    assert!(member_offer::confirm(&f.bootstrap, &offer, &receipt, &archive).is_ok());
    assert!(matches!(
        pending
            .finish(reply, ancestry, &mut f.store, &mut f.session, &mut || Ok(
                f.current
            ))
            .unwrap(),
        Outcome::Created(_)
    ));
    assert_eq!(f.store.descriptor().scope().epoch, 1);
}

fn request(f: &Fixture, subject: [u8; 32]) -> MemberMutation {
    let parent = f.context.version(102, [23; 32]).unwrap();
    let tier = f.context.grant_tier(parent.id).unwrap();
    let parent_bytes = f.context.governance.record_bytes(102, parent.id).unwrap();
    let parent_value = wire::decode(parent_bytes).unwrap();
    let parent_fields = parent_value.array(17).unwrap();
    MemberMutation::Delegate {
        parent,
        child: a(vec![
            b(&[24; 32]),
            b(&subject),
            version_value(&tier),
            a(vec![V::Uint(0)]),
            a(vec![a(vec![V::Uint(0), b(&[20; 32])])]),
            parent_fields[12].clone(),
            V::Uint(0),
            a(vec![V::Uint(0), V::Uint(1), V::Uint(0), V::Uint(1)]),
        ]),
    }
}
fn value(pending: &GovernancePrepared) -> V {
    let Mode::Member(member) = &pending.mode else {
        panic!("expected member mutation")
    };
    let mut refs = pending.expected.clone();
    refs.push(member.reference.clone());
    refs.sort_by_key(VersionRef::index);
    a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text(member.action.into()),
        a(refs.iter().map(version_value).collect()),
        b(&member.created),
        V::Uint(member.mutation.snapshot().height + 1),
    ])
}
fn delegate(f: &mut Fixture, candidate: &SigningKey) -> V {
    let request = request(f, candidate.verifying_key().to_bytes());
    let pending = GovernancePrepared::member(
        &f.context,
        MemberRequest {
            bootstrap: &f.bootstrap,
            mutation: request,
            receipt: None,
        },
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let (reply, ancestry) = certified(
        &pending,
        value(&pending),
        f.current.observe().unwrap().wall_ms,
        &f.store,
        false,
    );
    let intent = Intent::from_signed(&pending.intent).unwrap();
    let completion = a(vec![
        V::Uint(intent.sequence),
        b(&intent.digest),
        V::Uint(0),
        V::Uint(0),
        b(&wire::digest(&reply.result)),
    ]);
    let Outcome::Created(result) = pending
        .finish(reply, ancestry, &mut f.store, &mut f.session, &mut || {
            Ok(f.current)
        })
        .unwrap()
    else {
        panic!("expected created grant")
    };
    f.context = result.context;
    // The next operation starts after the delegation's final monotonic observation.
    f.issued = f.current;
    let now = f.current.observe().unwrap();
    f.current = ClockHealth::new(
        now.wall_ms + 2000,
        now.boot_ms + 2000,
        now.boot_ms + 30000,
        100,
    )
    .unwrap()
    .frozen();
    completion
}
fn offer(f: &Fixture) -> Vec<u8> {
    offer_with_lifetime(f, 3_600_000)
}
fn offer_with_lifetime(f: &Fixture, acceptance_ms: u64) -> Vec<u8> {
    let value = wire::decode(f.context.governance.record_bytes(102, [24; 32]).unwrap()).unwrap();
    let span = value.array(17).unwrap()[12].array(2).unwrap();
    member_offer::invite(
        &f.bootstrap,
        &f.context,
        &f.store,
        member_offer::Invitation {
            member: [25; 32],
            reader_grant: [24; 32],
            validity: (span[0].uint().unwrap(), span[1].uint().unwrap()),
            acceptance_ms,
        },
        &f.signer,
        f.issued,
    )
    .unwrap()
}
fn accepted(f: &Fixture, candidate: &SigningKey) -> (Vec<u8>, member_offer::Offer) {
    let offered = member_offer::Offer::parse(&f.bootstrap, &offer(f), false).unwrap();
    let bytes = offered.accept(&f.bootstrap, candidate, None).unwrap();
    let accepted = member_offer::Offer::parse(&f.bootstrap, &bytes, true).unwrap();
    (bytes, accepted)
}
#[test]
fn invitation_requires_exact_reader_candidate_and_authenticated_inviter() {
    let mut f = Fixture::new();
    let candidate = SigningKey::from_bytes(&[42; 32]);
    delegate(&mut f, &candidate);
    let bytes = offer(&f);
    let offered = member_offer::Offer::parse(&f.bootstrap, &bytes, false).unwrap();
    assert!(
        offered
            .accept(&f.bootstrap, &SigningKey::from_bytes(&[43; 32]), None)
            .is_err()
    );
    assert!(
        offered
            .accept(&f.bootstrap, &candidate, Some([99; 32]))
            .is_err()
    );
    let accepted = offered.accept(&f.bootstrap, &candidate, None).unwrap();
    assert!(member_offer::Offer::parse(&f.bootstrap, &accepted, true).is_ok());
    assert!(member_offer::Offer::parse(&f.bootstrap, &bytes, true).is_err());
    let mut forged = wire::decode(&accepted).unwrap().array(5).unwrap().to_vec();
    let mut reader = wire::decode(&offered.reader_grant)
        .unwrap()
        .array(17)
        .unwrap()
        .to_vec();
    reader[8] = b(&SigningKey::from_bytes(&[43; 32]).verifying_key().to_bytes());
    forged[4] = b(&wire::encode(&a(reader)).unwrap());
    assert!(
        member_offer::Offer::parse(&f.bootstrap, &wire::encode(&a(forged)).unwrap(), true).is_err()
    );
}
#[test]
fn invitation_window_includes_clock_allowance_within_its_requested_duration() {
    let mut f = Fixture::new();
    let candidate = SigningKey::from_bytes(&[42; 32]);
    delegate(&mut f, &candidate);
    let now = f.issued.observe().unwrap().wall_ms;
    let start = now - crate::authority_governance::UNCERTAINTY_MS;
    for (duration, expires, expected_end) in [
        (86_400_000, now + 86_500_000, start + 86_400_000),
        (3_600_000, now + 86_500_000, start + 3_600_000),
        (86_400_000, now + 30_000, now + 30_000),
    ] {
        let bytes = member_offer::invite(
            &f.bootstrap,
            &f.context,
            &f.store,
            member_offer::Invitation {
                member: [25; 32],
                reader_grant: [24; 32],
                validity: (now - 10_000, expires),
                acceptance_ms: duration,
            },
            &f.signer,
            f.issued,
        )
        .unwrap();
        let offered = member_offer::Offer::parse(&f.bootstrap, &bytes, false).unwrap();
        assert_eq!(offered.acceptance_validity, (start, expected_end));
        assert!(offered.acceptance_validity.1 - offered.acceptance_validity.0 <= duration);
        let accepted = offered.accept(&f.bootstrap, &candidate, None).unwrap();
        assert!(member_offer::Offer::parse(&f.bootstrap, &accepted, true).is_ok());
    }
    assert!(
        member_offer::invite(
            &f.bootstrap,
            &f.context,
            &f.store,
            member_offer::Invitation {
                member: [25; 32],
                reader_grant: [24; 32],
                validity: (now - 10_000, now + 86_500_000),
                acceptance_ms: 86_400_001,
            },
            &f.signer,
            f.issued,
        )
        .is_err()
    );
}
#[test]
fn delegation_does_not_supply_membership_or_implicit_inspection() {
    let mut f = Fixture::new();
    let candidate = SigningKey::from_bytes(&[42; 32]);
    delegate(&mut f, &candidate);
    assert!(
        f.context
            .governance
            .current_capability(
                [24; 32],
                &Requirement {
                    subject: candidate.verifying_key().to_bytes(),
                    actions: &[0],
                    scope: (0, [20; 32]),
                    namespace: None,
                    usage: [0, 1, 0, 1],
                    evaluated_at_ms: f.current.observe().unwrap().wall_ms,
                    expected: &[]
                }
            )
            .is_err()
    );
    let (_, offer) = accepted(&f, &candidate);
    let pending = GovernancePrepared::member(
        &f.context,
        MemberRequest {
            bootstrap: &f.bootstrap,
            mutation: MemberMutation::Admit {
                grant: [23; 32],
                accepted: offer.envelope,
            },
            receipt: None,
        },
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let (reply, ancestry) = certified(
        &pending,
        value(&pending),
        f.current.observe().unwrap().wall_ms,
        &f.store,
        false,
    );
    let Outcome::Created(result) = pending
        .finish(reply, ancestry, &mut f.store, &mut f.session, &mut || {
            Ok(f.current)
        })
        .unwrap()
    else {
        panic!("admission")
    };
    let request = Requirement {
        subject: candidate.verifying_key().to_bytes(),
        actions: &[0],
        scope: (0, [20; 32]),
        namespace: None,
        usage: [0, 1, 0, 1],
        evaluated_at_ms: f.current.observe().unwrap().wall_ms,
        expected: &[],
    };
    assert!(
        result
            .context
            .governance
            .current_capability([24; 32], &request)
            .is_ok()
    );
    assert!(
        result
            .context
            .governance
            .current_capability(
                [24; 32],
                &Requirement {
                    actions: &[25],
                    ..request
                }
            )
            .is_err()
    );
}
#[test]
fn historical_confirmation_cannot_replace_current_authority_and_rejects_substitution() {
    let mut f = Fixture::new();
    let candidate = SigningKey::from_bytes(&[42; 32]);
    delegate(&mut f, &candidate);
    let (_, offer) = accepted(&f, &candidate);
    let pending = GovernancePrepared::member(
        &f.context,
        MemberRequest {
            bootstrap: &f.bootstrap,
            mutation: MemberMutation::Admit {
                grant: [23; 32],
                accepted: offer.envelope.clone(),
            },
            receipt: None,
        },
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let (reply, _) = certified(
        &pending,
        value(&pending),
        f.current.observe().unwrap().wall_ms,
        &f.store,
        false,
    );
    let evidence = member_offer::receipt(
        &pending.intent,
        &pending.challenge,
        &pending.ordered,
        &reply,
    )
    .unwrap();
    let before = f.store.prefix().height();
    let confirmation = member_offer::confirm(&f.bootstrap, &offer, &evidence, &[]).unwrap();
    assert!(confirmation.certified_height() > before);
    assert_eq!(f.store.prefix().height(), before);
    let mut substitute = offer.clone();
    substitute.member = [90; 32];
    assert!(member_offer::confirm(&f.bootstrap, &substitute, &evidence, &[]).is_err());
    let mut corrupt = wire::decode(&evidence).unwrap().array(9).unwrap().to_vec();
    corrupt[6] = b(&wire::encode(&a(vec![
        V::Uint(24),
        V::Uint(1),
        V::Text("AuthorityAdmitMember".into()),
        V::Uint(1),
        V::Uint(3),
        b(&[0]),
    ]))
    .unwrap());
    assert!(
        member_offer::confirm(
            &f.bootstrap,
            &offer,
            &wire::encode(&a(corrupt)).unwrap(),
            &[]
        )
        .is_err()
    );
}
#[test]
fn member_result_checks_complete_dependencies_and_exact_created_record() {
    let mut f = Fixture::new();
    let candidate = SigningKey::from_bytes(&[42; 32]);
    let request = request(&f, candidate.verifying_key().to_bytes());
    let pending = GovernancePrepared::member(
        &f.context,
        MemberRequest {
            bootstrap: &f.bootstrap,
            mutation: request,
            receipt: None,
        },
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let intent = Intent::from_signed(&pending.intent).unwrap();
    let (reply, _) = certified(
        &pending,
        value(&pending),
        f.current.observe().unwrap().wall_ms,
        &f.store,
        false,
    );
    let result = OperationResult::parse(&reply.result).unwrap();
    let executed =
        ExecutedResult::parse(&pending.descriptor.quorum(&reply.certificate).unwrap()).unwrap();
    assert!(pending.candidate(&intent, &result, &executed).is_ok());
    for position in [3, 4] {
        let mut altered = wire::decode(&result.value)
            .unwrap()
            .array(6)
            .unwrap()
            .to_vec();
        altered[position] = if position == 3 { a(vec![]) } else { b(&[0]) };
        let corrupt = OperationResult::parse(
            &wire::encode(&a(vec![
                V::Uint(24),
                V::Uint(1),
                V::Text(pending.action().into()),
                V::Uint(0),
                V::Uint(0),
                b(&wire::encode(&a(altered)).unwrap()),
            ]))
            .unwrap(),
        )
        .unwrap();
        assert!(pending.candidate(&intent, &corrupt, &executed).is_err());
    }
    let mutation = Mutation::parse(&intent).unwrap();
    assert_eq!(mutation.subject(), candidate.verifying_key().to_bytes());
    assert!(Acceptance::parse(&pending.intent, intent.network, intent.incarnation, true).is_err());
}

#[test]
fn receipt_failure_reopens_and_resumes_exact_admission_after_acceptance_expires() {
    let mut f = Fixture::new();
    let candidate = SigningKey::from_bytes(&[42; 32]);
    delegate(&mut f, &candidate);
    let grant = wire::decode(f.context.governance.record_bytes(102, [24; 32]).unwrap()).unwrap();
    let span = grant.array(17).unwrap()[12].array(2).unwrap();
    let offered = member_offer::invite(
        &f.bootstrap,
        &f.context,
        &f.store,
        member_offer::Invitation {
            member: [25; 32],
            reader_grant: [24; 32],
            validity: (span[0].uint().unwrap(), span[1].uint().unwrap()),
            // The synthetic certificate retains the full first challenge lifetime.
            acceptance_ms: DURATION + crate::authority_governance::UNCERTAINTY_MS,
        },
        &f.signer,
        f.issued,
    )
    .unwrap();
    let offered = member_offer::Offer::parse(&f.bootstrap, &offered, false).unwrap();
    let accepted = offered.accept(&f.bootstrap, &candidate, None).unwrap();
    let offer = member_offer::Offer::parse(&f.bootstrap, &accepted, true).unwrap();
    let request = MemberMutation::Admit {
        grant: [23; 32],
        accepted: offer.envelope.clone(),
    };
    let destination = f.directory.0.join("Admission.cbor");
    files::create_directory(&destination).unwrap();
    let pending = GovernancePrepared::member(
        &f.context,
        MemberRequest {
            bootstrap: &f.bootstrap,
            mutation: request.clone(),
            receipt: Some(&destination),
        },
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let original = pending.intent.clone();
    let (reply, ancestry) = certified(
        &pending,
        value(&pending),
        f.current.observe().unwrap().wall_ms,
        &f.store,
        false,
    );
    assert!(
        pending
            .finish(reply, ancestry, &mut f.store, &mut f.session, &mut || Ok(
                f.current
            ))
            .is_err()
    );
    drop(f.store);
    f.store = Store::open(&f.directory.0, f.bootstrap.descriptor().clone()).unwrap();
    f.context = ContextState::load(&f.bootstrap, &f.store, &f.directory.0).unwrap();
    f.session = Session::new().unwrap();
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        original
    );
    assert!(
        f.context
            .governance
            .versions()
            .iter()
            .any(|v| v.kind == 125 && v.id == offer.member)
    );
    std::fs::remove_dir(&destination).unwrap();
    let now = f.current.observe().unwrap();
    f.issued = ClockHealth::new(
        now.wall_ms + 6000,
        now.boot_ms + 6000,
        now.boot_ms + 30000,
        100,
    )
    .unwrap()
    .frozen();
    f.current = ClockHealth::new(
        now.wall_ms + 8000,
        now.boot_ms + 8000,
        now.boot_ms + 30000,
        100,
    )
    .unwrap()
    .frozen();
    let pending = GovernancePrepared::member(
        &f.context,
        MemberRequest {
            bootstrap: &f.bootstrap,
            mutation: request,
            receipt: Some(&destination),
        },
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    assert_eq!(pending.intent, original);
    let (reply, ancestry) = certified(
        &pending,
        value(&pending),
        f.current.observe().unwrap().wall_ms,
        &f.store,
        false,
    );
    let Outcome::Created(result) = pending
        .finish(reply, ancestry, &mut f.store, &mut f.session, &mut || {
            Ok(f.current)
        })
        .unwrap()
    else {
        panic!("admission")
    };
    assert_eq!(result.reference.id, offer.member);
    assert!(f.store.resume_ordinary().unwrap().is_none());
    let bytes = files::read_single(&destination, member_offer::RECEIPT_LIMIT, true).unwrap();
    assert!(member_offer::confirm(&f.bootstrap, &offer, &bytes, &[]).is_ok());
    assert!(member_offer::save_receipt(&destination, &bytes, &original).is_ok());
    assert!(member_offer::save_receipt(&destination, &bytes, b"different intent").is_err());
}

#[test]
fn high_dependency_receipt_fits_the_declared_bound_before_submission() {
    let mut f = Fixture::new();
    let candidate = SigningKey::from_bytes(&[42; 32]);
    let request = request(&f, candidate.verifying_key().to_bytes());
    let pending = GovernancePrepared::member(
        &f.context,
        MemberRequest {
            bootstrap: &f.bootstrap,
            mutation: request,
            receipt: None,
        },
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let mut intent = Intent::from_signed(&pending.intent).unwrap();
    intent.expected = (1..=63)
        .map(|n| VersionRef {
            kind: 102,
            id: [n; 32],
            generation: u64::MAX,
            digest: [n; 32],
        })
        .collect();
    let mut parameters = wire::decode(&intent.parameters)
        .unwrap()
        .array(6)
        .unwrap()
        .to_vec();
    parameters[5] = a(vec![
        a(vec![
            V::Uint(0),
            V::Uint(intent.minimum_policy_height),
            b(&[254; 32]),
        ]),
        a(intent.expected.iter().map(version_value).collect()),
    ]);
    intent.parameters = wire::encode(&a(parameters)).unwrap();
    let created = Mutation::parse(&intent).unwrap().derive(&intent).unwrap();
    let reference = VersionRef {
        kind: 102,
        id: intent.resource,
        generation: 1,
        digest: wire::digest(&created),
    };
    // Give the new grant a distinct ID from all dependency IDs.
    intent.resource = [254; 32];
    let mut parameters = wire::decode(&intent.parameters)
        .unwrap()
        .array(6)
        .unwrap()
        .to_vec();
    let mut child = parameters[4].array(8).unwrap().to_vec();
    child[0] = b(&intent.resource);
    parameters[4] = a(child);
    intent.parameters = wire::encode(&a(parameters)).unwrap();
    let created = Mutation::parse(&intent).unwrap().derive(&intent).unwrap();
    let reference = VersionRef {
        id: intent.resource,
        digest: wire::digest(&created),
        ..reference
    };
    member_offer::preflight_receipt(&intent, &created, &reference).unwrap();
    let (payload, _) = wire::envelope(&pending.intent, 1).unwrap();
    let mut raw = wire::decode(&payload).unwrap().array(17).unwrap().to_vec();
    raw[10] = b(&intent.resource);
    raw[15] = a(intent.expected.iter().map(version_value).collect());
    raw[16] = b(&intent.parameters);
    let signed = wire::sign_envelope(&wire::encode(&a(raw)).unwrap(), &f.signer).unwrap();
    let mut ordered = wire::decode(&pending.ordered)
        .unwrap()
        .array(6)
        .unwrap()
        .to_vec();
    ordered[3] = b(&signed);
    let mut versions = intent.expected.clone();
    versions.push(reference);
    versions.sort_by_key(VersionRef::index);
    let result = wire::encode(&a(vec![
        V::Uint(24),
        V::Uint(1),
        V::Text(intent.action.clone()),
        V::Uint(0),
        V::Uint(0),
        b(&wire::encode(&a(vec![
            V::Uint(201),
            V::Uint(1),
            V::Text(intent.action),
            a(versions.iter().map(version_value).collect()),
            b(&created),
            V::Uint(u64::MAX),
        ]))
        .unwrap()),
    ]))
    .unwrap();
    let bytes = member_offer::receipt(
        &signed,
        &pending.challenge,
        &wire::encode(&a(ordered)).unwrap(),
        &CertifiedReply {
            node: vec![0; 512],
            certificate: vec![0; 4096],
            result,
        },
    )
    .unwrap();
    assert!(bytes.len() > 32768);
    assert!(bytes.len() <= member_offer::RECEIPT_LIMIT);
}

#[path = "AuthorityMemberReplayTests.rs"]
mod replay;
