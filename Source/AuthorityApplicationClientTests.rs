// SPDX-License-Identifier: MIT
// Application receipts, scoped caches and independent consent retain their own trust boundaries.
use super::super::tests::{Fixture, voters};
use super::*;
use ed25519_dalek::Signer;

#[path = "AuthorityApplicationReplayTests.rs"]
mod replay;

fn certified(
    p: &Prepared,
    mut value: V,
    time: u64,
    store: &Store,
) -> (CertifiedReply, AncestryEvidence) {
    let scope = p.bootstrap.descriptor().scope();
    let height = store.prefix().height() + 1;
    let intent = Intent::from_signed(&p.intent).unwrap();
    let challenge = Challenge::from_signed(&p.challenge).unwrap();
    if matches!(
        p.request,
        Request::Delegate { .. } | Request::Register { .. } | Request::Withdraw(_)
    ) {
        let V::Array(fields) = &mut value else {
            panic!("mutation result")
        };
        assert_eq!(fields.len(), 5);
        fields.push(V::Uint(intent.minimum_policy_height + 1));
    }
    let result = wire::encode(&a(vec![
        V::Uint(24),
        V::Uint(1),
        V::Text(p.request.action().into()),
        V::Uint(0),
        V::Uint(0),
        b(&wire::encode(&value).unwrap()),
    ]))
    .unwrap();
    let node = wire::encode(&a(vec![
        V::Uint(14),
        V::Uint(1),
        scope.value(),
        V::Uint(height),
        V::Uint(height),
        b(store.prefix().node()),
        b(&wire::digest(&p.ordered)),
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
        b(&wire::digest(&p.ordered)),
        b(&intent.digest),
        b(&challenge.digest),
        b(&intent.requester),
        b(&challenge.recipient),
        V::Text(p.request.action().into()),
        b(&intent.resource),
        V::Uint(intent.revision),
        V::Uint(0),
        V::Uint(1),
        b(&wire::digest(&result)),
        b(&[81; 32]),
        V::Uint(intent.minimum_policy_height),
        V::Uint(time),
        V::Uint(challenge.expires_at_ms),
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
    (
        CertifiedReply {
            node: node.clone(),
            certificate,
            result,
        },
        AncestryEvidence::direct(vec![node]),
    )
}
fn advance(f: &mut Fixture, millis: u64) {
    f.issued = f.current;
    let now = f.current.observe().unwrap();
    f.current = ClockHealth::new(
        now.wall_ms + millis,
        now.boot_ms + millis,
        now.boot_ms + 30000,
        100,
    )
    .unwrap()
    .frozen();
}
fn selection() -> Selection {
    Selection {
        parent: [23; 32],
        tier: [22; 32],
        child: None,
    }
}
fn discover(f: &mut Fixture, selection: Selection, records: &[Vec<u8>]) -> DelegationContext {
    let p = Prepared::new(
        &f.bootstrap,
        Request::Context(selection),
        None,
        None,
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let intent = Intent::from_signed(&p.intent).unwrap();
    let decision = Operation::parse(&intent)
        .unwrap()
        .authorise(
            records,
            &Reservations(f.bootstrap.reservations().to_vec()),
            &intent,
            f.current.observe().unwrap().wall_ms,
            false,
        )
        .unwrap();
    assert_eq!(decision.code, 0);
    let (reply, evidence) = certified(
        &p,
        decision.value,
        f.current.observe().unwrap().wall_ms,
        &f.store,
    );
    let context = p
        .finish(reply, evidence, &mut f.store, &mut f.session, &mut || {
            Ok(f.current)
        })
        .unwrap()
        .context
        .unwrap();
    advance(f, 2000);
    context
}
fn delegated(f: &mut Fixture, app: &SigningKey) -> DelegationContext {
    let entries = f.bootstrap.governance_records().to_vec();
    let context = discover(f, selection(), &entries);
    let parent = context.version(102, [23; 32]).unwrap();
    let tier = context.version(101, [22; 32]).unwrap();
    let bytes = context.record(102, [23; 32]).unwrap();
    let value = wire::decode(bytes).unwrap();
    let validity = value.array(17).unwrap()[12].clone();
    let child = a(vec![
        b(&[40; 32]),
        b(&app.verifying_key().to_bytes()),
        version_value(&tier),
        a(vec![V::Uint(0)]),
        a(vec![a(vec![V::Uint(0), b(&[20; 32])])]),
        validity,
        V::Uint(0),
        a(vec![V::Uint(0), V::Uint(1), V::Uint(0), V::Uint(1)]),
    ]);
    let p = Prepared::new(
        &f.bootstrap,
        Request::Delegate { parent, child },
        Some(&context),
        None,
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let intent = Intent::from_signed(&p.intent).unwrap();
    let mutation = Mutation::parse(&intent).unwrap();
    let decision = mutation
        .authorise(
            &p.source,
            &Reservations(f.bootstrap.reservations().to_vec()),
            &intent,
            f.current.observe().unwrap().wall_ms,
            false,
        )
        .unwrap();
    assert_eq!(decision.code, 0);
    let mut refs = decision.dependencies;
    refs.push(decision.created);
    refs.sort_by_key(VersionRef::index);
    let value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text(intent.action.clone()),
        a(refs.iter().map(version_value).collect()),
        b(&decision.record),
    ]);
    let (reply, evidence) = certified(&p, value, f.current.observe().unwrap().wall_ms, &f.store);
    let result = p
        .finish(reply, evidence, &mut f.store, &mut f.session, &mut || {
            Ok(f.current)
        })
        .unwrap();
    advance(f, 2000);
    let entries = merged(&f.bootstrap, &result.context.unwrap().entries).unwrap();
    discover(
        f,
        Selection {
            child: Some([40; 32]),
            ..selection()
        },
        &entries,
    )
}
fn offered(f: &Fixture, context: &DelegationContext, lifetime: u64) -> application_offer::Offer {
    let now = f.issued.observe().unwrap().wall_ms;
    let bytes = application_offer::invite(
        &f.bootstrap,
        context,
        &f.store,
        application_offer::Invitation {
            grant: [40; 32],
            validity: (now - 10000, now + 300000),
            acceptance_ms: lifetime,
        },
        &f.signer,
        f.issued,
    )
    .unwrap();
    application_offer::Offer::parse(&f.bootstrap, &bytes, false).unwrap()
}
#[test]
fn scoped_context_does_not_require_unrelated_minimum_disclosure_or_load_as_full_context() {
    let mut f = Fixture::new();
    let records = f.bootstrap.governance_records().to_vec();
    let context = discover(&mut f, selection(), &records);
    let refs = versions(&context.entries).unwrap();
    let unrelated = VersionRef {
        kind: 102,
        id: [91; 32],
        generation: 1,
        digest: [92; 32],
    };
    let mut minimum = refs.clone();
    minimum.push(unrelated);
    assert!(relevant_minima(&refs, &minimum).is_ok());
    assert!(DelegationContext::load(&f.bootstrap, &f.store, selection()).is_ok());
    assert!(ContextState::load(&f.bootstrap, &f.store, &f.directory.0).is_err());
    assert!(
        DelegationContext::load(
            &f.bootstrap,
            &f.store,
            Selection {
                child: Some([40; 32]),
                ..selection()
            }
        )
        .is_err()
    );
    let revoked = VersionRef {
        kind: 126,
        id: [23; 32],
        generation: 1,
        digest: [93; 32],
    };
    minimum.push(revoked);
    assert!(relevant_minima(&refs, &minimum).is_err());
}
#[test]
fn application_offer_binds_exact_grant_owner_pin_and_full_acceptance_interval() {
    let mut f = Fixture::new();
    let app = SigningKey::from_bytes(&[41; 32]);
    let context = delegated(&mut f, &app);
    let offer = offered(&f, &context, 86_400_000);
    assert!(
        offer.acceptance.acceptance_validity.1 - offer.acceptance.acceptance_validity.0
            <= 86_400_000
    );
    assert!(offer.accept(&f.bootstrap, &app, Some([99; 32])).is_err());
    assert!(
        offer
            .accept(&f.bootstrap, &SigningKey::from_bytes(&[42; 32]), None)
            .is_err()
    );
    let accepted = offer.accept(&f.bootstrap, &app, None).unwrap();
    assert!(application_offer::Offer::parse(&f.bootstrap, &accepted, true).is_ok());
    let mut forged = wire::decode(&accepted).unwrap().array(5).unwrap().to_vec();
    let mut grant = wire::decode(&offer.grant)
        .unwrap()
        .array(17)
        .unwrap()
        .to_vec();
    grant[14] = V::Uint(1);
    forged[4] = b(&wire::encode(&a(grant)).unwrap());
    assert!(
        application_offer::Offer::parse(&f.bootstrap, &wire::encode(&a(forged)).unwrap(), true)
            .is_err()
    );
}
#[test]
fn registration_receipt_failure_reopens_exact_pending_request_after_consent_expiry() {
    let mut f = Fixture::new();
    let app = SigningKey::from_bytes(&[41; 32]);
    let context = delegated(&mut f, &app);
    let offer = offered(
        &f,
        &context,
        DURATION + crate::authority_governance::UNCERTAINTY_MS,
    );
    let accepted = offer.accept(&f.bootstrap, &app, None).unwrap();
    let offer = application_offer::Offer::parse(&f.bootstrap, &accepted, true).unwrap();
    let receipt = f.directory.0.join("Missing").join("Receipt.cbor");
    let p = Prepared::new(
        &f.bootstrap,
        Request::Register {
            parent: context.version(102, [23; 32]).unwrap(),
            accepted: offer.acceptance.envelope.clone(),
        },
        Some(&context),
        Some(&receipt),
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let original = p.intent.clone();
    let intent = Intent::from_signed(&original).unwrap();
    let decision = Operation::parse(&intent)
        .unwrap()
        .authorise(
            &p.source,
            &Reservations(f.bootstrap.reservations().to_vec()),
            &intent,
            f.current.observe().unwrap().wall_ms,
            false,
        )
        .unwrap();
    assert_eq!(decision.code, 0);
    let (reply, evidence) = certified(
        &p,
        decision.value,
        f.current.observe().unwrap().wall_ms,
        &f.store,
    );
    assert!(
        p.finish(reply, evidence, &mut f.store, &mut f.session, &mut || Ok(
            f.current
        ))
        .is_err()
    );
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        original
    );
    let directory = f.directory.0.clone();
    let descriptor = f.bootstrap.descriptor().clone();
    drop(f.store);
    f.store = Store::open(&directory, descriptor).unwrap();
    f.session = Session::new().unwrap();
    files::create_directory(receipt.parent().unwrap()).unwrap();
    advance(&mut f, 8000);
    advance(&mut f, 2000);
    let retained =
        DelegationContext::load(&f.bootstrap, &f.store, context.selection.clone()).unwrap();
    let p = Prepared::new(
        &f.bootstrap,
        Request::Register {
            parent: retained.version(102, [23; 32]).unwrap(),
            accepted: offer.acceptance.envelope.clone(),
        },
        Some(&retained),
        Some(&receipt),
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    assert_eq!(p.intent, original);
    let decision = Operation::parse(&intent)
        .unwrap()
        .authorise(
            &p.source,
            &Reservations(f.bootstrap.reservations().to_vec()),
            &intent,
            f.current.observe().unwrap().wall_ms,
            true,
        )
        .unwrap();
    assert_eq!(decision.code, 0);
    let (reply, evidence) = certified(
        &p,
        decision.value,
        f.current.observe().unwrap().wall_ms,
        &f.store,
    );
    let result = p
        .finish(reply, evidence, &mut f.store, &mut f.session, &mut || {
            Ok(f.current)
        })
        .unwrap();
    assert!(f.store.resume_ordinary().unwrap().is_none());
    let bytes = files::read_single(&receipt, application_offer::RECEIPT_LIMIT, true).unwrap();
    assert_eq!(
        application_offer::confirm(&f.bootstrap, &offer, &bytes, &[]).unwrap(),
        result.prefix.height()
    );
}
#[test]
fn complete_owner_list_crosses_ordinary_reference_bound_and_refuses_truncation() {
    let mut f = Fixture::new();
    let mut rows = Vec::new();
    let mut refs = Vec::new();
    for seed in 60..100u8 {
        let key = SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        let admission = VersionRef {
            kind: 127,
            id: key,
            generation: 1,
            digest: [seed; 32],
        };
        let grant = VersionRef {
            kind: 102,
            id: [seed; 32],
            generation: 1,
            digest: [seed + 1; 32],
        };
        rows.push(a(vec![
            b(&key),
            version_value(&admission),
            version_value(&grant),
            V::Null,
        ]));
        refs.extend([admission, grant]);
    }
    rows.sort_by_key(|v| v.array(4).unwrap()[0].fixed::<32>().unwrap());
    refs.sort_by_key(VersionRef::index);
    assert_eq!(refs.len(), 80);
    assert!(ActionValidation::new(refs.clone()).is_err());
    let p = Prepared::new(
        &f.bootstrap,
        Request::List,
        None,
        None,
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityApplicationList".into()),
        a(refs.iter().map(version_value).collect()),
        a(rows),
    ]);
    let (reply, evidence) = certified(&p, value, f.current.observe().unwrap().wall_ms, &f.store);
    p.finish(reply, evidence, &mut f.store, &mut f.session, &mut || {
        Ok(f.current)
    })
    .unwrap();
    assert_eq!(
        f.store
            .generations()
            .iter()
            .filter(|v| v.kind == 127)
            .count(),
        40
    );
    let empty = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityApplicationList".into()),
        a(vec![]),
        a(vec![]),
    ]);
    assert!(check_list_cache(&f.store, &empty).is_err());
}

#[test]
fn lifecycle_metadata_keeps_working_with_a_retained_child_grant_tombstone() {
    let mut f = Fixture::new();
    let app = SigningKey::from_bytes(&[41; 32]);
    let context = delegated(&mut f, &app);
    let offer = offered(&f, &context, 300000);
    let bytes = offer.accept(&f.bootstrap, &app, None).unwrap();
    let accepted = application_offer::Offer::parse(&f.bootstrap, &bytes, true).unwrap();
    let p = Prepared::new(
        &f.bootstrap,
        Request::Register {
            parent: context.version(102, [23; 32]).unwrap(),
            accepted: accepted.acceptance.envelope,
        },
        Some(&context),
        None,
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let original = Intent::from_signed(&p.intent).unwrap();
    let registration = Operation::parse(&original)
        .unwrap()
        .derive(&original)
        .unwrap()
        .unwrap();
    let admission = applications::record_reference(&registration).unwrap();
    let grant = context.version(102, [40; 32]).unwrap();
    let revoked = VersionRef {
        kind: 126,
        id: grant.id,
        generation: 1,
        digest: [96; 32],
    };
    let application = app.verifying_key().to_bytes();
    let mut intent = original.clone();
    intent.action = "AuthorityApplicationGet".into();
    intent.resource = application;
    intent.revision = 0;
    intent.expected.clear();
    intent.parameters = wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text(intent.action.clone()),
        b(&application),
        a(vec![version_value(&revoked)]),
    ]))
    .unwrap();
    let mut refs = vec![grant.clone(), admission.clone()];
    refs.sort_by_key(VersionRef::index);
    let get = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text(intent.action.clone()),
        a(refs.iter().map(version_value).collect()),
        b(&registration),
        b(&accepted.grant),
        V::Null,
    ]);
    let checked = applications::validate_lifecycle_result(&intent, &get).unwrap();
    assert!(metadata_minima(&checked, std::slice::from_ref(&revoked)).is_ok());
    assert!(relevant_minima(&checked, std::slice::from_ref(&revoked)).is_err());
    intent.action = "AuthorityApplicationList".into();
    intent.resource = intent.requester;
    intent.parameters = wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text(intent.action.clone()),
        b(&intent.requester),
        a(vec![version_value(&revoked)]),
    ]))
    .unwrap();
    let list = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text(intent.action.clone()),
        a(refs.iter().map(version_value).collect()),
        a(vec![a(vec![
            b(&application),
            version_value(&admission),
            version_value(&grant),
            V::Null,
        ])]),
    ]);
    assert!(
        metadata_minima(
            &applications::validate_lifecycle_result(&intent, &list).unwrap(),
            std::slice::from_ref(&revoked)
        )
        .is_ok()
    );
    let withdrawal = VersionRef {
        kind: 128,
        id: application,
        generation: 1,
        digest: [97; 32],
    };
    refs.push(withdrawal);
    assert!(metadata_minima(&refs, &[revoked]).is_ok());
}

#[test]
fn offline_offer_rejects_malformed_grants_even_when_owner_signs_their_exact_digest() {
    let mut f = Fixture::new();
    let application = SigningKey::from_bytes(&[41; 32]);
    let context = delegated(&mut f, &application);
    let offer = offered(&f, &context, 300000);
    let grant = wire::decode(&offer.grant)
        .unwrap()
        .array(17)
        .unwrap()
        .to_vec();
    let mut wrong_parent = grant[13].array(4).unwrap().to_vec();
    wrong_parent[0] = V::Uint(127);
    let mut wrong_tier = grant[9].array(4).unwrap().to_vec();
    wrong_tier[0] = V::Uint(102);
    let malformed = [
        (13, a(wrong_parent)),
        (9, a(wrong_tier)),
        (10, a(vec![V::Uint(0), V::Uint(0)])),
        (10, a(vec![V::Uint(32)])),
        (11, a(vec![a(vec![V::Uint(0), b(&[99; 32])])])),
        (15, a(vec![V::Uint(0)])),
        (16, V::Null),
    ];
    for (index, bad) in malformed {
        let mut forged = grant.clone();
        forged[index] = bad;
        let bytes = wire::encode(&a(forged)).unwrap();
        let mut payload = wire::decode(&offer.acceptance.payload)
            .unwrap()
            .array(11)
            .unwrap()
            .to_vec();
        let mut reference = offer.acceptance.grant.clone();
        reference.digest = wire::digest(&bytes);
        payload[7] = version_value(&reference);
        let envelope = wire::sign_envelope(&wire::encode(&a(payload)).unwrap(), &f.signer).unwrap();
        let artifact = wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityApplicationOffer".into()),
            b(&envelope),
            b(&bytes),
        ]))
        .unwrap();
        assert!(
            application_offer::Offer::parse(&f.bootstrap, &artifact, false).is_err(),
            "malformed grant field {index} was accepted"
        );
    }
    let mut payload = wire::decode(&offer.acceptance.payload)
        .unwrap()
        .array(11)
        .unwrap()
        .to_vec();
    let mut reference = offer.acceptance.grant.clone();
    reference.generation = 2;
    payload[7] = version_value(&reference);
    let envelope = wire::sign_envelope(&wire::encode(&a(payload)).unwrap(), &f.signer).unwrap();
    let artifact = wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("AuthorityApplicationOffer".into()),
        b(&envelope),
        b(&offer.grant),
    ]))
    .unwrap();
    assert!(
        application_offer::Offer::parse(&f.bootstrap, &artifact, false).is_err(),
        "acceptance naming another grant generation was accepted"
    );
}
