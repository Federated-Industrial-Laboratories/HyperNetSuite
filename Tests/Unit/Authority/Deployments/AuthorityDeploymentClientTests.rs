// SPDX-License-Identifier: MIT
// Deployment consent, current capability and restrictive receipts remain independently verified.
use super::super::tests::{Fixture, voters};
use super::*;
use ed25519_dalek::Signer;

#[path = "AuthorityDeploymentDomainTests.rs"]
mod domain;
#[path = "AuthorityDeploymentReplayTests.rs"]
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
        Request::Register { .. } | Request::Withdraw { .. }
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
fn fixture() -> Fixture {
    Fixture::with_actions(vec![0, 9, 10, 11, 12, 13, 25])
}
fn discover(f: &mut Fixture) -> Cache {
    let p = Prepared::new(
        &f.bootstrap,
        Request::Context {
            grant: [23; 32],
            deployment: [60; 32],
        },
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
            f.bootstrap.governance_records(),
            &Reservations(f.bootstrap.reservations().to_vec()),
            &intent,
            f.current.observe().unwrap().wall_ms,
            false,
            None,
        )
        .unwrap();
    assert_eq!(decision.code, 0);
    let (reply, evidence) = certified(
        &p,
        decision.value,
        f.current.observe().unwrap().wall_ms,
        &f.store,
    );
    let cache = p
        .finish(reply, evidence, &mut f.store, &mut f.session, &mut || {
            Ok(f.current)
        })
        .unwrap()
        .cache;
    advance(f, 2000);
    cache
}
fn offer_for(f: &Fixture) -> Offer {
    offer_for_roles(f, &(1..9).collect::<Vec<_>>())
}
fn offer_for_roles(f: &Fixture, roles: &[u64]) -> Offer {
    let mut m = crate::authority_deployment_tests::manifest();
    m.roles.retain(|r| roles.contains(&r.role));
    let services: Vec<_> = m.roles.iter().map(|r| r.service_key).collect();
    m.endpoints.retain(|e| services.contains(&e.service_key));
    m.volumes
        .retain(|v| m.roles.iter().any(|r| r.volume_ids.contains(&v.volume_id)));
    m.placement.volumes = m.volumes.iter().map(|v| v.volume_id).collect();
    m.authority_config = None;
    let now = f.current.observe().unwrap().wall_ms;
    m.validity = (now - 10000, now + 3600000);
    let consent = wire::sign_envelope(
        &m.unsigned_consent(0).unwrap(),
        &crate::authority_deployment_tests::key(90),
    )
    .unwrap();
    let mut signers: Vec<_> = roles
        .iter()
        .map(|role| (0, 99 + *role as u8))
        .chain(roles.iter().map(|role| (1, 109 + *role as u8)))
        .chain(std::iter::once((2, 91)))
        .collect();
    signers.sort_by_key(|(class, seed)| {
        (
            *class,
            crate::authority_deployment_tests::key(*seed)
                .verifying_key()
                .to_bytes(),
        )
    });
    let proofs = signers
        .iter()
        .map(|(class, seed)| {
            let k = crate::authority_deployment_tests::key(*seed);
            b(&wire::sign_envelope(
                &Offer::possession(
                    &m,
                    *class,
                    k.verifying_key().to_bytes(),
                    [120; 32],
                    m.validity,
                )
                .unwrap(),
                &k,
            )
            .unwrap())
        })
        .collect();
    Offer::parse(&m.encode().unwrap(), &consent, &a(proofs)).unwrap()
}
fn register(f: &mut Fixture, context: &Cache, offer: Offer) -> Cache {
    let p = Prepared::new(
        &f.bootstrap,
        Request::Register {
            historical: false,
            grant: context.version(102, [23; 32]).unwrap(),
            offer,
        },
        Some(context),
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let intent = Intent::from_signed(&p.intent).unwrap();
    let d = Operation::parse(&intent)
        .unwrap()
        .authorise(
            &p.source,
            &Reservations(f.bootstrap.reservations().to_vec()),
            &intent,
            f.current.observe().unwrap().wall_ms,
            false,
            None,
        )
        .unwrap();
    assert_eq!(d.code, 0);
    let (reply, evidence) = certified(&p, d.value, f.current.observe().unwrap().wall_ms, &f.store);
    let result = p
        .finish(reply, evidence, &mut f.store, &mut f.session, &mut || {
            Ok(f.current)
        })
        .unwrap();
    assert!(result.cache.version(105, [60; 32]).is_ok());
    assert!(result.cache.version(117, [60; 32]).is_ok());
    assert!(result.cache.version(129, [60; 32]).is_ok());
    advance(f, 2000);
    result.cache
}
#[test]
fn registration_certifies_all_ownership_records_and_get_rejects_manifest_substitution() {
    let mut f = fixture();
    let context = discover(&mut f);
    let offer = offer_for(&f);
    let state = register(&mut f, &context, offer.clone());
    let loaded = Cache::load(&f.bootstrap, &f.store, [60; 32], None).unwrap();
    loaded.provenance().unwrap();
    let p = Prepared::new(
        &f.bootstrap,
        Request::Get {
            deployment: [60; 32],
            grant: Some([23; 32]),
        },
        Some(&state),
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let intent = Intent::from_signed(&p.intent).unwrap();
    let d = Operation::parse(&intent)
        .unwrap()
        .authorise(
            &p.source,
            &Reservations(f.bootstrap.reservations().to_vec()),
            &intent,
            f.current.observe().unwrap().wall_ms,
            false,
            Some((&offer.manifest_bytes, &offer.consent)),
        )
        .unwrap();
    assert_eq!(d.code, 0);
    let mut malformed = d.value.array(9).unwrap().to_vec();
    let mut other = offer.manifest.clone();
    other.software_digest = [199; 32];
    malformed[7] = b(&other.encode().unwrap());
    let (reply, evidence) = certified(
        &p,
        a(malformed),
        f.current.observe().unwrap().wall_ms,
        &f.store,
    );
    let before = f.store.prefix().height();
    assert!(
        p.finish(reply, evidence, &mut f.store, &mut f.session, &mut || Ok(
            f.current
        ))
        .is_err()
    );
    assert_eq!(f.store.prefix().height(), before);
    assert!(f.store.resume_ordinary().unwrap().is_some());
    let p = Prepared::new(
        &f.bootstrap,
        Request::Get {
            deployment: [60; 32],
            grant: Some([23; 32]),
        },
        Some(&state),
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let (reply, evidence) = certified(&p, d.value, f.current.observe().unwrap().wall_ms, &f.store);
    p.finish(reply, evidence, &mut f.store, &mut f.session, &mut || {
        Ok(f.current)
    })
    .unwrap();
}
#[test]
fn registration_resume_preserves_original_intent_and_refuses_changed_offer() {
    let mut f = fixture();
    let context = discover(&mut f);
    let offer = offer_for(&f);
    let grant = context.version(102, [23; 32]).unwrap();
    let p = Prepared::new(
        &f.bootstrap,
        Request::Register {
            historical: false,
            grant: grant.clone(),
            offer: offer.clone(),
        },
        Some(&context),
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let original = p.intent.clone();
    f.session.discard(&p.challenge).unwrap();
    drop(p);
    let mut changed = offer.clone();
    changed.manifest_bytes.push(0);
    assert!(
        Prepared::new(
            &f.bootstrap,
            Request::Register {
                historical: false,
                grant: grant.clone(),
                offer: changed
            },
            Some(&context),
            &f.signer,
            &mut f.store,
            &mut f.session,
            f.issued
        )
        .is_err()
    );
    let p = Prepared::new(
        &f.bootstrap,
        Request::Register {
            grant,
            offer,
            historical: false,
        },
        Some(&context),
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    assert_eq!(p.intent, original);
}
#[test]
fn local_withdrawal_receipt_binds_profile_and_accepts_unfinished_cleanup() {
    let mut f = fixture();
    let context = discover(&mut f);
    let offer = offer_for(&f);
    register(&mut f, &context, offer);
    let state = Cache::load(&f.bootstrap, &f.store, [60; 32], None).unwrap();
    let (m, r) = state.provenance().unwrap();
    let mut payload = vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("HyperNetLocalWithdrawal".into()),
        b(&m.network),
        b(&m.incarnation),
        b(&m.deployment),
        b(&m.operator),
        b(&m.operational_digest().unwrap()),
        V::Uint(2),
        V::Bool(false),
    ];
    let sign = |p: &[V], seed| {
        wire::sign_envelope(
            &wire::encode(&a(p.to_vec())).unwrap(),
            &crate::authority_deployment_tests::key(seed),
        )
        .unwrap()
    };
    assert_eq!(
        state.withdrawal(&sign(&payload, 90)).unwrap(),
        (r.reference.clone(), 2)
    );
    assert!(state.withdrawal(&sign(&payload, 91)).is_err());
    payload[7] = b(&[250; 32]);
    assert!(state.withdrawal(&sign(&payload, 90)).is_err());
    let refs = versions(&state.scope, &state.entries).unwrap();
    let mut floor = refs.clone();
    floor.push(VersionRef {
        kind: 130,
        id: m.deployment,
        generation: 1,
        digest: [99; 32],
    });
    assert!(minimum(&refs, &floor, false).is_err());
}

#[test]
fn committed_withdrawal_repairs_only_the_exact_pending_cache_restriction() {
    use crate::authority_deployment_tests as fixture;
    let f = fixture::Fixture::new();
    let offer = fixture::offer(fixture::manifest());
    let (entries, registration, _, _) = fixture::admitted(&f, &offer);
    let state = Cache {
        scope: f.scope.clone(),
        deployment: registration.deployment,
        grant: None,
        entries: entries
            .into_iter()
            .filter(|v| records::reference(v).is_ok_and(|r| matches!(r.kind, 105 | 117 | 129)))
            .collect(),
        manifest: Some(offer.manifest_bytes.clone()),
        consent: Some(offer.consent.clone()),
    };
    let original_refs = versions(&state.scope, &state.entries).unwrap();
    let pending = |generation, seed| {
        Intent::from_signed(&fixture::signed(
            &fixture::key(seed),
            "AuthorityDeploymentWithdraw",
            state.deployment,
            1,
            a(vec![
                V::Uint(200),
                V::Uint(1),
                V::Text("AuthorityDeploymentWithdraw".into()),
                version_value(&registration.reference),
                V::Uint(generation),
                fixture::snapshot(&original_refs),
            ]),
            original_refs.clone(),
        ))
        .unwrap()
    };
    let intent = pending(1, 90);
    let created = Operation::parse(&intent).unwrap().derive(&intent).unwrap();
    let restriction = records::reference(&created[0]).unwrap();
    let mut retained = original_refs.clone();
    retained.push(restriction.clone());
    assert!(minimum(&original_refs, &retained, false).is_err());

    let mut uncommitted = state.clone();
    uncommitted
        .recover_withdrawal(&intent, &original_refs)
        .unwrap();
    assert!(uncommitted.version(130, state.deployment).is_err());

    let mut recovered = state.clone();
    recovered.recover_withdrawal(&intent, &retained).unwrap();
    assert_eq!(
        recovered.version(130, state.deployment).unwrap(),
        restriction
    );
    minimum(
        &versions(&state.scope, &recovered.entries).unwrap(),
        &retained,
        false,
    )
    .unwrap();
    recovered.provenance().unwrap();
    let exact = recovered.entries.clone();
    recovered.recover_withdrawal(&intent, &retained).unwrap();
    assert_eq!(recovered.entries, exact);

    let mut changed = state.clone();
    changed
        .recover_withdrawal(&pending(2, 90), &retained)
        .unwrap();
    assert!(
        minimum(
            &versions(&state.scope, &changed.entries).unwrap(),
            &retained,
            false
        )
        .is_err()
    );
    assert!(
        state
            .clone()
            .recover_withdrawal(&pending(1, 91), &retained)
            .is_err()
    );
    let mut foreign = intent.clone();
    foreign.network = [240; 32];
    assert!(
        state
            .clone()
            .recover_withdrawal(&foreign, &retained)
            .is_err()
    );
}

#[test]
fn withdrawal_cache_failure_reopens_and_completes_the_same_request() {
    use crate::authority_deployment_tests as vectors;
    let mut f = Fixture::with_actions_and_signer(vec![0, 13, 25], vectors::key(90));
    let offer = offer_for_roles(&f, &[1]);
    let scope = f.bootstrap.descriptor().scope().clone();
    let reservations = Reservations(f.bootstrap.reservations().to_vec());
    let mut entries = f.bootstrap.governance_records().to_vec();
    let grant = versions(&scope, &entries)
        .unwrap()
        .into_iter()
        .find(|r| r.kind == 102)
        .unwrap();
    let sign_registration = |refs: &[VersionRef]| {
        let parameters = a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityDeploymentRegister".into()),
            version_value(&grant),
            b(&offer.manifest_bytes),
            b(&offer.consent),
            offer.possessions_value(),
            vectors::snapshot(refs),
            V::Bool(false),
        ]);
        Intent::from_signed(&vectors::signed(
            &vectors::key(5),
            "AuthorityDeploymentRegister",
            [60; 32],
            1,
            parameters,
            refs.to_vec(),
        ))
        .unwrap()
    };
    let intent = sign_registration(&[]);
    let preflight = Operation::parse(&intent)
        .unwrap()
        .prepare(
            &entries,
            &reservations,
            &intent,
            f.current.observe().unwrap().wall_ms,
            false,
            None,
        )
        .unwrap();
    assert_eq!(preflight.code, 0);
    let refs = preflight
        .dependencies
        .into_iter()
        .filter(|r| !matches!(r.kind, 105 | 117 | 129))
        .collect::<Vec<_>>();
    let intent = sign_registration(&refs);
    let admitted = Operation::parse(&intent)
        .unwrap()
        .authorise(
            &entries,
            &reservations,
            &intent,
            f.current.observe().unwrap().wall_ms,
            false,
            None,
        )
        .unwrap();
    assert_eq!(admitted.code, 0);
    entries.extend(admitted.records);
    membership::sort_records(&mut entries).unwrap();

    // Offer preparation is outside the bounded recipient request interval.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let boot = boot_time_ms().unwrap();
    f.current = ClockHealth::new(now, boot, boot + 30000, 100)
        .unwrap()
        .frozen();
    advance(&mut f, 2000);
    // Loss of the optional acceptance record cannot trap an operator's terminal veto.
    files::atomic_at(
        f.store.profile_directory(),
        std::ffi::OsStr::new("AcceptedPolicy.cbor"),
        b"Unavailable acceptance record",
        true,
    )
    .unwrap();
    assert!(crate::authority_inspection::policy::require_accepted(&f.bootstrap, &f.store).is_err());
    assert!(
        Prepared::new(
            &f.bootstrap,
            Request::Get {
                deployment: [60; 32],
                grant: Some(grant.id),
            },
            None,
            &f.signer,
            &mut f.store,
            &mut f.session,
            f.issued,
        )
        .is_err()
    );
    let p = Prepared::new(
        &f.bootstrap,
        Request::Get {
            deployment: [60; 32],
            grant: None,
        },
        None,
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let intent = Intent::from_signed(&p.intent).unwrap();
    let result = Operation::parse(&intent)
        .unwrap()
        .authorise(
            &entries,
            &reservations,
            &intent,
            f.current.observe().unwrap().wall_ms,
            false,
            Some((&offer.manifest_bytes, &offer.consent)),
        )
        .unwrap();
    assert_eq!(result.code, 0);
    let (reply, evidence) = certified(
        &p,
        result.value,
        f.current.observe().unwrap().wall_ms,
        &f.store,
    );
    let state = p
        .finish(reply, evidence, &mut f.store, &mut f.session, &mut || {
            Ok(f.current)
        })
        .unwrap()
        .cache;
    let admission = state.version(129, [60; 32]).unwrap();
    advance(&mut f, 2000);
    let p = Prepared::new(
        &f.bootstrap,
        Request::Withdraw {
            admission: admission.clone(),
            generation: 1,
        },
        Some(&state),
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let original = p.intent.clone();
    let intent = Intent::from_signed(&original).unwrap();
    let operation = Operation::parse(&intent).unwrap();
    let restriction = records::reference(&operation.derive(&intent).unwrap()[0]).unwrap();
    let result = operation
        .authorise(
            &p.source,
            &reservations,
            &intent,
            f.current.observe().unwrap().wall_ms,
            false,
            None,
        )
        .unwrap();
    assert_eq!(result.code, 0);
    let (reply, evidence) = certified(
        &p,
        result.value,
        f.current.observe().unwrap().wall_ms,
        &f.store,
    );

    let path = f
        .directory
        .0
        .join(format!("DeploymentState{}.cbor", hex::encode([60; 32])));
    let backup = f.directory.0.join("PriorDeployment.cbor");
    let old_bytes = std::fs::read(&path).unwrap();
    std::fs::rename(&path, &backup).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(
        p.finish(reply, evidence, &mut f.store, &mut f.session, &mut || Ok(
            f.current
        ))
        .is_err()
    );
    assert!(f.store.generations().contains(&restriction));
    assert!(state.current(&f.store).is_err());
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        original
    );
    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(&backup, &path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), old_bytes);
    drop(f.store);
    f.store = Store::open(&f.directory.0, f.bootstrap.descriptor().clone()).unwrap();
    f.session = Session::new().unwrap();
    let recovered = Cache::load(&f.bootstrap, &f.store, [60; 32], None).unwrap();
    assert_eq!(recovered.version(130, [60; 32]).unwrap(), restriction);
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        original
    );
    advance(&mut f, 2000);
    let p = Prepared::new(
        &f.bootstrap,
        Request::Withdraw {
            admission,
            generation: 1,
        },
        Some(&recovered),
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    assert_eq!(p.intent, original);
    let result = operation
        .authorise(
            &p.source,
            &reservations,
            &intent,
            f.current.observe().unwrap().wall_ms,
            true,
            None,
        )
        .unwrap();
    assert_eq!(result.code, 0);
    assert!(result.records.is_empty());
    let (reply, evidence) = certified(
        &p,
        result.value,
        f.current.observe().unwrap().wall_ms,
        &f.store,
    );
    p.finish(reply, evidence, &mut f.store, &mut f.session, &mut || {
        Ok(f.current)
    })
    .unwrap();
    assert!(f.store.resume_ordinary().unwrap().is_none());
    assert!(f.store.generations().contains(&restriction));
    let saved = Cache::load(&f.bootstrap, &f.store, [60; 32], None).unwrap();
    assert_eq!(saved.version(130, [60; 32]).unwrap(), restriction);
}

fn activation_fixture() -> (Fixture, Cache, crate::authority_runtime_activation::Request) {
    let mut f = Fixture::with_actions(vec![0, 9, 10, 11, 12, 13, 25, 26]);
    let context = discover(&mut f);
    let offer = offer_for_roles(&f, &[8]);
    let mut cache = register(&mut f, &context, offer);
    cache.grant = Some([23; 32]);
    let request = activation_client::prepare(
        &f.bootstrap,
        &cache,
        &f.signer,
        &mut f.store,
        8,
        1,
        f.current,
    )
    .unwrap();
    (f, cache, request)
}
struct ActivationEvidence {
    receipt: crate::authority_runtime_activation::Receipt,
    proof: proof::VerifiedResult,
    challenge: Vec<u8>,
    ordered: Vec<u8>,
    node: Vec<u8>,
}
fn activation_certificate(reply: &[u8], generation: u64, consent: Option<[u8; 32]>) -> Vec<u8> {
    let value = wire::decode(reply).unwrap();
    let reply = value.array(10).unwrap();
    let (payload, _) = wire::envelope(reply[7].bytes().unwrap(), 4).unwrap();
    let mut fields = wire::decode(&payload).unwrap().array(23).unwrap().to_vec();
    fields[13] = V::Uint(generation);
    fields[20] = consent.map_or(V::Null, |digest| b(&digest));
    let payload = wire::encode(&a(fields)).unwrap();
    let signatures = voters()[..3]
        .iter()
        .map(|k| {
            let key = k.verifying_key().to_bytes();
            a(vec![
                b(&key),
                b(&k.sign(&wire::signature_message(&payload, &key)).to_bytes()),
            ])
        })
        .collect();
    wire::encode(&a(vec![V::Uint(0), V::Uint(1), b(&payload), a(signatures)])).unwrap()
}
fn activation_evidence(
    f: &Fixture,
    cache: &Cache,
    request: &crate::authority_runtime_activation::Request,
    parent: [u8; 32],
) -> ActivationEvidence {
    use super::super::tests::certified_request;
    use crate::authority_runtime_activation::Receipt;
    let recipient = crate::authority_deployment_tests::key(107);
    assert_ne!(recipient.verifying_key(), f.signer.verifying_key());
    let mut serving = Session::new().unwrap();
    let challenge = serving
        .issue(request.signed(), &recipient, [92; 32], 5000, f.issued)
        .unwrap();
    let parsed = Challenge::from_signed(&challenge).unwrap();
    let ordered = wire::encode(&a(vec![
        V::Uint(22),
        V::Uint(1),
        f.store.descriptor().scope().value(),
        b(request.signed()),
        b(&challenge),
        V::Uint(parsed.expires_at_ms),
    ]))
    .unwrap();
    let source = merged(&f.bootstrap, &cache.entries).unwrap();
    let decision = request
        .operation()
        .authorise(
            &source,
            &Reservations(f.bootstrap.reservations().to_vec()),
            request.intent(),
            recipient.verifying_key().to_bytes(),
            f.current.observe().unwrap().wall_ms,
            false,
        )
        .unwrap();
    assert_eq!(decision.code, 0);
    let (reply, node) = certified_request(
        f.store.descriptor(),
        request.signed(),
        &challenge,
        &ordered,
        decision.value,
        f.current.observe().unwrap().wall_ms,
        parent,
        f.store.prefix().height() + 1,
        0,
    );
    let certificate = activation_certificate(
        &reply,
        request.intent().profile_generation,
        decision.restrictions.consent,
    );
    let value = wire::decode(&reply).unwrap();
    let reply = value.array(10).unwrap();
    let proof = request
        .verify(
            &f.bootstrap,
            f.store.descriptor(),
            &challenge,
            &ordered,
            reply[8].bytes().unwrap(),
            &certificate,
            std::slice::from_ref(&node),
        )
        .unwrap();
    let completed_at = f.current.observe().unwrap().wall_ms;
    let receipt = Receipt::create(
        request,
        &challenge,
        &ordered,
        &proof,
        &recipient,
        completed_at,
    )
    .unwrap();
    ActivationEvidence {
        receipt,
        proof,
        challenge,
        ordered,
        node,
    }
}
#[test]
fn manager_activation_retries_exactly_and_remote_completion_never_releases_a_permit() {
    use crate::authority_runtime_activation::{self as activation, Receipt};
    let (mut f, cache, request) = activation_fixture();
    let retry = activation_client::prepare(
        &f.bootstrap,
        &cache,
        &f.signer,
        &mut f.store,
        8,
        1,
        f.current,
    )
    .unwrap();
    assert_eq!(request.signed(), retry.signed());
    assert!(
        activation_client::prepare(
            &f.bootstrap,
            &cache,
            &f.signer,
            &mut f.store,
            8,
            2,
            f.current
        )
        .is_err()
    );
    let ActivationEvidence {
        receipt,
        proof,
        challenge,
        ordered,
        ..
    } = activation_evidence(&f, &cache, &request, *f.store.prefix().node());
    let recipient = crate::authority_deployment_tests::key(107);
    let parsed = Challenge::from_signed(&challenge).unwrap();
    let completed_at = f.current.observe().unwrap().wall_ms;
    assert!(
        Receipt::create(
            &request,
            &challenge,
            &ordered,
            &proof,
            &f.signer,
            completed_at
        )
        .is_err()
    );
    // Completion reporting is historical. No requester Session or fresh status is needed,
    // even after the original challenge can no longer authorize a protected effect.
    advance(&mut f, 6000);
    assert!(f.current.observe().unwrap().wall_ms > parsed.expires_at_ms);
    let report = receipt.verify(&f.bootstrap, f.store.descriptor()).unwrap();
    assert_eq!(report.request().digest, request.intent().digest);
    assert_eq!(
        f.store
            .complete_activation(report, |_| panic!("connected receipt must stay offline"))
            .unwrap(),
        request.intent().digest
    );
    assert!(f.store.resume_ordinary().unwrap().is_none());
    // The same historical report completes no second effect and leaves the exact retained floor.
    let height = f.store.prefix().height();
    let report = receipt.verify(&f.bootstrap, f.store.descriptor()).unwrap();
    f.store
        .complete_activation(report, |_| panic!("known completion must stay offline"))
        .unwrap();
    assert_eq!(f.store.prefix().height(), height);
    let expired = Receipt::create(
        &request,
        &challenge,
        &ordered,
        &proof,
        &recipient,
        parsed.expires_at_ms,
    )
    .unwrap();
    assert!(expired.verify(&f.bootstrap, f.store.descriptor()).is_err());
    assert!(f.store.ordinary_slot().is_ok());
    assert_eq!(request.intent().action, activation::ACTION);
}

#[test]
fn activation_completion_refuses_another_request_and_unconnected_ancestry() {
    let (mut f, cache, request) = activation_fixture();
    let before = std::fs::read(f.directory.0.join("AuthorityFloor.json")).unwrap();
    let (payload, _) = wire::envelope(request.signed(), 1).unwrap();
    let mut fields = wire::decode(&payload).unwrap().array(17).unwrap().to_vec();
    let mut parameters = wire::decode(fields[16].bytes().unwrap())
        .unwrap()
        .array(9)
        .unwrap()
        .to_vec();
    fields[11] = V::Uint(2);
    parameters[7] = V::Uint(2);
    fields[16] = b(&wire::encode(&a(parameters)).unwrap());
    let other = crate::authority_runtime_activation::Request::new(
        wire::sign_envelope(&wire::encode(&a(fields)).unwrap(), &f.signer).unwrap(),
        merged(&f.bootstrap, &cache.entries).unwrap(),
    )
    .unwrap();
    let other = activation_evidence(&f, &cache, &other, *f.store.prefix().node());
    let report = other
        .receipt
        .verify(&f.bootstrap, f.store.descriptor())
        .unwrap();
    assert!(
        f.store
            .complete_activation(report, |_| panic!(
                "another request must be rejected locally"
            ))
            .is_err()
    );

    let disconnected = activation_evidence(&f, &cache, &request, [199; 32]);
    let report = disconnected
        .receipt
        .verify(&f.bootstrap, f.store.descriptor())
        .unwrap();
    let mut reconciled = false;
    assert!(
        f.store
            .complete_activation(report, |_| {
                reconciled = true;
                Ok(())
            })
            .is_err()
    );
    assert!(reconciled);
    assert_eq!(
        std::fs::read(f.directory.0.join("AuthorityFloor.json")).unwrap(),
        before
    );
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        request.signed()
    );
}

#[test]
fn activation_completion_after_a_later_refusal_requires_exact_status_reconciliation() {
    use super::super::tests::certified_request;
    let (mut f, cache, request) = activation_fixture();
    let evidence = activation_evidence(&f, &cache, &request, *f.store.prefix().node());
    advance(&mut f, 6000);
    // A later expired attempt advances the floor without establishing the remote
    // attempt's original completion. The older receipt cannot roll that floor back.
    let (reply, node) = certified_request(
        f.store.descriptor(),
        request.signed(),
        &evidence.challenge,
        &evidence.ordered,
        a(vec![
            V::Uint(201),
            V::Uint(1),
            V::Text(crate::authority_runtime_activation::ACTION.into()),
            a(vec![]),
        ]),
        f.current.observe().unwrap().wall_ms,
        wire::digest(&evidence.node),
        f.store.prefix().height() + 2,
        7,
    );
    let certificate = activation_certificate(&reply, request.intent().profile_generation, None);
    let value = wire::decode(&reply).unwrap();
    let refusal = request
        .verify(
            &f.bootstrap,
            f.store.descriptor(),
            &evidence.challenge,
            &evidence.ordered,
            value.array(10).unwrap()[8].bytes().unwrap(),
            &certificate,
            &[evidence.node.clone(), node],
        )
        .unwrap();
    f.store.observe(refusal).unwrap();
    let later = f.store.prefix().clone();
    let before = std::fs::read(f.directory.0.join("AuthorityFloor.json")).unwrap();
    let report = evidence
        .receipt
        .verify(&f.bootstrap, f.store.descriptor())
        .unwrap();
    assert_eq!(
        f.store
            .complete_activation(report, |_| bail!("fresh status unavailable"))
            .unwrap_err()
            .to_string(),
        "fresh status unavailable"
    );
    assert_eq!(
        std::fs::read(f.directory.0.join("AuthorityFloor.json")).unwrap(),
        before
    );
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        request.signed()
    );

    advance(&mut f, 2000);
    let report = evidence
        .receipt
        .verify(&f.bootstrap, f.store.descriptor())
        .unwrap();
    let signer = &f.signer;
    let issued = f.issued;
    let current = f.current;
    let mut reconciled = false;
    f.store
        .complete_activation(report, |store| {
            reconciled = true;
            let descriptor = store.descriptor().clone();
            let scope = descriptor.scope();
            let intent = request.intent();
            let status = wire::sign_envelope(
                &wire::encode(&a(vec![
                    V::Uint(55),
                    V::Uint(1),
                    b(&scope.network),
                    b(&scope.incarnation),
                    b(&store.requester()),
                    b(&[198; 32]),
                    V::Uint(scope.epoch),
                    V::Uint(store.prefix().height()),
                ]))?,
                signer,
            )?;
            let mut session = Session::new()?;
            let challenge = session.issue(&status, signer, [197; 32], 5000, issued)?;
            let parsed = Challenge::from_signed(&challenge)?;
            let ordered = wire::encode(&a(vec![
                V::Uint(22),
                V::Uint(1),
                scope.value(),
                b(&status),
                b(&challenge),
                V::Uint(parsed.expires_at_ms),
            ]))?;
            let metadata = a(vec![
                V::Uint(56),
                V::Uint(1),
                scope.value(),
                b(&store.requester()),
                V::Bool(true),
                V::Uint(intent.generation),
                b(&intent.generation_id),
                V::Uint(intent.sequence - 1),
                a(vec![
                    V::Uint(intent.sequence),
                    b(&intent.digest),
                    V::Uint(0),
                    V::Uint(0),
                    b(&wire::digest(evidence.proof.operation_result_bytes())),
                ]),
                V::Null,
            ]);
            let (reply, node) = certified_request(
                &descriptor,
                &status,
                &challenge,
                &ordered,
                metadata,
                current.observe()?.wall_ms,
                *store.prefix().node(),
                store.prefix().height() + 1,
                0,
            );
            let value = wire::decode(&reply)?;
            let fields = value.array(10)?;
            let verified = proof::verify_response(
                &descriptor,
                proof::ProofContext {
                    intent: &status,
                    challenge: &challenge,
                    restrictions: Restrictions::default(),
                    minimum_height: store.prefix().height(),
                    maximum_effect: 1,
                    expected_stream: None,
                },
                proof::Response {
                    ordered_request: &ordered,
                    operation_result: fields[8].bytes()?,
                    certificate: fields[7].bytes()?,
                    ancestry: &[node],
                },
                |_, _, _| bail!("status requires the fixed verifier"),
            )?;
            let permit = store.accept(verified, &mut session, current, parsed.created_at_ms)?;
            permit.perform(store, &mut session, current, 1, |_| Ok(()), |_, _| Ok(()))
        })
        .unwrap();
    assert!(reconciled);
    assert!(f.store.resume_ordinary().unwrap().is_none());
    assert_eq!(f.store.prefix().height(), later.height() + 1);
    let height = f.store.prefix().height();
    let report = evidence
        .receipt
        .verify(&f.bootstrap, f.store.descriptor())
        .unwrap();
    f.store
        .complete_activation(report, |_| panic!("known original must stay offline"))
        .unwrap();
    assert_eq!(f.store.prefix().height(), height);
}

#[test]
fn operational_successor_prepares_from_certified_context_and_replaces_cached_generations() {
    let mut f = fixture();
    let context = discover(&mut f);
    let initial = offer_for_roles(&f, &[1]);
    let state = register(&mut f, &context, initial.clone());
    let mut manifest = initial.manifest.clone();
    manifest.generation = 2;
    manifest.previous_profile = Some(wire::digest(&initial.manifest.desired().unwrap()));
    manifest.previous_consent = Some(wire::digest(&initial.manifest.unsigned_consent(0).unwrap()));
    let now = f.current.observe().unwrap().wall_ms;
    manifest.validity.1 = now + 3600000;
    let consent = wire::sign_envelope(
        &manifest.unsigned_consent(0).unwrap(),
        &crate::authority_deployment_tests::key(90),
    )
    .unwrap();
    let successor = Offer::parse(&manifest.encode().unwrap(), &consent, &a(vec![])).unwrap();
    assert!(
        successor
            .current(f.issued.observe().unwrap().wall_ms)
            .unwrap()
    );
    assert!(successor.current(now).unwrap());
    let current = register(&mut f, &state, successor);
    let network = f.bootstrap.descriptor().scope().network;
    assert_eq!(
        current.version(100, network).unwrap(),
        context.version(100, network).unwrap()
    );
    for kind in [105, 117, 129] {
        assert_eq!(
            current
                .version(kind, manifest.deployment)
                .unwrap()
                .generation,
            2
        );
    }
    let cached = Cache::load(&f.bootstrap, &f.store, manifest.deployment, None).unwrap();
    let (retained, _) = cached.provenance().unwrap();
    assert_eq!(retained, manifest);
    assert!(state.current(&f.store).is_err());
    for kind in [105, 117, 129] {
        assert!(
            f.store
                .generations()
                .contains(&current.version(kind, manifest.deployment).unwrap())
        );
    }
}

#[test]
fn successor_cache_failure_reopens_and_completes_the_exact_registration() {
    let mut f = fixture();
    let context = discover(&mut f);
    let initial = offer_for_roles(&f, &[1]);
    let state = register(&mut f, &context, initial.clone());
    let mut manifest = initial.manifest.clone();
    manifest.generation = 2;
    manifest.previous_profile = Some(wire::digest(&initial.manifest.desired().unwrap()));
    manifest.previous_consent = Some(wire::digest(&initial.manifest.unsigned_consent(0).unwrap()));
    manifest.validity.1 += 2000;
    let consent = wire::sign_envelope(
        &manifest.unsigned_consent(0).unwrap(),
        &crate::authority_deployment_tests::key(90),
    )
    .unwrap();
    let offer = Offer::parse(&manifest.encode().unwrap(), &consent, &a(vec![])).unwrap();
    let request = || Request::Register {
        historical: false,
        grant: context.version(102, [23; 32]).unwrap(),
        offer: offer.clone(),
    };
    let p = Prepared::new(
        &f.bootstrap,
        request(),
        Some(&state),
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let original = p.intent.clone();
    let intent = Intent::from_signed(&original).unwrap();
    let operation = Operation::parse(&intent).unwrap();
    let reservations = Reservations(f.bootstrap.reservations().to_vec());
    let decision = operation
        .authorise(
            &p.source,
            &reservations,
            &intent,
            f.current.observe().unwrap().wall_ms,
            false,
            None,
        )
        .unwrap();
    assert_eq!(decision.code, 0);
    let (reply, evidence) = certified(
        &p,
        decision.value,
        f.current.observe().unwrap().wall_ms,
        &f.store,
    );
    let path = f.directory.0.join(format!(
        "DeploymentContext{}{}.cbor",
        hex::encode(manifest.deployment),
        hex::encode([23; 32])
    ));
    let backup = f.directory.0.join("PriorDeploymentContext.cbor");
    std::fs::rename(&path, &backup).unwrap();
    std::fs::create_dir(&path).unwrap();
    let error = p
        .finish(reply, evidence, &mut f.store, &mut f.session, &mut || {
            Ok(f.current)
        })
        .err()
        .expect("Cache destination must reject publication");
    assert!(
        format!("{error:#}")
            .contains("cannot publish file without changing the destination policy")
    );
    assert!(state.current(&f.store).is_err());
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        original
    );
    for bytes in operation.derive(&intent).unwrap() {
        assert!(
            f.store
                .generations()
                .contains(&records::reference(&bytes).unwrap())
        );
    }
    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(&backup, &path).unwrap();
    drop(f.store);
    f.store = Store::open(&f.directory.0, f.bootstrap.descriptor().clone()).unwrap();
    f.session = Session::new().unwrap();
    let recovered =
        Cache::load(&f.bootstrap, &f.store, manifest.deployment, Some([23; 32])).unwrap();
    for kind in [105, 117, 129] {
        assert_eq!(
            recovered
                .version(kind, manifest.deployment)
                .unwrap()
                .generation,
            2
        );
    }
    advance(&mut f, 2000);
    let p = Prepared::new(
        &f.bootstrap,
        request(),
        Some(&recovered),
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    assert_eq!(p.intent, original);
    let decision = operation
        .authorise(
            &p.source,
            &reservations,
            &intent,
            f.current.observe().unwrap().wall_ms,
            true,
            None,
        )
        .unwrap();
    assert_eq!(decision.code, 0);
    let (reply, evidence) = certified(
        &p,
        decision.value,
        f.current.observe().unwrap().wall_ms,
        &f.store,
    );
    p.finish(reply, evidence, &mut f.store, &mut f.session, &mut || {
        Ok(f.current)
    })
    .unwrap();
    assert!(f.store.resume_ordinary().unwrap().is_none());
    let saved = Cache::load(&f.bootstrap, &f.store, manifest.deployment, None).unwrap();
    assert_eq!(saved.provenance().unwrap().0, manifest);
}
