// SPDX-License-Identifier: MIT
// Discovery and revocation preserve original challenges and certified context dependencies.
use super::super::tests::{Fixture, voters};
use super::*;
use ed25519_dalek::Signer;
fn value(pending: &GovernancePrepared) -> V {
    match &pending.mode {
        Mode::Member(_) => panic!("membership requires its exact derived record"),
        Mode::Refresh { .. } => panic!("context fixture must supply its exact source records"),
        Mode::Revoke {
            target, tombstone, ..
        } => {
            let mut refs = pending.expected.clone();
            refs.push(VersionRef {
                kind: 126,
                id: target.id,
                generation: 1,
                digest: wire::digest(tombstone),
            });
            refs.sort_by_key(VersionRef::index);
            a(vec![
                V::Uint(201),
                V::Uint(1),
                V::Text(REVOKE.into()),
                a(refs.iter().map(version_value).collect()),
                b(tombstone),
            ])
        }
    }
}
fn context_value(pending: &GovernancePrepared, governance: &Governance) -> V {
    let refs = governance.versions();
    let start = match &pending.mode {
        Mode::Refresh { pages, .. } => pages.as_ref().map_or(0, |p| p.entries.len()),
        _ => 0,
    };
    let end = (start + 64).min(refs.len());
    a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text(CONTEXT.into()),
        a(refs[start..end].iter().map(version_value).collect()),
        a(vec![
            b(&paging::root(pending.descriptor.scope(), &refs).unwrap()),
            V::Uint(refs.len() as u64),
            V::Uint(start as u64),
            if end == refs.len() {
                V::Null
            } else {
                V::Uint(end as u64)
            },
            a(records(governance).unwrap()[start..end]
                .iter()
                .map(|v| b(v))
                .collect()),
        ]),
    ])
}
pub(super) fn certified(
    pending: &GovernancePrepared,
    value: V,
    time: u64,
    store: &Store,
    refused: bool,
) -> (CertifiedReply, Vec<Vec<u8>>) {
    let scope = pending.descriptor.scope();
    let height = store.prefix().height() + 1;
    let intent = Intent::from_signed(&pending.intent).unwrap();
    let challenge = Challenge::from_signed(&pending.challenge).unwrap();
    let result = wire::encode(&a(vec![
        V::Uint(24),
        V::Uint(1),
        V::Text(pending.action().into()),
        V::Uint(if refused { 1 } else { 0 }),
        V::Uint(if refused { 7 } else { 0 }),
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
        b(&wire::digest(&pending.ordered)),
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
        b(&wire::digest(&pending.ordered)),
        b(&intent.digest),
        b(&challenge.digest),
        b(&intent.requester),
        b(&challenge.recipient),
        V::Text(pending.action().into()),
        b(&intent.resource),
        V::Uint(intent.revision),
        V::Uint(0),
        V::Uint(if refused { 0 } else { 1 }),
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
        vec![node],
    )
}
fn refresh(f: &mut Fixture) -> GovernancePrepared<'static> {
    GovernancePrepared::refresh(
        &f.bootstrap,
        [23; 32],
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap()
}
fn target(f: &Fixture) -> VersionRef {
    f.context
        .governance
        .versions()
        .into_iter()
        .find(|v| v.kind == 102)
        .unwrap()
}
fn changed_governance(f: &Fixture) -> Governance {
    let mut entries = records(&f.context.governance).unwrap();
    for bytes in &mut entries {
        let mut record = wire::decode(bytes).unwrap();
        if let V::Array(fields) = &mut record
            && fields[0] == V::Uint(114)
        {
            fields[4] = V::Uint(2);
            fields[5] = b(&wire::digest(bytes));
            fields[12] = a(vec![
                point(f.store.prefix()),
                a(f.context
                    .governance
                    .versions()
                    .iter()
                    .map(version_value)
                    .collect()),
            ]);
            *bytes = wire::encode(&record).unwrap();
        }
    }
    // Updating recovery also updates its exact reference in network policy.
    let recovery = entries
        .iter()
        .find(|v| wire::decode(v).unwrap().list(32).unwrap()[0] == V::Uint(114))
        .unwrap();
    let reference = VersionRef {
        kind: 114,
        id: [20; 32],
        generation: 2,
        digest: wire::digest(recovery),
    };
    for bytes in &mut entries {
        let mut record = wire::decode(bytes).unwrap();
        if let V::Array(fields) = &mut record
            && fields[0] == V::Uint(100)
        {
            fields[4] = V::Uint(2);
            fields[5] = b(&wire::digest(bytes));
            fields[12] = version_value(&reference);
            fields[16] = a(vec![
                point(f.store.prefix()),
                a(f.context
                    .governance
                    .versions()
                    .iter()
                    .map(version_value)
                    .collect()),
            ]);
            *bytes = wire::encode(&record).unwrap();
        }
    }
    Governance::parse([20; 32], [21; 32], &entries).unwrap()
}

#[test]
fn discovery_keeps_minima_local_and_accepts_newer_complete_certified_context() {
    let mut f = Fixture::new();
    let pending = refresh(&mut f);
    let intent = Intent::from_signed(&pending.intent).unwrap();
    assert!(intent.expected.is_empty());
    assert_eq!(intent.revision, 0);
    let parameters = wire::decode(&intent.parameters).unwrap();
    let p = parameters.array(6).unwrap();
    assert_eq!(p[4], point(f.store.prefix()));
    assert_eq!(p[5], V::Null);
    let changed = changed_governance(&f);
    let output = context_value(&pending, &changed);
    let (reply, ancestry) = certified(
        &pending,
        output,
        f.current.observe().unwrap().wall_ms,
        &f.store,
        false,
    );
    let Outcome::Context(context) = pending
        .finish(reply, ancestry, &mut f.store, &mut f.session, &mut || {
            Ok(f.current)
        })
        .unwrap()
    else {
        panic!("context expected")
    };
    assert_eq!(f.store.prefix().height(), 2);
    assert_eq!(context.governance.versions(), changed.versions());
    context.save(&f.store).unwrap();
    assert_eq!(
        ContextState::load(&f.bootstrap, &f.store, &f.directory.0)
            .unwrap()
            .governance
            .versions(),
        changed.versions()
    );
    assert!(
        ContextState::retained(&f.bootstrap, &f.store, f.bootstrap.governance_records()).is_err()
    );
}

#[test]
fn discovery_refuses_missing_conflicting_extra_and_unquorate_records_before_floor() {
    for case in 0..5 {
        let mut f = Fixture::new();
        let pending = refresh(&mut f);
        let mut output = context_value(&pending, &f.context.governance);
        let V::Array(fields) = &mut output else {
            unreachable!()
        };
        match case {
            0 => {
                let V::Array(refs) = &mut fields[3] else {
                    unreachable!()
                };
                refs.pop();
            }
            1 => {
                let V::Array(body) = &mut fields[4] else {
                    unreachable!()
                };
                let V::Array(entries) = &mut body[4] else {
                    unreachable!()
                };
                entries.pop();
            }
            2 => {
                let V::Array(refs) = &mut fields[3] else {
                    unreachable!()
                };
                let V::Array(r) = &mut refs[0] else {
                    unreachable!()
                };
                r[3] = b(&[99; 32]);
            }
            3 => {
                let V::Array(body) = &mut fields[4] else {
                    unreachable!()
                };
                let V::Array(entries) = &mut body[4] else {
                    unreachable!()
                };
                entries.push(entries[0].clone());
            }
            _ => {}
        }
        let (mut reply, ancestry) = certified(
            &pending,
            output,
            f.current.observe().unwrap().wall_ms,
            &f.store,
            false,
        );
        if case == 4 {
            let mut env = wire::decode(&reply.certificate).unwrap();
            let V::Array(e) = &mut env else {
                unreachable!()
            };
            let V::Array(signatures) = &mut e[3] else {
                unreachable!()
            };
            signatures.pop();
            reply.certificate = wire::encode(&env).unwrap();
        }
        assert!(
            pending
                .finish(reply, ancestry, &mut f.store, &mut f.session, &mut || Ok(
                    f.current
                ))
                .is_err()
        );
        assert_eq!(f.store.prefix().height(), 1);
    }
}

#[test]
fn exact_revocation_self_tombstone_is_durable_and_denies_subsequent_authority() {
    let mut f = Fixture::new();
    let target = target(&f);
    let pending = GovernancePrepared::revoke(
        &f.context,
        [23; 32],
        target.clone(),
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let intent = Intent::from_signed(&pending.intent).unwrap();
    let p = wire::decode(&intent.parameters).unwrap();
    assert_eq!(
        p.array(6).unwrap()[5].array(2).unwrap()[0],
        point(f.store.prefix())
    );
    let output = value(&pending);
    let (reply, ancestry) = certified(
        &pending,
        output,
        f.current.observe().unwrap().wall_ms,
        &f.store,
        false,
    );
    let Outcome::Revoked(result) = pending
        .finish(reply, ancestry, &mut f.store, &mut f.session, &mut || {
            Ok(f.current)
        })
        .unwrap()
    else {
        panic!("revocation expected")
    };
    result.context.save(&f.store).unwrap();
    assert_eq!(result.reference.id, target.id);
    assert_eq!(result.reference.kind, 126);
    let loaded = ContextState::load(&f.bootstrap, &f.store, &f.directory.0).unwrap();
    assert!(
        loaded
            .governance
            .current_capability(
                [23; 32],
                &Requirement {
                    subject: f.signer.verifying_key().to_bytes(),
                    actions: &[25],
                    scope: (0, [20; 32]),
                    namespace: None,
                    usage: [0, 1, 0, 1],
                    evaluated_at_ms: f.current.observe().unwrap().wall_ms,
                    expected: &[]
                }
            )
            .is_err()
    );
    assert!(
        GovernancePrepared::revoke(
            &loaded,
            [23; 32],
            target,
            &f.signer,
            &mut f.store,
            &mut f.session,
            f.current
        )
        .is_err()
    );
    assert!(
        ContextState::retained(&f.bootstrap, &f.store, f.bootstrap.governance_records()).is_err()
    );
}

#[test]
fn revocation_rejects_wrong_target_snapshot_record_and_missing_tombstone_reference() {
    for case in 0..4 {
        let mut f = Fixture::new();
        let mut target = target(&f);
        if case == 0 {
            target.generation += 1;
            assert!(
                GovernancePrepared::revoke(
                    &f.context,
                    [23; 32],
                    target,
                    &f.signer,
                    &mut f.store,
                    &mut f.session,
                    f.issued
                )
                .is_err()
            );
            continue;
        }
        let pending = GovernancePrepared::revoke(
            &f.context,
            [23; 32],
            target,
            &f.signer,
            &mut f.store,
            &mut f.session,
            f.issued,
        )
        .unwrap();
        let mut output = value(&pending);
        let V::Array(fields) = &mut output else {
            unreachable!()
        };
        if case == 1 {
            let V::Array(refs) = &mut fields[3] else {
                unreachable!()
            };
            refs.pop();
        } else {
            let mut record = wire::decode(fields[4].bytes().unwrap()).unwrap();
            let V::Array(r) = &mut record else {
                unreachable!()
            };
            if case == 2 {
                r[7] = b(&SigningKey::from_bytes(&[50; 32]).verifying_key().to_bytes());
            } else {
                let V::Array(snapshot) = &mut r[8] else {
                    unreachable!()
                };
                let V::Array(point) = &mut snapshot[0] else {
                    unreachable!()
                };
                point[2] = b(&[99; 32]);
            }
            fields[4] = b(&wire::encode(&record).unwrap());
        }
        let (reply, ancestry) = certified(
            &pending,
            output,
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
        assert_eq!(f.store.prefix().height(), 1);
    }
}

#[test]
fn no_context_output_before_durable_floor_and_expired_results_do_not_release_records() {
    for damage in [false, true] {
        let mut f = Fixture::new();
        let pending = refresh(&mut f);
        let output = context_value(&pending, &f.context.governance);
        let (reply, ancestry) = certified(
            &pending,
            output,
            f.current.observe().unwrap().wall_ms,
            &f.store,
            false,
        );
        if damage {
            std::fs::write(f.directory.0.join("AuthorityFloor.json"), b"broken").unwrap();
        }
        let now = f.current.observe().unwrap();
        let health = if damage {
            f.current
        } else {
            ClockHealth::new(
                now.wall_ms + 6000,
                now.boot_ms + 6000,
                now.boot_ms + 10000,
                0,
            )
            .unwrap()
            .frozen()
        };
        assert!(
            pending
                .finish(reply, ancestry, &mut f.store, &mut f.session, &mut || Ok(
                    health
                ))
                .is_err()
        );
    }
}

#[test]
fn context_cache_corruption_and_write_failure_never_rewind_certified_floor() {
    let mut f = Fixture::new();
    let pending = refresh(&mut f);
    let original = pending.intent.clone();
    let output = context_value(&pending, &f.context.governance);
    let (reply, ancestry) = certified(
        &pending,
        output,
        f.current.observe().unwrap().wall_ms,
        &f.store,
        false,
    );
    std::fs::create_dir(f.directory.0.join(CACHE)).unwrap();
    assert!(
        pending
            .finish(reply, ancestry, &mut f.store, &mut f.session, &mut || Ok(
                f.current
            ))
            .is_err()
    );
    assert_eq!(f.store.prefix().height(), 2);
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        original
    );
    std::fs::remove_dir(f.directory.0.join(CACHE)).unwrap();
    // The original exact request survives the failed protected callback; no new mutation is created.
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
    let pending = refresh(&mut f);
    assert_eq!(pending.intent, original);
    let output = context_value(&pending, &f.context.governance);
    let (reply, ancestry) = certified(
        &pending,
        output,
        f.current.observe().unwrap().wall_ms,
        &f.store,
        false,
    );
    let Outcome::Context(context) = pending
        .finish(reply, ancestry, &mut f.store, &mut f.session, &mut || {
            Ok(f.current)
        })
        .unwrap()
    else {
        panic!("context expected")
    };
    assert!(f.store.resume_ordinary().unwrap().is_none());
    assert_eq!(
        ContextState::load(&f.bootstrap, &f.store, &f.directory.0)
            .unwrap()
            .governance
            .versions(),
        context.governance.versions()
    );
    std::fs::write(f.directory.0.join(CACHE), b"invalid").unwrap();
    assert!(ContextState::load(&f.bootstrap, &f.store, &f.directory.0).is_err());
    assert_eq!(f.store.prefix().height(), 3);
}

#[test]
fn interrupted_revocation_resumes_after_its_exact_tombstone_is_cached() {
    let mut f = Fixture::new();
    let parent = target(&f);
    let mut delegated = wire::decode(
        f.context
            .governance
            .record_bytes(parent.kind, parent.id)
            .unwrap(),
    )
    .unwrap();
    let V::Array(fields) = &mut delegated else {
        unreachable!()
    };
    fields[6] = b(&[24; 32]);
    fields[13] = version_value(&parent);
    fields[14] = V::Uint(7);
    fields[16] = a(vec![
        point(f.store.prefix()),
        a(vec![version_value(&parent)]),
    ]);
    let delegated = wire::encode(&delegated).unwrap();
    let target = VersionRef {
        kind: 102,
        id: [24; 32],
        generation: 1,
        digest: wire::digest(&delegated),
    };
    let mut entries = records(&f.context.governance).unwrap();
    entries.push(delegated);
    entries.sort_by_key(|bytes| {
        let value = wire::decode(bytes).unwrap();
        let fields = value.list(32).unwrap();
        (
            fields[0].uint().unwrap(),
            fields[6].fixed::<32>().unwrap_or([0; 32]),
        )
    });
    let governance = Governance::parse([20; 32], [21; 32], &entries).unwrap();
    let pending = refresh(&mut f);
    let (reply, ancestry) = certified(
        &pending,
        context_value(&pending, &governance),
        f.current.observe().unwrap().wall_ms,
        &f.store,
        false,
    );
    let Outcome::Context(context) = pending
        .finish(reply, ancestry, &mut f.store, &mut f.session, &mut || {
            Ok(f.current)
        })
        .unwrap()
    else {
        panic!("context expected")
    };
    f.context = *context;
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
    let pending = GovernancePrepared::revoke(
        &f.context,
        [23; 32],
        target.clone(),
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
    let verified = proof::verify_response(
        &pending.descriptor,
        proof::ProofContext {
            intent: &pending.intent,
            challenge: &pending.challenge,
            restrictions: Restrictions::default(),
            minimum_height: f.store.prefix().height(),
            maximum_effect: 1,
            expected_stream: None,
        },
        proof::Response {
            ordered_request: &pending.ordered,
            operation_result: &reply.result,
            certificate: &reply.certificate,
            ancestry: &ancestry,
        },
        |i, r, e| pending.validate(i, r, e),
    )
    .unwrap();
    let candidate = pending
        .candidate(
            verified.request().ordinary().unwrap(),
            &verified.result,
            &verified.executed,
        )
        .unwrap();
    let permit = f
        .store
        .accept(verified, &mut f.session, f.current, candidate.not_before)
        .unwrap();
    // The callback's error leaves the same durable files as a stop after cache publication.
    let interrupted: Result<()> = permit.perform(
        &mut f.store,
        &mut f.session,
        f.current,
        1,
        |_| Ok(()),
        |_, store| {
            ContextState {
                descriptor: pending.descriptor.clone(),
                governance: candidate.governance.unwrap(),
            }
            .save(store)?;
            bail!("interrupted after governance cache publication")
        },
    );
    assert!(interrupted.is_err());
    let descriptor = f.bootstrap.descriptor().clone();
    drop(pending);
    drop(f.store);
    f.store = Store::open(&f.directory.0, descriptor).unwrap();
    f.session = Session::new().unwrap();
    f.context = ContextState::load(&f.bootstrap, &f.store, &f.directory.0).unwrap();
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        original
    );
    assert!(
        f.context
            .governance
            .versions()
            .iter()
            .any(|v| v.kind == 126 && v.id == target.id)
    );
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
    let pending = GovernancePrepared::revoke(
        &f.context,
        [23; 32],
        target.clone(),
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
    let Outcome::Revoked(result) = pending
        .finish(reply, ancestry, &mut f.store, &mut f.session, &mut || {
            Ok(f.current)
        })
        .unwrap()
    else {
        panic!("revocation expected")
    };
    assert_eq!(result.reference.id, target.id);
    assert!(f.store.resume_ordinary().unwrap().is_none());
    assert_eq!(f.store.prefix().height(), 4);
}

#[test]
fn context_constructor_is_bounded_and_does_not_raise_ordinary_action_limit() {
    let refs = (1..=65)
        .map(|n| VersionRef {
            kind: 102,
            id: [n; 32],
            generation: 1,
            digest: [n; 32],
        })
        .collect::<Vec<_>>();
    assert!(ActionValidation::new(refs.clone()).is_err());
    assert!(ActionValidation::governance_context(refs).is_err());
    assert!(
        ActionValidation::governance_context(vec![VersionRef {
            kind: 104,
            id: [1; 32],
            generation: 1,
            digest: [2; 32]
        }])
        .is_err()
    );
}

#[path = "AuthorityContextPagingTests.rs"]
mod paging_tests;
