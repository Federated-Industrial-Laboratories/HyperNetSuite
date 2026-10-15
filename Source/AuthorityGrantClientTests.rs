// SPDX-License-Identifier: MIT
// A certified preview does not create a grant; apply retains the exact separately reviewed mutation.
use super::super::tests::certified;
use super::*;
use crate::authority_inspection::tests::Fixture;
fn proposal(f: &Fixture) -> Proposal {
    let parent = f.context.version(102, [23; 32]).unwrap();
    let tier = f.context.grant_tier(parent.id).unwrap();
    let record = wire::decode(f.context.governance.record_bytes(102, parent.id).unwrap()).unwrap();
    let child = a(vec![
        b(&[24; 32]),
        b(&SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes()),
        version_value(&tier),
        a(vec![V::Uint(0)]),
        a(vec![a(vec![V::Uint(0), b(&[20; 32])])]),
        record.array(17).unwrap()[12].clone(),
        V::Uint(0),
        a(vec![V::Uint(0), V::Uint(1), V::Uint(0), V::Uint(1)]),
    ]);
    delegate(
        &f.context,
        &f.bootstrap,
        &f.store,
        parent,
        child,
        f.current.observe().unwrap().wall_ms,
    )
    .unwrap()
}
fn pending<'a>(f: &mut Fixture, proposal: Proposal, apply: bool) -> GovernancePrepared<'a> {
    let proposal = proposal.rebased(&f.store).unwrap();
    let token = apply.then_some([70; 32]);
    let prepared = Prepared {
        proposal: proposal.clone(),
        token,
        apply,
        source: records(&f.context.governance).unwrap(),
        reservations: Reservations(f.bootstrap.reservations().to_vec()),
    };
    let canonical = wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text(prepared.action().into()),
        b(&proposal.parameters),
        token.map_or(V::Null, |v| b(&v)),
    ]))
    .unwrap();
    GovernancePrepared::new(
        Parameters {
            descriptor: f.store.descriptor().clone(),
            grant: proposal.grant,
            mode: Mode::Grant(prepared),
            expected: proposal.expected,
            canonical,
        },
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap()
}
fn preview(pending: &GovernancePrepared) -> V {
    let intent = Intent::from_signed(&pending.intent).unwrap();
    let reviewed = review::Operation::parse(&intent).unwrap();
    a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityGrantPreview".into()),
        a(intent.expected.iter().map(version_value).collect()),
        a(vec![
            b(&reviewed.request_digest().unwrap()),
            b(&[70; 32]),
            b(&wire::digest(&wire::encode_state(&a(vec![])).unwrap())),
            V::Uint(0),
            V::Uint(0),
            a(vec![]),
            V::Null,
        ]),
    ])
}
#[test]
fn certified_preview_does_not_create_and_apply_keeps_exact_proposal() {
    let mut f = Fixture::new();
    let proposal = proposal(&f);
    let prepared = pending(&mut f, proposal.clone(), false);
    let (reply, ancestry) = certified(
        &prepared,
        preview(&prepared),
        f.current.observe().unwrap().wall_ms,
        &f.store,
        false,
    );
    assert!(matches!(
        prepared
            .finish(reply, ancestry, &mut f.store, &mut f.session, &mut || Ok(
                f.current
            ))
            .unwrap(),
        Outcome::Grant(_)
    ));
    assert!(
        !f.store
            .generations()
            .iter()
            .any(|r| r.kind == 102 && r.id == [24; 32])
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
    let prepared = pending(&mut f, proposal, true);
    let intent = Intent::from_signed(&prepared.intent).unwrap();
    let inner = review::Operation::parse(&intent).unwrap().inner;
    let created = Mutation::parse(&inner).unwrap().derive(&inner).unwrap();
    let reference = VersionRef {
        kind: 102,
        id: [24; 32],
        generation: 1,
        digest: wire::digest(&created),
    };
    let mut refs = intent.expected.clone();
    refs.push(reference.clone());
    refs.sort_by_key(VersionRef::index);
    let result = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityGrantApply".into()),
        a(refs.iter().map(version_value).collect()),
        b(&created),
        V::Uint(f.store.prefix().height() + 1),
    ]);
    let (reply, ancestry) = certified(
        &prepared,
        result,
        f.current.observe().unwrap().wall_ms,
        &f.store,
        false,
    );
    assert!(matches!(
        prepared
            .finish(reply, ancestry, &mut f.store, &mut f.session, &mut || Ok(
                f.current
            ))
            .unwrap(),
        Outcome::Grant(_)
    ));
    assert!(f.store.generations().contains(&reference));
}
#[test]
fn certified_preview_with_another_proposal_digest_is_rejected() {
    let mut f = Fixture::new();
    let proposal = proposal(&f);
    let prepared = pending(&mut f, proposal, false);
    let mut value = preview(&prepared).array(5).unwrap().to_vec();
    let mut body = value[4].array(7).unwrap().to_vec();
    body[0] = b(&[90; 32]);
    value[4] = a(body);
    let (reply, ancestry) = certified(
        &prepared,
        a(value),
        f.current.observe().unwrap().wall_ms,
        &f.store,
        false,
    );
    assert!(
        prepared
            .finish(reply, ancestry, &mut f.store, &mut f.session, &mut || Ok(
                f.current
            ))
            .is_err()
    );
    assert!(
        !f.store
            .generations()
            .iter()
            .any(|r| r.kind == 102 && r.id == [24; 32])
    );
}
