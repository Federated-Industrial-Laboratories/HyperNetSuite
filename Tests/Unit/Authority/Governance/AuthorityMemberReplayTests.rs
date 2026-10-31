// SPDX-License-Identifier: MIT
// A certified creation height separates delayed first execution from retained replay.
use super::*;

#[test]
fn membership_creation_height_preserves_first_execution_checks_and_uncached_replay() {
    let mut f = Fixture::new();
    let candidate = SigningKey::from_bytes(&[42; 32]);
    delegate(&mut f, &candidate);
    let offered = member_offer::Offer::parse(
        &f.bootstrap,
        &offer_with_lifetime(&f, DURATION + crate::authority_governance::UNCERTAINTY_MS),
        false,
    )
    .unwrap();
    let accepted = offered.accept(&f.bootstrap, &candidate, None).unwrap();
    let accepted = member_offer::Offer::parse(&f.bootstrap, &accepted, true)
        .unwrap()
        .envelope;
    let pending = GovernancePrepared::member(
        &f.context,
        MemberRequest {
            bootstrap: &f.bootstrap,
            mutation: MemberMutation::Admit {
                grant: [23; 32],
                accepted,
            },
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
    let mut executed =
        ExecutedResult::parse(&pending.descriptor.quorum(&reply.certificate).unwrap()).unwrap();
    let Mode::Member(member) = &pending.mode else {
        panic!("member mutation")
    };
    let mut fields = value(&pending).array(6).unwrap().to_vec();
    let versions = parse_versions(&fields[3]).unwrap();
    let creation_height = executed.height + 3;
    executed.height = creation_height;
    fields[5] = V::Uint(creation_height);
    let result = |fields: Vec<V>| OperationResult {
        action: intent.action.clone(),
        disposition: Disposition::Permit,
        code: 0,
        value: wire::encode(&a(fields)).unwrap(),
    };
    assert!(
        member
            .candidate(&intent, &result(fields.clone()), &executed, &versions)
            .is_ok()
    );
    for invalid in [
        V::Uint(0),
        V::Uint(intent.minimum_policy_height),
        V::Uint(creation_height + 1),
        V::Bool(true),
        V::Null,
    ] {
        let mut malformed = fields.clone();
        malformed[5] = invalid;
        assert!(
            member
                .candidate(&intent, &result(malformed), &executed, &versions)
                .is_err()
        );
    }
    assert!(
        member
            .candidate(&intent, &result(fields[..5].to_vec()), &executed, &versions)
            .is_err()
    );
    let mut extra = fields.clone();
    extra.push(V::Null);
    assert!(
        member
            .candidate(&intent, &result(extra), &executed, &versions)
            .is_err()
    );

    let mut entries = records(&member.context.governance).unwrap();
    entries.push(member.created.clone());
    crate::authority_membership::sort_records(&mut entries).unwrap();
    let cached_context = ContextState {
        descriptor: member.context.descriptor.clone(),
        governance: Governance::parse(intent.network, intent.incarnation, &entries).unwrap(),
    };
    let cached = MemberPrepared {
        context: &cached_context,
        action: member.action,
        mutation: member.mutation.clone(),
        reservations: member.reservations.clone(),
        reference: member.reference.clone(),
        created: member.created.clone(),
        receipt: None,
    };
    assert!(
        cached
            .candidate(&intent, &result(fields.clone()), &executed, &versions)
            .is_err()
    );

    let Mutation::Admit { acceptance, .. } = &member.mutation else {
        panic!("admission")
    };
    executed.evaluated_at_ms = acceptance.acceptance_validity.1 + 1000;
    // The delayed first commit still requires an unexpired acceptance.
    assert!(
        member
            .candidate(&intent, &result(fields.clone()), &executed, &versions)
            .is_err()
    );
    // A later certificate discloses the same original result even without a local cache.
    executed.height += 1;
    assert!(
        !member
            .context
            .governance
            .versions()
            .contains(&member.reference)
    );
    assert!(
        member
            .candidate(&intent, &result(fields.clone()), &executed, &versions)
            .is_ok()
    );
    assert!(
        cached
            .candidate(&intent, &result(fields), &executed, &versions)
            .is_ok()
    );
}
