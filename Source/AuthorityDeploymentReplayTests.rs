// SPDX-License-Identifier: MIT
// Deployment result metadata names the first commit independently of relay bookkeeping.
use super::*;

#[test]
fn deployment_creation_height_distinguishes_delayed_execution_from_uncached_replay() {
    let mut f = fixture();
    let context = discover(&mut f);
    let offer = offer_for(&f);
    let mut p = Prepared::new(
        &f.bootstrap,
        Request::Register {
            grant: context.version(102, [23; 32]).unwrap(),
            offer,
        },
        Some(&context),
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let intent = Intent::from_signed(&p.intent).unwrap();
    let operation = Operation::parse(&intent).unwrap();
    let decision = operation
        .authorise(
            &p.source,
            &Reservations(f.bootstrap.reservations().to_vec()),
            &intent,
            f.current.observe().unwrap().wall_ms,
            false,
            None,
        )
        .unwrap();
    assert_eq!(decision.code, 0);
    let (reply, _) = certified(
        &p,
        decision.value,
        f.current.observe().unwrap().wall_ms,
        &f.store,
    );
    let mut executed =
        ExecutedResult::parse(&p.descriptor.quorum(&reply.certificate).unwrap()).unwrap();
    let result = OperationResult::parse(&reply.result).unwrap();
    let mut fields = wire::decode(&result.value)
        .unwrap()
        .array(6)
        .unwrap()
        .to_vec();
    executed.height += 3;
    fields[5] = V::Uint(executed.height);
    let result = |fields: Vec<V>| OperationResult {
        action: intent.action.clone(),
        disposition: Disposition::Permit,
        code: 0,
        value: wire::encode(&a(fields)).unwrap(),
    };
    assert!(
        p.candidate(&intent, &result(fields.clone()), &executed)
            .is_ok()
    );
    for invalid in [
        V::Uint(0),
        V::Uint(intent.minimum_policy_height),
        V::Uint(executed.height + 1),
        V::Bool(true),
        V::Null,
    ] {
        let mut malformed = fields.clone();
        malformed[5] = invalid;
        assert!(p.candidate(&intent, &result(malformed), &executed).is_err());
    }
    assert!(
        p.candidate(&intent, &result(fields[..5].to_vec()), &executed)
            .is_err()
    );
    let mut extra = fields.clone();
    extra.push(V::Null);
    assert!(p.candidate(&intent, &result(extra), &executed).is_err());
    let source = p.source.clone();
    let created = operation.derive(&intent).unwrap();
    assert!(created.iter().all(|record| !p.source.contains(record)));
    p.source.extend(created);
    membership::sort_records(&mut p.source).unwrap();
    assert!(
        p.candidate(&intent, &result(fields.clone()), &executed)
            .is_err()
    );
    executed.height += 1;
    assert!(
        p.candidate(&intent, &result(fields.clone()), &executed)
            .is_ok()
    );
    p.source = source;
    assert!(p.candidate(&intent, &result(fields), &executed).is_ok());
}
