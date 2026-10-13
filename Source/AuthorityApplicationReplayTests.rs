// SPDX-License-Identifier: MIT
// Original commit metadata preserves fresh consent checks after unrelated authority orders.
use super::*;

#[test]
fn application_creation_height_distinguishes_delayed_execution_from_uncached_replay() {
    let mut f = Fixture::new();
    let app = SigningKey::from_bytes(&[41; 32]);
    let context = delegated(&mut f, &app);
    let offer = offered(&f, &context, 300000);
    let accepted = offer.accept(&f.bootstrap, &app, None).unwrap();
    let accepted = application_offer::Offer::parse(&f.bootstrap, &accepted, true)
        .unwrap()
        .acceptance
        .envelope;
    let mut p = Prepared::new(
        &f.bootstrap,
        Request::Register {
            parent: context.version(102, [23; 32]).unwrap(),
            accepted,
        },
        Some(&context),
        None,
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
    let created = operation.derive(&intent).unwrap().unwrap();
    assert!(!p.source.contains(&created));
    p.source.push(created.clone());
    membership::sort_records(&mut p.source).unwrap();
    // A retained record cannot turn a claimed first execution into a replay.
    assert!(
        p.candidate(&intent, &result(fields.clone()), &executed)
            .is_err()
    );
    executed.height += 1;
    assert!(
        p.candidate(&intent, &result(fields.clone()), &executed)
            .is_ok()
    );
    p.source.retain(|record| record != &created);
    assert!(p.candidate(&intent, &result(fields), &executed).is_ok());
}
