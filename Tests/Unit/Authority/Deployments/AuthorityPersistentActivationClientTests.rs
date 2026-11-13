// SPDX-License-Identifier: MIT
// Persistent activation follows certified context reads and retains the exact manager request.
use super::*;

#[test]
fn persistent_activation_after_context_preserves_exact_request_on_reopen() {
    let (authority, records, _, manager) =
        crate::authority_deployment_tests::persistent_activation_manager();
    let bootstrap = crate::trust_bootstrap::check(&authority.bootstrap, true, 5000).unwrap();
    let mut f =
        Fixture::with_bootstrap(bootstrap, crate::authority_deployment_tests::key(80), 5000);
    let context = Prepared::new(
        &f.bootstrap,
        Request::Context {
            grant: manager.id,
            deployment: [60; 32],
        },
        None,
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let intent = Intent::from_signed(&context.intent).unwrap();
    assert_eq!(intent.sequence, 1);
    assert_eq!(intent.acknowledged_through, 0);
    let decision = Operation::parse(&intent)
        .unwrap()
        .authorise(
            &records,
            &authority.reservations,
            &intent,
            f.current.observe().unwrap().wall_ms,
            false,
            None,
        )
        .unwrap();
    assert_eq!(decision.code, 0);
    let (reply, evidence) = certified(
        &context,
        decision.value,
        f.current.observe().unwrap().wall_ms,
        &f.store,
    );
    context
        .finish(reply, evidence, &mut f.store, &mut f.session, &mut || {
            Ok(f.current)
        })
        .unwrap();
    assert!(f.store.resume_ordinary().unwrap().is_none());
    advance(&mut f, 2000);
    let cache = Cache::load(&f.bootstrap, &f.store, [60; 32], Some(manager.id)).unwrap();
    let request = activation_client::prepare_persistent(
        &f.bootstrap,
        &cache,
        &f.signer,
        &mut f.store,
        8,
        1,
        f.current,
    )
    .unwrap();
    assert!(request.persistent());
    assert_eq!(request.intent().generation, 1);
    assert_eq!(request.intent().sequence, 2);
    assert_eq!(request.intent().acknowledged_through, 1);
    let encoded = request.encode().unwrap();
    let floor = std::fs::read(f.directory.0.join("AuthorityFloor.json")).unwrap();
    let pending = f.store.resume_ordinary().unwrap().unwrap();
    assert_eq!(pending.signed(), request.signed());
    drop(f.store);
    f.store = Store::open(&f.directory.0, f.bootstrap.descriptor().clone()).unwrap();
    let cache = Cache::load(&f.bootstrap, &f.store, [60; 32], Some(manager.id)).unwrap();
    let retried = activation_client::prepare_persistent(
        &f.bootstrap,
        &cache,
        &f.signer,
        &mut f.store,
        8,
        1,
        f.current,
    )
    .unwrap();
    assert_eq!(retried.encode().unwrap(), encoded);
    assert_eq!(retried.intent().digest, request.intent().digest);
    for (role, generation) in [(7, 1), (8, 2)] {
        assert!(
            activation_client::prepare_persistent(
                &f.bootstrap,
                &cache,
                &f.signer,
                &mut f.store,
                role,
                generation,
                f.current,
            )
            .is_err()
        );
    }
    assert!(
        Prepared::new(
            &f.bootstrap,
            Request::Context {
                grant: manager.id,
                deployment: [60; 32],
            },
            Some(&cache),
            &f.signer,
            &mut f.store,
            &mut f.session,
            f.current,
        )
        .is_err()
    );
    assert_eq!(
        std::fs::read(f.directory.0.join("AuthorityFloor.json")).unwrap(),
        floor
    );
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        request.signed()
    );
}
