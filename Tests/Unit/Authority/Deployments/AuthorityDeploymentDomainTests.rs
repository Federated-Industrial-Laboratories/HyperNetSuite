// SPDX-License-Identifier: MIT
// Domain operations resume after deployment updates only with exact certified successor metadata.
use super::*;
use crate::authority_inspection::{ContextState, domain_client};

fn updated_fixture() -> (Fixture, Vec<Vec<u8>>, Cache) {
    let mut f = fixture();
    let context = discover(&mut f);
    let initial = offer_for_roles(&f, &[1]);
    let state = register(&mut f, &context, initial.clone());
    let governance = ContextState::retained(
        &f.bootstrap,
        &f.store,
        &merged(&f.bootstrap, &state.entries).unwrap(),
    )
    .unwrap();
    domain_client::Cache::retain_context(&f.bootstrap, &f.store, &governance).unwrap();
    let prior = domain_client::Cache::load(&f.bootstrap, &f.store)
        .unwrap()
        .records;
    let mut manifest = initial.manifest.clone();
    manifest.generation = 2;
    manifest.previous_profile = Some(wire::digest(&initial.manifest.desired().unwrap()));
    manifest.previous_consent = Some(wire::digest(&initial.manifest.unsigned_consent(0).unwrap()));
    manifest.validity.1 = f.current.observe().unwrap().wall_ms + 3600000;
    let consent = wire::sign_envelope(
        &manifest.unsigned_consent(0).unwrap(),
        &crate::authority_deployment_tests::key(90),
    )
    .unwrap();
    let successor = Offer::parse(&manifest.encode().unwrap(), &consent, &a(vec![])).unwrap();
    let current = register(&mut f, &state, successor);
    (f, prior, current)
}

#[test]
fn domain_cache_reopens_with_certified_deployment_successors() {
    let (mut f, prior, current) = updated_fixture();
    assert!(
        versions(f.store.descriptor().scope(), &prior)
            .unwrap()
            .iter()
            .any(|r| !f.store.generations().contains(r))
    );
    drop(f.store);
    f.store = Store::open(&f.directory.0, f.bootstrap.descriptor().clone()).unwrap();
    let refreshed = domain_client::Cache::load(&f.bootstrap, &f.store).unwrap();
    let refs = versions(f.store.descriptor().scope(), &refreshed.records).unwrap();
    for kind in [105, 117, 129] {
        assert!(refs.contains(&current.version(kind, [60; 32]).unwrap()));
    }
    for r in versions(f.store.descriptor().scope(), &prior).unwrap() {
        if !matches!(r.kind, 105 | 117 | 129) {
            assert!(refs.contains(&r));
        }
    }
    assert!(refreshed.state.records.is_empty());
    assert!(f.store.resume_ordinary().unwrap().is_none());
}

#[test]
fn domain_cache_refuses_missing_or_altered_successor_evidence() {
    let (f, _, _) = updated_fixture();
    let path = f
        .directory
        .0
        .join(format!("DeploymentState{}.cbor", hex::encode([60; 32])));
    let exact = std::fs::read(&path).unwrap();
    let absent = path.with_extension("Absent");
    std::fs::rename(&path, &absent).unwrap();
    assert!(domain_client::Cache::load(&f.bootstrap, &f.store).is_err());
    std::fs::rename(&absent, &path).unwrap();
    let mut value = wire::decode(&exact).unwrap();
    let V::Array(fields) = &mut value else {
        panic!("cache");
    };
    fields[7] = b(b"altered manifest");
    std::fs::write(&path, wire::encode(&value).unwrap()).unwrap();
    assert!(domain_client::Cache::load(&f.bootstrap, &f.store).is_err());
    std::fs::write(&path, exact).unwrap();
    assert!(domain_client::Cache::load(&f.bootstrap, &f.store).is_ok());
}
