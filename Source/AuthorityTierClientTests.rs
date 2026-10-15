// SPDX-License-Identifier: MIT
// Certified tier edits repair retained governance without trusting an unauthenticated replacement.
use super::super::tests::certified;
use super::*;
use crate::authority_inspection::tests::Fixture;

fn rank_edit(f: &mut Fixture) -> (GovernancePrepared<'static>, V, VersionRef) {
    let scope = f.bootstrap.descriptor().scope();
    let previous = f
        .context
        .governance
        .record_bytes(101, f.context.grant_tier([23; 32]).unwrap().id)
        .unwrap()
        .to_vec();
    let (mut spec, old) = Spec::from_record(&previous, scope.network, scope.incarnation).unwrap();
    spec.rank += 1;
    let mut tier = Prepared {
        request: Request::Change {
            previous: Some(previous),
            spec: Box::new(spec),
            expected: vec![],
            token: Some([70; 32]),
            apply: true,
        },
        grant: [23; 32],
        network: scope.network,
        incarnation: scope.incarnation,
        source: records(&f.context.governance).unwrap(),
    };
    let expected = tier
        .permission(
            &tier.source,
            f.store.requester(),
            f.current.observe().unwrap().wall_ms,
        )
        .unwrap()
        .0;
    if let Request::Change {
        expected: reviewed, ..
    } = &mut tier.request
    {
        *reviewed = expected.clone();
    }
    let canonical = tier.parameters(&f.store).unwrap();
    let prepared = GovernancePrepared::new(
        Parameters {
            descriptor: f.store.descriptor().clone(),
            grant: tier.grant,
            mode: Mode::Tier(tier),
            expected: expected.clone(),
            canonical,
        },
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let intent = Intent::from_signed(&prepared.intent).unwrap();
    let created = tiers::Operation::parse(&intent)
        .unwrap()
        .derive(&intent)
        .unwrap()
        .unwrap();
    let reference = tiers::record_reference(&created, scope.network, scope.incarnation).unwrap();
    let mut versions = expected;
    versions.retain(|r| r.index() != old.index());
    versions.push(reference.clone());
    versions.sort_by_key(VersionRef::index);
    let result = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityTierApply".into()),
        a(versions.iter().map(version_value).collect()),
        b(&created),
        V::Uint(f.store.prefix().height() + 1),
    ]);
    (prepared, result, reference)
}

#[test]
fn certified_rank_edit_crosses_floor_advance_and_retains_exact_successor() {
    let mut f = Fixture::new();
    let (prepared, result, reference) = rank_edit(&mut f);
    let created = result.array(6).unwrap()[4].bytes().unwrap().to_vec();
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
        Outcome::Tier(_)
    ));
    assert!(f.store.generations().contains(&reference));
    assert!(f.store.resume_ordinary().unwrap().is_none());
    let retained = load(&f.bootstrap, &f.store).unwrap();
    let scope = f.bootstrap.descriptor().scope();
    let governance = Governance::parse(scope.network, scope.incarnation, &retained).unwrap();
    assert_eq!(governance.record_bytes(101, reference.id).unwrap(), created);
}

#[test]
fn certified_tier_result_cannot_substitute_another_successor() {
    let mut f = Fixture::new();
    let (prepared, result, reference) = rank_edit(&mut f);
    let mut result = result.array(6).unwrap().to_vec();
    let mut created = wire::decode(result[4].bytes().unwrap())
        .unwrap()
        .array(14)
        .unwrap()
        .to_vec();
    created[7] = V::Uint(created[7].uint().unwrap() + 1);
    let created = wire::encode(&a(created)).unwrap();
    let substituted = VersionRef {
        digest: wire::digest(&created),
        ..reference.clone()
    };
    let mut versions = parse_versions(&result[3]).unwrap();
    *versions
        .iter_mut()
        .find(|r| r.index() == reference.index())
        .unwrap() = substituted.clone();
    result[3] = a(versions.iter().map(version_value).collect());
    result[4] = b(&created);
    let (reply, ancestry) = certified(
        &prepared,
        a(result),
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
    assert!(!f.store.generations().contains(&reference));
    assert!(!f.store.generations().contains(&substituted));
}

#[test]
fn cached_tier_edit_uses_only_the_exact_certified_successor() {
    let f = Fixture::new();
    let s = f.bootstrap.descriptor().scope();
    let original = f.bootstrap.governance_records().to_vec();
    let old = original
        .iter()
        .find(|bytes| wire::decode(bytes).unwrap().list(20).unwrap()[0] == V::Uint(101))
        .unwrap();
    let mut fields = wire::decode(old).unwrap().array(14).unwrap().to_vec();
    fields[4] = V::Uint(2);
    fields[5] = b(&wire::digest(old));
    fields[7] = V::Uint(fields[7].uint().unwrap() + 1);
    fields[13] = a(vec![point(f.store.prefix()), a(vec![])]);
    let current = wire::encode(&a(fields.clone())).unwrap();
    let version = tiers::record_reference(&current, s.network, s.incarnation).unwrap();
    let mut cached = original.clone();
    merge_cached_tiers(
        s.network,
        s.incarnation,
        &[],
        std::slice::from_ref(&current),
        &mut cached,
    )
    .unwrap();
    assert_eq!(cached, original);
    merge_cached_tiers(
        s.network,
        s.incarnation,
        std::slice::from_ref(&version),
        std::slice::from_ref(&current),
        &mut cached,
    )
    .unwrap();
    let parsed = Governance::parse(s.network, s.incarnation, &cached).unwrap();
    assert_eq!(parsed.record_bytes(101, version.id).unwrap(), current);
    for bytes in &original {
        let refs =
            Governance::record_versions(s.network, s.incarnation, std::slice::from_ref(bytes))
                .unwrap();
        if refs[0].kind != 101 {
            assert!(cached.contains(bytes));
        }
    }
    fields[7] = V::Uint(fields[7].uint().unwrap() + 1);
    let conflicting = wire::encode(&a(fields)).unwrap();
    cached.retain(|bytes| bytes != &current);
    cached.push(conflicting);
    crate::authority_membership::sort_records(&mut cached).unwrap();
    assert!(
        merge_cached_tiers(
            s.network,
            s.incarnation,
            &[version],
            &[current],
            &mut cached
        )
        .is_err()
    );
}
