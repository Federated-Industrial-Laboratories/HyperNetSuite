// SPDX-License-Identifier: MIT
// Discovery resumes a certified records view without exposing partial governance.
use super::*;

fn page_request(f: &mut Fixture) -> GovernancePrepared<'static> {
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
    refresh(f)
}

fn large_governance(f: &Fixture) -> Governance {
    let mut entries = records(&f.context.governance).unwrap();
    let template = entries
        .iter()
        .find(|r| wire::decode(r).unwrap().list(32).unwrap()[0] == V::Uint(101))
        .unwrap()
        .clone();
    for index in 0u64..140 {
        let V::Array(mut fields) = wire::decode(&template).unwrap() else {
            unreachable!()
        };
        let mut id = [223; 32];
        id[24..].copy_from_slice(&index.to_be_bytes());
        fields[6] = b(&id);
        entries.push(wire::encode(&V::Array(fields)).unwrap());
    }
    crate::authority_membership::sort_records(&mut entries).unwrap();
    Governance::parse([20; 32], [21; 32], &entries).unwrap()
}
#[test]
fn paged_discovery_resumes_from_private_assembly_without_publishing_partial_context() {
    let mut f = Fixture::new();
    let governance = large_governance(&f);
    let pending = page_request(&mut f);
    let output = context_value(&pending, &governance);
    let (reply, ancestry) = certified(
        &pending,
        output,
        f.current.observe().unwrap().wall_ms,
        &f.store,
        false,
    );
    assert!(matches!(
        pending
            .finish(reply, ancestry, &mut f.store, &mut f.session, &mut || Ok(
                f.current
            ))
            .unwrap(),
        Outcome::Page
    ));
    assert!(ContextState::load(&f.bootstrap, &f.store, &f.directory.0).is_err());
    let retained = paging::Pages::load(f.bootstrap.descriptor(), [23; 32], &f.store)
        .unwrap()
        .unwrap();
    assert_eq!(retained.entries.len(), 64);
    let mut finished = None;
    for _ in 0..3 {
        let pending = page_request(&mut f);
        let parameters =
            wire::decode(&Intent::from_signed(&pending.intent).unwrap().parameters).unwrap();
        assert_ne!(parameters.array(6).unwrap()[5], V::Null);
        let (reply, ancestry) = certified(
            &pending,
            context_value(&pending, &governance),
            f.current.observe().unwrap().wall_ms,
            &f.store,
            false,
        );
        match pending
            .finish(reply, ancestry, &mut f.store, &mut f.session, &mut || {
                Ok(f.current)
            })
            .unwrap()
        {
            Outcome::Context(context) => {
                finished = Some(context);
                break;
            }
            Outcome::Page => (),
            _ => panic!("unexpected discovery result"),
        }
    }
    assert_eq!(
        finished.unwrap().governance.versions(),
        governance.versions()
    );
    assert_eq!(
        ContextState::load(&f.bootstrap, &f.store, &f.directory.0)
            .unwrap()
            .governance
            .versions(),
        governance.versions()
    );
}
#[test]
fn page_cursor_root_and_early_terminal_changes_fail_before_floor() {
    for case in 0..3 {
        let mut f = Fixture::new();
        let governance = large_governance(&f);
        let pending = page_request(&mut f);
        let (reply, ancestry) = certified(
            &pending,
            context_value(&pending, &governance),
            f.current.observe().unwrap().wall_ms,
            &f.store,
            false,
        );
        assert!(matches!(
            pending
                .finish(reply, ancestry, &mut f.store, &mut f.session, &mut || Ok(
                    f.current
                ))
                .unwrap(),
            Outcome::Page
        ));
        let pending = page_request(&mut f);
        let mut output = context_value(&pending, &governance);
        let V::Array(fields) = &mut output else {
            unreachable!()
        };
        let V::Array(body) = &mut fields[4] else {
            unreachable!()
        };
        match case {
            0 => body[0] = b(&[99; 32]),
            1 => body[2] = V::Uint(65),
            _ => body[3] = V::Null,
        }
        let height = f.store.prefix().height();
        let (reply, ancestry) = certified(
            &pending,
            output,
            f.current.observe().unwrap().wall_ms,
            &f.store,
            false,
        );
        assert!(ContextState::restart_discovery(&f.store).is_err());
        assert!(
            pending
                .finish(reply, ancestry, &mut f.store, &mut f.session, &mut || Ok(
                    f.current
                ))
                .is_err()
        );
        assert_eq!(f.store.prefix().height(), height);
    }
}

#[test]
fn final_page_cache_failure_resumes_the_same_request_after_staging_completed() {
    let mut f = Fixture::new();
    let governance = large_governance(&f);
    for _ in 0..2 {
        let pending = page_request(&mut f);
        let (reply, ancestry) = certified(
            &pending,
            context_value(&pending, &governance),
            f.current.observe().unwrap().wall_ms,
            &f.store,
            false,
        );
        assert!(matches!(
            pending
                .finish(reply, ancestry, &mut f.store, &mut f.session, &mut || Ok(
                    f.current
                ))
                .unwrap(),
            Outcome::Page
        ));
    }
    let pending = page_request(&mut f);
    let original = pending.intent.clone();
    let (reply, ancestry) = certified(
        &pending,
        context_value(&pending, &governance),
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
    assert!(
        paging::Pages::load(f.bootstrap.descriptor(), [23; 32], &f.store)
            .unwrap()
            .unwrap()
            .complete()
    );
    assert!(ContextState::restart_discovery(&f.store).is_err());
    std::fs::remove_dir(f.directory.0.join(CACHE)).unwrap();
    let pending = page_request(&mut f);
    assert_eq!(pending.intent, original);
    let (reply, ancestry) = certified(
        &pending,
        context_value(&pending, &governance),
        f.current.observe().unwrap().wall_ms,
        &f.store,
        false,
    );
    assert!(matches!(
        pending
            .finish(reply, ancestry, &mut f.store, &mut f.session, &mut || Ok(
                f.current
            ))
            .unwrap(),
        Outcome::Context(_)
    ));
    assert!(f.store.resume_ordinary().unwrap().is_none());
    ContextState::restart_discovery(&f.store).unwrap();
    assert!(
        paging::Pages::load(f.bootstrap.descriptor(), [23; 32], &f.store)
            .unwrap()
            .is_none()
    );
}
