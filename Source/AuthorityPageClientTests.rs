// SPDX-License-Identifier: MIT
// Interrupted multi-record Page publication retains the original request and exact source identity.
use super::super::tests::{Fixture, certified_request};
use super::*;
use crate::{
    authority_domains::page::{self, Command as PageCommand, objects::Author},
    authority_objects::Resolved,
};

fn current_clocks() -> (ClockHealth, ClockHealth) {
    let boot = boot_time_ms().unwrap();
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    let issued = ClockHealth::new(wall, boot, boot + 30000, 100)
        .unwrap()
        .frozen();
    // Exercise the effect strictly inside its conservative absolute interval.
    let elapsed = crate::authority_challenge::DELTA_MS + 1;
    assert!(elapsed + crate::authority_challenge::DELTA_MS < DURATION);
    let current = ClockHealth::new(wall + elapsed, boot + elapsed, boot + 30000, 100)
        .unwrap()
        .frozen();
    (issued, current)
}

#[test]
fn page_host_withdrawal_resumes_retained_signed_mutation_without_a_context_read() {
    let signer = crate::authority_deployment_tests::key(90);
    let mut f = Fixture::with_actions_and_signer(vec![0], signer);
    let host = crate::authority_deployment_tests::key(100)
        .verifying_key()
        .to_bytes();
    let request = || Request {
        command: PageCommand::HostWithdraw {
            role: 1,
            host,
            generation: 1,
        }
        .into(),
        grant: None,
    };
    // Retain the already-issued mutation, then lose its transient context and
    // session. A retry must not insert another ordinary read before this slot.
    let expected = vec![VersionRef {
        kind: 147,
        id: host,
        generation: 1,
        digest: [77; 32],
    }];
    let operation = request().operation(&f.store, &expected).unwrap();
    let descriptor = f.store.descriptor().clone();
    let signed = prepare_ordinary(
        &descriptor,
        &f.signer,
        &mut f.store,
        "AuthorityDomain",
        host,
        1,
        &expected,
        &operation.parameters().unwrap(),
    )
    .unwrap();
    drop(f.store);
    f.store = Store::open(&f.directory.0, f.bootstrap.descriptor().clone()).unwrap();
    f.session = Session::new().unwrap();
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    assert!(cache.state.records.is_empty() && cache.records.is_empty());
    (f.issued, f.current) = current_clocks();
    let context = Request {
        command: PageCommand::HostGet { role: 1, host }.into(),
        grant: None,
    };
    assert!(
        Prepared::new(
            &f.bootstrap,
            context,
            cache.clone(),
            &f.signer,
            &mut f.store,
            &mut f.session,
            f.issued
        )
        .is_err()
    );
    let resumed = Prepared::new(
        &f.bootstrap,
        request(),
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    assert_eq!(resumed.intent, signed);
    assert_eq!(f.store.resume_ordinary().unwrap().unwrap().signed(), signed);
}

fn reply(
    p: &Prepared,
    f: &Fixture,
    state: &State,
    replay: bool,
) -> (CertifiedReply, AncestryEvidence, State) {
    let intent = Intent::from_signed(&p.intent).unwrap();
    let operation = Operation::parse(&intent).unwrap();
    let inputs = evaluation_inputs(&operation.command, state, &p.objects).unwrap();
    let result = operation
        .prepare_with_inputs(
            state,
            f.bootstrap.governance_records(),
            &Reservations(f.bootstrap.reservations().to_vec()),
            &intent,
            f.current.observe().unwrap().wall_ms,
            replay,
            true,
            &inputs,
        )
        .unwrap();
    assert_eq!(result.code, 0);
    let next = result.state.clone().unwrap_or_else(|| state.clone());
    let (packet, node) = certified_request(
        &p.descriptor,
        &p.intent,
        &p.challenge,
        &p.ordered,
        result.value,
        f.current.observe().unwrap().wall_ms,
        *f.store.prefix().node(),
        f.store.prefix().height() + 1,
        0,
    );
    let value = wire::decode(&packet).unwrap();
    let fields = value.array(10).unwrap();
    (
        CertifiedReply {
            node: node.clone(),
            certificate: fields[7].bytes().unwrap().to_vec(),
            result: fields[8].bytes().unwrap().to_vec(),
        },
        AncestryEvidence::direct(vec![node]),
        next,
    )
}

#[test]
fn page_source_metadata_survives_floor_before_cache_interruption() {
    let mut f = Fixture::with_actions(vec![0, 2, 3]);
    let scope = f.bootstrap.descriptor().scope();
    let source = b"HyperNetPage/2\n# Bookshop\n: Opening hours.\n";
    let grant = references(
        f.bootstrap.governance_records(),
        scope.network,
        scope.incarnation,
    )
    .unwrap()
    .into_iter()
    .find(|r| r.kind == 102)
    .unwrap();
    let parameters = Author::parameters(
        [71; 16],
        "Books",
        source,
        &grant,
        None,
        f.current.observe().unwrap().wall_ms + 600000,
    )
    .unwrap();
    let signed = crate::authority_deployment_tests::signed(
        &f.signer,
        "PageAuthorStatement",
        page::page_id(&[71; 16]).unwrap(),
        1,
        wire::decode(&parameters).unwrap(),
        vec![],
    );
    let author = Author::parse(&signed, scope.network, scope.incarnation).unwrap();
    let request = || Request {
        command: PageCommand::Submit {
            author: author.clone(),
        }
        .into(),
        grant: Some(grant.clone()),
    };
    let objects = Vec::new;
    let authority = State::empty(scope.network, scope.incarnation);
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    // Bootstrap verification and durable fixture setup precede this request's live deadline.
    (f.issued, f.current) = current_clocks();
    let prepared = Prepared::new_with_objects(
        &f.bootstrap,
        request(),
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        objects(),
        f.issued,
    )
    .unwrap();
    let original = prepared.intent.clone();
    let (certified, evidence, authority) = reply(&prepared, &f, &authority, false);
    let path = f.directory.0.join(CACHE);
    std::fs::create_dir(&path).unwrap();
    let interruption = prepared
        .finish_with_objects(
            certified,
            evidence,
            Resolved::default(),
            &mut f.store,
            &mut f.session,
            &mut || Ok(f.current),
        )
        .err()
        .expect("a directory at the cache path must prevent cache publication");
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        original
    );
    assert!(
        f.store.generations().iter().any(|r| r.kind == 140),
        "result failed before the intended cache interruption: {interruption:#}"
    );
    assert!(
        f.store.generations().iter().any(|r| r.kind == 141),
        "result failed before retaining the source revision: {interruption:#}"
    );
    std::fs::remove_dir(&path).unwrap();
    drop(f.store);
    f.store = Store::open(&f.directory.0, f.bootstrap.descriptor().clone()).unwrap();
    f.session = Session::new().unwrap();
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    (f.issued, f.current) = current_clocks();
    let prepared = Prepared::new_with_objects(
        &f.bootstrap,
        request(),
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        objects(),
        f.issued,
    )
    .unwrap();
    assert_eq!(prepared.intent, original);
    let (certified, evidence, _) = reply(&prepared, &f, &authority, true);
    let (result, output) = prepared
        .finish_with_objects(
            certified,
            evidence,
            Resolved::default(),
            &mut f.store,
            &mut f.session,
            &mut || Ok(f.current),
        )
        .unwrap();
    assert!(output.is_empty());
    assert!(f.store.resume_ordinary().unwrap().is_none());
    assert_eq!(result.cache.state.value(), authority.value());
    let reopened = Cache::load(&f.bootstrap, &f.store).unwrap();
    assert_eq!(reopened.state.value(), authority.value());
}
