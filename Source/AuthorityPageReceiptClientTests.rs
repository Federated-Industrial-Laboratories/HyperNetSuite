// SPDX-License-Identifier: MIT
// Connected serving receipts retain exact outcome and progress before requester acknowledgement.
use super::*;
use crate::{
    authority_deployment_tests as deployment, authority_inspection::page_media_client as media,
    authority_proof::Digest,
};
use page::content::{self, Effect};
use sha2::{Digest as _, Sha256};

struct View {
    f: Fixture,
    state: State,
    records: Vec<Vec<u8>>,
    grant: VersionRef,
    placement: VersionRef,
    host: VersionRef,
    source: Vec<u8>,
    result: ResultState,
}
fn view(search: bool) -> View {
    let (bootstrap, state, records, grant, placement, source) =
        page::tests::view_tests::consumer_fixture(search);
    let mut f = Fixture::with_bootstrap(bootstrap, deployment::key(5), 6000);
    let cache = Cache::load(&f.bootstrap, &f.store).unwrap();
    let boot = boot_time_ms().unwrap();
    let delta = crate::authority_challenge::DELTA_MS + 1;
    f.issued = ClockHealth::new(6000 - delta, boot, boot + 30000, 100)
        .unwrap()
        .frozen();
    f.current = ClockHealth::new(6000, boot + delta, boot + 30000, 100)
        .unwrap()
        .frozen();
    let prepared = Prepared::new(
        &f.bootstrap,
        Request {
            command: PageCommand::SearchList {
                namespace: "Books".into(),
                after: None,
            }
            .into(),
            grant: Some(grant.clone()),
        },
        cache,
        &f.signer,
        &mut f.store,
        &mut f.session,
        f.issued,
    )
    .unwrap();
    let (reply, ancestry, _) = certify_view(&prepared, &state, &records, 6000, f.store.prefix());
    let result = prepared
        .finish(reply, ancestry, &mut f.store, &mut f.session, &mut || {
            Ok(f.current)
        })
        .unwrap();
    let host = content::Placement::parse(&state.record(159, placement.id).unwrap().payload)
        .unwrap()
        .hosts[0]
        .clone();
    View {
        f,
        state,
        records,
        grant,
        placement,
        host,
        source,
        result,
    }
}

fn content_request(v: &mut View, effect: Effect) -> page::MediaRequest {
    media::prepare(
        &v.f.bootstrap,
        &v.f.signer,
        &mut v.f.store,
        PageCommand::Content(content::Command::Authorise {
            placement: v.placement.clone(),
            host: v.host.clone(),
            effect,
            offset: 0,
            bytes: v.source.len() as u64,
            digest: None,
        }),
        v.grant.clone(),
        v.f.current,
    )
    .unwrap()
}

// The recipient's real typed verifier checks this signed quorum result and completion.
fn receipt(v: &View, request: &page::MediaRequest, parent: Digest, refused: bool) -> Vec<u8> {
    let host = deployment::key(100);
    let mut serving = Session::new().unwrap();
    let issued = v.f.current;
    let at = issued.observe().unwrap().wall_ms + crate::authority_challenge::DELTA_MS + 1;
    let challenge = serving
        .issue(request.signed(), &host, [92; 32], 5000, issued)
        .unwrap();
    let parsed = Challenge::from_signed(&challenge).unwrap();
    let (value, expiry, code) = if refused {
        (
            a(vec![
                V::Uint(201),
                V::Uint(1),
                V::Text("AuthorityDomain".into()),
                a(vec![]),
            ]),
            parsed.expires_at_ms,
            3,
        )
    } else {
        let decision = Operation::parse(request.intent())
            .unwrap()
            .prepare_with_inputs(
                &v.state,
                &v.records,
                &Reservations(v.f.bootstrap.reservations().to_vec()),
                request.intent(),
                at,
                false,
                true,
                &Resolved::default(),
            )
            .unwrap();
        assert_eq!(decision.code, 0);
        (
            decision.value,
            decision.expires_ms.min(parsed.expires_at_ms),
            0,
        )
    };
    if !refused {
        let returned = value.array(5).unwrap()[4].array(4).unwrap()[2]
            .list(64)
            .unwrap();
        assert!(returned.iter().all(|record| {
            wire::decode(record.bytes().unwrap())
                .unwrap()
                .list(32)
                .unwrap()[0]
                .uint()
                .unwrap()
                != 131
        }));
        assert!(v.f.bootstrap.governance_records().iter().any(|record| {
            wire::decode(record).unwrap().list(32).unwrap()[0]
                .uint()
                .unwrap()
                == 131
        }));
        let registration = returned
            .iter()
            .find_map(|record| {
                let bytes = record.bytes().unwrap();
                (wire::decode(bytes).unwrap().list(32).unwrap()[0]
                    .uint()
                    .unwrap()
                    == 129)
                    .then(|| {
                        crate::authority_deployment_records::Registration::parse(
                            bytes,
                            v.state.network,
                            v.state.incarnation,
                        )
                        .unwrap()
                    })
            })
            .unwrap();
        assert!(
            registration.services.contains_key(&0),
            "the valid combined deployment needs its accepted bootstrap transport appointment"
        );
    }
    let ordered = wire::encode(&a(vec![
        V::Uint(22),
        V::Uint(1),
        v.f.store.descriptor().scope().value(),
        b(request.signed()),
        b(&challenge),
        V::Uint(expiry),
    ]))
    .unwrap();
    let (packet, node) = certified_request(
        v.f.store.descriptor(),
        request.signed(),
        &challenge,
        &ordered,
        value,
        at,
        parent,
        v.f.store.prefix().height() + 1,
        code,
    );
    let decoded = wire::decode(&packet).unwrap();
    let fields = decoded.array(10).unwrap();
    let proof = request
        .verify(
            &v.f.bootstrap,
            v.f.store.descriptor(),
            &challenge,
            &ordered,
            fields[8].bytes().unwrap(),
            fields[7].bytes().unwrap(),
            std::slice::from_ref(&node),
            &[],
        )
        .unwrap();
    let (completion, response) = if refused {
        (V::Null, V::Null)
    } else {
        let (_, placement, _) = request.result_content(&proof.result).unwrap();
        assert_eq!(placement.digest, Digest::from(Sha256::digest(&v.source)));
        assert_eq!(placement.bytes, v.source.len() as u64);
        let mut copy = content::Copy {
            placement: v.placement.clone(),
            host: v.host.clone(),
            request: request.intent().digest,
            digest: placement.digest,
            bytes: placement.bytes,
            recorded_ms: at,
            expires_ms: placement.expires_ms,
            envelope: vec![],
        };
        let scope = v.f.store.descriptor().scope();
        copy.envelope = wire::sign_envelope(
            &copy.payload(scope.network, scope.incarnation).unwrap(),
            &host,
        )
        .unwrap();
        let PageCommand::Content(content::Command::Authorise { effect, .. }) = request.command()
        else {
            unreachable!()
        };
        let payload = if *effect == Effect::Search {
            wire::encode(&a(vec![
                V::Uint(201),
                V::Uint(1),
                V::Text("PageSearchResult".into()),
                b(&[93; 32]),
                b(&v.source),
                V::Null,
            ]))
            .unwrap()
        } else {
            v.source.clone()
        };
        let payload_hash: Digest = Sha256::digest(&payload).into();
        let response = wire::encode(&a(vec![
            V::Uint(201),
            V::Uint(1),
            V::Text("PageContentEffect".into()),
            version_value(&v.placement),
            version_value(&v.host),
            V::Uint(effect.code()),
            V::Uint(0),
            V::Uint(v.source.len() as u64),
            b(&payload_hash),
            b(&payload),
            b(&copy.envelope),
        ]))
        .unwrap();
        let completion = wire::sign_envelope(
            &wire::encode(&a(vec![
                V::Uint(200),
                V::Uint(1),
                V::Text(request.completion_tag().into()),
                scope.value(),
                b(&request.intent().digest),
                b(&wire::digest(proof.operation_result_bytes())),
                b(&wire::digest(&response)),
                V::Uint(at),
            ]))
            .unwrap(),
            &host,
        )
        .unwrap();
        (b(&completion), b(&response))
    };
    let bytes = wire::encode_state(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text(request.receipt_tag().into()),
        b(request.signed()),
        b(&challenge),
        b(&ordered),
        b(proof.operation_result_bytes()),
        b(proof.point().certificate()),
        a(vec![b(&node)]),
        V::Null,
        V::Null,
        completion,
        response,
    ]))
    .unwrap();
    page::MediaReceipt::parse(&bytes)
        .unwrap()
        .verify(&v.f.bootstrap, v.f.store.descriptor())
        .unwrap();
    bytes
}

fn retain_status(v: &mut View, request: &page::MediaRequest, receipt: &[u8]) {
    let report = page::MediaReceipt::parse(receipt)
        .unwrap()
        .verify(&v.f.bootstrap, v.f.store.descriptor())
        .unwrap();
    let descriptor = v.f.store.descriptor().clone();
    let scope = descriptor.scope();
    let intent = request.intent();
    let status = wire::sign_envelope(
        &wire::encode(&a(vec![
            V::Uint(55),
            V::Uint(1),
            b(&scope.network),
            b(&scope.incarnation),
            b(&v.f.store.requester()),
            b(&[94; 32]),
            V::Uint(scope.epoch),
            V::Uint(v.f.store.prefix().height()),
        ]))
        .unwrap(),
        &v.f.signer,
    )
    .unwrap();
    let at = v.f.current.observe().unwrap();
    let delta = crate::authority_challenge::DELTA_MS + 1;
    // The host completed at the first delta. The later status starts there and
    // completes at the next delta, on the same monotonic recipient timeline.
    let issued = ClockHealth::new(
        at.wall_ms + delta,
        at.boot_ms + delta,
        at.boot_ms + 30000,
        100,
    )
    .unwrap()
    .frozen();
    let current = ClockHealth::new(
        at.wall_ms + 2 * delta,
        at.boot_ms + 2 * delta,
        at.boot_ms + 30000,
        100,
    )
    .unwrap()
    .frozen();
    let mut session = Session::new().unwrap();
    let challenge = session
        .issue(&status, &v.f.signer, [95; 32], 5000, issued)
        .unwrap();
    let parsed = Challenge::from_signed(&challenge).unwrap();
    let ordered = wire::encode(&a(vec![
        V::Uint(22),
        V::Uint(1),
        scope.value(),
        b(&status),
        b(&challenge),
        V::Uint(parsed.expires_at_ms),
    ]))
    .unwrap();
    let metadata = a(vec![
        V::Uint(56),
        V::Uint(1),
        scope.value(),
        b(&v.f.store.requester()),
        V::Bool(true),
        V::Uint(intent.generation),
        b(&intent.generation_id),
        V::Uint(intent.sequence - 1),
        a(vec![
            V::Uint(intent.sequence),
            b(&intent.digest),
            V::Uint(0),
            V::Uint(0),
            b(&wire::digest(report.result().operation_result_bytes())),
        ]),
        V::Null,
    ]);
    let (packet, node) = certified_request(
        &descriptor,
        &status,
        &challenge,
        &ordered,
        metadata,
        current.observe().unwrap().wall_ms,
        *v.f.store.prefix().node(),
        v.f.store.prefix().height() + 1,
        0,
    );
    let decoded = wire::decode(&packet).unwrap();
    let fields = decoded.array(10).unwrap();
    let verified = proof::verify_response(
        &descriptor,
        proof::ProofContext {
            intent: &status,
            challenge: &challenge,
            restrictions: Restrictions::default(),
            minimum_height: v.f.store.prefix().height(),
            maximum_effect: 1,
            expected_stream: None,
        },
        proof::Response {
            ordered_request: &ordered,
            operation_result: fields[8].bytes().unwrap(),
            certificate: fields[7].bytes().unwrap(),
            ancestry: &[node],
        },
        |_, _, _| bail!("status requires its fixed verifier"),
    )
    .unwrap();
    v.f.store
        .accept(verified, &mut session, current, parsed.created_at_ms)
        .unwrap()
        .perform(
            &mut v.f.store,
            &mut session,
            current,
            1,
            |_| Ok(()),
            |_, _| Ok(()),
        )
        .unwrap();
    v.f.current = current;
}

#[test]
fn connected_content_receipt_recovers_progress_without_status_or_host_replay() {
    for effect in [Effect::Read, Effect::Search] {
        let mut v = view(effect == Effect::Search);
        let request = content_request(&mut v, effect);
        let socket = v.f.directory.0.join("UnavailableAuthority.sock");
        let floor = v.f.store.prefix().clone();
        for bytes in [
            receipt(&v, &request, [199; 32], false),
            receipt(&v, &request, *floor.node(), true),
        ] {
            let error = media::complete(
                &v.f.bootstrap,
                &bytes,
                &socket,
                &v.f.signer,
                &mut v.f.store,
                &mut v.f.session,
                || Ok(v.f.current),
                |_, _| -> Result<()> { panic!("unreconciled completion must not apply") },
            )
            .unwrap_err();
            assert!(
                error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                "{error:#}"
            );
            assert_eq!(*v.f.store.prefix(), floor);
        }
        let bytes = receipt(&v, &request, *floor.node(), false);
        assert!(
            media::complete(
                &v.f.bootstrap,
                &bytes,
                &socket,
                &deployment::key(99),
                &mut v.f.store,
                &mut v.f.session,
                || panic!("another signer must fail locally"),
                |_, _| -> Result<()> { panic!("another signer cannot complete this request") }
            )
            .is_err()
        );
        let mut invalid = wire::decode_state(&bytes)
            .unwrap()
            .array(13)
            .unwrap()
            .to_vec();
        let mut changed = invalid[12].bytes().unwrap().to_vec();
        changed[0] ^= 1;
        invalid[12] = b(&changed);
        assert!(
            media::complete(
                &v.f.bootstrap,
                &wire::encode_state(&a(invalid)).unwrap(),
                &socket,
                &v.f.signer,
                &mut v.f.store,
                &mut v.f.session,
                || panic!("invalid receipt must fail locally"),
                |_, _| -> Result<()> { panic!("invalid receipt must not apply") }
            )
            .is_err()
        );
        assert_eq!(*v.f.store.prefix(), floor);
        let progress = v.f.directory.0.join("ReceivedContent");
        let directory = files::private_directory(&v.f.directory.0).unwrap();
        let error = media::complete(
            &v.f.bootstrap,
            &bytes,
            &socket,
            &v.f.signer,
            &mut v.f.store,
            &mut v.f.session,
            || panic!("connected receipt needs no new challenge"),
            |exact, response| -> Result<()> {
                assert_eq!(exact.signed(), request.signed());
                files::atomic_at(&directory, OsStr::new("ReceivedContent"), response, true)?;
                bail!("progress acknowledgement interrupted")
            },
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "progress acknowledgement interrupted");
        assert_eq!(v.f.store.prefix().height(), floor.height() + 1);
        assert!(v.f.store.generations().contains(&v.placement));
        assert_eq!(
            v.f.store.resume_ordinary().unwrap().unwrap().signed(),
            request.signed()
        );
        assert!(v.f.store.ordinary_slot().is_err());
        drop(v.f.store);
        v.f.store = Store::open(&v.f.directory.0, v.f.bootstrap.descriptor().clone()).unwrap();
        // A later certified status may advance the floor while progress is pending.
        retain_status(&mut v, &request, &bytes);
        let later = v.f.store.prefix().clone();
        let generations = v.f.store.generations().to_vec();
        media::complete(
            &v.f.bootstrap,
            &bytes,
            &socket,
            &v.f.signer,
            &mut v.f.store,
            &mut v.f.session,
            || panic!("known historical completion needs no new status"),
            |exact, response| {
                assert_eq!(exact.signed(), request.signed());
                assert_eq!(std::fs::read(&progress)?, response);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(*v.f.store.prefix(), later);
        assert_eq!(v.f.store.generations(), generations.as_slice());
        assert!(v.f.store.resume_ordinary().unwrap().is_none());
        assert!(!v.f.store.needs_stream_status().unwrap());
        assert_eq!(
            v.f.store.ordinary_slot().unwrap().sequence(),
            request.intent().sequence + 1
        );
        let next = content_request(&mut v, effect);
        assert_ne!(next.intent().digest, request.intent().digest);
        assert!(
            media::complete(
                &v.f.bootstrap,
                &bytes,
                &socket,
                &v.f.signer,
                &mut v.f.store,
                &mut v.f.session,
                || panic!("another pending intent must fail locally"),
                |_, _| -> Result<()> { panic!("old receipt cannot complete new request") }
            )
            .is_err()
        );
        assert_eq!(
            v.f.store.resume_ordinary().unwrap().unwrap().signed(),
            next.signed()
        );
    }
}

#[test]
fn first_search_content_reuses_only_current_catalogue_with_indexing_consent() {
    for consent in [false, true] {
        let mut v = view(consent);
        let now = v.f.current.observe().unwrap();
        assert_eq!(
            media::current_content_view(
                &v.f.bootstrap,
                &v.f.store,
                &v.result,
                &v.placement,
                &v.host,
                Effect::Search,
                || Ok(now)
            )
            .unwrap(),
            consent
        );
        let socket = v.f.directory.0.join("UnavailableAuthority.sock");
        let prepared = media::ensure_content_view(
            &v.f.bootstrap,
            &mut v.f.store,
            &socket,
            &v.f.signer,
            &mut v.f.session,
            || Ok(v.f.current),
            Some((&v.result, &v.placement, &v.host, Effect::Search)),
        );
        if !consent {
            assert!(
                prepared
                    .unwrap_err()
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            );
            continue;
        }
        prepared.unwrap();
        assert!(v.f.store.resume_ordinary().unwrap().is_none());
        let mut expired = now;
        expired.boot_ms = v.result.deadline_boot_ms;
        assert!(
            !media::current_content_view(
                &v.f.bootstrap,
                &v.f.store,
                &v.result,
                &v.placement,
                &v.host,
                Effect::Search,
                || Ok(expired)
            )
            .unwrap()
        );
        let mut host = v.host.clone();
        host.generation += 1;
        assert!(
            !media::current_content_view(
                &v.f.bootstrap,
                &v.f.store,
                &v.result,
                &v.placement,
                &host,
                Effect::Search,
                || Ok(now)
            )
            .unwrap()
        );
        let request = content_request(&mut v, Effect::Search);
        assert!(
            !media::current_content_view(
                &v.f.bootstrap,
                &v.f.store,
                &v.result,
                &v.placement,
                &v.host,
                Effect::Search,
                || panic!("pending recovery precedes clock sampling")
            )
            .unwrap()
        );
        assert_eq!(
            v.f.store.resume_ordinary().unwrap().unwrap().signed(),
            request.signed()
        );
    }
}
