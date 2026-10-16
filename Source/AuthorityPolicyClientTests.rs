// SPDX-License-Identifier: MIT
// A certified successor cannot silently replace a reader's accepted trust contract.
use super::*;
use crate::authority_inspection::tests::Fixture;
#[test]
fn weaker_candidate_is_refused_before_use_and_non_policy_records_do_not_change_trust() {
    let f = Fixture::new();
    let (p, r) = current(&f.bootstrap, &f.store).unwrap();
    let mut fields = wire::decode(&p).unwrap().array(17).unwrap().to_vec();
    fields[4] = V::Uint(2);
    fields[5] = b(&wire::digest(&p));
    fields[8] = V::Uint(0);
    let weaker = wire::encode(&a(fields)).unwrap();
    let candidate = vec![weaker, r];
    assert!(require_records_accepted(&f.bootstrap, &f.store, &candidate).is_err());
    assert!(retain_records(&f.bootstrap, &f.store, &candidate).is_err());
    assert_eq!(current(&f.bootstrap, &f.store).unwrap().0, p);
    let unrelated = wire::encode(&a(vec![V::Uint(169), V::Uint(1)])).unwrap();
    require_records_accepted(&f.bootstrap, &f.store, &[unrelated]).unwrap();
}
#[test]
fn discovery_requires_exact_linked_custody_and_current_candidate_references() {
    let f = Fixture::new();
    let (p, r) = current(&f.bootstrap, &f.store).unwrap();
    let scope = f.store.descriptor().scope();
    let refs = [100, 114]
        .into_iter()
        .zip([&p, &r])
        .map(|(kind, bytes)| {
            policies::record_reference(bytes, scope.network, scope.incarnation, kind).unwrap()
        })
        .collect::<Vec<_>>();
    let mut value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityPolicyContext".into()),
        a(refs.iter().map(version_value).collect()),
        a(vec![b(&p), b(&r)]),
    ]);
    discovery::pair_from_value(&value, scope.network, scope.incarnation).unwrap();
    let V::Array(fields) = &mut value else {
        unreachable!()
    };
    fields[3] = a(vec![version_value(&refs[0]), version_value(&refs[0])]);
    assert!(discovery::pair_from_value(&value, scope.network, scope.incarnation).is_err());
}

#[test]
fn policy_discovery_prepares_transport_before_sampling_challenge_clock() {
    let mut f = Fixture::new();
    let descriptor = f.store.descriptor().clone();
    let scope = descriptor.scope();
    let parameters = wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("AuthorityPolicyContext".into()),
        b(&scope.network),
    ]))
    .unwrap();
    let original = prepare_ordinary(
        &descriptor,
        &f.signer,
        &mut f.store,
        "AuthorityPolicyContext",
        scope.network,
        0,
        &[],
        &parameters,
    )
    .unwrap();
    assert!(!f.store.needs_stream_status().unwrap());
    let socket = f.directory.0.join("Unavailable.sock");
    for _ in 0..2 {
        let mut sampled = false;
        let error = discover(
            &f.bootstrap,
            &socket,
            &f.signer,
            &mut f.store,
            &mut f.session,
            || {
                sampled = true;
                Ok(f.issued)
            },
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );
        assert!(
            !sampled,
            "transport preparation consumed challenge freshness"
        );
        assert_eq!(
            f.store.resume_ordinary().unwrap().unwrap().signed(),
            original
        );
    }
}

#[test]
fn pending_discovery_resumes_after_lost_reply_and_does_not_replace_a_domain_intent() {
    discovery_recovery(false);
}

#[test]
fn policy_discovery_recovers_one_expired_exchange_with_exact_intent() {
    discovery_recovery(true);
}

fn discovery_recovery(expire: bool) {
    use crate::authority_inspection::tests::{
        certified_request, live_clock, mature, receive_control, send_control, submitted,
    };
    use std::{
        io::Read,
        os::unix::{fs::PermissionsExt, net::UnixListener},
        time::Duration,
    };
    let mut f = Fixture::new();
    let socket = f.directory.0.join("Discovery.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (p, r) = current(&f.bootstrap, &f.store).unwrap();
    let descriptor = f.store.descriptor().clone();
    let scope = descriptor.scope();
    let refs = [100, 114]
        .into_iter()
        .zip([&p, &r])
        .map(|(kind, bytes)| {
            policies::record_reference(bytes, scope.network, scope.incarnation, kind).unwrap()
        })
        .collect::<Vec<_>>();
    let value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityPolicyContext".into()),
        a(refs.iter().map(version_value).collect()),
        a(vec![b(&p), b(&r)]),
    ]);
    let parent = *f.store.prefix().node();
    let height = f.store.prefix().height() + 1;
    assert!(f.store.needs_stream_status().unwrap());
    let metadata = f
        .store
        .stream_metadata()
        .unwrap()
        .unwrap()
        .canonical()
        .to_vec();
    let server = std::thread::spawn(move || {
        let (stream, status) = receive_control(&listener);
        let (ordered, status, challenge) = submitted(&status);
        assert!(matches!(
            proof::SignedRequest::from_signed(&status).unwrap(),
            proof::SignedRequest::StreamStatus(_)
        ));
        let (response, status_node) = certified_request(
            &descriptor,
            &status,
            &challenge,
            &ordered,
            wire::decode(&metadata).unwrap(),
            mature(&challenge),
            parent,
            height,
            0,
        );
        send_control(stream, &response);

        let (mut stream, first) = receive_control(&listener);
        let (_, original, old_challenge) = submitted(&first);
        assert_eq!(
            Intent::from_signed(&original).unwrap().action,
            "AuthorityPolicyContext"
        );
        if expire {
            // Keep the reply absent until the client's original request deadline closes this connection.
            stream
                .set_read_timeout(Some(Duration::from_secs(7)))
                .unwrap();
            assert_eq!(stream.read(&mut [0; 1]).unwrap(), 0);
        }
        drop(stream);
        let (stream, retry) = receive_control(&listener);
        let (ordered, intent, challenge) = submitted(&retry);
        assert_eq!(intent, original);
        assert_ne!(challenge, old_challenge);
        if expire {
            assert!(
                Challenge::from_signed(&challenge).unwrap().created_at_ms
                    > Challenge::from_signed(&old_challenge)
                        .unwrap()
                        .created_at_ms
            );
        }
        let (response, _) = certified_request(
            &descriptor,
            &intent,
            &challenge,
            &ordered,
            value,
            mature(&challenge),
            wire::digest(&status_node),
            height + 1,
            0,
        );
        send_control(stream, &response);
        original
    });
    let result = discover(
        &f.bootstrap,
        &socket,
        &f.signer,
        &mut f.store,
        &mut f.session,
        live_clock,
    );
    let retained = if expire {
        result.unwrap();
        None
    } else {
        assert!(result.is_err());
        let retained = f
            .store
            .resume_ordinary()
            .unwrap()
            .unwrap()
            .signed()
            .to_vec();
        resume_pending_discovery(
            &f.bootstrap,
            &socket,
            &f.signer,
            &mut f.store,
            &mut f.session,
            live_clock,
        )
        .unwrap();
        Some(retained)
    };
    let original = server.join().unwrap();
    if let Some(retained) = retained {
        assert_eq!(original, retained);
    }
    assert!(f.store.resume_ordinary().unwrap().is_none());
    assert_eq!(current(&f.bootstrap, &f.store).unwrap(), (p, r));

    let descriptor = f.store.descriptor().clone();
    let original = prepare_ordinary(
        &descriptor,
        &f.signer,
        &mut f.store,
        "AuthorityDomain",
        [20; 32],
        0,
        &[],
        &wire::encode(&a(vec![])).unwrap(),
    )
    .unwrap();
    resume_pending_discovery(
        &f.bootstrap,
        &socket,
        &f.signer,
        &mut f.store,
        &mut f.session,
        || anyhow::bail!("domain recovery must not issue discovery"),
    )
    .unwrap();
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().signed(),
        original
    );
}
