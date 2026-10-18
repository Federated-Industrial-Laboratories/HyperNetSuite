// SPDX-License-Identifier: MIT
// Private-socket reads preserve nonce binding, independent stream state and durable anchor provenance.
use super::*;
use crate::authority_inspection::tests::{Fixture, receive_control, send_control, voters};
use ed25519_dalek::Signer;
use std::os::unix::{fs::PermissionsExt, net::UnixListener};

pub(crate) fn submitted(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let value = wire::decode(bytes).unwrap();
    let fields = value.array(5).unwrap();
    assert_eq!(fields[0], V::Uint(41));
    assert_eq!(fields[3], V::Uint(6));
    let value = wire::decode(fields[4].bytes().unwrap()).unwrap();
    let fields = value.array(2).unwrap();
    (
        fields[0].bytes().unwrap().to_vec(),
        fields[1].bytes().unwrap().to_vec(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn response(
    request: &[u8],
    challenge: &[u8],
    node: &[u8],
    state: [u8; 32],
    value: V,
    evaluated: u64,
    expiry: u64,
    code: u64,
) -> Vec<u8> {
    let parsed = read::Request::from_signed(request).unwrap();
    let challenge_parsed = Challenge::from_signed(challenge).unwrap();
    let result = wire::encode(&a(vec![
        V::Uint(24),
        V::Uint(1),
        V::Text(parsed.query.action().into()),
        V::Uint(u64::from(code != 0)),
        V::Uint(code),
        b(&wire::encode(&value).unwrap()),
    ]))
    .unwrap();
    let anchor = proof::Node::parse(node).unwrap();
    let statement = read::Statement {
        scope: parsed.scope.clone(),
        request: parsed.digest,
        challenge: challenge_parsed.digest,
        requester: parsed.requester,
        recipient: parsed.recipient,
        height: anchor.height(),
        node: *anchor.digest(),
        state,
        evaluated_at_ms: evaluated,
        expires_at_ms: challenge_parsed
            .evaluation_expiry(evaluated, expiry.min(challenge_parsed.expires_at_ms))
            .unwrap(),
        result: wire::digest(&result),
    }
    .encode()
    .unwrap();
    let signatures = voters()[..3]
        .iter()
        .map(|key| {
            let public = key.verifying_key().to_bytes();
            a(vec![
                b(&public),
                b(&key
                    .sign(&wire::signature_message(&statement, &public))
                    .to_bytes()),
            ])
        })
        .collect();
    let certificate = wire::encode(&a(vec![
        V::Uint(0),
        V::Uint(1),
        b(&statement),
        a(signatures),
    ]))
    .unwrap();
    wire::encode(&a(vec![
        V::Uint(62),
        V::Uint(1),
        parsed.scope.value(),
        V::Uint(1),
        V::Uint(0),
        b(&read::read_id(request, challenge).unwrap()),
        b(node),
        b(&certificate),
        b(&result),
        a(vec![]),
    ]))
    .unwrap()
}

#[test]
fn fresh_policy_roundtrip_preserves_stream_and_anchor_on_reopen() {
    let mut f = Fixture::new();
    let socket = f.directory.0.join("Read.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let prefix = f.store.prefix().clone();
    let metadata = f
        .store
        .stream_metadata()
        .unwrap()
        .unwrap()
        .canonical()
        .to_vec();
    let status_needed = f.store.needs_stream_status().unwrap();
    let (p, r) = policy::current(&f.bootstrap, &f.store).unwrap();
    let scope = f.store.descriptor().scope();
    let refs = [100, 114]
        .into_iter()
        .zip([&p, &r])
        .map(|(kind, bytes)| {
            crate::authority_policies::record_reference(
                bytes,
                scope.network,
                scope.incarnation,
                kind,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityPolicyContext".into()),
        a(refs.iter().map(version_value).collect()),
        a(vec![b(&p), b(&r)]),
    ]);
    let node = f.status_node.clone();
    let state = *prefix.policy_state();
    let evaluated = f.current.observe().unwrap().wall_ms;
    let server = std::thread::spawn(move || {
        let (stream, bytes) = receive_control(&listener);
        let (request, challenge) = submitted(&bytes);
        assert!(matches!(
            read::Request::from_signed(&request).unwrap().query,
            Query::PolicyContext
        ));
        send_control(
            stream,
            &response(
                &request,
                &challenge,
                &node,
                state,
                value,
                evaluated,
                u64::MAX,
                0,
            ),
        );
    });
    let mut first = true;
    policy::discover(
        &f.bootstrap,
        &socket,
        &f.signer,
        &mut f.store,
        &mut f.session,
        || {
            let health = if first { f.issued } else { f.current };
            first = false;
            Ok(health)
        },
    )
    .unwrap();
    server.join().unwrap();
    assert_eq!(f.store.prefix(), &prefix);
    assert_eq!(
        f.store.stream_metadata().unwrap().unwrap().canonical(),
        metadata
    );
    assert_eq!(f.store.needs_stream_status().unwrap(), status_needed);
    assert!(f.store.resume_ordinary().unwrap().is_none());
    assert!(refs.iter().all(|r| f.store.generations().contains(r)));
    let descriptor = f.store.descriptor().clone();
    drop(f.store);
    let reopened = Store::open(&f.directory.0, descriptor).unwrap();
    assert_eq!(reopened.prefix(), &prefix);
    assert_eq!(
        reopened.stream_metadata().unwrap().unwrap().canonical(),
        metadata
    );
    assert!(refs.iter().all(|r| reopened.generations().contains(r)));
}

#[test]
fn unavailable_fresh_read_leaves_no_ordinary_operation_or_floor_change() {
    let mut f = Fixture::new();
    let socket = f.directory.0.join("UnavailableRead.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let prefix = f.store.prefix().clone();
    let server = std::thread::spawn(move || {
        let (stream, bytes) = receive_control(&listener);
        let (request, challenge) = submitted(&bytes);
        let parsed = read::Request::from_signed(&request).unwrap();
        let reply = wire::encode(&a(vec![
            V::Uint(62),
            V::Uint(1),
            parsed.scope.value(),
            V::Uint(2),
            V::Uint(1),
            b(&read::read_id(&request, &challenge).unwrap()),
            V::Null,
            V::Null,
            V::Null,
            a(vec![]),
        ]))
        .unwrap();
        send_control(stream, &reply);
    });
    let error = policy::discover(
        &f.bootstrap,
        &socket,
        &f.signer,
        &mut f.store,
        &mut f.session,
        || Ok(f.issued),
    )
    .unwrap_err();
    server.join().unwrap();
    assert!(error.is::<crate::authority_local_transport::ReadUnavailable>());
    assert_eq!(f.store.prefix(), &prefix);
    assert!(f.store.resume_ordinary().unwrap().is_none());
}

#[test]
fn replayed_read_certificate_cannot_satisfy_a_new_query_nonce() {
    let mut f = Fixture::new();
    let socket = f.directory.0.join("ReplayRead.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (p, r) = policy::current(&f.bootstrap, &f.store).unwrap();
    let scope = f.store.descriptor().scope();
    let refs = [100, 114]
        .into_iter()
        .zip([&p, &r])
        .map(|(kind, bytes)| {
            crate::authority_policies::record_reference(
                bytes,
                scope.network,
                scope.incarnation,
                kind,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityPolicyContext".into()),
        a(refs.iter().map(version_value).collect()),
        a(vec![b(&p), b(&r)]),
    ]);
    let node = f.status_node.clone();
    let state = *f.store.prefix().policy_state();
    let evaluated = f.current.observe().unwrap().wall_ms;
    let server = std::thread::spawn(move || {
        let (stream, bytes) = receive_control(&listener);
        let (first_request, first_challenge) = submitted(&bytes);
        let first = response(
            &first_request,
            &first_challenge,
            &node,
            state,
            value,
            evaluated,
            u64::MAX,
            0,
        );
        send_control(stream, &first);
        let (stream, bytes) = receive_control(&listener);
        let (request, challenge) = submitted(&bytes);
        assert_ne!(request, first_request);
        assert_ne!(challenge, first_challenge);
        let mut fields = wire::decode(&first).unwrap().array(10).unwrap().to_vec();
        // Transport correlation is not the quorum certificate's cryptographic request binding.
        fields[5] = b(&read::read_id(&request, &challenge).unwrap());
        send_control(stream, &wire::encode(&a(fields)).unwrap());
    });
    let mut first = true;
    policy::discover(
        &f.bootstrap,
        &socket,
        &f.signer,
        &mut f.store,
        &mut f.session,
        || {
            let health = if first { f.issued } else { f.current };
            first = false;
            Ok(health)
        },
    )
    .unwrap();
    let retained = std::fs::read(f.directory.0.join("AuthorityFloor.json")).unwrap();
    let error = policy::discover(
        &f.bootstrap,
        &socket,
        &f.signer,
        &mut f.store,
        &mut f.session,
        || Ok(f.current),
    )
    .unwrap_err();
    server.join().unwrap();
    assert!(
        error.to_string().contains("fresh response binding differs"),
        "{error:#}"
    );
    assert_eq!(
        std::fs::read(f.directory.0.join("AuthorityFloor.json")).unwrap(),
        retained
    );
    assert!(f.store.resume_ordinary().unwrap().is_none());
}
