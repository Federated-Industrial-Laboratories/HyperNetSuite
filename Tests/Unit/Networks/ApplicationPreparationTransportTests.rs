// SPDX-License-Identifier: MIT
// Application acceptance retains the original preparation bound through real nested TLS.
use super::*;
use crate::authority_domains::streams;

fn application_preparation(accept: bool) {
    let f = Fixture::new();
    let (relay, service) = certificates(&f.directory.0);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let possession = SigningKey::from_bytes(&[99; 32]);
    let scope = f.store.prefix().scope().clone();
    let reference = |kind, id, digest| VersionRef {
        kind,
        id,
        generation: 1,
        digest,
    };
    let voucher = domains::routes::Voucher {
        baseline: None,
        relay: reference(165, relay.identity.service, [93; 32]),
        destination: reference(165, service.identity.service, [94; 32]),
        possession: possession.verifying_key().to_bytes(),
        sponsor: f.signer.verifying_key().to_bytes(),
        grant: reference(102, [95; 32], [96; 32]),
        action: 0,
        scope: (0, scope.network),
        connections: 1,
        bytes: 1048576,
        expires: u64::MAX,
        creation: [97; 32],
    };
    let voucher = domains::Record::next(
        &domains::State::empty(scope.network, scope.incarnation),
        166,
        [98; 32],
        voucher.value(),
    )
    .unwrap();
    let limits = route::Limits {
        bytes: 1048576,
        duration_ms: 10000,
        idle_ms: 5000,
    };
    let profile = route::Profile {
        version: 1,
        network: scope.network,
        incarnation: scope.incarnation,
        relay_address: listener.local_addr().unwrap(),
        relay: relay.identity.clone(),
        destination: service.identity.clone(),
        domain: "Destination".into(),
        relay_domain: "Relay".into(),
        protocol: streams::PROTOCOL,
        assurance: route::Assurance::Independent,
        minimum_assurance: route::Assurance::Independent,
        limits,
        voucher: voucher.bytes.clone(),
    };
    let relay_config = route_tls::server(&relay.identity, &relay.pem, &relay.key).unwrap();
    let final_config = route_tls::server(&service.identity, &service.pem, &service.key).unwrap();
    let application = [80; 32];
    let application_binding = [81; 32];
    std::thread::scope(|threads| {
        let server = threads.spawn(|| {
            let end = std::time::Instant::now() + Duration::from_secs(4);
            let socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < end,
                            "application did not connect"
                        );
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("application TLS fixture accept failed: {error}"),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket.set_nodelay(true).unwrap();
            let mut outer = StreamOwned::new(ServerConnection::new(relay_config).unwrap(), socket);
            let open = route_protocol::Open::parse(&framed_read(&mut outer)).unwrap();
            let exporter = outer
                .conn
                .export_keying_material([0; 32], route_protocol::EXPORTER, None)
                .unwrap();
            let nonce = [89; 32];
            framed_send(&mut outer, &route_protocol::challenge(nonce).unwrap());
            assert_eq!(
                open.verify(nonce, exporter, &framed_read(&mut outer))
                    .unwrap(),
                possession.verifying_key().to_bytes()
            );
            let binding = wire::digest(&open.binding(nonce, exporter).unwrap());
            framed_send(&mut outer, &route_protocol::ready(binding, limits).unwrap());
            let mut inner = StreamOwned::new(ServerConnection::new(final_config).unwrap(), outer);
            framed_send(
                &mut inner,
                &route_protocol::endpoint_ready(
                    scope.network,
                    scope.incarnation,
                    service.identity.service,
                    streams::PROTOCOL,
                )
                .unwrap(),
            );
            framed_send(
                &mut inner,
                &streams::protocol::challenge(
                    scope.network,
                    scope.incarnation,
                    application,
                    [82; 32],
                )
                .unwrap(),
            );
            let proof =
                streams::Proof::parse(&framed_read(&mut inner), scope.network, scope.incarnation)
                    .unwrap();
            assert_eq!(proof.principal, f.signer.verifying_key().to_bytes());
            assert_eq!(
                proof.exporter,
                inner
                    .conn
                    .export_keying_material([0; 32], streams::protocol::EXPORTER, None)
                    .unwrap()
            );
            if accept {
                let admitted = reference(173, proof.id().unwrap(), [83; 32]);
                framed_send(
                    &mut inner,
                    &streams::protocol::accepted(&admitted, &proof, application_binding).unwrap(),
                );
                assert_eq!(framed_read(&mut inner), b"after preparation");
                framed_send(&mut inner, b"active stream");
            } else {
                // The client must end its original preparation while acceptance is withheld.
                match inner.read(&mut [0; 1]) {
                    Ok(0) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
                    other => panic!("expired application preparation did not close TLS: {other:?}"),
                }
            }
        });
        let preparation_end = boot_time_ms().unwrap() + 1000;
        let stream_end = preparation_end + 9000;
        let mut session = crate::route_connector::Session::connect_with_deadlines(
            &profile,
            &possession,
            stream_end,
            preparation_end,
            &|| false,
        )
        .unwrap();
        let mut proof = streams::Proof {
            service: reference(172, application, [84; 32]),
            principal: f.signer.verifying_key().to_bytes(),
            grant: reference(102, [85; 32], [86; 32]),
            protocol: "test.application".into(),
            slot: 0,
            generation: 1,
            nonce: [1; 32],
            challenge: [1; 32],
            exporter: [1; 32],
            limits,
            expires: wall() + 10000,
            envelope: vec![],
        };
        let result = session.authenticate_application_before(
            scope.network,
            scope.incarnation,
            &mut proof,
            application_binding,
            &f.signer,
            preparation_end,
        );
        if accept {
            assert_eq!(result.unwrap().id, proof.id().unwrap());
            std::thread::sleep(Duration::from_millis(
                preparation_end.saturating_sub(boot_time_ms().unwrap()) + 10,
            ));
            assert_eq!(
                session
                    .exchange(b"after preparation", boot_time_ms().unwrap() + 1000, 64)
                    .unwrap(),
                b"active stream"
            );
        } else {
            let error = result.unwrap_err();
            assert!(
                error.chain().any(|cause| cause
                    .downcast_ref::<std::io::Error>()
                    .and_then(|e| e.get_ref())
                    .and_then(
                        |e| e.downcast_ref::<crate::route_connector::OperationDeadlineExpired>()
                    )
                    .is_some_and(|e| e.deadline == preparation_end)),
                "{error:#}"
            );
            assert!(
                boot_time_ms().unwrap() < preparation_end + 500,
                "preparation borrowed the active stream lifetime"
            );
            assert!(
                session
                    .exchange(b"no replacement action", stream_end, 64)
                    .is_err()
            );
        }
        drop(session);
        server.join().unwrap();
    });
}

#[test]
fn application_acceptance_obeys_original_preparation_deadline() {
    application_preparation(false);
}

#[test]
fn accepted_application_keeps_its_later_stream_lifetime() {
    application_preparation(true);
}
