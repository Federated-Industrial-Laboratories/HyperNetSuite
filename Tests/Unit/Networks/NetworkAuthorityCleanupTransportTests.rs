// SPDX-License-Identifier: MIT
// Negotiated cleanup preserves one admitted transport across supported and legacy authorities.
use super::*;
use crate::networks::authority_connector::{exchange_cleanup, packet};

#[test]
fn authority_connector_cleanup_negotiates_without_probe_or_legacy_session_churn() {
    let f = Fixture::new();
    let (relay, service) = certificates(&f.directory.0);
    let possession = SigningKey::from_bytes(&[99; 32]);
    let scope = f.store.prefix().scope().clone();
    let reference = |kind, id| VersionRef {
        kind,
        id,
        generation: 1,
        digest: [93; 32],
    };
    let voucher = domains::routes::Voucher {
        baseline: None,
        relay: reference(165, relay.identity.service),
        destination: reference(165, service.identity.service),
        possession: possession.verifying_key().to_bytes(),
        sponsor: f.signer.verifying_key().to_bytes(),
        grant: reference(102, [95; 32]),
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
    let signed = wire::sign_envelope(
        &wire::encode(&a(vec![
            V::Uint(63),
            V::Uint(1),
            scope.value(),
            b(&[4; 32]),
            b(&[5; 32]),
            b(&[6; 32]),
            V::Uint(wall() + 4000),
        ]))
        .unwrap(),
        &f.signer,
    )
    .unwrap();
    let request = wire::encode(&a(vec![
        V::Uint(41),
        V::Uint(1),
        scope.value(),
        V::Uint(8),
        b(&signed),
    ]))
    .unwrap();
    let cleanup = packet::validate(scope.network, scope.incarnation, &request)
        .unwrap()
        .unwrap();
    for supported in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let profile = route::Profile {
            version: 1,
            network: scope.network,
            incarnation: scope.incarnation,
            relay_address: listener.local_addr().unwrap(),
            relay: relay.identity.clone(),
            destination: service.identity.clone(),
            domain: "Destination".into(),
            relay_domain: "Relay".into(),
            protocol: 1,
            assurance: route::Assurance::Independent,
            minimum_assurance: route::Assurance::Independent,
            limits,
            voucher: voucher.bytes.clone(),
        };
        let relay_config = route_tls::server(&relay.identity, &relay.pem, &relay.key).unwrap();
        let mut final_config =
            route_tls::server(&service.identity, &service.pem, &service.key).unwrap();
        if supported {
            std::sync::Arc::make_mut(&mut final_config).alpn_protocols =
                vec![route_tls::READ_ACK_ALPN.to_vec(), route_tls::ALPN.to_vec()];
        }
        std::thread::scope(|threads| {
            let server = threads.spawn(|| {
                let end = std::time::Instant::now() + Duration::from_secs(4);
                let socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                std::time::Instant::now() < end,
                                "connector did not open its one admitted session"
                            );
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("private TLS fixture accept failed: {error}"),
                    }
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                socket.set_nodelay(true).unwrap();
                let mut outer =
                    StreamOwned::new(ServerConnection::new(relay_config.clone()).unwrap(), socket);
                let open = route_protocol::Open::parse(&framed_read(&mut outer)).unwrap();
                assert_eq!(outer.conn.alpn_protocol(), Some(route_tls::ALPN));
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
                let mut inner =
                    StreamOwned::new(ServerConnection::new(final_config.clone()).unwrap(), outer);
                framed_send(
                    &mut inner,
                    &route_protocol::endpoint_ready(
                        scope.network,
                        scope.incarnation,
                        service.identity.service,
                        1,
                    )
                    .unwrap(),
                );
                assert_eq!(framed_read(&mut inner), b"ordinary before cleanup");
                framed_send(&mut inner, b"first result");
                if supported {
                    assert_eq!(framed_read(&mut inner), request);
                    let mut fields = wire::decode(&cleanup.not_released().unwrap())
                        .unwrap()
                        .array(7)
                        .unwrap()
                        .to_vec();
                    fields[6] = V::Bool(true);
                    framed_send(&mut inner, &wire::encode(&a(fields)).unwrap());
                }
                // The legacy endpoint sees no cleanup or capability probe between ordinary requests.
                assert_eq!(framed_read(&mut inner), b"ordinary after cleanup");
                framed_send(&mut inner, b"second result");
                assert_eq!(
                    listener.accept().unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
            });
            let deadline = boot_time_ms().unwrap() + 5000;
            let mut session =
                crate::route_connector::Session::connect(&profile, &possession, deadline, &|| {
                    false
                })
                .unwrap();
            assert_eq!(session.read_acknowledgements(), supported);
            assert_eq!(
                session
                    .exchange(b"ordinary before cleanup", deadline, 1024)
                    .unwrap(),
                b"first result"
            );
            let reply = exchange_cleanup(Some(&mut session), &request, deadline, &cleanup).unwrap();
            cleanup.receipt(&reply).unwrap();
            assert_eq!(
                wire::decode(&reply).unwrap().array(7).unwrap()[6],
                V::Bool(supported)
            );
            assert_eq!(
                session
                    .exchange(b"ordinary after cleanup", deadline, 1024)
                    .unwrap(),
                b"second result"
            );
            server.join().unwrap();
        });
    }
}
