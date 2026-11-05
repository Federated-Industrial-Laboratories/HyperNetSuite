// SPDX-License-Identifier: MIT
// Caller bounds cover cold authority admission and history without shortening retained transport.
use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

fn authority_preparation(stage: &str) {
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
        protocol: 1,
        assurance: route::Assurance::Independent,
        minimum_assurance: route::Assurance::Independent,
        limits,
        voucher: voucher.bytes.clone(),
    };
    let relay_config = route_tls::server(&relay.identity, &relay.pem, &relay.key).unwrap();
    let final_config = route_tls::server(&service.identity, &service.pem, &service.key).unwrap();
    let profile_path = f.directory.0.join("BudgetClient.json");
    files::write_new(&profile_path, b"{}").unwrap();
    let unavailable = unavailable(&f);
    let cancel = Arc::new(AtomicBool::new(false));
    std::thread::scope(|threads| {
        let server = threads.spawn(|| {
            let end = std::time::Instant::now() + Duration::from_secs(3);
            let socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(std::time::Instant::now() < end);
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("authority fixture accept failed: {error}"),
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
            if stage == "admission" {
                closed(&mut outer);
                return;
            }
            let binding = wire::digest(&open.binding(nonce, exporter).unwrap());
            framed_send(&mut outer, &route_protocol::ready(binding, limits).unwrap());
            let mut inner = StreamOwned::new(ServerConnection::new(final_config).unwrap(), outer);
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
            let query = wire::decode(&framed_read(&mut inner)).unwrap();
            assert_eq!(record(&query, 41, 5).unwrap()[3], V::Uint(4));
            if stage == "cancel" {
                cancel.store(true, Ordering::Release);
            }
            if stage != "retained" {
                closed(&mut inner);
                return;
            }
            framed_send(&mut inner, &unavailable);
            assert_eq!(framed_read(&mut inner), b"after caller deadline");
            framed_send(&mut inner, b"same admitted connection");
        });
        let caller_end = boot_time_ms().unwrap() + if stage == "cancel" { 5000 } else { 1000 };
        let session_end = boot_time_ms().unwrap() + 10000;
        let signal = cancel.clone();
        let budget =
            crate::authority_inspection::read_client::RetryBudget::new(caller_end, move || {
                signal.load(Ordering::Acquire)
            });
        let endpoint = crate::private_route_client::Endpoint {
            format: "HyperNetRelayEndpoint/1".into(),
            profile: profile_path,
            route: profile.clone(),
        };
        let pool = crate::private_route_client::AuthorityPool::shared();
        let result = crate::route_connector::Session::connect_with_budget(
            &profile,
            &possession,
            session_end,
            session_end,
            &|| false,
            Some(budget.transport()),
        )
        .and_then(|session| {
            let prepared = crate::private_route_client::Prepared::from_channel(
                endpoint.clone(),
                session,
                session_end,
            )
            .in_pool(&pool);
            LocalControl::prepared_for_test(prepared, &f.store)
        });
        if stage == "retained" {
            result.unwrap().retain(&f.store);
            std::thread::sleep(Duration::from_millis(
                caller_end.saturating_sub(boot_time_ms().unwrap()) + 10,
            ));
            let prepared = crate::private_route_client::AuthorityPool::take(&pool, &endpoint)
                .unwrap()
                .unwrap();
            let control = LocalControl::from_prepared_test(prepared);
            assert_eq!(
                control
                    .exchange(b"after caller deadline", boot_time_ms().unwrap() + 1000)
                    .unwrap(),
                b"same admitted connection"
            );
        } else {
            let error = result
                .err()
                .expect("withheld authority preparation must fail");
            if stage == "cancel" {
                assert!(
                    format!("{error:#}").contains("application preparation cancelled"),
                    "{error:#}"
                );
                assert!(boot_time_ms().unwrap() + 3000 < caller_end);
            } else {
                assert!(
                    error.chain().any(|e| e
                        .downcast_ref::<std::io::Error>()
                        .and_then(|e| e.get_ref())
                        .and_then(|e| e
                            .downcast_ref::<crate::route_connector::OperationDeadlineExpired>())
                        .is_some_and(|e| e.deadline == caller_end)),
                    "{error:#}"
                );
                assert!(boot_time_ms().unwrap() < caller_end + 500);
            }
        }
        server.join().unwrap();
        assert!(
            matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "preparation must not reconnect"
        );
    });
}
fn closed(stream: &mut impl Read) {
    match stream.read(&mut [0; 1]) {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
        other => panic!("caller bound did not close transport: {other:?}"),
    }
}
#[test]
fn authority_admission_uses_original_caller_deadline() {
    authority_preparation("admission");
}
#[test]
fn authority_history_uses_original_caller_deadline() {
    authority_preparation("history");
}
#[test]
fn authority_history_observes_caller_cancellation() {
    authority_preparation("cancel");
}
#[test]
fn completed_caller_budget_does_not_shorten_retained_authority_lifetime() {
    authority_preparation("retained");
}
