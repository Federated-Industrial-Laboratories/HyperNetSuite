// SPDX-License-Identifier: MIT
// Prepared history remains inert until the fresh result and its exact suffix are accepted.
use super::*;
use crate::{authority_domains as domains, route_profile as route, route_protocol, route_tls};
use rustls::{
    ServerConnection, StreamOwned,
    pki_types::{CertificateDer, pem::PemObject},
};
use std::{net::TcpListener, process::Command};

#[path = "../Pages/AuthorityPageContentTransportTests.rs"]
mod content_transport_tests;

fn prefetch_packet(f: &mut Fixture) -> (Vec<u8>, Vec<u8>) {
    let pending = f
        .context
        .prepare(request(), &f.signer, &mut f.store, &mut f.session, f.issued)
        .unwrap();
    let (_, _, packet) = packets(&pending, 161, wall(), &f.status_node);
    pending.cancel(&mut f.session).unwrap();
    let mut fields = wire::decode(&packet).unwrap().array(7).unwrap().to_vec();
    let checkpoint = wire::decode(fields[4].bytes().unwrap()).unwrap();
    let anchor = checkpoint.array(4).unwrap()[3].bytes().unwrap().to_vec();
    fields[3] = b(&wire::digest(&anchor));
    fields[6] = a(vec![]);
    (wire::encode(&a(fields)).unwrap(), anchor)
}
fn unavailable(f: &Fixture) -> Vec<u8> {
    wire::encode(&a(vec![
        V::Uint(42),
        V::Uint(1),
        f.store.prefix().scope().value(),
        V::Uint(2),
        V::Uint(1),
        V::Null,
        V::Null,
        V::Null,
        V::Null,
        a(vec![]),
    ]))
    .unwrap()
}
#[test]
fn prepared_direct_successor_requires_no_redundant_ancestry_request() {
    let mut f = Fixture::new();
    let socket = f.directory.0.join("DirectSuccessor.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let pending = f
        .context
        .prepare(request(), &f.signer, &mut f.store, &mut f.session, f.issued)
        .unwrap();
    let time = f.current.observe().unwrap().wall_ms;
    let scope = f.store.prefix().scope().clone();
    let (reply, anchor, _) = packets(&pending, 32, time, &f.status_node);
    let mut nodes = vec![f.status_node.clone()];
    for height in 2..32 {
        nodes.push(
            wire::encode(&a(vec![
                V::Uint(14),
                V::Uint(1),
                scope.value(),
                V::Uint(height),
                V::Uint(height),
                b(&wire::digest(nodes.last().unwrap())),
                b(&[80; 32]),
                V::Uint(time),
                b(&[81; 32]),
            ]))
            .unwrap(),
        );
    }
    nodes.push(anchor.clone());
    let response = wire::decode(&reply).unwrap();
    let response = record(&response, 42, 10).unwrap();
    pending
        .finish(
            CertifiedReply {
                node: anchor.clone(),
                certificate: response[7].bytes().unwrap().to_vec(),
                result: response[8].bytes().unwrap().to_vec(),
            },
            nodes[1..].to_vec(),
            &mut f.store,
            &mut f.session,
            &mut || Ok(f.current),
        )
        .unwrap();
    assert_eq!(f.store.prefix().height(), 32);
    assert!(f.store.tree_head().is_none());
    let statement = wire::encode(&a(vec![
        V::Uint(45),
        V::Uint(1),
        scope.value(),
        V::Uint(32),
        b(&wire::digest(&anchor)),
        V::Uint(time),
        b(f.store.prefix().policy_state()),
        V::Uint(32),
        b(&tree(&nodes)),
        V::Bool(false),
    ]))
    .unwrap();
    let checkpoint = wire::encode(&a(vec![
        V::Uint(46),
        V::Uint(1),
        b(&signed(&statement)),
        b(&anchor),
    ]))
    .unwrap();
    let history = wire::encode(&a(vec![
        V::Uint(47),
        V::Uint(1),
        scope.value(),
        V::Uint(32),
        b(&wire::digest(&anchor)),
        b(&wire::digest(&statement)),
        a(inclusion(&nodes, 31).iter().map(|value| b(value)).collect()),
        V::Uint(0),
        V::Null,
        a(vec![]),
    ]))
    .unwrap();
    let packet = wire::encode(&a(vec![
        V::Uint(54),
        V::Uint(1),
        scope.value(),
        b(&wire::digest(&anchor)),
        b(&checkpoint),
        b(&history),
        a(vec![]),
    ]))
    .unwrap();
    let observed = f.current.observe().unwrap();
    let advance = crate::authority_governance::UNCERTAINTY_MS + 1;
    let completed = ClockHealth::new(
        observed.wall_ms + advance,
        observed.boot_ms + advance,
        observed.boot_ms + 30000,
        100,
    )
    .unwrap()
    .frozen();
    let pending = f
        .context
        .prepare(
            request(),
            &f.signer,
            &mut f.store,
            &mut f.session,
            f.current,
        )
        .unwrap();
    let (reply, target) = certified(
        &pending,
        result_value(&pending),
        completed.observe().unwrap().wall_ms,
        wire::digest(&anchor),
        33,
    );
    let control = LocalControl::open(&socket)
        .unwrap()
        .with_prefetch_for_test(&f.store, &packet)
        .unwrap();
    let evidence = crate::authority_local_transport::HistoryEvidence::fetch(
        &control,
        f.store.prefix(),
        f.store.tree_head(),
        &target,
        pending.deadline,
    )
    .unwrap();
    assert_eq!(evidence.nodes, vec![target.clone()]);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let response = wire::decode(&reply).unwrap();
    let response = record(&response, 42, 10).unwrap();
    let result = pending
        .finish_evidence(
            CertifiedReply {
                node: target,
                certificate: response[7].bytes().unwrap().to_vec(),
                result: response[8].bytes().unwrap().to_vec(),
            },
            AncestryEvidence::from_shared(evidence),
            &mut f.store,
            &mut f.session,
            &mut || Ok(completed),
        )
        .unwrap();
    assert_eq!(result.prefix().height(), 33);
    assert_eq!(f.store.prefix().height(), 33);
}
#[test]
fn prepared_history_requires_quorum_exact_continuity_and_no_floor_mutation() {
    let mut f = Fixture::new();
    let (packet, _) = prefetch_packet(&mut f);
    let floor_path = f.directory.0.join("AuthorityFloor.json");
    let before = std::fs::read(&floor_path).unwrap();
    let prefix = f.store.prefix().clone();
    let pending = f.store.resume_ordinary().unwrap().unwrap().digest();
    assert!(LocalControl::validate_prefetch_for_test(&f.store, &packet).unwrap());
    assert!(!LocalControl::validate_prefetch_for_test(&f.store, &unavailable(&f)).unwrap());
    let fields = wire::decode(&packet).unwrap().array(7).unwrap().to_vec();
    for index in [2, 3, 5, 6] {
        let mut altered = fields.clone();
        altered[index] = match index {
            2 => {
                let mut scope = f.store.prefix().scope().clone();
                scope.network = [97; 32];
                scope.value()
            }
            3 => b(&[97; 32]),
            5 => {
                let mut history = wire::decode(fields[5].bytes().unwrap())
                    .unwrap()
                    .array(10)
                    .unwrap()
                    .to_vec();
                history[4] = b(&[97; 32]);
                b(&wire::encode(&a(history)).unwrap())
            }
            _ => a(vec![b(&[97; 32])]),
        };
        assert!(
            LocalControl::validate_prefetch_for_test(&f.store, &wire::encode(&a(altered)).unwrap())
                .is_err()
        );
    }
    for terminal in [false, true] {
        let mut altered = fields.clone();
        let mut package = wire::decode(fields[4].bytes().unwrap())
            .unwrap()
            .array(4)
            .unwrap()
            .to_vec();
        let envelope = wire::decode(package[2].bytes().unwrap()).unwrap();
        let mut statement = wire::decode(envelope.array(4).unwrap()[2].bytes().unwrap())
            .unwrap()
            .array(10)
            .unwrap()
            .to_vec();
        if terminal {
            statement[9] = V::Bool(true);
            package[2] = b(&signed(&wire::encode(&a(statement)).unwrap()));
        } else {
            let mut bad_signature = package[2].bytes().unwrap().to_vec();
            *bad_signature.last_mut().unwrap() ^= 1;
            package[2] = b(&bad_signature);
        }
        altered[4] = b(&wire::encode(&a(package)).unwrap());
        assert!(
            LocalControl::validate_prefetch_for_test(&f.store, &wire::encode(&a(altered)).unwrap())
                .is_err()
        );
    }
    for index in [6, 9] {
        let mut altered = fields.clone();
        let mut history = wire::decode(fields[5].bytes().unwrap())
            .unwrap()
            .array(10)
            .unwrap()
            .to_vec();
        history[index] = a(vec![b(&[97; 32])]);
        altered[5] = b(&wire::encode(&a(history)).unwrap());
        assert!(
            LocalControl::validate_prefetch_for_test(&f.store, &wire::encode(&a(altered)).unwrap())
                .is_err()
        );
    }
    assert_eq!(std::fs::read(floor_path).unwrap(), before);
    assert_eq!(f.store.prefix(), &prefix);
    assert_eq!(
        f.store.resume_ordinary().unwrap().unwrap().digest(),
        pending
    );
    assert!(f.store.tree_head().is_none());
}

struct Certificate {
    identity: route::Identity,
    pem: Vec<u8>,
    key: Vec<u8>,
}
fn certificates(root: &Path) -> (Certificate, Certificate) {
    let run = |arguments: &[&str]| {
        let output = Command::new("openssl")
            .current_dir(root)
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "test certificate generation failed"
        );
    };
    run(&[
        "req",
        "-x509",
        "-newkey",
        "ed25519",
        "-nodes",
        "-keyout",
        "Root.key",
        "-out",
        "Root.pem",
        "-days",
        "1",
        "-subj",
        "/CN=HyperNetHistoryTestRoot",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
    ]);
    let ca = std::fs::read_to_string(root.join("Root.pem")).unwrap();
    let leaf = |name: &str, service| {
        run(&[
            "req",
            "-new",
            "-newkey",
            "ed25519",
            "-nodes",
            "-keyout",
            "Leaf.key",
            "-out",
            "Leaf.csr",
            "-subj",
            &format!("/CN={name}"),
        ]);
        std::fs::write(root.join("Leaf.txt"), format!("subjectAltName=DNS:{name}\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n")).unwrap();
        run(&[
            "x509",
            "-req",
            "-in",
            "Leaf.csr",
            "-CA",
            "Root.pem",
            "-CAkey",
            "Root.key",
            "-CAcreateserial",
            "-out",
            "Leaf.pem",
            "-days",
            "1",
            "-extfile",
            "Leaf.txt",
        ]);
        let pem = std::fs::read(root.join("Leaf.pem")).unwrap();
        let key = std::fs::read(root.join("Leaf.key")).unwrap();
        let der = CertificateDer::pem_slice_iter(&pem)
            .next()
            .unwrap()
            .unwrap()
            .as_ref()
            .to_vec();
        Certificate {
            identity: route::Identity {
                service,
                server_name: name.into(),
                transport_key: crate::runtime_manifest::leaf_key(&der).unwrap(),
                leaf_der: der,
                certificate_authority_pem: ca.clone(),
            },
            pem,
            key,
        }
    };
    (
        leaf("relay.history.test", [91; 32]),
        leaf("service.history.test", [92; 32]),
    )
}
fn framed_read(stream: &mut impl Read) -> Vec<u8> {
    let mut size = [0; 4];
    stream.read_exact(&mut size).unwrap();
    let size = u32::from_be_bytes(size) as usize;
    assert!((1..=wire::MAXIMUM).contains(&size));
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).unwrap();
    bytes
}
fn framed_send(stream: &mut impl Write, bytes: &[u8]) {
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(bytes).unwrap();
    stream.flush().unwrap();
}

#[test]
fn private_tls_operation_expiry_reaches_bounded_authority_recovery() {
    use crate::authority_local_transport::{RequestDeadlineExpired, retry_expired_exchange};
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
        relay: reference(165, relay.identity.service, [93; 32]),
        destination: reference(165, service.identity.service, [94; 32]),
        possession: possession.verifying_key().to_bytes(),
        sponsor: f.signer.verifying_key().to_bytes(),
        grant: reference(102, [95; 32], [96; 32]),
        action: 0,
        scope: (0, scope.network),
        connections: 3,
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
    let profile_path = f.directory.0.join("RecoveryClient.json");
    files::write_new(&profile_path, b"{}").unwrap();
    let unavailable = unavailable(&f);
    std::thread::scope(|threads| {
        let server = threads.spawn(|| {
            for attempt in 0..3 {
                let end = std::time::Instant::now() + Duration::from_secs(4);
                let socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                std::time::Instant::now() < end,
                                "route recovery did not reconnect"
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
                assert_eq!(
                    open.voucher,
                    wire::encode(&crate::authority_membership::reference(&voucher.reference))
                        .unwrap()
                );
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
                let query = wire::decode(&framed_read(&mut inner)).unwrap();
                assert_eq!(record(&query, 41, 5).unwrap()[3], V::Uint(4));
                framed_send(&mut inner, &unavailable);
                if attempt < 2 {
                    assert_eq!(framed_read(&mut inner), b"deadline recovery");
                }
                if attempt != 1 {
                    // Failure must close both TLS layers without another application frame.
                    match inner.read(&mut [0; 1]) {
                        Ok(0) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
                        other => panic!("expired route was not closed: {other:?}"),
                    }
                } else {
                    framed_send(&mut inner, b"recovered");
                }
            }
        });
        let prepare = |setup_deadline| {
            let channel = crate::route_connector::Session::connect(
                &profile,
                &possession,
                setup_deadline,
                &|| false,
            )?;
            let endpoint = crate::private_route_client::Endpoint {
                format: "HyperNetRelayEndpoint/1".into(),
                profile: profile_path.clone(),
                route: profile.clone(),
            };
            let route = crate::private_route_client::Prepared::from_channel(
                endpoint,
                channel,
                setup_deadline,
            );
            LocalControl::prepared_for_test(route, &f.store)
        };
        let mut attempts = 0;
        let response = retry_expired_exchange(|| {
            attempts += 1;
            let control = prepare(boot_time_ms()? + 10000)?;
            let deadline = boot_time_ms()? + 250;
            let result = control.exchange(b"deadline recovery", deadline);
            if attempts == 1 {
                assert_eq!(
                    result
                        .as_ref()
                        .err()
                        .unwrap()
                        .downcast_ref::<RequestDeadlineExpired>()
                        .unwrap()
                        .deadline,
                    deadline
                );
            }
            drop(control);
            Ok((deadline, result))
        })
        .unwrap();
        assert_eq!(response, b"recovered");
        assert_eq!(attempts, 2);
        // An already-expired operation must not hide the same connection's exhausted total budget.
        let total_deadline = boot_time_ms().unwrap() + 1000;
        let control = prepare(total_deadline).unwrap();
        std::thread::sleep(Duration::from_millis(
            total_deadline.saturating_sub(boot_time_ms().unwrap()) + 1,
        ));
        let mut calls = 0;
        let failure = retry_expired_exchange(|| {
            calls += 1;
            Ok((
                total_deadline,
                control.exchange(b"deadline recovery", total_deadline),
            ))
        })
        .unwrap_err();
        assert_eq!(calls, 1);
        assert!(failure.downcast_ref::<RequestDeadlineExpired>().is_none());
        assert_eq!(
            failure.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::TimedOut
        );
        drop(control);
        server.join().unwrap();
    });
}

#[test]
fn remote_history_preparation_exceeds_five_seconds_before_fresh_challenge_on_one_route() {
    let mut f = Fixture::new();
    let (prefetch, anchor) = prefetch_packet(&mut f);
    let packet = wire::decode(&prefetch).unwrap();
    let checkpoint = crate::authority_history::verify_checkpoint(
        f.store.descriptor(),
        packet.array(7).unwrap()[4].bytes().unwrap(),
    )
    .unwrap();
    let prefix = f.store.prefix().clone();
    let floor_bytes = std::fs::read(f.directory.0.join("AuthorityFloor.json")).unwrap();
    let pending_digest = f.store.resume_ordinary().unwrap().unwrap().digest();
    let (relay, service) = certificates(&f.directory.0);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let possession = SigningKey::from_bytes(&[99; 32]);
    let scope = f.store.prefix().scope().clone();
    let unavailable_packet = unavailable(&f);
    let reference = |kind, id, digest| VersionRef {
        kind,
        id,
        generation: 1,
        digest,
    };
    let voucher = domains::routes::Voucher {
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
        duration_ms: 30000,
        idle_ms: 15000,
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
    let profile_path = f.directory.0.join("Client.json");
    files::write_new(&profile_path, b"{}").unwrap();
    let endpoint = crate::private_route_client::Endpoint {
        format: "HyperNetRelayEndpoint/1".into(),
        profile: profile_path,
        route: profile.clone(),
    };
    let pool = crate::private_route_client::AuthorityPool::shared();
    let context = &f.context;
    std::thread::scope(|threads| {
        let server = threads.spawn(|| {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(20)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(20)))
                .unwrap();
            socket.set_nodelay(true).unwrap();
            let mut outer = StreamOwned::new(ServerConnection::new(relay_config).unwrap(), socket);
            let open = route_protocol::Open::parse(&framed_read(&mut outer)).unwrap();
            assert_eq!(
                open.voucher,
                wire::encode(&crate::authority_membership::reference(&voucher.reference)).unwrap()
            );
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
                    1,
                )
                .unwrap(),
            );
            let bytes = framed_read(&mut inner);
            let frame = wire::decode(&bytes).unwrap();
            let frame = record(&frame, 41, 5).unwrap();
            assert_eq!(frame[3].uint().unwrap(), 4);
            assert_eq!(
                wire::decode(frame[4].bytes().unwrap())
                    .unwrap()
                    .array(5)
                    .unwrap()[2],
                V::Null
            );
            std::thread::sleep(Duration::from_millis(5200));
            framed_send(&mut inner, &prefetch);
            let prepared_at = wall();
            let packet = framed_read(&mut inner);
            let (ordered, intent, challenge) = submitted(&packet);
            let fresh = Challenge::from_signed(&challenge).unwrap();
            assert!(fresh.created_at_ms >= prepared_at.saturating_sub(1));
            assert_eq!(fresh.expires_at_ms - fresh.created_at_ms, 5000);
            let parsed = Intent::from_signed(&intent).unwrap();
            let pending = Prepared {
                context,
                request: request(),
                target: context
                    .governance
                    .versions()
                    .into_iter()
                    .find(|v| v.kind == 100)
                    .unwrap(),
                expected: parsed.expected,
                intent,
                challenge,
                ordered,
                deadline: boot_time_ms().unwrap() + 5000,
            };
            framed_send(
                &mut inner,
                &wire::encode(&a(vec![
                    V::Uint(42),
                    V::Uint(1),
                    scope.value(),
                    V::Uint(0),
                    V::Uint(0),
                    b(&wire::digest(&pending.ordered)),
                    V::Null,
                    V::Null,
                    V::Null,
                    a(vec![]),
                ]))
                .unwrap(),
            );
            let poll = wire::decode(&framed_read(&mut inner)).unwrap();
            let poll = record(&poll, 41, 5).unwrap();
            assert_eq!(poll[3].uint().unwrap(), 1);
            assert_eq!(poll[4].bytes().unwrap(), wire::digest(&pending.ordered));
            let (reply, target) = certified(
                &pending,
                result_value(&pending),
                wall(),
                wire::digest(&anchor),
                161,
            );
            framed_send(&mut inner, &reply);
            let bytes = framed_read(&mut inner);
            let frame = wire::decode(&bytes).unwrap();
            let frame = record(&frame, 41, 5).unwrap();
            assert_eq!(
                frame[3].uint().unwrap(),
                3,
                "fresh result must fetch only the short suffix"
            );
            let query = wire::decode(frame[4].bytes().unwrap()).unwrap();
            assert_eq!(
                query,
                a(vec![
                    V::Uint(160),
                    b(&wire::digest(&anchor)),
                    b(&wire::digest(&target))
                ])
            );
            framed_send(
                &mut inner,
                &wire::encode(&a(vec![
                    V::Uint(43),
                    V::Uint(1),
                    scope.value(),
                    a(vec![b(&target)]),
                ]))
                .unwrap(),
            );
            listener.set_nonblocking(true).unwrap();
            assert!(
                listener.accept().is_err(),
                "proof retrieval must not open another admitted stream"
            );
            // Exact completed-floor reuse must not send another speculative checkpoint query.
            assert_eq!(framed_read(&mut inner), b"reused authority connection");
            framed_send(&mut inner, b"same admitted connection");
            let packet = framed_read(&mut inner);
            let (ordered, intent, challenge) = submitted(&packet);
            let parsed = Intent::from_signed(&intent).unwrap();
            let pending = Prepared {
                context,
                request: request(),
                target: context
                    .governance
                    .versions()
                    .into_iter()
                    .find(|v| v.kind == 100)
                    .unwrap(),
                expected: parsed.expected,
                intent,
                challenge,
                ordered,
                deadline: boot_time_ms().unwrap() + 5000,
            };
            let (reply, _) = certified(
                &pending,
                result_value(&pending),
                mature(&pending.challenge),
                wire::digest(&target),
                162,
            );
            framed_send(&mut inner, &reply);
            // Another verified result advances the local floor while this route is pooled.
            let query = wire::decode(&framed_read(&mut inner)).unwrap();
            let fields = record(&query, 41, 5).unwrap();
            assert_eq!(fields[3], V::Uint(4));
            let query = wire::decode(fields[4].bytes().unwrap()).unwrap();
            let query = query.array(5).unwrap();
            assert_eq!(query[0], V::Uint(163));
            assert_eq!(query[2], V::Null);
            assert_eq!(query[3], V::Uint(160));
            framed_send(&mut inner, &unavailable_packet);
            // Pending recovery is also cold; malformed history must discard the connection.
            let query = wire::decode(&framed_read(&mut inner)).unwrap();
            assert_eq!(record(&query, 41, 5).unwrap()[3], V::Uint(4));
            framed_send(&mut inner, b"invalid checkpoint response");
            match inner.read(&mut [0; 1]) {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
                other => panic!("failed history validation retained its connection: {other:?}"),
            }
        });
        let deadline = boot_time_ms().unwrap() + 30000;
        let channel =
            crate::route_connector::Session::connect(&profile, &possession, deadline, &|| false)
                .unwrap();
        let route = crate::private_route_client::Prepared::from_channel(
            endpoint.clone(),
            channel,
            deadline,
        )
        .in_pool(&pool);
        let start = boot_time_ms().unwrap();
        let control = LocalControl::prepared_for_test(route, &f.store).unwrap();
        use std::os::unix::fs::MetadataExt;
        let observation = crate::private_route_client::observation_path(&endpoint.profile).unwrap();
        let observed_inode = std::fs::metadata(&observation).unwrap().ino();
        let observed_bytes = std::fs::read(&observation).unwrap();
        assert!(boot_time_ms().unwrap() - start >= 5000);
        assert_eq!(f.store.prefix(), &prefix);
        assert_eq!(
            std::fs::read(f.directory.0.join("AuthorityFloor.json")).unwrap(),
            floor_bytes
        );
        assert_eq!(
            f.store.resume_ordinary().unwrap().unwrap().digest(),
            pending_digest
        );
        assert!(
            crate::authority_local_transport::HistoryEvidence::fetch(
                &control,
                &checkpoint.prefix(),
                None,
                &anchor,
                deadline
            )
            .is_err()
        );
        assert!(
            crate::authority_local_transport::HistoryEvidence::fetch(
                &control,
                &prefix,
                Some(checkpoint.head()),
                &anchor,
                deadline
            )
            .is_err()
        );
        let result = context
            .inspect_prepared(
                &control,
                request(),
                &f.signer,
                &mut f.store,
                &mut f.session,
                live_clock,
            )
            .unwrap();
        assert_eq!(result.prefix().height(), 161);
        assert_eq!(f.store.tree_head().unwrap().size(), 160);
        assert!(f.store.resume_ordinary().unwrap().is_none());
        assert!(!LocalControl::validate_prefetch_for_test(&f.store, &unavailable_packet).unwrap());
        control.retain(&f.store);
        // The next TUI request can run on another worker thread while its command owns the pool.
        let route = threads
            .spawn(|| {
                crate::private_route_client::AuthorityPool::take(&pool, &endpoint)
                    .unwrap()
                    .unwrap()
            })
            .join()
            .unwrap();
        assert_eq!(route.setup_deadline(), deadline);
        assert!(route.reused());
        let control = LocalControl::prepared_for_test(route, &f.store).unwrap();
        assert_eq!(
            control
                .exchange(b"reused authority connection", deadline)
                .unwrap(),
            b"same admitted connection"
        );
        assert_eq!(
            std::fs::metadata(&observation).unwrap().ino(),
            observed_inode
        );
        assert_eq!(std::fs::read(&observation).unwrap(), observed_bytes);
        let result = context
            .inspect_prepared(
                &control,
                request(),
                &f.signer,
                &mut f.store,
                &mut f.session,
                live_clock,
            )
            .unwrap();
        assert_eq!(result.prefix().height(), 162);
        control.retain(&f.store);
        let pending = context
            .prepare(
                request(),
                &f.signer,
                &mut f.store,
                &mut f.session,
                live_clock().unwrap(),
            )
            .unwrap();
        let (reply, target) = certified(
            &pending,
            result_value(&pending),
            mature(&pending.challenge),
            *f.store.prefix().node(),
            163,
        );
        let reply = wire::decode(&reply).unwrap();
        let reply = record(&reply, 42, 10).unwrap();
        pending
            .finish(
                CertifiedReply {
                    node: target.clone(),
                    certificate: reply[7].bytes().unwrap().to_vec(),
                    result: reply[8].bytes().unwrap().to_vec(),
                },
                vec![target],
                &mut f.store,
                &mut f.session,
                &mut live_clock,
            )
            .unwrap();
        assert_eq!(f.store.prefix().height(), 163);
        let route = crate::private_route_client::AuthorityPool::take(&pool, &endpoint)
            .unwrap()
            .unwrap();
        let control = LocalControl::prepared_for_test(route, &f.store).unwrap();
        let pending = context
            .prepare(
                request(),
                &f.signer,
                &mut f.store,
                &mut f.session,
                live_clock().unwrap(),
            )
            .unwrap();
        let pending_digest = f.store.resume_ordinary().unwrap().unwrap().digest();
        control.retain(&f.store);
        let route = crate::private_route_client::AuthorityPool::take(&pool, &endpoint)
            .unwrap()
            .unwrap();
        assert!(LocalControl::prepared_for_test(route, &f.store).is_err());
        assert!(
            crate::private_route_client::AuthorityPool::take(&pool, &endpoint)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            f.store.resume_ordinary().unwrap().unwrap().digest(),
            pending_digest
        );
        pending.cancel(&mut f.session).unwrap();
        server.join().unwrap();
    });
}
