// SPDX-License-Identifier: MIT
// Prepared history remains inert until the fresh result and its exact suffix are accepted.
use super::*;
use crate::{authority_domains as domains, route_profile as route, route_protocol, route_tls};
use rustls::{
    ServerConnection, StreamOwned,
    pki_types::{CertificateDer, pem::PemObject},
};
use std::{net::TcpListener, process::Command};

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
        });
        let deadline = boot_time_ms().unwrap() + 30000;
        let channel =
            crate::route_connector::Session::connect(&profile, &possession, deadline, &|| false)
                .unwrap();
        let route =
            crate::private_route_client::Prepared::from_channel(endpoint, channel, deadline);
        let start = boot_time_ms().unwrap();
        let control = LocalControl::prepared_for_test(route, &f.store).unwrap();
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
        server.join().unwrap();
    });
}
