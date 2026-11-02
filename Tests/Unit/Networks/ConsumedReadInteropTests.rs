// SPDX-License-Identifier: MIT
// The paired Core fixture retains and removes the exact result consumed through native Suite TLS.
use super::*;
use std::os::{fd::AsRawFd, unix::net::UnixStream};
use std::process::Child;

struct Collector(Child);
impl Drop for Collector {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}
fn private_child(root: &Path, name: &str) -> std::path::PathBuf {
    let path = root.join(name);
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path
}
#[test]
#[ignore = "requires HYPERNET_CORE_TEST_BINARY from the matching Core source"]
fn consumed_suite_read_releases_actual_core_collection_over_one_admitted_tls_session() {
    let binary =
        std::env::var_os("HYPERNET_CORE_TEST_BINARY").expect("matching Core test binary required");
    let directory = Directory::new();
    let (relay, service) = certificates(&directory.0);
    let collector_root = private_child(&directory.0, "Collector");
    let output = std::fs::File::create(directory.0.join("Collector.log")).unwrap();
    let mut collector = Collector(Command::new(binary)
        .args(["--exact", "consensus::runtime::tests::fresh_reads::interop::consumed_read_collector_for_suite_interop", "--ignored", "--test-threads=1", "--nocapture"])
        .env("HYPERNET_READ_ACK_FIXTURE", &collector_root)
        .stdout(output.try_clone().unwrap()).stderr(output).spawn().unwrap());
    let end = std::time::Instant::now() + Duration::from_secs(10);
    while !collector_root.join("Ready").exists() {
        assert!(
            collector.0.try_wait().unwrap().is_none(),
            "collector failed: {}",
            std::fs::read_to_string(directory.0.join("Collector.log")).unwrap()
        );
        assert!(
            std::time::Instant::now() < end,
            "collector setup exceeded its bound"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let bootstrap = crate::trust_bootstrap::check(
        &std::fs::read(collector_root.join("Bootstrap.cbor")).unwrap(),
        true,
        wall(),
    )
    .unwrap();
    let scope = bootstrap.descriptor().scope().clone();
    let signer = SigningKey::from_bytes(&[5; 32]);
    let health = || {
        let boot = boot_time_ms().unwrap();
        ClockHealth::new(wall(), boot, boot + 1000, 1)
            .unwrap()
            .frozen()
    };
    let mut store = Store::initialise(
        &private_child(&directory.0, "Consumer"),
        bootstrap.descriptor().clone(),
        signer.verifying_key().to_bytes(),
        health(),
    )
    .unwrap();
    let possession = SigningKey::from_bytes(&[99; 32]);
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
        sponsor: signer.verifying_key().to_bytes(),
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
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
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
        voucher: voucher.bytes,
    };
    let relay_config = route_tls::server(&relay.identity, &relay.pem, &relay.key).unwrap();
    let mut final_config =
        route_tls::server(&service.identity, &service.pem, &service.key).unwrap();
    std::sync::Arc::make_mut(&mut final_config).alpn_protocols =
        vec![route_tls::READ_ACK_ALPN.to_vec(), route_tls::ALPN.to_vec()];
    std::thread::scope(|threads| {
        let server = threads.spawn(|| {
            let end = std::time::Instant::now() + Duration::from_secs(5);
            let socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < end,
                            "admitted TLS connection absent"
                        );
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("TLS accept: {error}"),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
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
            let parent = crate::transfer_files::private_directory(&collector_root).unwrap();
            let socket = Path::new("/proc/self/fd")
                .join(parent.as_raw_fd().to_string())
                .join("Control.sock");
            // Real TLS frames are forwarded unchanged to the actual Core Driver.
            for expected in [6, 8, 7] {
                let packet = framed_read(&mut inner);
                assert_eq!(
                    wire::decode(&packet).unwrap().array(5).unwrap()[3],
                    V::Uint(expected)
                );
                let mut local = UnixStream::connect(&socket).unwrap();
                local
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                local
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                framed_send(&mut local, &packet);
                framed_send(&mut inner, &framed_read(&mut local));
            }
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        });
        let channel = crate::route_connector::Session::connect(
            &profile,
            &possession,
            boot_time_ms().unwrap() + 10000,
            &|| false,
        )
        .unwrap();
        let profile_file = directory.0.join("Profile.json");
        std::fs::write(&profile_file, b"{}").unwrap();
        let endpoint = crate::private_route_client::Endpoint {
            format: "HyperNetRelayEndpoint/1".into(),
            profile: profile_file,
            route: profile,
        };
        let prepared = crate::private_route_client::Prepared::from_channel(
            endpoint,
            channel,
            boot_time_ms().unwrap() + 10000,
        );
        let control = crate::authority_local_transport::LocalControl::from_prepared_test(prepared);
        let mut session = Session::new().unwrap();
        let request = crate::authority_read::Request::sign(
            &scope,
            &signer,
            signer.verifying_key().to_bytes(),
            [67; 32],
            0,
            crate::authority_read::Query::PolicyContext,
        )
        .unwrap();
        let now = health();
        let deadline = now.observe().unwrap().boot_ms + 5000;
        let challenge = session
            .issue_read(&request, &signer, [67; 32], 5000, now)
            .unwrap();
        let id = crate::authority_read::read_id(&request, &challenge).unwrap();
        let command = |operation, bytes: Vec<u8>| {
            wire::encode(&a(vec![
                V::Uint(41),
                V::Uint(1),
                scope.value(),
                V::Uint(operation),
                b(&bytes),
            ]))
            .unwrap()
        };
        let submitted = wire::encode(&a(vec![b(&request), b(&challenge)])).unwrap();
        let reply = control
            .exchange_limit(&command(6, submitted), deadline, 4 * wire::MAXIMUM)
            .unwrap();
        let value = wire::decode(&reply).unwrap();
        let fields = value.array(10).unwrap();
        let node = fields[6].bytes().unwrap();
        let verified = crate::authority_read::verify_response(
            bootstrap.descriptor(),
            &request,
            &challenge,
            crate::authority_read::Response {
                node,
                certificate: fields[7].bytes().unwrap(),
                result: fields[8].bytes().unwrap(),
                ancestry: &[node.to_vec()],
            },
            |_, result, _| crate::authority_read::result_versions(result),
        )
        .unwrap();
        let (result, consumed) = store
            .accept_read_consumed(verified, &mut session, &mut || Ok(health()), 0, |_, _| {
                Ok(42)
            })
            .unwrap();
        assert_eq!(result, 42);
        control.acknowledge_read(&consumed, &signer, deadline);
        let absent = control
            .exchange_limit(&command(7, id.to_vec()), deadline, 4 * wire::MAXIMUM)
            .unwrap();
        let absent = wire::decode(&absent).unwrap();
        let fields = absent.array(10).unwrap();
        assert_eq!(
            (fields[3].uint().unwrap(), fields[4].uint().unwrap()),
            (2, 1)
        );
        assert!(store.resume_ordinary().unwrap().is_none());
        server.join().unwrap();
    });
    let end = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = collector.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "collector failed: {}",
                std::fs::read_to_string(directory.0.join("Collector.log")).unwrap()
            );
            break;
        }
        assert!(std::time::Instant::now() < end, "collector did not finish");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(collector_root.join("Released").exists());
}
