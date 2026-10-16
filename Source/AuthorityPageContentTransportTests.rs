// SPDX-License-Identifier: MIT
// Content transport reuse keeps profile validation and explicit successful completion at every checkout.
use super::*;
use crate::{
    authority_deployment_tests as deployment,
    authority_domains::page::{self, content},
    authority_pages::media::Transport,
    private_route_client::{ContentPool, Endpoint},
    trust_bootstrap as bootstrap,
};
use sha2::Digest as _;

fn content_profile(
    root: &Path,
    relay: &Certificate,
    service: &Certificate,
    address: std::net::SocketAddr,
    possession: &SigningKey,
) -> (Endpoint, Vec<u8>) {
    let public = |seed| hex::encode(deployment::key(seed).verifying_key().to_bytes());
    let original = deployment::Fixture::new();
    let checked = bootstrap::inspect(&original.bootstrap, true).unwrap();
    let summary = checked.summary;
    let mut route = summary.route;
    route.relay_service = hex::encode(relay.identity.service);
    route.relay_transport_key = hex::encode(relay.identity.transport_key);
    route.admission_service = hex::encode(service.identity.service);
    route.admission_transport_key = hex::encode(service.identity.transport_key);
    let spec = bootstrap::DraftSpec {
        voters: summary.voters,
        authority_transports: summary.authority_transports,
        clock_monitors: summary.clock_monitors,
        administrator: public(5),
        administrator_actions: vec![0, 10, 11, 12, 13, 26],
        enrolment: summary.enrolment,
        public_reading: summary.public_reading,
        minimum_route: summary.minimum_route,
        publication_modes: summary.publication_modes,
        default_publication_mode: summary.default_publication_mode,
        limits: [268435456, 20480, 128, 32],
        recovery: summary.recovery.clone(),
        route,
    };
    let draft = bootstrap::draft(spec, [[20; 32], [21; 32], [22; 32], [23; 32]], 1000).unwrap();
    let accepts = (6..=8)
        .filter(|seed| summary.recovery.accepted_keys.contains(&public(*seed)))
        .map(|seed| bootstrap::accept(&draft, &deployment::key(seed), 1000).unwrap())
        .collect::<Vec<_>>();
    let complete = bootstrap::assemble(&draft, &accepts, 1000).unwrap();
    let checked = bootstrap::inspect(&complete, true).unwrap();
    let profile = root.join("ContentClient.json");
    let device = deployment::key(98);
    let identity = |key: &SigningKey| {
        serde_json::json!({
            "secretKey": hex::encode(key.to_bytes()),
            "publicKey": hex::encode(key.verifying_key().to_bytes())
        })
    };
    let bytes = serde_json::to_vec(&serde_json::json!({
        "format":"HyperNetOfflineClient/1", "bootstrap":hex::encode(complete),
        "fingerprint":checked.summary.fingerprint,
        "descriptorDigest":checked.summary.descriptor_digest,
        "clientId":"34".repeat(32), "device":identity(&device),
        "relayIdentity":identity(possession), "minimumRoute":"Independent",
        "acceptedRelayDomains":[checked.summary.route.relay_domain],
        "requiredPublicationModes":["HostReadable"], "permitNetworkSearch":false,
        "joined": {"directory":root,"clockWitness":root.join("Clock.json"),
            "invitationDigest":"35".repeat(32),"member":"36".repeat(32),
            "readerGrant":"37".repeat(32),"admitted":true}
    }))
    .unwrap();
    files::write_new(&profile, &bytes).unwrap();
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
        sponsor: deployment::key(5).verifying_key().to_bytes(),
        grant: reference(102, [95; 32], [96; 32]),
        action: 0,
        scope: (0, [20; 32]),
        connections: 16,
        bytes: 1048576,
        expires: u64::MAX,
        creation: [97; 32],
    };
    let voucher = domains::Record::next(
        &domains::State::empty([20; 32], [21; 32]),
        166,
        [99; 32],
        voucher.value(),
    )
    .unwrap();
    (
        Endpoint {
            format: "HyperNetRelayEndpoint/1".into(),
            profile,
            route: route::Profile {
                version: 1,
                network: [20; 32],
                incarnation: [21; 32],
                relay_address: address,
                relay: relay.identity.clone(),
                destination: service.identity.clone(),
                domain: checked.summary.route.admission_domain,
                relay_domain: checked.summary.route.relay_domain,
                protocol: 2,
                assurance: route::Assurance::Independent,
                minimum_assurance: route::Assurance::Independent,
                limits: route::Limits {
                    bytes: 1048576,
                    duration_ms: 60000,
                    idle_ms: 30000,
                },
                voucher: voucher.bytes,
            },
        },
        bytes,
    )
}
fn content_packet(host: [u8; 32], offset: u64) -> Vec<u8> {
    let version = |kind, id| VersionRef {
        kind,
        id,
        generation: 1,
        digest: [81; 32],
    };
    let operation = domains::Operation {
        grant: Some(version(102, [82; 32])),
        command: page::Command::Content(content::Command::Authorise {
            placement: version(159, [83; 32]),
            host: version(147, host),
            effect: content::Effect::Read,
            offset,
            bytes: 16,
            digest: None,
        })
        .into(),
        snapshot: domains::snapshot(&deployment::snapshot(&[])).unwrap(),
    };
    let signed = deployment::signed(
        &deployment::key(98),
        "AuthorityDomain",
        operation.command.resource(),
        0,
        wire::decode(&operation.parameters().unwrap()).unwrap(),
        vec![],
    );
    let request = page::MediaRequest::parse(&signed).unwrap();
    crate::authority_inspection::page_media_client::packet(&request, &[], false).unwrap()
}
fn publish_content_route(root: &Path, endpoint: &Endpoint, host: [u8; 32]) {
    let directory = files::private_directory(root).unwrap();
    let digest = sha2::Sha256::digest(serde_json::to_vec(&endpoint.route).unwrap());
    files::atomic_at(
        &directory,
        std::ffi::OsStr::new("Routes.json"),
        &serde_json::to_vec(&serde_json::json!([{
            "service":hex::encode(endpoint.route.destination.service),
            "subject":hex::encode(host), "protocol":2, "routeDigest":hex::encode(digest)
        }]))
        .unwrap(),
        true,
    )
    .unwrap();
    files::atomic_at(
        &directory,
        std::ffi::OsStr::new("ContentRoute.json"),
        &serde_json::to_vec(endpoint).unwrap(),
        true,
    )
    .unwrap();
}

#[test]
fn content_transport_reuses_only_after_completion_and_discards_failed_or_changed_routes() {
    let f = Fixture::new();
    let root = f.directory.0.canonicalize().unwrap();
    let (relay, service) = certificates(&root);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let possession = deployment::key(99);
    let host = deployment::key(100).verifying_key().to_bytes();
    let (mut endpoint, profile_bytes) = content_profile(
        &root,
        &relay,
        &service,
        listener.local_addr().unwrap(),
        &possession,
    );
    publish_content_route(&root, &endpoint, host);
    let relay_config = route_tls::server(&relay.identity, &relay.pem, &relay.key).unwrap();
    let service_config = route_tls::server(&service.identity, &service.pem, &service.key).unwrap();
    let transport = Transport::socket(host, root.join("ContentRoute.json"));
    let packets = (0..9)
        .map(|n| content_packet(host, n * 16))
        .collect::<Vec<_>>();
    let limits = endpoint.route.limits;
    std::thread::scope(|threads| {
        let server = threads.spawn(|| {
            // The first three exchanges share admission; every later failed completion or
            // changed profile must close it. The final peer withdrawal fails the active exchange.
            for indices in [&[0, 1, 2][..], &[3], &[4], &[5], &[6], &[7, 8]] {
                let end = std::time::Instant::now() + Duration::from_secs(4);
                let socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(std::time::Instant::now() < end, "Content admission absent");
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("Content accept failed: {error}"),
                    }
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(4)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(4)))
                    .unwrap();
                socket.set_nodelay(true).unwrap();
                let mut outer =
                    StreamOwned::new(ServerConnection::new(relay_config.clone()).unwrap(), socket);
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
                let mut inner = StreamOwned::new(
                    ServerConnection::new(service_config.clone()).unwrap(),
                    outer,
                );
                framed_send(
                    &mut inner,
                    &route_protocol::endpoint_ready(
                        [20; 32],
                        [21; 32],
                        service.identity.service,
                        2,
                    )
                    .unwrap(),
                );
                for index in indices {
                    assert_eq!(framed_read(&mut inner), packets[*index]);
                    if *index != 8 {
                        framed_send(&mut inner, &[*index as u8 + 1]);
                    }
                }
                if indices.last() != Some(&8) {
                    match inner.read(&mut [0; 1]) {
                        Ok(0) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
                        other => panic!("failed or changed Content route stayed open: {other:?}"),
                    }
                }
            }
            assert!(
                listener.accept().is_err(),
                "Content unexpectedly admitted another connection"
            );
        });
        let mut pool = ContentPool::default();
        let success = |pool: &mut ContentPool, index: usize| {
            transport
                .exchange_content(&packets[index], &root, pool)
                .unwrap()
                .complete(pool, |bytes| {
                    ensure!(bytes == [index as u8 + 1], "unexpected Content response");
                    Ok(())
                })
                .unwrap();
            assert!(!pool.is_empty());
        };
        success(&mut pool, 0);
        use std::os::unix::fs::MetadataExt;
        let observed = crate::private_route_client::observation_path(&endpoint.profile).unwrap();
        let inode = std::fs::metadata(&observed).unwrap().ino();
        let observation = std::fs::read(&observed).unwrap();
        success(&mut pool, 1);
        assert_eq!(std::fs::metadata(&observed).unwrap().ino(), inode);
        assert_eq!(std::fs::read(&observed).unwrap(), observation);
        // The real receipt parser refuses this malformed authenticated transport response.
        assert!(
            transport
                .exchange_content(&packets[2], &root, &mut pool)
                .unwrap()
                .complete(&mut pool, page::MediaReceipt::parse)
                .is_err()
        );
        assert!(pool.is_empty());
        assert!(
            transport
                .exchange_content(&packets[3], &root, &mut pool)
                .unwrap()
                .complete(&mut pool, |_| -> Result<()> {
                    anyhow::bail!("progress persistence failed")
                })
                .is_err()
        );
        assert!(pool.is_empty());
        // Cancellation before completion cannot retain an otherwise successful exchange.
        drop(
            transport
                .exchange_content(&packets[4], &root, &mut pool)
                .unwrap(),
        );
        assert!(pool.is_empty());
        success(&mut pool, 5);
        endpoint.route.limits.bytes += 1;
        publish_content_route(&root, &endpoint, host);
        success(&mut pool, 6);
        let directory = files::private_directory(&root).unwrap();
        let mut profile: serde_json::Value = serde_json::from_slice(&profile_bytes).unwrap();
        profile["acceptedRelayDomains"] = serde_json::json!([]);
        files::atomic_at(
            &directory,
            std::ffi::OsStr::new("ContentClient.json"),
            &serde_json::to_vec(&profile).unwrap(),
            true,
        )
        .unwrap();
        assert!(
            transport
                .exchange_content(&packets[7], &root, &mut pool)
                .is_err()
        );
        assert!(pool.is_empty());
        files::atomic_at(
            &directory,
            std::ffi::OsStr::new("ContentClient.json"),
            &profile_bytes,
            true,
        )
        .unwrap();
        success(&mut pool, 7);
        assert!(
            transport
                .exchange_content(&packets[8], &root, &mut pool)
                .is_err()
        );
        assert!(pool.is_empty());
        server.join().unwrap();
    });
}
