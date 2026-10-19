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

fn content_profile(
    root: &Path,
    relay: &Certificate,
    service: &Certificate,
    address: std::net::SocketAddr,
    possession: &SigningKey,
    protocol: u64,
    byte_limit: u64,
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
        bytes: byte_limit,
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
                protocol,
                assurance: route::Assurance::Independent,
                minimum_assurance: route::Assurance::Independent,
                limits: route::Limits {
                    bytes: byte_limit,
                    duration_ms: 60000,
                    idle_ms: 30000,
                },
                voucher: voucher.bytes,
            },
        },
        bytes,
    )
}
fn content_packet(host: [u8; 32], offset: u64, count: u64, protocol: u64) -> Vec<u8> {
    let version = |kind, id| VersionRef {
        kind,
        id,
        generation: 1,
        digest: [81; 32],
    };
    let command: domains::Command = if protocol == 3 {
        page::Command::MediaAuthorise {
            asset: version(144, [83; 32]),
            host: version(143, host),
            effect: page::MediaEffect::Read,
            offset,
            bytes: count,
            digest: None,
        }
        .into()
    } else if protocol == 5 {
        domains::transfer::Command::Execute {
            id: [83; 32],
            effect: domains::transfer::Effect::Fetch,
            offset,
            bytes: count,
            digest: None,
        }
        .into()
    } else {
        page::Command::Content(content::Command::Authorise {
            placement: version(159, [83; 32]),
            host: version(147, host),
            effect: content::Effect::Read,
            offset,
            bytes: count,
            digest: None,
        })
        .into()
    };
    let operation = domains::Operation {
        grant: (protocol != 5).then(|| version(102, [82; 32])),
        command,
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
    if protocol == 5 {
        let request = domains::transfer::Request::parse(&signed).unwrap();
        crate::authority_inspection::transfer_client::packet(&request, &[], false).unwrap()
    } else {
        let request = page::MediaRequest::parse(&signed).unwrap();
        crate::authority_inspection::page_media_client::packet(&request, &[], false).unwrap()
    }
}
fn publish_content_route(root: &Path, endpoint: &Endpoint, host: [u8; 32]) {
    let directory = files::private_directory(root).unwrap();
    let digest = sha2::Sha256::digest(serde_json::to_vec(&endpoint.route).unwrap());
    files::atomic_at(
        &directory,
        std::ffi::OsStr::new("Routes.json"),
        &serde_json::to_vec(&serde_json::json!([{
            "service":hex::encode(endpoint.route.destination.service),
            "subject":hex::encode(host), "protocol":endpoint.route.protocol, "routeDigest":hex::encode(digest)
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
    transport_reuse(2, false);
}

#[test]
fn media_transport_reuses_five_chunks_and_discards_failed_or_changed_routes() {
    transport_reuse(3, false);
}

#[test]
fn media_transport_rotates_before_next_range_exhausts_a_small_admission() {
    transport_reuse(3, true);
}

#[test]
fn transfer_transport_reuses_only_completed_chunks_and_discards_failures() {
    transport_reuse(5, false);
}

#[test]
fn transfer_transport_rotates_before_next_chunk_exhausts_admission() {
    transport_reuse(5, true);
}

enum Exchange {
    Content(crate::authority_pages::media::ContentExchange),
    Transfer(crate::transfers::TransferExchange),
}
impl Exchange {
    fn complete<T>(
        self,
        pool: &mut ContentPool,
        verify: impl FnOnce(&[u8]) -> Result<T>,
    ) -> Result<T> {
        match self {
            Self::Content(value) => value.complete(pool, verify),
            Self::Transfer(value) => value.complete(pool, verify),
        }
    }
}

fn transport_reuse(protocol: u64, constrained: bool) {
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
        protocol,
        if constrained { 65536 } else { 4 * 1048576 },
    );
    publish_content_route(&root, &endpoint, host);
    let relay_config = route_tls::server(&relay.identity, &relay.pem, &relay.key).unwrap();
    let service_config = route_tls::server(&service.identity, &service.pem, &service.key).unwrap();
    let transport = Transport::socket(host, root.join("ContentRoute.json"));
    let payloads = (0..12)
        .map(|index| {
            vec![
                index as u8 + 1;
                if index < 4 {
                    32768
                } else if index == 4 {
                    7168
                } else {
                    16
                }
            ]
        })
        .collect::<Vec<_>>();
    assert_eq!(payloads[..5].iter().map(Vec::len).sum::<usize>(), 138240);
    let packets = payloads
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            content_packet(host, index as u64 * 32768, bytes.len() as u64, protocol)
        })
        .collect::<Vec<_>>();
    let limits = endpoint.route.limits;
    std::thread::scope(|threads| {
        let server = threads.spawn(|| {
            // A small admission must rotate before another request. No request is
            // replayed after submission; the final peer withdrawal remains terminal.
            let mut connections = if constrained {
                (0..6).map(|index| vec![index]).collect::<Vec<_>>()
            } else {
                vec![vec![0, 1, 2, 3, 4, 5]]
            };
            connections.extend([vec![6], vec![7], vec![8], vec![9]]);
            if constrained {
                connections.extend([vec![10], vec![11]]);
            } else {
                connections.push(vec![10, 11]);
            }
            for indices in connections {
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
                        protocol,
                    )
                    .unwrap(),
                );
                for index in &indices {
                    assert_eq!(framed_read(&mut inner), packets[*index]);
                    if *index != 11 {
                        framed_send(&mut inner, &payloads[*index]);
                    }
                }
                if indices.last() != Some(&11) {
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
        let transfer = crate::transfers::Transport::socket(root.join("ContentRoute.json"));
        let exchange = |packet: &[u8], pool: &mut ContentPool| {
            if protocol == 5 {
                transfer
                    .exchange_pooled(&root, packet, host, pool)
                    .map(Exchange::Transfer)
            } else if protocol == 3 {
                transport
                    .exchange_media_read(packet, &root, pool)
                    .map(Exchange::Content)
            } else {
                transport
                    .exchange_content(packet, &root, pool)
                    .map(Exchange::Content)
            }
        };
        let success = |pool: &mut ContentPool, index: usize| {
            exchange(&packets[index], pool)
                .unwrap()
                .complete(pool, |bytes| {
                    ensure!(
                        bytes == payloads[index],
                        "unexpected Content or Media response"
                    );
                    Ok(())
                })
                .unwrap();
            assert!(!pool.is_empty());
        };
        let started = std::time::Instant::now();
        success(&mut pool, 0);
        use std::os::unix::fs::MetadataExt;
        let observed = crate::private_route_client::observation_path(&endpoint.profile).unwrap();
        let inode = std::fs::metadata(&observed).unwrap().ino();
        let observation = std::fs::read(&observed).unwrap();
        for index in 1..5 {
            success(&mut pool, index);
        }
        eprintln!(
            "protocol {protocol}: 138240 bytes in five ranges through {} relay admissions, {:.3}s",
            if constrained { 5 } else { 1 },
            started.elapsed().as_secs_f64()
        );
        if !constrained {
            assert_eq!(std::fs::metadata(&observed).unwrap().ino(), inode);
            assert_eq!(std::fs::read(&observed).unwrap(), observation);
        }
        // The real receipt parser refuses this malformed authenticated transport response.
        assert!(
            exchange(&packets[5], &mut pool)
                .unwrap()
                .complete(&mut pool, |bytes| {
                    if protocol == 5 {
                        domains::transfer::Receipt::parse(bytes).map(|_| ())
                    } else {
                        page::MediaReceipt::parse(bytes).map(|_| ())
                    }
                })
                .is_err()
        );
        assert!(pool.is_empty());
        assert!(
            exchange(&packets[6], &mut pool)
                .unwrap()
                .complete(&mut pool, |_| -> Result<()> {
                    anyhow::bail!("progress persistence failed")
                })
                .is_err()
        );
        assert!(pool.is_empty());
        // Cancellation before completion cannot retain an otherwise successful exchange.
        drop(exchange(&packets[7], &mut pool).unwrap());
        assert!(pool.is_empty());
        success(&mut pool, 8);
        endpoint.route.limits.bytes += 1;
        publish_content_route(&root, &endpoint, host);
        success(&mut pool, 9);
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
        assert!(exchange(&packets[10], &mut pool).is_err());
        assert!(pool.is_empty());
        files::atomic_at(
            &directory,
            std::ffi::OsStr::new("ContentClient.json"),
            &profile_bytes,
            true,
        )
        .unwrap();
        endpoint.route.protocol = if protocol == 3 { 2 } else { 3 };
        publish_content_route(&root, &endpoint, host);
        assert!(exchange(&packets[10], &mut pool).is_err());
        assert!(pool.is_empty());
        endpoint.route.protocol = protocol;
        if protocol == 5 {
            publish_content_route(&root, &endpoint, [77; 32]);
            assert!(exchange(&packets[10], &mut pool).is_err());
            assert!(pool.is_empty());
        }
        publish_content_route(&root, &endpoint, host);
        success(&mut pool, 10);
        assert!(exchange(&packets[11], &mut pool).is_err());
        assert!(pool.is_empty());
        server.join().unwrap();
    });
}
