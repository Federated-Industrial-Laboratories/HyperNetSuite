// SPDX-License-Identifier: MIT
// Interrupted joins retain their invitation while admitting only an expired transport successor.
use super::*;
use crate::{authority_domains::routes::Voucher, authority_proof::VersionRef, route_profile};
fn voucher(now: u64) -> Voucher {
    let reference = |kind, id| VersionRef {
        kind,
        id: [id; 32],
        generation: 1,
        digest: [id; 32],
    };
    Voucher {
        relay: reference(165, 3),
        destination: reference(165, 4),
        grant: reference(102, 5),
        sponsor: crate::authority_deployment_tests::key(6)
            .verifying_key()
            .to_bytes(),
        possession: crate::authority_deployment_tests::key(7)
            .verifying_key()
            .to_bytes(),
        action: 10,
        scope: (0, [1; 32]),
        connections: 64,
        bytes: 65536,
        expires: now - 1,
        creation: [8; 32],
        baseline: Some((0, 0)),
    }
}
#[test]
fn join_successor_cannot_change_identity_budget_or_refresh_a_live_voucher() {
    let old = voucher(5000);
    let mut next = old.clone();
    next.expires = 10000;
    successor_voucher(&old, &next, 5000).unwrap();
    assert!(successor_voucher(&old, &next, 4998).is_err());
    for mutation in 0..11 {
        let mut other = next.clone();
        match mutation {
            0 => other.sponsor = [9; 32],
            1 => other.possession = [9; 32],
            2 => other.action = 0,
            3 => other.scope.1 = [9; 32],
            4 => other.connections += 1,
            5 => other.bytes += 1,
            6 => other.grant.id = [9; 32],
            7 => other.relay.id = [9; 32],
            8 => other.destination.id = [9; 32],
            9 => other.grant.digest = [9; 32],
            _ => other.expires = 5000,
        }
        assert!(
            successor_voucher(&old, &other, 5000).is_err(),
            "mutation {mutation}"
        );
    }
}
fn encoded_voucher(v: &Voucher, generation: u64) -> Vec<u8> {
    crate::trust_wire::encode(&V::Array(vec![
        V::Uint(166),
        V::Uint(1),
        V::Bytes(vec![1; 32]),
        V::Bytes(vec![2; 32]),
        V::Uint(generation),
        if generation == 1 {
            V::Null
        } else {
            V::Bytes(vec![9; 32])
        },
        V::Bytes(vec![10; 32]),
        v.value(),
    ]))
    .unwrap()
}
#[test]
fn explicit_successor_allows_proven_certificate_renewal_without_changing_invitation() {
    let fixture = crate::runtime_manifest::certificates::tests::fixture();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let identity = |index: usize, renewed: bool| {
        let endpoint = &if renewed {
            &fixture.renewed
        } else {
            &fixture.original
        }
        .endpoints[index];
        route_profile::Identity {
            service: [index as u8 + 3; 32],
            server_name: endpoint.address.to_string(),
            transport_key: endpoint.transport_key,
            leaf_der: endpoint.leaf_der.clone(),
            certificate_authority_pem: if renewed {
                fixture.next_issuer.clone()
            } else {
                fixture.issuer.clone()
            },
        }
    };
    let old_voucher = voucher(now);
    let original = route_profile::Profile {
        version: 1,
        network: [1; 32],
        incarnation: [2; 32],
        relay_address: std::net::SocketAddr::new(fixture.original.endpoints[0].address, 1234),
        relay: identity(0, false),
        destination: identity(1, false),
        domain: "authority".into(),
        relay_domain: "relay".into(),
        protocol: 1,
        assurance: route_profile::Assurance::Organisation,
        minimum_assurance: route_profile::Assurance::Organisation,
        limits: route_profile::Limits {
            bytes: 65536,
            duration_ms: 60000,
            idle_ms: 10000,
        },
        voucher: encoded_voucher(&old_voucher, 1),
    };
    let mut next = original.clone();
    let mut next_voucher = old_voucher.clone();
    next_voucher.expires = now + 3600000;
    next.voucher = encoded_voucher(&next_voucher, 2);
    next.relay = identity(0, true);
    next.destination = identity(1, true);
    let root = std::env::temp_dir().join(format!(
        "HyperNetJoinSuccessor{}",
        crate::random_hex::<16>()
    ));
    files::create_directory(&root).unwrap();
    let original_bytes = serde_json::to_vec(&original).unwrap();
    files::write_new(&root.join("Original.json"), &original_bytes).unwrap();
    let check = |route: &route_profile::Profile, name: &str, pin: Option<&str>| {
        let path = root.join(name);
        let raw = serde_json::to_vec(route).unwrap();
        files::write_new(&path, &raw).unwrap();
        let digest = hex::encode(sha2::Sha256::digest(&raw));
        successor_route(&original, &path, pin.unwrap_or(&digest), now)
    };
    assert_eq!(check(&next, "Next.json", None).unwrap(), next);
    assert!(check(&next, "WrongPin.json", Some(&"00".repeat(32))).is_err());
    let mut changed = next.clone();
    changed.relay_address.set_port(4321);
    assert!(check(&changed, "OtherEndpoint.json", None).is_err());
    let mut changed = next;
    changed.destination.service = [30; 32];
    assert!(check(&changed, "OtherIdentity.json", None).is_err());
    assert_eq!(
        files::read_single(&root.join("Original.json"), 600000, true).unwrap(),
        original_bytes
    );
    std::fs::remove_dir_all(root).unwrap();
}
