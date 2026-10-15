// SPDX-License-Identifier: MIT
// Candidate extent cannot consume the selected result page's fresh authority budget.
use super::*;

fn selected_route(protocol: u64) -> crate::route_profile::Profile {
    use crate::route_profile::{Assurance, Identity, Limits, Profile};
    let identity = |service, key| Identity {
        service: [service; 32],
        server_name: "Search.invalid".into(),
        transport_key: [key; 32],
        leaf_der: vec![],
        certificate_authority_pem: String::new(),
    };
    Profile {
        version: 1,
        network: [1; 32],
        incarnation: [2; 32],
        relay_address: "127.0.0.1:1".parse().unwrap(),
        relay: identity(3, 5),
        destination: identity(4, 6),
        domain: "Content".into(),
        relay_domain: "ReaderRelay".into(),
        protocol,
        assurance: Assurance::Independent,
        minimum_assurance: Assurance::Independent,
        limits: Limits {
            bytes: 16384,
            duration_ms: 1000,
            idle_ms: 1000,
        },
        voucher: vec![1],
    }
}

#[test]
fn selected_search_service_is_checked_before_route_preparation_or_query_exchange() {
    use crate::{authority_local_transport::LocalControl, private_route_client::Endpoint};
    for protocol in [2, 6] {
        let route = selected_route(protocol);
        // The opaque route identifier is deliberately different from its pinned application subject.
        assert!(
            route_binding(
                Some((&route, [7; 32])),
                false,
                [1; 32],
                [2; 32],
                protocol,
                [7; 32]
            )
            .is_ok()
        );
        for changed in 0..4 {
            let mut selected = route.clone();
            let mut subject = [7; 32];
            match changed {
                0 => selected.network = [9; 32],
                1 => selected.incarnation = [9; 32],
                2 => selected.protocol = 3,
                _ => subject = [9; 32],
            }
            // The handoff is the same loaded object used by open_checked. Preparing this
            // fixture would fail while loading its absent client profile, before any TLS.
            let endpoint = Endpoint {
                format: "HyperNetRelayEndpoint/1".into(),
                profile: PathBuf::from("/AbsentSearchRouteProfile.json"),
                route: selected,
            };
            let result = LocalControl::from_relay_checked(endpoint, |loaded| {
                route_binding(
                    loaded.map(|v| (&v.route, subject)),
                    false,
                    [1; 32],
                    [2; 32],
                    protocol,
                    [7; 32],
                )
            })
            .and_then(|control| control.exchange(b"Private search query", u64::MAX));
            let error = result.unwrap_err().to_string();
            assert!(error.contains("search route differs"), "{error}");
        }
    }
    assert!(route_binding(None, false, [1; 32], [2; 32], 2, [4; 32]).is_err());
    assert!(route_binding(None, true, [1; 32], [2; 32], 2, [4; 32]).is_ok());
}

#[test]
fn large_candidate_corpus_refreshes_only_page_and_one_continuation() {
    let hits = (1u8..=65)
        .map(|value| local::Hit {
            id: hex::encode([value; 32]),
            namespace: "Books".into(),
            matched: search_text::Match {
                title: "Books".into(),
                snippet: "An approved book".into(),
                tags: vec![],
                score: 66 - u64::from(value),
            },
            uri: None,
            provenance: json!({"kind":"Native"}),
        })
        .collect::<Vec<_>>();
    let mut request = Request {
        network: [1; 32],
        incarnation: [2; 32],
        operation: [3; 32],
        scope: 1,
        terms: vec!["book".into()],
        combination: 0,
        namespaces: vec![],
        limit: 1,
        cursor: None,
        historical: false,
        snapshot: V::Array(vec![
            V::Array(vec![V::Uint(1), V::Uint(1), V::Bytes(vec![4; 32])]),
            V::Array(vec![]),
        ]),
    };
    let binding = request.digest().unwrap();
    assert_eq!(
        refresh_selection(&hits, &request, binding).unwrap(),
        [hex::encode([1; 32]), hex::encode([2; 32])]
            .into_iter()
            .collect()
    );
    let (_, next, _) = local::page(hits.clone(), &request, binding).unwrap();
    request.cursor = Some(id(&next.unwrap()).unwrap());
    assert_eq!(
        refresh_selection(&hits, &request, binding).unwrap(),
        [hex::encode([2; 32]), hex::encode([3; 32])]
            .into_iter()
            .collect()
    );
    assert!(refresh_selection(&hits, &request, [9; 32]).is_err());

    request.cursor = None;
    assert_eq!(
        refresh_selection(&hits[..1], &request, binding).unwrap(),
        [hex::encode([1; 32])].into_iter().collect()
    );
}
