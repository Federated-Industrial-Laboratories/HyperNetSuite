// SPDX-License-Identifier: MIT
use super::*;
#[test]
fn full_v2_status_fits_one_frame_and_excludes_private_configuration() {
    let h = "f".repeat(64);
    let n = u64::MAX;
    let privacy = json!({"direction":"outgoing","transport":"HyperNet","transportAuthenticated":true,"tls":"TLS1.3","relayPath":"nestedTlsViaRelay","relayService":h,"destinationService":h,"selectedMinimum":"Independent","configuredAssurance":"Independent","provenance":"observedAuthenticatedTransport","certifiedEndpointProfile":{"source":"certifiedServiceLookup","service":h,"generation":n,"recordDigest":h,"profileDigest":h,"endpointMode":3,"evaluatedAtMs":n,"expiresAtMs":n,"notAfterBootMs":n},"certifiedRelayProfile":null,"physicalIndependenceVerified":false,"profileCurrentnessAsserted":false,"endToEndMessageEncryption":"applicationDefined"});
    let state = State {
        active: (0..16)
            .map(|i| {
                let id = format!("{i:064x}");
                (
                    id.clone(),
                    Active {
                        info: ipc::ActiveInfo {
                            id,
                            direction: "outgoing".into(),
                            service: h.clone(),
                            peer: json!({"principal":h,"owner":h,"endpoint":h}),
                        },
                        cancel: Arc::new(AtomicBool::new(false)),
                        reference: None,
                        accepted: false,
                        privacy: privacy.clone(),
                        privacy_generation: None,
                    },
                )
            })
            .collect(),
        errors: VecDeque::from([json!({"message":"PRIVATE_DIAGNOSTIC"})]),
        controls: 0,
    };
    let (jobs, _) = mpsc::sync_channel(1);
    let (_, incoming) = mpsc::sync_channel(1);
    let runtime = Runtime {
        state: Arc::new(Mutex::new(State {
            active: BTreeMap::new(),
            errors: VecDeque::new(),
            controls: 0,
        })),
        jobs,
        incoming: Arc::new(Mutex::new(incoming)),
        targets: Arc::new(
            (0..16)
                .map(|_| Target {
                    service: h.clone(),
                    protocol: "p".repeat(96),
                    grant: h.clone(),
                    route: "/PRIVATE_ROUTE".into(),
                    renewal_ms: 0,
                })
                .collect(),
        ),
        binding: None,
        clock: Arc::new(crate::authority_clock::Source::Private {
            path: "/PRIVATE_CLOCK".into(),
        }),
        started: Instant::now(),
        profile: json!({"network":h,"incarnation":h,"principal":h,"binding":{"service":h,"owner":h,"endpoint":h,"protocol":"p".repeat(96)}}),
        checks: None,
    };
    let mut value = status_v2(&runtime, &state);
    // Reserve the largest ready-channel identity and numeric fields too.
    value["capabilities"]["checkAuthority"] = json!({"supported":true,"capability":streams::control::CAPABILITY,"endpointReady":true,"companionInstance":h,"endpointInstance":h,"controlGeneration":n});
    value["uptimeMs"] = json!(n);
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(
        bytes.len() <= ipc::MAXIMUM,
        "status was {} bytes",
        bytes.len()
    );
    assert!(!String::from_utf8(bytes).unwrap().contains("PRIVATE_"));
    assert_eq!(value["connections"].as_array().unwrap().len(), 16);
    assert_eq!(
        value["connections"][0]["privacy"]["certifiedEndpointProfile"]["profileDigest"],
        h
    );
}
