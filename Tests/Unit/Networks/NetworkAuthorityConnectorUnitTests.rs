// SPDX-License-Identifier: MIT
// Unit tests for NetworkAuthorityConnector.
use super::*;
use crate::{authority_proof::Scope, trust_wire::Value as V};

#[test]
fn authority_connector_binding_and_packet_limits_are_exact() {
    let binding = Binding {
        format: "HyperNetAuthorityConnector/1".into(),
        network: "01".repeat(32),
        incarnation: "02".repeat(32),
        bootstrap_digest: "03".repeat(32),
        target_digest: "04".repeat(32),
    };
    let bytes = binding.encode().unwrap();
    assert_eq!(Binding::parse(&bytes).unwrap(), binding);
    let mut wrong = binding.clone();
    wrong.target_digest = "AB".repeat(32);
    assert!(wrong.encode().is_err());
    let mut extra: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    extra["fallback"] = json!("127.0.0.1:1");
    assert!(Binding::parse(&serde_json::to_vec(&extra).unwrap()).is_err());
    let scope = Scope {
        network: [1; 32],
        incarnation: [2; 32],
        configuration: [3; 32],
        epoch: 0,
    };
    let frame = |operation| {
        wire::encode(&V::Array(vec![
            V::Uint(41),
            V::Uint(1),
            scope.value(),
            V::Uint(operation),
            V::Bytes(wire::encode(&V::Array(vec![])).unwrap()),
        ]))
        .unwrap()
    };
    packet::validate([1; 32], [2; 32], &frame(2)).unwrap();
    assert!(packet::validate([1; 32], [9; 32], &frame(2)).is_err());
    assert!(packet::validate([1; 32], [2; 32], &frame(5)).is_err());
}
