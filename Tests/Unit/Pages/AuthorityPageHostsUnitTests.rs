// SPDX-License-Identifier: MIT
// Unit tests for AuthorityPageHosts.
use super::*;
use crate::{authority_deployment_tests as fixture, authority_proof::Intent};

#[test]
fn page_host_withdrawal_resumes_only_its_exact_context_or_mutation() {
    let host = fixture::key(100).verifying_key().to_bytes();
    let pending = |command: Action, grant| {
        let operation = domain::Operation {
            command: command.into(),
            grant,
            snapshot: domain::snapshot(&fixture::snapshot(&[])).unwrap(),
        };
        Intent::from_signed(&fixture::signed(
            &fixture::key(90),
            "AuthorityDomain",
            operation.command.resource(),
            u64::from(operation.mutation()),
            wire::decode(&operation.parameters().unwrap()).unwrap(),
            vec![],
        ))
        .unwrap()
    };
    assert!(withdrawal_needs_context(None, 1, host, 1).unwrap());
    let read = pending(Action::HostGet { role: 1, host }, None);
    assert!(withdrawal_needs_context(Some(&read), 1, host, 1).unwrap());
    assert!(withdrawal_needs_context(Some(&read), 2, host, 1).is_err());
    let mutation = pending(
        Action::HostWithdraw {
            role: 1,
            host,
            generation: 1,
        },
        None,
    );
    assert!(!withdrawal_needs_context(Some(&mutation), 1, host, 1).unwrap());
    assert!(withdrawal_needs_context(Some(&mutation), 1, host, 2).is_err());
    assert!(
        withdrawal_needs_context(
            Some(&mutation),
            1,
            fixture::key(101).verifying_key().to_bytes(),
            1
        )
        .is_err()
    );
    let discretionary = pending(
        Action::HostGet { role: 1, host },
        Some(VersionRef {
            kind: 102,
            id: [23; 32],
            generation: 1,
            digest: [24; 32],
        }),
    );
    assert!(withdrawal_needs_context(Some(&discretionary), 1, host, 1).is_err());
}
