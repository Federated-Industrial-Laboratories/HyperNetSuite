// SPDX-License-Identifier: MIT
// Unit tests for AuthoritySealedIdentityCliClient.
use super::*;
#[test]
fn recipient_directory_retry_preserves_cursor_member_and_exact_grant() {
    let member = [1; 32];
    let grant = VersionRef {
        kind: 102,
        id: [2; 32],
        generation: 1,
        digest: [3; 32],
    };
    let view = Some([4; 32]);
    let after = Some((108, [5; 32]));
    let mut operation = domain::Operation {
        command: identity::Command::Directory {
            member,
            view,
            after,
        }
        .into(),
        grant: Some(grant.clone()),
        snapshot: domain::snapshot(&a(vec![
            a(vec![V::Uint(1), V::Uint(0), b(&[6; 32])]),
            a(vec![]),
        ]))
        .unwrap(),
    };
    assert_eq!(
        directory_cursor(None, member, &grant).unwrap(),
        (None, None)
    );
    assert_eq!(
        directory_cursor(Some(&operation), member, &grant).unwrap(),
        (view, after)
    );
    assert!(directory_cursor(Some(&operation), [7; 32], &grant).is_err());
    let mut changed = grant.clone();
    changed.generation = 2;
    assert!(directory_cursor(Some(&operation), member, &changed).is_err());
    operation.command = identity::Command::Context {
        kind: 107,
        lookup: member,
    }
    .into();
    assert!(directory_cursor(Some(&operation), member, &grant).is_err());
}
