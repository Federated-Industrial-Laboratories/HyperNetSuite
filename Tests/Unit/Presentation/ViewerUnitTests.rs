// SPDX-License-Identifier: MIT
// Unit tests for Viewer.
use super::*;

#[test]
fn terminal_viewer_delegates_requests_and_refuses_noninteractive_confirmation() {
    run(false, false, false, |session| {
        assert!(!session.interactive());
        assert_eq!(session.request(|| Ok(17))?, Some(17));
        assert!(
            session
                .confirm_form(&serde_json::json!({"submission":"Exact"}))
                .is_err()
        );
        Ok(())
    })
    .unwrap();
}

#[test]
fn conflicting_viewers_never_start_the_workflow() {
    assert!(
        run(true, true, false, |_| panic!(
            "conflicting viewer started work"
        ))
        .is_err()
    );
}

#[cfg(not(feature = "gui"))]
#[test]
fn unavailable_graphical_viewer_never_starts_the_workflow() {
    let error = run(true, false, false, |_| {
        panic!("unavailable viewer started work")
    })
    .unwrap_err();
    assert!(error.to_string().contains("gui feature"));
}
