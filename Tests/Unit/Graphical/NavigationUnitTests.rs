// SPDX-License-Identifier: MIT
use super::*;
fn address(n: u8) -> String {
    format!(
        "hypernet://{}/{}/Docs/{}",
        "a".repeat(64),
        "b".repeat(64),
        format!("{n:02x}").repeat(16)
    )
}
#[test]
fn bounded_navigation_retains_accepted_links_and_tracks_actual_window_lifetime() {
    let (sender, mut inbox) = navigation_channel();
    let context = egui::Context::default();
    assert!(!sender.is_attached());
    assert_eq!(
        sender.try_open(Some("https://example.invalid/".into())),
        Err(NavigationError::Invalid)
    );
    assert_eq!(
        sender.try_open(Some(format!(
            "{}\n=> https://example.invalid/ injected",
            address(0)
        ))),
        Err(NavigationError::Invalid)
    );
    inbox.attach(&context);
    assert!(sender.is_attached());
    for n in 0..8 {
        sender.try_open(Some(address(n))).unwrap();
    }
    assert_eq!(
        sender.try_open(Some(address(8))),
        Err(NavigationError::Full)
    );
    inbox.poll(&context);
    for n in 8..16 {
        sender.try_open(Some(address(n))).unwrap();
    }
    inbox.poll(&context); // A full deferred queue does not consume or drop the channel.
    for n in 0..8 {
        assert_eq!(inbox.next(), Some(address(n)));
    }
    inbox.poll(&context);
    for n in 8..16 {
        assert_eq!(inbox.next(), Some(address(n)));
    }
    sender.try_open(None).unwrap();
    inbox.poll(&context);
    assert_eq!(inbox.queued(), 0);
    drop(inbox);
    assert!(!sender.is_attached());
    assert_eq!(sender.try_open(None), Err(NavigationError::Closed));
}
#[test]
fn scoped_registration_is_consumed_once_and_never_replaces_an_active_registration() {
    let (_, inbox) = navigation_channel();
    let guard = install_navigation(inbox).unwrap();
    assert!(take_registered().is_some());
    assert!(take_registered().is_none());
    let (_, inbox) = navigation_channel();
    assert!(install_navigation(inbox).is_err());
    drop(guard);
    let (sender, inbox) = navigation_channel();
    let guard = install_navigation(inbox).unwrap();
    drop(guard);
    assert!(take_registered().is_none());
    assert_eq!(sender.try_open(None), Err(NavigationError::Closed));
}
