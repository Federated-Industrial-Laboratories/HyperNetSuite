// SPDX-License-Identifier: MIT
// Unit tests for Browser.
use super::*;
#[test]
fn cache_identity_includes_profile_dimensions_and_digest() {
    let asset = markup::media::Asset {
        id: "Image".into(),
        profile: markup::media::RASTER_PROFILE.into(),
        width: 2,
        height: 1,
        bytes: 6,
        digest: "a".repeat(64),
        hosts: vec!["b".repeat(64)],
        copies: 1,
    };
    let mut other = asset.clone();
    other.id = "Alias".into();
    assert_eq!(image_key(&asset), image_key(&other));
    other.digest = "c".repeat(64);
    assert_ne!(image_key(&asset), image_key(&other));
    other = asset.clone();
    other.width = 1;
    other.height = 2;
    assert_ne!(image_key(&asset), image_key(&other));
    other = asset.clone();
    other.profile = markup::media::VECTOR_PROFILE.into();
    assert_ne!(image_key(&asset), image_key(&other));
}

#[test]
fn external_navigation_waits_for_busy_work_and_forms_until_explicit_navigation() {
    let (_, receiver) = sync_channel(1);
    let mut browser = Browser::new(receiver, Arc::new(AtomicBool::new(false)));
    let ctx = egui::Context::default();
    let (sender, inbox) = navigation::navigation_channel();
    inbox.attach(&ctx);
    browser.navigation = Some(inbox);
    let address = format!(
        "hypernet://{}/{}/Docs/{}",
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(32)
    );
    sender.try_open(Some(address.clone())).unwrap();
    let (reply, result) = sync_channel(1);
    let mut document = markup::parse(&format!("{}\n# Form\n", markup::PROFILE)).unwrap();
    document.forms.push(crate::markup::forms::Form {
        id: "Form".into(),
        label: "Form".into(),
        profile: crate::markup::forms::PROFILE.into(),
        recipient: "a".repeat(64),
        owner: "b".repeat(64),
        schema_digest: "c".repeat(64),
        fields: vec![],
    });
    browser.page = Some(Box::new(Page {
        document,
        metadata: vec![],
        view: page_view::View::new(),
        status: String::new(),
        mode: reader::Mode::Page,
        reply: Some(reply),
    }));
    browser.poll_navigation(&ctx);
    assert!(result.try_recv().is_err());
    browser.busy = false;
    browser.poll_navigation(&ctx);
    assert!(result.try_recv().is_err());
    assert_eq!(browser.navigation.as_ref().unwrap().queued(), 1);
    browser.open_queued();
    assert!(matches!(result.try_recv().unwrap().0,reader::Action::Address(a)if a==address));
    assert!(browser.busy);
    browser.shutdown();
    assert!(!sender.is_attached());
}
