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
