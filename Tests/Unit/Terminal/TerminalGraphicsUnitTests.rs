// SPDX-License-Identifier: MIT
// Unit tests for TerminalGraphics.
use super::*;
#[test]
fn generated_encoders_have_bounded_frames_and_no_external_transport() {
    let p = Pixels {
        width: 2,
        height: 2,
        rgb: vec![255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255],
    };
    for adapter in [Adapter::Kitty, Adapter::ITerm2, Adapter::Sixel] {
        let b = encode(adapter, &p, 41).unwrap();
        assert!(b.len() < 4096);
        let s = String::from_utf8(b).unwrap();
        assert!(!s.contains("name="));
        assert!(!s.contains("t=f"));
        assert!(!s.contains("t=s"));
    }
    let bytes = encode(
        Adapter::Kitty,
        &Pixels {
            width: 512,
            height: 512,
            rgb: vec![7; 512 * 512 * 3],
        },
        1,
    )
    .unwrap();
    for chunk in bytes.split(|b| *b == b';').skip(1) {
        let end = chunk.iter().position(|b| *b == 27).unwrap();
        assert!(end <= 4096)
    }
}
#[test]
fn graphics_default_to_off_and_reject_incomplete_geometry() {
    assert_eq!(Options::default().graphics, Adapter::Off);
    assert!(Options::default().geometry().is_none());
    assert!(
        Options {
            graphics_cell_width: Some(8),
            ..Options::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        Options {
            graphics_cell_width: Some(0),
            graphics_cell_height: Some(16),
            ..Options::default()
        }
        .validate()
        .is_err()
    );
}
#[test]
fn crop_and_aggregate_rate_cannot_escape_limits() {
    let bounded = bounded_viewport(1800, 800).unwrap();
    assert!(bounded.0 <= 1024 && bounded.1 <= 800 && bounded.0 * bounded.1 <= 262144);
    let p = Pixels {
        width: 2,
        height: 2,
        rgb: vec![42; 12],
    };
    let p = fit(&p, 20, 20, Fit::Contain, 8, 12, None).unwrap();
    assert_eq!((p.width, p.height, p.rgb.len()), (20, 4, 240));
    let now = Instant::now();
    let mut b = Budget::default();
    assert!(b.allow(MAX_OPERATION, now));
    assert!(!b.allow(1, now));
    assert!(b.allow(1, now + Duration::from_secs(1)));
}
