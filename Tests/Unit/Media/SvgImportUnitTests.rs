// SPDX-License-Identifier: MIT
// Unit tests for SvgImport.
use super::*;
#[test]
fn safe_shapes_remain_vectors_and_active_content_is_reported() {
    let source=br##"<svg xmlns="http://www.w3.org/2000/svg" width="80" height="40" viewBox="0 0 80 40"><script>alert(1)</script><g transform="translate(2 1)" fill="#fa0"><rect width="20" height="10" onclick="bad()"/><circle cx="40" cy="20" r="8"/></g></svg>"##;
    let (h, b) = convert(source, 1024).unwrap();
    let v = media::vector(&b).unwrap();
    assert_eq!(v.paths.len(), 2);
    assert!(h.warnings.iter().any(|w| w.contains("scripts")));
    assert!(h.warnings.iter().any(|w| w.contains("event")));
    assert!(!String::from_utf8(b).unwrap().contains("script"));
}
#[test]
fn canonical_geometry_rasterises_literal_shapes_without_xml() {
    let (_, bytes) = convert(
        br#"<svg width="4" height="4"><rect width="4" height="4" fill="red"/></svg>"#,
        1024,
    )
    .unwrap();
    let vector = media::vector(&bytes).unwrap();
    let rgb = crate::media_import::render_vector(&vector).unwrap();
    assert_eq!(rgb.len(), 48);
    assert!(rgb.chunks_exact(3).all(|pixel| pixel == [255, 0, 0]));
}
#[test]
fn rounded_rectangle_radii_are_inherited_before_independent_clamps() {
    let (_, bytes) = convert(
        br#"<svg width="4" height="40"><rect width="4" height="40" rx="10"/></svg>"#,
        1024,
    )
    .unwrap();
    let vector = media::vector(&bytes).unwrap();
    assert!(vector.paths[0].commands.iter().any(|command| matches!(
        command,
        C::Cubic {
            x: 4096,
            y: 10240,
            ..
        }
    )));
}
#[test]
fn shape_opacity_cannot_change_fill_and_stroke_compositing() {
    for attributes in [
        "fill='red' stroke='red' stroke-width='4' opacity='.5'",
        "style='fill:red;stroke:red;stroke-width:4;opacity:.5'",
    ] {
        let source = format!(
            "<svg width='20' height='20'><rect x='4' y='4' width='12' height='12' {attributes}/></svg>"
        );
        assert!(convert(source.as_bytes(), 1024).is_err());
    }
    let (_, bytes) = convert(
        b"<svg width='4' height='4'><rect width='4' height='4' fill='red' opacity='.5'/></svg>",
        1024,
    )
    .unwrap();
    let pixels = crate::media_import::render_vector(&media::vector(&bytes).unwrap()).unwrap();
    assert!(pixels.chunks_exact(3).all(|pixel| pixel == [255, 127, 127]));
}
#[test]
fn dangerous_or_unsupported_visual_semantics_are_refused() {
    for body in [
        "<image href='https://x' width='4' height='4'/>",
        "<foreignObject/>",
        "<text>text</text>",
        "<animate/>",
        "<rect width='4' height='4' filter='url(#x)'/>",
        "<g opacity='.5'><rect width='4' height='4'/></g>",
        "<path d='M0 0 L4 4' stroke='red' transform='scale(2 1)'/>",
    ] {
        assert!(
            convert(
                format!("<svg width='8' height='8'>{body}</svg>").as_bytes(),
                1024
            )
            .is_err(),
            "{body}"
        );
    }
    assert!(convert(b"<!DOCTYPE svg []><svg width='8' height='8'/>", 1024).is_err());
}
