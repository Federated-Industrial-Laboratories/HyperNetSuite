// SPDX-License-Identifier: MIT
// Convert a static SVG shape subset to bounded canonical paths; never retain XML.
use crate::{
    markup::media::{self, PathCommand as C, Vector, VectorPath, VectorStroke},
    media_import::WorkerHeader,
};
use anyhow::{Context, Result, bail, ensure};
use roxmltree::Node;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Copy)]
struct Matrix([f64; 6]);
impl Matrix {
    fn identity() -> Self {
        Self([1., 0., 0., 1., 0., 0.])
    }
    fn then(self, next: Self) -> Self {
        let [a, b, c, d, e, f] = self.0;
        let [g, h, i, j, k, l] = next.0;
        Self([
            a * g + c * h,
            b * g + d * h,
            a * i + c * j,
            b * i + d * j,
            a * k + c * l + e,
            b * k + d * l + f,
        ])
    }
    fn point(self, x: f64, y: f64) -> Result<(i32, i32)> {
        let [a, b, c, d, e, f] = self.0;
        let fixed = |v: f64| -> Result<i32> {
            ensure!(
                v.is_finite() && v.abs() <= 16384.,
                "SVG coordinates exceed the vector bound"
            );
            Ok((v * 1024.).round() as i32)
        };
        Ok((fixed(a * x + c * y + e)?, fixed(b * x + d * y + f)?))
    }
    fn stroke_scale(self) -> Result<f64> {
        let [a, b, c, d, _, _] = self.0;
        let x = a.hypot(b);
        let y = c.hypot(d);
        ensure!(
            x.is_finite()
                && y.is_finite()
                && (x - y).abs() < 0.000001
                && (a * c + b * d).abs() < 0.000001,
            "stroked SVG shapes require a uniform scale without skew"
        );
        Ok(x)
    }
}
#[derive(Clone)]
struct Style {
    fill: Option<[u8; 4]>,
    stroke: Option<[u8; 4]>,
    width: f64,
    fill_alpha: f64,
    stroke_alpha: f64,
    rule: media::FillRule,
}
impl Default for Style {
    fn default() -> Self {
        Self {
            fill: Some([0, 0, 0, 255]),
            stroke: None,
            width: 1.,
            fill_alpha: 1.,
            stroke_alpha: 1.,
            rule: media::FillRule::NonZero,
        }
    }
}
fn number(value: &str) -> Result<f64> {
    let value = value.trim();
    let value = value.strip_suffix("px").unwrap_or(value);
    let n: f64 = value
        .parse()
        .context("SVG requires numeric or px lengths")?;
    ensure!(
        n.is_finite() && n.abs() <= 16_000_000.,
        "SVG numeric value is out of range"
    );
    Ok(n)
}
fn opacity(value: &str) -> Result<f64> {
    let n = number(value)?;
    ensure!((0.0..=1.0).contains(&n), "invalid SVG opacity");
    Ok(n)
}
fn paint(value: &str) -> Result<Option<[u8; 4]>> {
    if value.trim() == "none" {
        return Ok(None);
    }
    let c: svgtypes::Color = value
        .trim()
        .parse()
        .context("SVG paint requires a literal colour")?;
    Ok(Some([c.red, c.green, c.blue, c.alpha]))
}
fn transform(value: Option<&str>) -> Result<Matrix> {
    use svgtypes::TransformListToken as T;
    let mut m = Matrix::identity();
    if let Some(value) = value {
        for (index, token) in svgtypes::TransformListParser::from(value).enumerate() {
            ensure!(index < 32, "SVG transform list exceeds limit");
            let next = match token? {
                T::Matrix { a, b, c, d, e, f } => Matrix([a, b, c, d, e, f]),
                T::Translate { tx, ty } => Matrix([1., 0., 0., 1., tx, ty]),
                T::Scale { sx, sy } => Matrix([sx, 0., 0., sy, 0., 0.]),
                T::Rotate { angle } => {
                    let r = angle.to_radians();
                    Matrix([r.cos(), r.sin(), -r.sin(), r.cos(), 0., 0.])
                }
                T::SkewX { angle } => Matrix([1., 0., angle.to_radians().tan(), 1., 0., 0.]),
                T::SkewY { angle } => Matrix([1., angle.to_radians().tan(), 0., 1., 0., 0.]),
            };
            m = m.then(next);
            ensure!(
                m.0.iter().all(|v| v.is_finite() && v.abs() <= 16_000_000.),
                "SVG transform is out of range"
            );
        }
    }
    Ok(m)
}
fn attributes(
    node: Node<'_, '_>,
    warnings: &mut BTreeSet<String>,
) -> Result<BTreeMap<String, String>> {
    let mut attrs = BTreeMap::new();
    for attr in node.attributes() {
        let name = attr.name();
        if name.starts_with("on") {
            warnings.insert("SVG event handlers removed".into());
            continue;
        }
        if matches!(name, "id" | "class" | "version" | "baseProfile") {
            continue;
        }
        ensure!(
            attr.namespace().is_none(),
            "unsupported namespaced SVG attribute"
        );
        if name == "style" {
            for declaration in attr.value().split(';').filter(|s| !s.trim().is_empty()) {
                let (key, value) = declaration
                    .split_once(':')
                    .context("invalid SVG presentation style")?;
                let key = key.trim();
                ensure!(
                    matches!(
                        key,
                        "fill"
                            | "stroke"
                            | "stroke-width"
                            | "fill-rule"
                            | "fill-opacity"
                            | "stroke-opacity"
                            | "opacity"
                    ),
                    "unsupported SVG style property"
                );
                ensure!(
                    !attrs.contains_key(&format!("style:{key}")),
                    "duplicate SVG style property"
                );
                attrs.insert(format!("style:{key}"), value.trim().to_owned());
            }
        } else {
            attrs.insert(name.to_owned(), attr.value().to_owned());
        }
    }
    let styles: Vec<_> = attrs
        .iter()
        .filter_map(|(k, v)| {
            k.strip_prefix("style:")
                .map(|key| (key.to_owned(), v.clone()))
        })
        .collect();
    attrs.retain(|k, _| !k.starts_with("style:"));
    for (k, v) in styles {
        attrs.insert(k, v);
    }
    Ok(attrs)
}
fn take_style(
    attrs: &mut BTreeMap<String, String>,
    mut style: Style,
    group: bool,
) -> Result<Style> {
    if let Some(v) = attrs.remove("fill") {
        style.fill = paint(&v)?
    }
    if let Some(v) = attrs.remove("stroke") {
        style.stroke = paint(&v)?
    }
    if let Some(v) = attrs.remove("stroke-width") {
        style.width = number(&v)?;
        ensure!(style.width >= 0., "negative SVG stroke width")
    }
    if let Some(v) = attrs.remove("fill-opacity") {
        style.fill_alpha = opacity(&v)?
    }
    if let Some(v) = attrs.remove("stroke-opacity") {
        style.stroke_alpha = opacity(&v)?
    }
    if let Some(v) = attrs.remove("fill-rule") {
        style.rule = match v.as_str() {
            "nonzero" => media::FillRule::NonZero,
            "evenodd" => media::FillRule::EvenOdd,
            _ => bail!("unsupported SVG fill rule"),
        }
    }
    if let Some(v) = attrs.remove("opacity") {
        let v = opacity(&v)?;
        ensure!(
            !group || v == 1.,
            "SVG group opacity requires an unsupported compositing layer"
        );
        ensure!(
            v == 0.
                || v == 1.
                || style.fill.is_none()
                || style.stroke.is_none()
                || style.width == 0.,
            "SVG shape opacity with fill and stroke requires an unsupported compositing layer"
        );
        style.fill_alpha *= v;
        style.stroke_alpha *= v;
    }
    Ok(style)
}
fn num(attrs: &mut BTreeMap<String, String>, key: &str, default: f64) -> Result<f64> {
    attrs.remove(key).map(|v| number(&v)).unwrap_or(Ok(default))
}
fn path_data(name: &str, attrs: &mut BTreeMap<String, String>) -> Result<String> {
    Ok(match name {
        "path" => attrs.remove("d").context("SVG path has no geometry")?,
        "line" => format!(
            "M {} {} L {} {}",
            num(attrs, "x1", 0.)?,
            num(attrs, "y1", 0.)?,
            num(attrs, "x2", 0.)?,
            num(attrs, "y2", 0.)?
        ),
        "polyline" | "polygon" => {
            let points = attrs.remove("points").context("missing SVG points")?;
            let mut data = String::new();
            for (index, (x, y)) in svgtypes::PointsParser::from(points.as_str()).enumerate() {
                ensure!(index < 2048, "SVG points exceed limit");
                data.push_str(&format!("{} {x} {y} ", if index == 0 { "M" } else { "L" }));
            }
            // PointsParser is permissive at malformed suffixes; validate the complete numeric stream too.
            let values = svgtypes::NumberListParser::from(points.as_str())
                .collect::<std::result::Result<Vec<_>, _>>()?;
            ensure!(
                values.len() >= 4 && values.len() % 2 == 0,
                "invalid SVG point list"
            );
            if name == "polygon" {
                data.push('Z')
            }
            data
        }
        "rect" => {
            let x = num(attrs, "x", 0.)?;
            let y = num(attrs, "y", 0.)?;
            let w = num(attrs, "width", 0.)?;
            let h = num(attrs, "height", 0.)?;
            ensure!(
                w > 0. && h > 0.,
                "SVG rectangle must have positive dimensions"
            );
            let rx = attrs.remove("rx").map(|v| number(&v)).transpose()?;
            let ry = attrs.remove("ry").map(|v| number(&v)).transpose()?;
            let radii = (rx.or(ry).unwrap_or(0.), ry.or(rx).unwrap_or(0.));
            let rx = radii.0.min(w / 2.);
            let ry = radii.1.min(h / 2.);
            ensure!(rx >= 0. && ry >= 0., "invalid SVG corner radius");
            if rx == 0. || ry == 0. {
                format!("M {x} {y} h {w} v {h} h {} Z", -w)
            } else {
                format!(
                    "M {} {y} H {} A {rx} {ry} 0 0 1 {} {} V {} A {rx} {ry} 0 0 1 {} {} H {} A {rx} {ry} 0 0 1 {x} {} V {} A {rx} {ry} 0 0 1 {} {y} Z",
                    x + rx,
                    x + w - rx,
                    x + w,
                    y + ry,
                    y + h - ry,
                    x + w - rx,
                    y + h,
                    x + rx,
                    y + h - ry,
                    y + ry,
                    x + rx
                )
            }
        }
        "circle" | "ellipse" => {
            let x = num(attrs, "cx", 0.)?;
            let y = num(attrs, "cy", 0.)?;
            let (rx, ry) = if name == "circle" {
                let r = num(attrs, "r", 0.)?;
                (r, r)
            } else {
                (num(attrs, "rx", 0.)?, num(attrs, "ry", 0.)?)
            };
            ensure!(rx > 0. && ry > 0., "SVG ellipse must have positive radii");
            format!(
                "M {} {y} A {rx} {ry} 0 1 0 {} {y} A {rx} {ry} 0 1 0 {} {y} Z",
                x - rx,
                x + rx,
                x - rx
            )
        }
        _ => bail!("unsupported SVG visual element"),
    })
}
fn geometry(data: &str, m: Matrix) -> Result<Vec<C>> {
    use svgtypes::SimplePathSegment as S;
    let mut result = Vec::new();
    for segment in svgtypes::SimplifyingPathParser::from(data) {
        ensure!(result.len() < 2048, "SVG path exceeds 2048 commands");
        result.push(match segment? {
            S::MoveTo { x, y } => {
                let (x, y) = m.point(x, y)?;
                C::Move { x, y }
            }
            S::LineTo { x, y } => {
                let (x, y) = m.point(x, y)?;
                C::Line { x, y }
            }
            S::Quadratic { x1, y1, x, y } => {
                let (x1, y1) = m.point(x1, y1)?;
                let (x, y) = m.point(x, y)?;
                C::Quad { x1, y1, x, y }
            }
            S::CurveTo {
                x1,
                y1,
                x2,
                y2,
                x,
                y,
            } => {
                let (x1, y1) = m.point(x1, y1)?;
                let (x2, y2) = m.point(x2, y2)?;
                let (x, y) = m.point(x, y)?;
                C::Cubic {
                    x1,
                    y1,
                    x2,
                    y2,
                    x,
                    y,
                }
            }
            S::ClosePath => C::Close,
        });
    }
    ensure!(!result.is_empty(), "empty SVG path");
    Ok(result)
}
fn visit(
    node: Node<'_, '_>,
    m: Matrix,
    parent: &Style,
    depth: usize,
    paths: &mut Vec<VectorPath>,
    warnings: &mut BTreeSet<String>,
) -> Result<()> {
    ensure!(depth <= 32, "SVG nesting exceeds 32");
    if !node.is_element() {
        return Ok(());
    }
    let name = node.tag_name().name();
    if matches!(name, "metadata" | "title" | "desc" | "script") {
        warnings.insert(
            if name == "script" {
                "SVG scripts removed"
            } else {
                "SVG metadata removed"
            }
            .into(),
        );
        return Ok(());
    }
    ensure!(
        node.tag_name()
            .namespace()
            .is_none_or(|v| v == "http://www.w3.org/2000/svg"),
        "unsupported SVG namespace"
    );
    let mut attrs = attributes(node, warnings)?;
    let m = m.then(transform(attrs.remove("transform").as_deref())?);
    let group = name == "g";
    let style = take_style(&mut attrs, parent.clone(), group)?;
    if group {
        ensure!(attrs.is_empty(), "unsupported SVG group attribute");
        for child in node.children() {
            visit(child, m, &style, depth + 1, paths, warnings)?
        }
    } else {
        ensure!(
            node.children()
                .all(|n| n.is_comment() || n.is_text() && n.text().unwrap_or("").trim().is_empty()),
            "unsupported child in SVG shape"
        );
        let data = path_data(name, &mut attrs)?;
        ensure!(attrs.is_empty(), "unsupported SVG shape attribute");
        ensure!(paths.len() < 512, "SVG exceeds 512 paths");
        let alpha = |c: Option<[u8; 4]>, factor: f64| {
            c.map(|mut p| {
                p[3] = (f64::from(p[3]) * factor).round() as u8;
                p
            })
        };
        let stroke =
            if let Some(c) = alpha(style.stroke, style.stroke_alpha).filter(|_| style.width > 0.) {
                let width = style.width * m.stroke_scale()?;
                ensure!(width > 0. && width <= 64., "SVG stroke exceeds 64 pixels");
                Some(VectorStroke {
                    colour: c,
                    width: (width * 1024.).round().max(1.) as u32,
                })
            } else {
                None
            };
        paths.push(VectorPath {
            commands: geometry(&data, m)?,
            fill: alpha(style.fill, style.fill_alpha),
            stroke,
            fill_rule: style.rule,
        });
        ensure!(
            paths.iter().map(|p| p.commands.len()).sum::<usize>() <= 8192,
            "SVG exceeds 8192 commands"
        );
    }
    Ok(())
}
pub fn convert(bytes: &[u8], axis: u32) -> Result<(WorkerHeader, Vec<u8>)> {
    let text = std::str::from_utf8(bytes).context("import accepts only PNG, JPEG or UTF-8 SVG")?;
    ensure!(
        !text.contains("<!DOCTYPE") && !text.contains("<!ENTITY"),
        "SVG DTDs and entities are forbidden"
    );
    let document = roxmltree::Document::parse_with_options(
        text,
        roxmltree::ParsingOptions {
            allow_dtd: false,
            nodes_limit: 8192,
            entity_resolver: None,
        },
    )?;
    let root = document.root_element();
    ensure!(
        root.tag_name().name() == "svg"
            && root
                .tag_name()
                .namespace()
                .is_none_or(|v| v == "http://www.w3.org/2000/svg"),
        "input is not SVG"
    );
    for node in document.descendants() {
        ensure!(!node.is_pi(), "SVG processing instructions are forbidden");
        for attr in node.attributes() {
            ensure!(
                !matches!(attr.name(), "href" | "src" | "base"),
                "SVG resource references are forbidden"
            );
            ensure!(
                !attr.value().to_ascii_lowercase().contains("url("),
                "SVG resource paints are forbidden"
            );
        }
    }
    let mut warnings = BTreeSet::new();
    let mut attrs = attributes(root, &mut warnings)?;
    let viewbox = attrs
        .remove("viewBox")
        .map(|v| v.parse::<svgtypes::ViewBox>())
        .transpose()?;
    let w = attrs
        .remove("width")
        .map(|v| number(&v))
        .transpose()?
        .or(viewbox.map(|v| v.w))
        .context("SVG needs width or viewBox")?;
    let h = attrs
        .remove("height")
        .map(|v| number(&v))
        .transpose()?
        .or(viewbox.map(|v| v.h))
        .context("SVG needs height or viewBox")?;
    ensure!(
        w > 0. && h > 0. && w * h <= 16_000_000.,
        "SVG exceeds intrinsic pixel budget"
    );
    let (width, height) = super::fitted(w.ceil() as u32, h.ceil() as u32, axis)?;
    let aspect = attrs
        .remove("preserveAspectRatio")
        .unwrap_or_else(|| "xMidYMid meet".into());
    let mut m = Matrix([f64::from(width) / w, 0., 0., f64::from(height) / h, 0., 0.]);
    if let Some(v) = viewbox {
        ensure!(v.w > 0. && v.h > 0., "empty SVG viewBox");
        let sx = w / v.w;
        let sy = h / v.h;
        let vb = if aspect == "none" {
            Matrix([sx, 0., 0., sy, -v.x * sx, -v.y * sy])
        } else {
            ensure!(
                matches!(aspect.as_str(), "xMidYMid" | "xMidYMid meet"),
                "unsupported SVG aspect ratio"
            );
            let s = sx.min(sy);
            Matrix([
                s,
                0.,
                0.,
                s,
                (w - v.w * s) / 2. - v.x * s,
                (h - v.h * s) / 2. - v.y * s,
            ])
        };
        m = m.then(vb);
    }
    m = m.then(transform(attrs.remove("transform").as_deref())?);
    let style = take_style(&mut attrs, Style::default(), true)?;
    ensure!(attrs.is_empty(), "unsupported SVG root attribute");
    let mut paths = Vec::new();
    for child in root.children() {
        visit(child, m, &style, 1, &mut paths, &mut warnings)?
    }
    let vector = Vector {
        profile: media::VECTOR_PROFILE.into(),
        width,
        height,
        background: [255, 255, 255],
        paths,
    };
    media::validate_vector(&vector).map_err(anyhow::Error::msg)?;
    let data = serde_json::to_vec(&vector)?;
    media::vector(&data).map_err(anyhow::Error::msg)?;
    warnings.insert("SVG converted to static paths; transparent areas use white".into());
    Ok((
        WorkerHeader {
            profile: media::VECTOR_PROFILE.into(),
            width,
            height,
            bytes: data.len(),
            warnings: warnings.into_iter().collect(),
        },
        data,
    ))
}
#[cfg(test)]
mod tests {
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
}
