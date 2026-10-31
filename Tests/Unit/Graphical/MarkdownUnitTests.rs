// SPDX-License-Identifier: MIT
// Unit tests for Markdown.
use super::*;
#[test]
fn formatting_preserves_inert_code_html_and_explicit_links() {
    let parsed = Markdown::parse(
        "**Strong** *Emphasis* [Open](hypernet://example)\n\n<script>alert(1)</script>\n\n```sh\nrm -rf /\n```\n\n| A | B |\n|---|---|\n| 1 | 2 |\n",
    );
    let debug = format!("{parsed:?}");
    for expected in [
        "Strong",
        "Emphasis",
        "Link(\"hypernet://example\")",
        "<script>alert(1)</script>",
        "rm -rf /",
        "Table",
    ] {
        assert!(debug.contains(expected), "{expected}: {debug}");
    }
}
#[test]
fn deep_markdown_falls_back_without_losing_text() {
    let source = format!("{}text", "> ".repeat(40));
    let parsed = Markdown::parse(&source);
    assert!(matches!(&parsed.elements[..], [Element::Text(value)] if value == &source));
}
#[test]
fn external_markdown_images_never_resolve_as_assets() {
    let document = crate::markup::parse("HyperNetPage/2\n# Example\n: Text\n").unwrap();
    assert!(asset(&document, "https://example.org/Image.png").is_none());
    assert!(asset(&document, "file:///etc/passwd").is_none());
}
