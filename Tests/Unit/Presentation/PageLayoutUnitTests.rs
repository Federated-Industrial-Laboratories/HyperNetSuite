// SPDX-License-Identifier: MIT
// Unit tests for PageLayout.
use super::*;
fn parse(source: &str) -> Document {
    crate::markup::parse(&format!("HyperNetPage/2\n# Layout\n{source}")).unwrap()
}
fn rows(layout: &Layout) -> Vec<String> {
    layout
        .lines
        .iter()
        .map(|l| l.cells.iter().map(|c| c.text.as_str()).collect::<String>())
        .collect()
}
#[test]
fn border_families_inherit_join_and_preserve_inset_dividers() {
    for (name, top, bottom, joined) in [
        ("Light", '┌', '└', "├──────────────────┤"),
        ("Heavy", '┏', '┗', "┣━━━━━━━━━━━━━━━━━━┫"),
        ("Double", '╔', '╚', "╠══════════════════╣"),
        ("Rounded", '╭', '╰', "├──────────────────┤"),
        ("Ascii", '+', '+', "+------------------+"),
    ] {
        let doc = parse(&format!(
            "@Panel {{\"label\":\"Frame\",\"border\":\"{name}\",\"padding\":2}}\n@Row {{\"minChildColumns\":12}}\n@Column {{}}\n@Separator {{}}\n@End\n@End\n@Column {{\"padding\":1}}\n@Separator {{}}\n@End\n@Panel {{\"label\":\"Child\",\"padding\":0,\"border\":null}}\n: Text\n@End\n@Panel {{\"label\":\"Override\",\"padding\":0,\"border\":\"Light\"}}\n: Text\n@End\n@End\n@Panel {{\"label\":\"Sibling\",\"padding\":0}}\n: Text\n@End\n"
        ));
        let layout = build(&doc, 20, &BTreeMap::new(), false).unwrap();
        let text = rows(&layout);
        assert!(text[0].starts_with(top));
        assert_eq!(text[3], joined);
        assert_eq!(
            layout.lines[5].cells[0].border.unwrap().part,
            Part::Vertical
        );
        assert!(text[5].chars().nth(1) == Some(' '));
        assert!(
            text.iter()
                .find(|line| line.contains("Child"))
                .unwrap()
                .contains(top)
        );
        assert!(
            text.iter()
                .find(|line| line.contains("Override"))
                .unwrap()
                .contains('┌')
        );
        assert!(
            text.iter()
                .find(|line| line.contains("Sibling"))
                .unwrap()
                .starts_with('┌')
        );
        assert!(text.iter().any(|line| line.starts_with(bottom)));
        let ascii = build(&doc, 20, &BTreeMap::new(), true).unwrap();
        assert!(rows(&ascii).iter().all(|line| line.is_ascii()));
        assert_eq!(rows(&ascii)[3], "+------------------+");
    }
}
#[test]
fn styled_scroll_dividers_clip_and_reflow_at_cell_boundaries() {
    let doc = parse(concat!(
        "@Panel {\"label\":\"世界 ─ +\",\"border\":\"Rounded\",\"padding\":1}\n",
        "@ScrollBox {\"id\":\"Guide\",\"label\":\"Guide\",\"rows\":2,\"border\":\"Double\"}\n",
        ": First 世界\n@Separator {}\n: Last café\n@End\n@End\n"
    ));
    for width in 1..=40 {
        for ascii in [false, true] {
            let layout = build(&doc, width, &BTreeMap::new(), ascii).unwrap();
            assert!(rows(&layout).iter().all(|line| line.width() == width));
            let key = layout.ids["Guide"];
            let offset = layout.scrolls[&key].maximum;
            let scrolled = build(&doc, width, &BTreeMap::from([(key, offset)]), ascii).unwrap();
            assert!(rows(&scrolled).iter().all(|line| line.width() == width));
            if width == 40 && !ascii {
                let text = rows(&scrolled).join("\n");
                assert!(text.contains("╠══════════════════════════════════╣"));
                assert!(text.contains("Last café") && !text.contains("First"));
            }
        }
    }
}
#[test]
fn images_are_clipped_to_every_scrollbox_and_alt_text_is_retained() {
    let asset = format!(
        r#"@Asset {{"id":"Picture","profile":"HyperNetRaster/1","width":1,"height":1,"bytes":3,"digest":"{}","hosts":["{}"],"copies":1}}"#,
        "0".repeat(64),
        "1".repeat(64)
    );
    let doc = parse(&format!(
        "{asset}\n@ScrollBox {{\"id\":\"Outer\",\"label\":\"Outer\",\"rows\":4}}\n: Above\n@ScrollBox {{\"id\":\"Inner\",\"label\":\"Inner\",\"rows\":6}}\n@Image {{\"id\":\"View\",\"asset\":\"Picture\",\"alt\":\"Red diagram\",\"rows\":8}}\n@End\n@End\n"
    ));
    let first = build(&doc, 40, &BTreeMap::new(), false).unwrap();
    let offsets = BTreeMap::from([(first.ids["Outer"], 2), (first.ids["Inner"], 3)]);
    let clipped = build(&doc, 40, &offsets, false).unwrap();
    let image = &clipped.visuals[0];
    assert!(image.top >= 1 && image.bottom <= 5);
    assert!(image.y < image.top && image.bottom - image.top <= 4);
    assert!(doc.lines.iter().any(|line| line.contains("Red diagram")));
}
#[test]
fn weighted_rows_stack_and_preserve_unicode_cell_boundaries() {
    let doc = parse(
        "@Row {\"minChildColumns\":12,\"gap\":2}\n@Column {\"weight\":1}\n: LEFT 世界 cafe\u{301}\n@End\n@Column {\"weight\":3}\n: RIGHT 👩\u{200d}💻\n@End\n@End\n",
    );
    let wide = build(&doc, 60, &BTreeMap::new(), false).unwrap();
    let wide_rows = rows(&wide);
    assert!(
        wide_rows
            .iter()
            .any(|line| line.contains("LEFT") && line.contains("RIGHT"))
    );
    assert!(wide_rows.iter().all(|line| line.width() == 60));
    let narrow = build(&doc, 20, &BTreeMap::new(), false).unwrap();
    let narrow_rows = rows(&narrow);
    let left = narrow_rows
        .iter()
        .position(|line| line.contains("LEFT"))
        .unwrap();
    let right = narrow_rows
        .iter()
        .position(|line| line.contains("RIGHT"))
        .unwrap();
    assert!(right > left);
    assert!(narrow_rows.iter().all(|line| line.width() == 20));
    for width in 1..8 {
        let clipped = build(&doc, width, &BTreeMap::new(), false).unwrap();
        assert!(rows(&clipped).iter().all(|line| line.width() == width));
    }
}
#[test]
fn panels_inherit_logical_colour_and_clip_nested_scroll_content() {
    let doc = parse(
        "@Panel {\"label\":\"Frame\",\"colour\":\"Cyan\",\"padding\":1}\n@ScrollBox {\"id\":\"Guide\",\"label\":\"Guide\",\"rows\":2}\n: FIRST\n: SECOND\n: HIDDEN\n@Text {\"value\":\"LAST\",\"colour\":\"BrightRed\",\"bold\":true}\n@End\n@End\n",
    );
    let layout = build(&doc, 30, &BTreeMap::new(), false).unwrap();
    let text = rows(&layout).join("\n");
    assert!(text.contains("FIRST") && !text.contains("HIDDEN"));
    let first_row = rows(&layout)
        .iter()
        .position(|line| line.contains("FIRST"))
        .unwrap();
    let first = layout.lines[first_row]
        .cells
        .iter()
        .find(|c| c.text == "F")
        .unwrap();
    assert_eq!(first.style.colour, Some(Colour::Cyan));
    let key = layout.ids["Guide"];
    let end = layout.scrolls[&key].maximum;
    drop(layout);
    let scrolled = build(&doc, 30, &BTreeMap::from([(key, end)]), false).unwrap();
    assert!(rows(&scrolled).join("\n").contains("LAST"));
    let last = scrolled
        .lines
        .iter()
        .flat_map(|l| &l.cells)
        .find(|c| c.text == "L")
        .unwrap();
    assert_eq!(last.style.colour, Some(Colour::BrightRed));
    assert!(last.style.bold);
    assert!(doc.lines.iter().any(|line| line.contains("HIDDEN")));
}
#[test]
fn explicit_cell_budget_bounds_large_static_layouts() {
    let doc = parse(&"@Spacer {\"rows\":8}\n".repeat(250));
    assert!(build(&doc, 300, &BTreeMap::new(), false).is_err());
    let narrow = build(&doc, 40, &BTreeMap::new(), false).unwrap();
    assert_eq!(narrow.lines.len(), 2000);
    assert!(build(&doc, MAX_COLUMNS + 1, &BTreeMap::new(), false).is_err());
}
