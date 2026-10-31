// SPDX-License-Identifier: MIT
// Unit tests for PageView.
use super::*;
#[test]
fn focus_reveals_nested_viewports_and_local_actions_stay_in_document() {
    let document = crate::markup::parse("HyperNetPage/2\n# Focus\n@ScrollBox {\"id\":\"Outer\",\"label\":\"Outer\",\"rows\":3}\n: Before\n@ScrollBox {\"id\":\"Inner\",\"label\":\"Inner\",\"rows\":2}\n: One\n: Two\n: Three\n@Button {\"label\":\"Visible target\",\"action\":{\"kind\":\"Focus\",\"target\":\"Inner\"}}\n@End\n@End\n@Button {\"label\":\"Scroll to end\",\"action\":{\"kind\":\"Scroll\",\"target\":\"Inner\",\"direction\":\"End\"}}\n").unwrap();
    let mut view = View::new();
    let initial = view.layout(&document, 30, 12, false).unwrap();
    assert!(view.focused.is_none());
    let target = initial
        .controls
        .iter()
        .find(|c| c.label == "Visible target")
        .unwrap()
        .key;
    view.focused = Some(target);
    drop(initial);
    let revealed = view.reveal(&document, 30, 12, false).unwrap();
    let control = view.selected(&revealed).unwrap();
    assert!(control.y >= view.offset as i64 && control.y < (view.offset + 12) as i64);
    for ancestor in &control.ancestors {
        let info = &revealed.scrolls[&ancestor.key];
        assert!(ancestor.content_y >= info.offset as i64);
        assert!(ancestor.content_y < (info.offset + info.rows) as i64);
    }
    let inner = revealed.ids["Inner"];
    assert!(view.activate(&revealed).unwrap().is_none());
    assert_eq!(view.focused, Some(inner));
    view.tab(&revealed, true);
    assert_ne!(view.focused, Some(inner));
    let end = revealed
        .controls
        .iter()
        .find(|c| c.label == "Scroll to end")
        .unwrap()
        .key;
    view.focused = Some(end);
    assert!(view.activate(&revealed).unwrap().is_none());
    assert_eq!(view.scrolls[&inner], revealed.scrolls[&inner].maximum);
    drop(revealed);
    let narrow = view.reveal(&document, 14, 4, false).unwrap();
    assert_eq!(view.focused, Some(end));
    assert!(view.offset <= narrow.lines.len().saturating_sub(4));
}
