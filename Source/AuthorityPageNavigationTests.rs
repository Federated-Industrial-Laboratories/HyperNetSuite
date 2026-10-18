// SPDX-License-Identifier: MIT
// Navigation refuses oversized layouts without losing verified content or local input.
use super::*;

fn identity() -> publication::Identity {
    publication::Identity {
        network: "01".repeat(32),
        incarnation: "02".repeat(32),
        page: "03".repeat(16),
        ledger: "Ledger".into(),
        revision: "Revision".into(),
        approval: "Approval".into(),
        bundle: "Bundle".into(),
    }
}
fn entry(oversized: bool) -> Entry {
    let source = if oversized {
        format!(
            "HyperNetPage/2\n# Budget\n{}",
            "@Spacer {\"rows\":8}\n".repeat(250)
        )
    } else {
        "HyperNetPage/2\n# Retained\n: Still available.\n".into()
    };
    Entry {
        location: Location::Catalogue("Example".into(), None),
        publication: None,
        document: markup::parse(&source).unwrap(),
        metadata: vec![],
        next: None,
        view: page_view::View::new(),
    }
}
fn wide(document: &markup::Document, view: &page_view::View) -> Result<()> {
    reader::preflight_at(document, view, (300, 30), false)
}

#[test]
fn unchanged_publication_refresh_preserves_drafts_focus_scroll_and_revealed_media() {
    let id = identity();
    let mut next = id.clone();
    next.ledger = "New pending revision".into();
    let mut view = page_view::View::new();
    view.offset = 7;
    view.focused = Some(3);
    view.scrolls.insert(4, 12);
    view.revealed.insert("Cafe".into());
    view.form_values
        .insert("Order".into(), [("Name".into(), json!("Unsent"))].into());
    let kept = refreshed_view(Some(&id), Some(&next), &view);
    assert_eq!(kept.offset, 7);
    assert_eq!(kept.focused, Some(3));
    assert_eq!(kept.scrolls, view.scrolls);
    assert_eq!(kept.revealed, view.revealed);
    assert_eq!(kept.form_values, view.form_values);
    next.approval = "Another approved revision".into();
    let reset = refreshed_view(Some(&id), Some(&next), &view);
    assert!(reset.form_values.is_empty() && reset.revealed.is_empty());
    assert_eq!(reset.focused, None);
    assert_eq!(reset.offset, 0);
}

#[test]
fn failed_navigation_and_back_keep_current_display_and_history() {
    let mut current = entry(false);
    current
        .view
        .form_values
        .insert("Order".into(), [("Name".into(), json!("Unsent"))].into());
    let mut history = VecDeque::from([entry(true)]);
    assert!(install_entry(&mut current, &mut history, entry(true), false, wide).is_err());
    assert_eq!(history.len(), 1);
    assert_eq!(current.view.form_values["Order"]["Name"], "Unsent");
    assert!(previous_entry(&mut current, &mut history, wide).is_err());
    assert_eq!(history.len(), 1);
    assert_eq!(current.view.form_values["Order"]["Name"], "Unsent");
    assert!(
        previous_entry(&mut current, &mut history, |d, v| reader::preflight_at(
            d,
            v,
            (40, 30),
            false
        ))
        .unwrap()
    );
    assert!(history.is_empty());
}

#[test]
fn plain_catalogue_metadata_exposes_exact_continuation() {
    let metadata = catalogue_metadata(17, Some([73; 32]));
    assert!(
        metadata
            .iter()
            .any(|s| s.contains(&format!("--after {}", hex::encode([73; 32]))))
    );
    assert_eq!(catalogue_metadata(18, None).len(), 1);
}
