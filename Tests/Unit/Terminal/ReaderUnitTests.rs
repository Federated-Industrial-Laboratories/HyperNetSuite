// SPDX-License-Identifier: MIT
// Unit tests for Reader.
use super::*;
use unicode_width::UnicodeWidthStr;
#[test]
fn oversized_field_save_preserves_the_view_and_editable_value() {
    let mut source = String::from("HyperNetPage/2\n# Forms\n");
    source.push_str(&"@Panel {\"label\":\"Panel\",\"padding\":4}\n".repeat(6));
    for index in 0..4 {
        source.push_str(&format!("@Form {{\"id\":\"F{index}\",\"label\":\"Form\",\"profile\":\"HyperNetFormMail/1\",\"recipient\":\"{}\",\"owner\":\"{}\"}}\n", "01".repeat(32), "02".repeat(32)));
        for field in 0..4 {
            source.push_str(&format!("@Field {{\"id\":\"T{field}\",\"label\":\"Text\",\"kind\":\"Text\",\"maxBytes\":2048}}\n"));
        }
        source.push_str("@Submit {\"label\":\"Review\"}\n@End\n");
    }
    source.push_str(&"@End\n".repeat(6));
    let document = crate::markup::parse(&source).unwrap();
    let mut view = crate::page_view::View::new();
    let long = serde_json::json!("x".repeat(2000));
    preflight_at(&document, &view, (80, 30), false).unwrap();
    let mut refused = false;
    'fields: for form in &document.forms {
        for field in &form.fields {
            let editor = crate::form_ui::Editor::new(form.id.clone(), field.clone(), Some(&long));
            let previous = view.form_values.clone();
            if save_field_value(
                &document,
                &mut view,
                &editor,
                Some(long.clone()),
                (80, 30),
                false,
            )
            .is_err()
            {
                refused = true;
                assert_eq!(view.form_values, previous);
                assert_eq!(editor.text.len(), 2000);
                preflight_at(&document, &view, (80, 30), false).unwrap();
                save_field_value(
                    &document,
                    &mut view,
                    &editor,
                    Some(serde_json::json!("Short")),
                    (80, 30),
                    false,
                )
                .unwrap();
                assert_eq!(view.form_values[&form.id][&field.id], "Short");
                break 'fields;
            }
            crate::markup::forms::validate_values(form, &view.form_values[&form.id]).unwrap();
        }
    }
    assert!(
        refused,
        "the fixture must reach the layout budget before the byte limit"
    );
}
#[test]
fn resize_refusal_preserves_view_until_a_bounded_layout_can_resume() {
    let source = format!(
        "HyperNetPage/2\n# Budget\n{}",
        "@Spacer {\"rows\":8}\n".repeat(250)
    );
    let document = crate::markup::parse(&source).unwrap();
    let mut view = crate::page_view::View::new();
    view.offset = 17;
    view.details_offset = 5;
    let narrow = prepare_layout(&document, &mut view, 35, 18, false, false).unwrap();
    assert_eq!(narrow.lines.len(), 2000);
    drop(narrow);
    assert!(prepare_layout(&document, &mut view, 295, 18, false, true).is_err());
    assert_eq!(view.offset, 17);
    assert_eq!(view.details_offset, 5);
    let restored = prepare_layout(&document, &mut view, 35, 18, false, true).unwrap();
    assert_eq!(restored.lines.len(), 2000);
    assert_eq!(view.offset, 17);
    assert_eq!(view.details_offset, 5);
    // Plain output does not allocate a cell grid.
    assert!(document.lines.len() >= 250);
}
#[test]
fn address_editor_rejects_controls_without_interpreting_shortcuts() {
    use crossterm::event::KeyEvent;
    let mut editor = AddressEditor::default();
    for character in "qrbo".chars() {
        assert_eq!(
            editor.input(&Event::Key(KeyEvent::new(
                KeyCode::Char(character),
                KeyModifiers::NONE
            ))),
            Edit::Changed
        );
    }
    assert_eq!(editor.value, "qrbo");
    assert_eq!(
        editor.input(&Event::Key(KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL
        ))),
        Edit::Quit
    );
    assert_eq!(
        editor.input(&Event::Paste("bad\x03q".into())),
        Edit::Rejected
    );
    assert_eq!(editor.input(&Event::Paste("bad\nq".into())), Edit::Rejected);
    assert_eq!(editor.value, "qrbo");
    assert_eq!(editor.input(&Event::Paste("x".repeat(513))), Edit::Rejected);
    assert_eq!(
        editor.input(&Event::Key(KeyEvent::new(
            KeyCode::Char('u'),
            KeyModifiers::CONTROL
        ))),
        Edit::Changed
    );
    assert!(editor.value.is_empty());
    assert_eq!(editor.input(&Event::Paste("x".repeat(512))), Edit::Changed);
    assert_eq!(editor.append("x"), Edit::Rejected);
    assert_eq!(
        editor.input(&Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))),
        Edit::Cancel
    );
    assert_eq!(
        editor.input(&Event::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::NONE
        ))),
        Edit::Submit
    );
}
#[test]
fn trusted_status_is_bounded_and_escapes_terminal_controls() {
    let status = bounded_status(&format!("{}\x1b]52;secret\x07", "x".repeat(1020)));
    assert!(status.chars().count() <= 1024);
    assert!(!status.contains('\x1b'));
    assert!(
        !bounded_status("bad\n\r\x1b\u{202e}")
            .chars()
            .any(char::is_control)
    );
}
#[test]
fn unicode_wrap_preserves_boundaries_and_ascii_fallback() {
    let value = "世界 cafe\u{301} 👩\u{200d}💻";
    for width in 1..12 {
        assert!(
            crate::page_layout::wrap(value, width)
                .iter()
                .all(|line| line.width() <= width)
        );
    }
    assert_eq!(text("世界", true), "\\u{4e16}\\u{754c}");
    assert!(!text("\x1b]52;bad\x07", false).contains('\x1b'));
}
