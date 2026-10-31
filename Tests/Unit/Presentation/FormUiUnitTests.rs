// SPDX-License-Identifier: MIT
// Unit tests for FormUi.
use super::*;
use crossterm::event::KeyEvent;
#[test]
fn field_input_is_bounded_inert_and_explicitly_saved() {
    let field = Field {
        id: "Reply".into(),
        label: "Reply".into(),
        required: true,
        kind: FieldKind::Multiline { max_bytes: 32 },
    };
    let mut editor = Editor::new("Enquiry".into(), field, None);
    assert!(matches!(
        editor.input(&Event::Paste("q\n世界".into())),
        Edit::Continue
    ));
    assert_eq!(editor.text, "q\n世界");
    editor.input(&Event::Paste("x".repeat(33)));
    assert_eq!(editor.text, "q\n世界");
    assert!(
        matches!(editor.input(&Event::Key(KeyEvent::new(KeyCode::Enter,KeyModifiers::NONE))),Edit::Save(Some(Value::String(value))) if value=="q\n世界")
    );
    assert!(matches!(
        editor.input(&Event::Key(KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL
        ))),
        Edit::Quit
    ));
}
