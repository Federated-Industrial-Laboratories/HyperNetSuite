// SPDX-License-Identifier: MIT
// Unit tests for FormFields.
use super::*;
fn integer() -> Field {
    Field {
        id: "Count".into(),
        label: "Count".into(),
        required: false,
        kind: FieldKind::Integer {
            minimum: -2,
            maximum: 2,
        },
    }
}
#[test]
fn invalid_edit_removes_stale_typed_value() {
    let field = integer();
    let mut values = BTreeMap::new();
    update(&field, "2", &mut values).unwrap();
    assert_eq!(values["Count"], Value::from(2));
    for invalid in ["3", "2.0", "x", "9223372036854775808"] {
        assert!(update(&field, invalid, &mut values).is_err());
        assert!(!values.contains_key("Count"));
    }
    update(&field, "", &mut values).unwrap();
    assert!(values.is_empty());
}
#[test]
fn invalid_optional_field_blocks_submission_even_when_typed_value_is_absent() {
    let field = integer();
    let form = Form {
        id: "Example".into(),
        label: "Example".into(),
        profile: forms::PROFILE.into(),
        recipient: "01".repeat(32),
        owner: "02".repeat(32),
        schema_digest: "03".repeat(32),
        fields: vec![field],
    };
    let mut view = View::new();
    let fields = Fields;
    assert!(fields.ready(&form, &view));
    view.form_edits.insert(
        (form.id.clone(), "Count".into()),
        FormEdit {
            text: "invalid".into(),
            invalid: true,
        },
    );
    assert!(!fields.ready(&form, &view));
}
#[test]
fn history_restores_raw_invalid_optional_edit_and_its_submission_blocker() {
    let field = integer();
    let form = Form {
        id: "Example".into(),
        label: "Example".into(),
        profile: forms::PROFILE.into(),
        recipient: "01".repeat(32),
        owner: "02".repeat(32),
        schema_digest: "03".repeat(32),
        fields: vec![field.clone()],
    };
    let context = egui::Context::default();
    let mut view = View::new();
    view.form_values
        .entry(form.id.clone())
        .or_default()
        .insert(field.id.clone(), Value::from(2));
    let mut fields = Fields;
    context
        .run_ui(egui::RawInput::default(), |ui| {
            fields.show(
                ui,
                &form.id,
                &field,
                &mut view,
                egui::Id::unique("HistoryField"),
            );
        })
        .drop_without_applying_deltas();
    let key = (form.id.clone(), field.id.clone());
    let edit = view.form_edits.get_mut(&key).unwrap();
    edit.text = "3".into();
    edit.invalid = update(
        &field,
        &edit.text,
        view.form_values.get_mut(&form.id).unwrap(),
    )
    .is_err();
    assert!(!fields.ready(&form, &view));
    let history = view.clone();
    let away = View::new();
    assert_ne!(away.instance, history.instance);
    assert!(away.form_edits.is_empty());
    let mut back = history.clone();
    let mut restored_fields = Fields;
    context
        .run_ui(egui::RawInput::default(), |ui| {
            restored_fields.show(
                ui,
                &form.id,
                &field,
                &mut back,
                egui::Id::unique("HistoryField"),
            );
        })
        .drop_without_applying_deltas();
    assert_eq!(back.instance, history.instance);
    assert_eq!(back.form_edits[&key].text, "3");
    assert!(back.form_edits[&key].invalid);
    assert!(!back.form_values[&form.id].contains_key(&field.id));
    assert!(!restored_fields.ready(&form, &back));
    let edit = back.form_edits.get_mut(&key).unwrap();
    edit.text = "2".into();
    edit.invalid = update(
        &field,
        &edit.text,
        back.form_values.get_mut(&form.id).unwrap(),
    )
    .is_err();
    assert!(restored_fields.ready(&form, &back));
    assert_eq!(history.form_edits[&key].text, "3");
    assert!(history.form_edits[&key].invalid);
}
#[test]
fn native_edits_obey_utf8_and_serialized_total_bounds() {
    let mut field = integer();
    field.kind = FieldKind::Text { max_bytes: 2048 };
    let mut values = BTreeMap::new();
    assert!(update(&field, &"é".repeat(1025), &mut values).is_err());
    assert!(values.is_empty());
    for number in 0..3 {
        field.id = format!("Field{number}");
        update(&field, &"\\".repeat(1024), &mut values).unwrap();
    }
    field.id = "Final".into();
    assert!(update(&field, &"\\".repeat(1024), &mut values).is_err());
    assert!(!values.contains_key("Final"));
    assert!(serde_json::to_vec(&values).unwrap().len() <= forms::MAX_VALUES_BYTES);
}
