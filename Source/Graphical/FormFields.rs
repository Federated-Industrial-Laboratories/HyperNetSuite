// SPDX-License-Identifier: MIT
// Native typed fields retain invalid edits without retaining stale submit values.
use crate::{
    markup::forms::{self, Field, FieldKind, Form},
    page_view::{FormEdit, View},
};
use eframe::egui::{self, ComboBox, Response, TextEdit, Ui};
use serde_json::Value;
use std::collections::BTreeMap;
use zeroize::Zeroize;

#[derive(Default)]
pub(super) struct Fields;
fn remove(values: &mut BTreeMap<String, Value>, id: &str) {
    if let Some(Value::String(mut text)) = values.remove(id) {
        text.zeroize();
    }
}
fn typed(field: &Field, text: &str) -> Result<Option<Value>, &'static str> {
    if text.is_empty() && !field.required {
        return Ok(None);
    }
    let value = match field.kind {
        FieldKind::Integer { .. } => Value::from(
            text.parse::<i64>()
                .map_err(|_| "Enter an integer within the field bounds")?,
        ),
        FieldKind::Boolean => match text {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            _ => return Err("Choose true or false"),
        },
        _ => Value::String(text.to_owned()),
    };
    forms::validate_field(field, &value)
        .map_err(|_| "Value does not meet the field requirements")?;
    Ok(Some(value))
}
fn update(
    field: &Field,
    text: &str,
    values: &mut BTreeMap<String, Value>,
) -> Result<(), &'static str> {
    // An invalid edit removes the previous value before any validation returns.
    remove(values, &field.id);
    if let Some(value) = typed(field, text)? {
        values.insert(field.id.clone(), value);
    }
    if serde_json::to_vec(values)
        .map_err(|_| "Invalid form values")?
        .len()
        > forms::MAX_VALUES_BYTES
    {
        remove(values, &field.id);
        return Err("Combined form values exceed 8 KiB");
    }
    Ok(())
}
impl Fields {
    pub(super) fn show(
        &mut self,
        ui: &mut Ui,
        form: &str,
        field: &Field,
        view: &mut View,
        id: egui::Id,
    ) -> Response {
        let values = view.form_values.entry(form.to_owned()).or_default();
        let edit = view
            .form_edits
            .entry((form.to_owned(), field.id.clone()))
            .or_insert_with(|| FormEdit {
                text: values
                    .get(&field.id)
                    .map(|v| {
                        v.as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| v.to_string())
                    })
                    .unwrap_or_default(),
                invalid: false,
            });
        let label = ui.add(
            egui::Label::new(format!(
                "{}{}",
                field.label,
                if field.required { " *" } else { "" }
            ))
            .sense(egui::Sense::click()),
        );
        let mut changed = false;
        let response = match &field.kind {
            FieldKind::Text { max_bytes } | FieldKind::Multiline { max_bytes } => {
                let widget = if matches!(field.kind, FieldKind::Multiline { .. }) {
                    TextEdit::multiline(&mut edit.text).desired_rows(4)
                } else {
                    TextEdit::singleline(&mut edit.text)
                };
                let response = ui.add(
                    widget
                        .id(id)
                        .desired_width(f32::INFINITY)
                        .char_limit(max_bytes.saturating_add(1)),
                );
                changed = response.changed();
                response
            }
            FieldKind::Integer { minimum, maximum } => {
                let response = ui.add(
                    TextEdit::singleline(&mut edit.text)
                        .id(id)
                        .char_limit(21)
                        .desired_width(180.0)
                        .hint_text(format!("{minimum} … {maximum}")),
                );
                changed = response.changed();
                response
            }
            FieldKind::Boolean | FieldKind::Choice { .. } => {
                ComboBox::from_id_salt(id)
                    .selected_text(if edit.text.is_empty() {
                        "Choose…"
                    } else {
                        &edit.text
                    })
                    .show_ui(ui, |ui| {
                        changed |= ui
                            .selectable_value(
                                &mut edit.text,
                                String::new(),
                                if field.required {
                                    "Choose…"
                                } else {
                                    "Not supplied"
                                },
                            )
                            .changed();
                        match &field.kind {
                            FieldKind::Boolean => {
                                for choice in ["true", "false"] {
                                    changed |= ui
                                        .selectable_value(&mut edit.text, choice.to_owned(), choice)
                                        .changed();
                                }
                            }
                            FieldKind::Choice { options } => {
                                for choice in options {
                                    changed |= ui
                                        .selectable_value(&mut edit.text, choice.clone(), choice)
                                        .changed();
                                }
                            }
                            _ => unreachable!(),
                        }
                    })
                    .response
            }
        }
        .labelled_by(label.id)
        .on_hover_text(forms::field_description(field));
        if label.clicked() {
            response.request_focus();
        }
        if changed {
            edit.invalid = update(field, &edit.text, values).is_err();
        }
        if edit.invalid {
            ui.colored_label(
                egui::Color32::from_rgb(234, 139, 119),
                "Invalid value or combined form limit exceeded",
            );
        }
        response
    }
    pub(super) fn ready(&self, form: &Form, view: &View) -> bool {
        if view
            .form_edits
            .iter()
            .any(|((id, _), edit)| id == &form.id && edit.invalid)
        {
            return false;
        }
        let empty = BTreeMap::new();
        forms::validate_values(form, view.form_values.get(&form.id).unwrap_or(&empty)).is_ok()
    }
}

#[cfg(test)]
mod tests {
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
}
