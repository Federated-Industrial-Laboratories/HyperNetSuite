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
#[path = "../../Tests/Unit/Graphical/FormFieldsUnitTests.rs"]
mod tests;
