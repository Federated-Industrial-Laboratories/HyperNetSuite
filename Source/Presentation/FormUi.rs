// SPDX-License-Identifier: MIT
// Bounded inert field editing with explicit local confirmation.
use crate::{
    markup::forms::{Field, FieldKind},
    terminal_input::Event,
};
use crossterm::event::{KeyCode, KeyModifiers};
use serde_json::Value;

pub struct Editor {
    pub form: String,
    pub field: Field,
    pub text: String,
    pub error: String,
    pub scroll: usize,
}
pub enum Edit {
    Continue,
    Cancel,
    Quit,
    Save(Option<Value>),
}
impl Editor {
    pub fn new(form: String, field: Field, value: Option<&Value>) -> Self {
        Self {
            form,
            field,
            text: value
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| v.to_string())
                })
                .unwrap_or_default(),
            error: String::new(),
            scroll: 0,
        }
    }
    fn append(&mut self, value: &str) {
        let maximum = match self.field.kind {
            FieldKind::Text { max_bytes } | FieldKind::Multiline { max_bytes } => max_bytes,
            _ => 2048,
        };
        let multiline = matches!(self.field.kind, FieldKind::Multiline { .. });
        if self.text.len().saturating_add(value.len()) > maximum
            || value
                .chars()
                .any(|ch| ch.is_control() && !(multiline && ch == '\n'))
        {
            self.error = "Input rejected: field byte limit or forbidden control".into();
        } else {
            self.text.push_str(value);
            self.scroll = usize::MAX;
            self.error.clear();
        }
    }
    pub fn input(&mut self, event: &Event) -> Edit {
        match event {
            Event::Paste(value) => self.append(value),
            Event::Rejected => self.error = "Input rejected; no field action was performed".into(),
            Event::Key(key) => match key.code {
                KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => return Edit::Quit,
                KeyCode::Esc => return Edit::Cancel,
                KeyCode::Char('u') if key.modifiers == KeyModifiers::CONTROL => {
                    self.text.clear();
                    self.error.clear();
                }
                KeyCode::Char('d') if key.modifiers == KeyModifiers::CONTROL => {
                    if !self.field.required {
                        return Edit::Save(None);
                    }
                    self.error = "A required field cannot be omitted".into();
                }
                KeyCode::Char('n') if key.modifiers == KeyModifiers::CONTROL => self.append("\n"),
                KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(8),
                KeyCode::PageDown => self.scroll = self.scroll.saturating_add(8),
                KeyCode::Backspace => {
                    self.text.pop();
                    self.error.clear();
                }
                KeyCode::Enter => {
                    let value = match self.field.kind {
                        FieldKind::Integer { .. } => self.text.parse::<i64>().ok().map(Value::from),
                        FieldKind::Boolean => match self.text.as_str() {
                            "true" => Some(Value::Bool(true)),
                            "false" => Some(Value::Bool(false)),
                            _ => None,
                        },
                        _ => Some(Value::String(self.text.clone())),
                    };
                    if let Some(value) = value {
                        match crate::markup::forms::validate_field(&self.field, &value) {
                            Ok(()) => return Edit::Save(Some(value)),
                            Err(error) => self.error = format!("Invalid field: {error}"),
                        }
                    } else {
                        self.error = "Enter a value of the stated type".into();
                    }
                }
                KeyCode::Char(ch)
                    if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT =>
                {
                    self.append(&ch.to_string())
                }
                _ => {}
            },
        }
        Edit::Continue
    }
}
impl Drop for Editor {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.text);
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Presentation/FormUiUnitTests.rs"]
mod tests;
