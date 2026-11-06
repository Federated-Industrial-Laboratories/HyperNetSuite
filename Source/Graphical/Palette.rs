// SPDX-License-Identifier: Apache-2.0
// Adapted from HyperNetRelayChat Source/Gui/ThemeData.rs (Apache-2.0).
// Changes: read-only Suite loading and native browser styling; no theme persistence.
//! Bounded, opaque colour data cannot select code, files or authority settings.
use eframe::egui::Color32;
use serde::{Deserialize, Deserializer};

pub const MAX_BYTES: usize = 16 * 1024;
pub type Result<T> = std::result::Result<T, &'static str>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Dark,
    Light,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Colour([u8; 3]);
impl Colour {
    pub fn colour(self) -> Color32 {
        Color32::from_rgb(self.0[0], self.0[1], self.0[2])
    }
    fn luminance(self) -> f64 {
        let linear = self.0.map(|v| {
            let v = f64::from(v) / 255.0;
            if v <= 0.04045 {
                v / 12.92
            } else {
                ((v + 0.055) / 1.055).powf(2.4)
            }
        });
        linear[0] * 0.2126 + linear[1] * 0.7152 + linear[2] * 0.0722
    }
    pub fn contrast(self, other: Self) -> f64 {
        let a = self.luminance();
        let b = other.luminance();
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }
}
impl<'de> Deserialize<'de> for Colour {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let mut rgb = [0; 3];
        if text.len() != 7
            || !text.starts_with('#')
            || hex::decode_to_slice(&text[1..], &mut rgb).is_err()
        {
            return Err(serde::de::Error::custom("expected opaque #RRGGBB colour"));
        }
        Ok(Self(rgb))
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Colours {
    pub panel: Colour,
    pub surface: Colour,
    pub window: Colour,
    pub input: Colour,
    pub faint: Colour,
    pub text: Colour,
    pub muted: Colour,
    pub accent: Colour,
    pub selection: Colour,
    pub selection_text: Colour,
    pub border: Colour,
    pub button: Colour,
    pub hover: Colour,
    pub pressed: Colour,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Display {
    pub corner_cut: f32,
    pub outline_width: f32,
}
impl Default for Display {
    fn default() -> Self {
        Self {
            corner_cut: 5.0,
            outline_width: 1.0,
        }
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Palette {
    pub version: u32,
    pub name: String,
    pub mode: Mode,
    pub colors: Colours,
    #[serde(default)]
    pub display: Display,
}
impl Palette {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BYTES {
            return Err("Theme exceeds the 16 KiB limit.");
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| "Theme JSON has an unknown field, repeated field or invalid value.")?;
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err("Unsupported theme version.");
        }
        if self.name.is_empty()
            || self.name.len() > 48
            || self.name.trim() != self.name
            || !self
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b" -_".contains(&b))
        {
            return Err("Theme names need 1-48 letters, digits, spaces, hyphens or underscores.");
        }
        if !self.display.corner_cut.is_finite()
            || !(0.0..=8.0).contains(&self.display.corner_cut)
            || !self.display.outline_width.is_finite()
            || !(0.5..=2.0).contains(&self.display.outline_width)
        {
            return Err("Theme outline settings exceed their supported range.");
        }
        let c = &self.colors;
        let backgrounds = [c.panel, c.surface, c.window, c.input, c.faint];
        if backgrounds.iter().any(|v| match self.mode {
            Mode::Dark => v.luminance() > 0.1,
            Mode::Light => v.luminance() < 0.5,
        }) {
            return Err("Theme backgrounds do not match its light or dark mode.");
        }
        if backgrounds
            .into_iter()
            .chain([c.button, c.hover, c.pressed, c.selection])
            .any(|v| c.text.contrast(v) < 4.5)
            || c.selection_text.contrast(c.selection) < 4.5
        {
            return Err("Theme text needs at least 4.5:1 contrast against its backgrounds.");
        }
        if backgrounds.iter().any(|v| c.muted.contrast(*v) < 3.0)
            || [c.panel, c.surface, c.window]
                .iter()
                .any(|v| c.accent.contrast(*v) < 3.0)
        {
            return Err("Theme secondary text and accents need at least 3:1 contrast.");
        }
        Ok(())
    }
}

impl Palette {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        use anyhow::Context;
        let bytes = crate::transfer_files::read(path, MAX_BYTES, true)
            .context("cannot read private browser theme")?;
        Self::parse(&bytes).map_err(anyhow::Error::msg)
    }

    pub fn apply(&self, style: &mut eframe::egui::Style) {
        use eframe::egui::{self, Stroke};
        let c = &self.colors;
        let width = self.display.outline_width;
        let visuals = &mut style.visuals;
        visuals.override_text_color = Some(c.text.colour());
        visuals.weak_text_color = Some(c.muted.colour());
        visuals.panel_fill = c.panel.colour();
        visuals.window_fill = c.window.colour();
        visuals.extreme_bg_color = c.input.colour();
        visuals.faint_bg_color = c.faint.colour();
        visuals.selection.bg_fill = c.selection.colour();
        visuals.selection.stroke = Stroke::new(width, c.selection_text.colour());
        visuals.hyperlink_color = c.accent.colour();
        visuals.window_stroke = Stroke::new(width, c.border.colour());
        visuals.warn_fg_color = if self.mode == Mode::Light {
            Color32::from_rgb(112, 64, 0)
        } else {
            Color32::from_rgb(246, 203, 125)
        };
        visuals.error_fg_color = if self.mode == Mode::Light {
            Color32::from_rgb(144, 18, 31)
        } else {
            Color32::from_rgb(255, 196, 189)
        };
        for (widget, fill) in [
            (&mut visuals.widgets.noninteractive, c.faint),
            (&mut visuals.widgets.inactive, c.button),
            (&mut visuals.widgets.hovered, c.hover),
            (&mut visuals.widgets.active, c.pressed),
            (&mut visuals.widgets.open, c.selection),
        ] {
            widget.bg_fill = fill.colour();
            widget.weak_bg_fill = fill.colour();
            widget.bg_stroke = Stroke::new(width, c.border.colour());
            widget.fg_stroke = Stroke::new(width, c.text.colour());
        }
        style.spacing.item_spacing = egui::vec2(8.0, 9.0);
        style.spacing.button_padding = egui::vec2(12.0, 7.0);
        style.spacing.interact_size = egui::vec2(128.0, 32.0);
        style.spacing.text_edit_width = 320.0;
        style.spacing.slider_width = 240.0;
        style.spacing.window_margin = egui::Margin::same(16);
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Graphical/PaletteUnitTests.rs"]
mod tests;
