// SPDX-License-Identifier: MIT
// Palette validation and private-file boundaries preserve inert appearance data.
use super::*;
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
};

fn palette(light: bool) -> Value {
    let (mode, background, foreground) = if light {
        ("light", "#FFFFFF", "#000000")
    } else {
        ("dark", "#000000", "#FFFFFF")
    };
    json!({
        "version":1, "name":"Shared Test", "mode":mode,
        "colors":{
            "panel":background, "surface":background, "window":background,
            "input":background, "faint":background, "text":foreground,
            "muted":foreground, "accent":foreground, "selection":background,
            "selectionText":foreground, "border":foreground, "button":background,
            "hover":background, "pressed":background
        },
        "display":{"cornerCut":7,"outlineWidth":1.5}
    })
}
fn parse(value: &Value) -> Result<Palette> {
    Palette::parse(&serde_json::to_vec(value).unwrap())
}

#[test]
fn shared_light_and_dark_palette_style_keeps_readable_surfaces() {
    use eframe::egui;
    for light in [false, true] {
        let palette = parse(&palette(light)).unwrap();
        let ctx = egui::Context::default();
        super::super::chrome::theme_palette(&ctx, Some(&palette));
        let style = ctx.global_style();
        assert_eq!(style.visuals.dark_mode, !light);
        assert_eq!(style.visuals.text_color(), palette.colors.text.colour());
        assert_eq!(style.visuals.panel_fill, palette.colors.panel.colour());
        assert_eq!(
            style.visuals.extreme_bg_color,
            palette.colors.input.colour()
        );
        assert_eq!(style.visuals.window_stroke.width, 1.5);
        assert_eq!(style.spacing.interact_size.y, 32.0);
        let output = ctx.run_ui(egui::RawInput::default(), |ui| {
            assert_eq!(
                super::super::theme::surface(ui),
                palette.colors.surface.colour()
            );
        });
        output.drop_without_applying_deltas();
    }
    let ctx = egui::Context::default();
    super::super::chrome::theme(&ctx);
    assert_eq!(
        ctx.global_style().visuals.panel_fill,
        Color32::from_rgb(27, 30, 34)
    );
    assert_eq!(ctx.global_style().spacing.interact_size.y, 28.0);
}

#[test]
fn palette_rejects_extra_capabilities_invalid_colours_and_low_contrast() {
    for (pointer, value) in [
        ("/version", json!(2)),
        ("/name", json!(" ../file")),
        ("/mode", json!("system")),
        ("/colors/text", json!("#FFFFFF00")),
        ("/colors/text", json!("#000000")),
        ("/colors/muted", json!("#000000")),
        ("/colors/accent", json!("#000000")),
        ("/colors/panel", json!("#FFFFFF")),
        ("/display/cornerCut", json!(8.1)),
        ("/display/outlineWidth", json!(0.4)),
    ] {
        let mut value_to_check = palette(false);
        *value_to_check.pointer_mut(pointer).unwrap() = value;
        assert!(parse(&value_to_check).is_err(), "{pointer}");
    }
    for pointer in ["", "/colors", "/display"] {
        let mut value = palette(false);
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("script".into(), json!("file"));
        assert!(parse(&value).is_err());
    }
    let duplicate =
        serde_json::to_string(&palette(false))
            .unwrap()
            .replacen("{", "{\"version\":1,", 1);
    assert!(Palette::parse(duplicate.as_bytes()).is_err());
    assert!(Palette::parse(&vec![b' '; MAX_BYTES + 1]).is_err());
    let mut defaults = palette(false);
    defaults.as_object_mut().unwrap().remove("display");
    assert_eq!(parse(&defaults).unwrap().display.corner_cut, 5.0);
}

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn palette_file_is_bounded_private_regular_unlinked_and_read_only() {
    let root = std::env::var_os("HYPERNET_TEST_DIRECTORY")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let fixture = Fixture(root.join(format!("BrowserPalette{}", crate::random_hex::<16>())));
    crate::transfer_files::create_directory(&fixture.0).unwrap();
    let file = fixture.0.join("Theme.json");
    let bytes = serde_json::to_vec(&palette(false)).unwrap();
    crate::transfer_files::write_new(&file, &bytes).unwrap();
    let loaded = Palette::load(&file).unwrap();
    fs::write(&file, b"invalid").unwrap();
    assert_eq!(loaded.name, "Shared Test");
    assert!(Palette::load(&file).is_err());
    fs::write(&file, &bytes).unwrap();
    let link = fixture.0.join("Link.json");
    symlink(&file, &link).unwrap();
    assert!(Palette::load(&link).is_err());
    fs::remove_file(&link).unwrap();
    fs::hard_link(&file, &link).unwrap();
    assert!(Palette::load(&file).is_err());
    fs::remove_file(&link).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Palette::load(&file).is_err());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&file, vec![b' '; MAX_BYTES + 1]).unwrap();
    assert!(Palette::load(&file).is_err());
    assert!(Palette::load(&fixture.0).is_err());
}

#[test]
fn palette_settings_slider_and_value_fit_current_window() {
    use super::super::{chrome, settings};
    use eframe::egui;
    for light in [false, true] {
        for (width, scale) in [(600.0, 1.0), (440.0, 1.0), (600.0, 2.0), (440.0, 2.0)] {
            let palette = parse(&palette(light)).unwrap();
            let ctx = egui::Context::default();
            chrome::theme_palette(&ctx, Some(&palette));
            ctx.enable_accesskit();
            let mut values = settings::Preferences {
                text_scale: scale,
                ..Default::default()
            };
            for _ in 0..2 {
                let output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(width, 400.0),
                        )),
                        ..Default::default()
                    },
                    |ui| {
                        chrome::text_size(ui, scale);
                        if ui.available_width() >= 560.0 * scale {
                            egui::Panel::left("SettingsCategories")
                                .exact_size(145.0)
                                .resizable(false)
                                .show(ui, |ui| {
                                    ui.label("Appearance");
                                });
                        }
                        egui::CentralPanel::default().show(ui, |ui| {
                            egui::ScrollArea::vertical().show(ui, |ui| {
                                ui.heading("Appearance");
                                ui.add_space(16.0);
                                assert!(!chrome::preferences(ui, &mut values));
                            });
                        });
                    },
                );
                let tree = output.platform_output.accesskit_update.as_ref().unwrap();
                let mut controls = 0;
                for (_, node) in &tree.nodes {
                    if matches!(node.role(), egui::Role::Slider | egui::Role::SpinButton) {
                        controls += 1;
                        let bounds = node.bounds().unwrap();
                        assert!(
                            bounds.x0 >= 0.0 && bounds.x1 <= f64::from(width),
                            "light={light}, width={width}, scale={scale}: {bounds:?}"
                        );
                    }
                }
                assert_eq!(
                    controls, 2,
                    "both slider and numeric editor must remain accessible"
                );
                output.drop_without_applying_deltas();
            }
        }
    }
}
