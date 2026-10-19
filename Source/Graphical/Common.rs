// SPDX-License-Identifier: MIT
// Native applications share appearance, accessible settings and a single-profile process lifetime.
use super::{chrome, settings};
use anyhow::Result;
use eframe::egui;

pub(crate) fn run(
    title: &'static str,
    builder: impl FnOnce(&eframe::CreationContext<'_>) -> Result<Box<dyn eframe::App>> + 'static,
) -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(title)
            .with_app_id(title.replace(' ', ""))
            .with_inner_size([1180.0, 800.0])
            .with_min_inner_size([620.0, 420.0]),
        renderer: eframe::Renderer::Glow,
        persist_window: false,
        ..Default::default()
    };
    let result = eframe::run_native(
        title,
        options,
        Box::new(move |cc| {
            chrome::theme(&cc.egui_ctx);
            builder(cc).map_err(Into::into)
        }),
    );
    crate::private_route_client::request_cancel();
    result.map_err(|error| anyhow::anyhow!("cannot open {title}: {error}"))
}

pub(crate) struct Appearance {
    pub settings_open: bool,
    pub help_open: bool,
    preferences: settings::Preferences,
    store: settings::Store,
    error: Option<String>,
    help_filter: String,
}

impl Appearance {
    pub(crate) fn new() -> Self {
        let (store, preferences, error) = settings::Store::load();
        Self {
            settings_open: error.is_some(),
            help_open: false,
            preferences,
            store,
            error,
            help_filter: String::new(),
        }
    }

    pub(crate) fn apply(&self, ui: &mut egui::Ui) {
        chrome::text_size(ui, self.preferences.text_scale);
    }

    pub(crate) fn windows(&mut self, ctx: &egui::Context, title: &str, help: &[(&str, &str)]) {
        ctx.input_mut(|input| {
            if input.consume_key(egui::Modifiers::CTRL, egui::Key::Comma) {
                self.settings_open = true;
            }
            if input.consume_key(egui::Modifiers::NONE, egui::Key::F1) {
                self.help_open = true;
            }
        });
        if self.settings_open {
            ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of("ApplicationSettings"),
                egui::ViewportBuilder::default()
                    .with_title(format!("Settings - {title}"))
                    .with_inner_size([600.0, 400.0])
                    .with_min_inner_size([440.0, 320.0]),
                |ui, _| {
                    self.apply(ui);
                    if ui.input(|input| input.viewport().close_requested()) {
                        self.settings_open = false;
                    }
                    egui::CentralPanel::default().show(ui, |ui| {
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            ui.heading("Appearance");
                            ui.add_space(16.0);
                            if chrome::preferences(ui, &mut self.preferences) {
                                self.error = self
                                    .store
                                    .save(&self.preferences)
                                    .err()
                                    .map(|error| error.to_string());
                                ctx.request_repaint_of(egui::ViewportId::ROOT);
                                ctx.request_repaint_of(egui::ViewportId::from_hash_of(
                                    "ApplicationHelp",
                                ));
                            }
                            if let Some(error) = &self.error {
                                ui.separator();
                                ui.colored_label(egui::Color32::LIGHT_RED, error);
                            }
                        });
                    });
                },
            );
        }
        if self.help_open {
            ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of("ApplicationHelp"),
                egui::ViewportBuilder::default()
                    .with_title(format!("Help - {title}"))
                    .with_inner_size([650.0, 500.0]),
                |ui, _| {
                    self.apply(ui);
                    if ui.input(|input| input.viewport().close_requested()) {
                        self.help_open = false;
                    }
                    egui::CentralPanel::default().show(ui, |ui| {
                        ui.heading(title);
                        let label = ui.label("Search help");
                        ui.add(egui::TextEdit::singleline(&mut self.help_filter).char_limit(128))
                            .labelled_by(label.id);
                        ui.separator();
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            for (heading, text) in help {
                                if format!("{heading} {text}")
                                    .to_lowercase()
                                    .contains(&self.help_filter.to_lowercase())
                                {
                                    ui.heading(*heading);
                                    ui.label(*text);
                                    ui.add_space(12.0);
                                }
                            }
                        });
                    });
                },
            );
        }
    }
}
