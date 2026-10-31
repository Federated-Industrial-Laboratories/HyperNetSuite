// SPDX-License-Identifier: MIT
// Trusted navigation, preferences and confirmation stay outside publisher content.
use super::*;

pub(super) fn theme(ctx: &egui::Context) {
    let mut style = egui::Style {
        visuals: egui::Visuals::dark(),
        ..Default::default()
    };
    style.visuals.panel_fill = egui::Color32::from_rgb(27, 30, 34);
    style.visuals.window_fill = egui::Color32::from_rgb(27, 30, 34);
    style.visuals.extreme_bg_color = egui::Color32::from_rgb(17, 20, 23);
    style.visuals.selection.bg_fill = egui::Color32::from_rgb(49, 80, 86);
    style.visuals.selection.stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(183, 218, 219));
    style.visuals.hyperlink_color = egui::Color32::from_rgb(139, 194, 201);
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(10.0, 6.0);
    style.spacing.interact_size.y = 28.0;
    super::theme::apply(ctx, &mut style);
    ctx.set_theme(egui::Theme::Dark);
    ctx.set_style_of(egui::Theme::Dark, style);
}

pub(super) fn text_size(ui: &mut egui::Ui, scale: f32) {
    let mut style = (*ui.ctx().global_style()).clone();
    for font in style.text_styles.values_mut() {
        font.size *= scale;
    }
    ui.set_style(style);
}

pub(super) fn preferences(ui: &mut egui::Ui, preferences: &mut settings::Preferences) -> bool {
    let stacked = ui.available_width() < 400.0 * preferences.text_scale;
    let mut changed = false;
    egui::Grid::new("Preferences")
        .num_columns(if stacked { 1 } else { 2 })
        .spacing([24.0, 16.0])
        .show(ui, |ui| {
            let label = ui.label("Animation");
            if stacked {
                ui.end_row();
            }
            let response = ui
                .checkbox(&mut preferences.animations, "On")
                .labelled_by(label.id)
                .on_hover_text(
                    "Allow local page animation. Off also blocks page animation controls.",
                );
            scrolling::reveal_focus(&response);
            changed |= response.changed();
            ui.end_row();
            let label = ui.label("Text size");
            if stacked {
                ui.end_row();
            }
            let response = ui
                .add(
                    egui::Slider::new(&mut preferences.text_scale, 0.75..=2.0)
                        .step_by(0.05)
                        .suffix("×"),
                )
                .labelled_by(label.id);
            scrolling::reveal_focus(&response);
            changed |= response.changed();
            ui.end_row();
            let label = ui.label("Page colours");
            if stacked {
                ui.end_row();
            }
            let response = ui
                .checkbox(&mut preferences.monochrome, "Monochrome")
                .labelled_by(label.id);
            scrolling::reveal_focus(&response);
            changed |= response.changed();
            ui.end_row();
        });
    changed
}

fn review_actions(ui: &mut egui::Ui, confirmation: &mut Confirmation) -> Option<bool> {
    let mut decision = None;
    ui.horizontal_wrapped(|ui| {
        let label = ui.label("Type SEND");
        ui.add(
            egui::TextEdit::singleline(&mut confirmation.acknowledgement)
                .char_limit(4)
                .desired_width(90.0),
        )
        .labelled_by(label.id);
        if ui
            .add_enabled(
                confirmation.end_seen && confirmation.acknowledgement == "SEND",
                egui::Button::new("Send"),
            )
            .clicked()
        {
            decision = Some(true);
        }
        if ui.button("Cancel").clicked() {
            decision = Some(false);
        }
    });
    decision
}

fn review_actions_height(ui: &egui::Ui) -> f32 {
    ui.text_style_height(&egui::TextStyle::Body)
        .max(ui.text_style_height(&egui::TextStyle::Monospace))
        + 2.0 * ui.spacing().button_padding.y
        + egui::Frame::side_top_panel(ui.style())
            .total_margin()
            .sum()
            .y
        + ui.visuals().widgets.noninteractive.bg_stroke.width
}

fn review_content(ui: &mut egui::Ui, confirmation: &mut Confirmation) {
    ui.heading("Review submission");
    ui.separator();
    let focus = scrolling::focus(
        ui,
        ui.available_rect_before_wrap(),
        ui.scope_id().with("ReviewFocus"),
        "Submission review",
    );
    let mut scroll = egui::ScrollArea::vertical().id_salt("Review");
    if let Some(offset) = confirmation.scroll_offset.take() {
        scroll = scroll.vertical_scroll_offset(offset);
    }
    let output = scroll.show(ui, |ui| {
        for (key, label) in [
            ("senderAddress", "From"),
            ("recipientAddress", "To"),
            ("formLabel", "Form"),
            ("values", "Values"),
            ("storageHosts", "Storage hosts"),
            ("requiredCopies", "Required copies"),
            ("retentionSeconds", "Retention (seconds)"),
            ("expires", "Expires"),
            ("private", "Private"),
        ] {
            if let Some(value) = confirmation.value.get(key) {
                ui.label(egui::RichText::new(label).strong());
                ui.label(match value {
                    serde_json::Value::String(text) => text.clone(),
                    _ => serde_json::to_string_pretty(value).unwrap_or_default(),
                });
                ui.add_space(8.0);
            }
        }
        let identity =
            egui::CollapsingHeader::new("Publication and recipient identity").show(ui, |ui| {
                ui.monospace(serde_json::to_string_pretty(&confirmation.value).unwrap_or_default());
            });
        scrolling::reveal_focus(&identity.header_response);
        let end = ui.label("End of review");
        if ui.is_rect_visible(end.rect) {
            confirmation.end_seen = true;
        }
    });
    confirmation.scroll_offset = scrolling::keys(
        ui,
        &focus,
        &output,
        ui.text_style_height(&egui::TextStyle::Body),
        &mut false,
    );
}

#[derive(Clone, Copy)]
enum Icon {
    Back,
    Refresh,
    Catalogue,
    Sidebar,
    Settings,
    Help,
    Info,
    Go,
}

fn icon(ui: &mut egui::Ui, kind: Icon, label: &str) -> egui::Response {
    let response = ui
        .add(egui::Button::new("").min_size(egui::vec2(30.0, 30.0)))
        .on_hover_text(label);
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, ui.is_enabled(), label));
    let p = ui.painter();
    let c = response.rect.center();
    let stroke = egui::Stroke::new(1.5, ui.visuals().widgets.style(&response).fg_stroke.color);
    let line = |a: [f32; 2], b: [f32; 2]| {
        p.line_segment(
            [c + egui::vec2(a[0], a[1]), c + egui::vec2(b[0], b[1])],
            stroke,
        );
    };
    match kind {
        Icon::Back => {
            line([-6.0, 0.0], [6.0, 0.0]);
            line([-6.0, 0.0], [-1.0, -5.0]);
            line([-6.0, 0.0], [-1.0, 5.0]);
        }
        Icon::Go => {
            line([-6.0, 0.0], [6.0, 0.0]);
            line([6.0, 0.0], [1.0, -5.0]);
            line([6.0, 0.0], [1.0, 5.0]);
        }
        Icon::Refresh => {
            p.circle_stroke(c, 6.0, stroke);
            line([6.0, -6.0], [6.0, 0.0]);
            line([6.0, 0.0], [0.0, 0.0]);
        }
        Icon::Catalogue => {
            for y in [-5.0, 0.0, 5.0] {
                line([-3.0, y], [7.0, y]);
                p.circle_filled(c + egui::vec2(-7.0, y), 1.0, stroke.color);
            }
        }
        Icon::Sidebar => {
            p.rect_stroke(
                egui::Rect::from_center_size(c, egui::vec2(15.0, 14.0)),
                1.0,
                stroke,
                egui::StrokeKind::Inside,
            );
            line([-2.0, -7.0], [-2.0, 7.0]);
        }
        Icon::Settings => {
            for (y, x) in [(-5.0, -3.0), (0.0, 4.0), (5.0, -1.0)] {
                line([-7.0, y], [7.0, y]);
                p.circle_filled(c + egui::vec2(x, y), 2.5, ui.visuals().panel_fill);
                p.circle_stroke(c + egui::vec2(x, y), 2.5, stroke);
            }
        }
        Icon::Help | Icon::Info => {
            p.circle_stroke(c, 7.0, stroke);
            p.text(
                c,
                egui::Align2::CENTER_CENTER,
                if matches!(kind, Icon::Help) { "?" } else { "i" },
                egui::FontId::proportional(14.0),
                stroke.color,
            );
        }
    }
    response
}

impl Browser {
    pub(super) fn toolbar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("BrowserToolbar")
            .resizable(false)
            .show(ui, |ui| {
                egui::MenuBar::new().ui(ui, |ui| {
                    ui.menu_button("File", |ui| {
                        if ui.button("Settings   Ctrl+,").clicked() {
                            self.settings_open = true;
                            ui.close();
                        }
                        if ui.button("Close").clicked() {
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    });
                    ui.menu_button("View", |ui| {
                        ui.checkbox(&mut self.sidebar, "Page links");
                        if ui.button("Page information").clicked() {
                            self.information_open = true;
                            ui.close();
                        }
                    });
                    if ui.button("Help").clicked() {
                        self.help_open = true;
                    }
                });
                ui.horizontal(|ui| {
                    let enabled = self.can_navigate();
                    ui.add_enabled_ui(enabled, |ui| {
                        if icon(ui, Icon::Back, "Back (Alt+Left)").clicked() {
                            self.action(reader::Action::Back);
                        }
                        if icon(ui, Icon::Refresh, "Refresh (Ctrl+R)").clicked() {
                            self.action(reader::Action::Refresh);
                        }
                        if icon(ui, Icon::Catalogue, "Catalogue").clicked() {
                            self.action(reader::Action::Catalogue);
                        }
                        if self.page.as_ref().is_some_and(|page| {
                            page.mode == reader::Mode::Catalogue && page.view.catalogue_next
                        }) && icon(ui, Icon::Go, "Next catalogue page").clicked()
                        {
                            self.action(reader::Action::Next);
                        }
                    });
                    if icon(ui, Icon::Sidebar, "Page links").clicked() {
                        self.sidebar = !self.sidebar;
                    }
                    let width = (ui.available_width() - 160.0).max(90.0);
                    let address = ui.add_enabled(
                        enabled,
                        egui::TextEdit::singleline(&mut self.address)
                            .id(egui::Id::unique("Address"))
                            .hint_text("HyperNet address")
                            .char_limit(512)
                            .desired_width(width),
                    );
                    address.widget_info(|| {
                        egui::WidgetInfo::labeled(
                            egui::Role::TextInput,
                            enabled,
                            "HyperNet address",
                        )
                    });
                    if self.focus_address {
                        address.request_focus();
                        self.focus_address = false;
                    }
                    let go = ui
                        .add_enabled_ui(enabled, |ui| icon(ui, Icon::Go, "Open address").clicked())
                        .inner;
                    if go || (address.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                    {
                        self.action(reader::Action::Address(self.address.trim().to_owned()));
                    }
                    if icon(ui, Icon::Info, "Page information").clicked() {
                        self.information_open = true;
                    }
                    if icon(ui, Icon::Settings, "Settings (Ctrl+,)").clicked() {
                        self.settings_open = true;
                    }
                    if icon(ui, Icon::Help, "Help (F1)").clicked() {
                        self.help_open = true;
                    }
                });
            });
    }

    pub(super) fn status_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::bottom("BrowserStatus")
            .resizable(false)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if self.busy {
                        ui.spinner();
                        ui.label("Loading");
                    } else if self.finished {
                        ui.label("Session ended");
                    } else if let Some(page) = &self.page {
                        ui.label(match page.mode {
                            reader::Mode::Preview => "Local preview",
                            reader::Mode::Page => "Retained Page",
                            reader::Mode::Catalogue => "Catalogue",
                        });
                    }
                    if let Some(page) = &self.page {
                        let status = page.status.lines().next().unwrap_or("");
                        if !status.is_empty() && !status.starts_with("Local preview;") {
                            ui.separator();
                            ui.label(status.chars().take(100).collect::<String>())
                                .on_hover_text(&page.status);
                        }
                    }
                    if self.settings_error.is_some() {
                        ui.separator();
                        if ui.small_button("Settings not saved").clicked() {
                            self.settings_open = true;
                        }
                    }
                });
            });
    }

    pub(super) fn sidebar(&mut self, ui: &mut egui::Ui) {
        if !self.sidebar {
            return;
        }
        let mut action = None;
        egui::Panel::left("PageLinks")
            .default_size(230.0)
            .size_range(180.0..=400.0)
            .show(ui, |ui| {
                ui.heading("Page links");
                ui.add(
                    egui::TextEdit::singleline(&mut self.filter)
                        .hint_text("Filter links")
                        .char_limit(128),
                );
                ui.separator();
                if let Some(page) = &self.page {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        for (index, link) in page.document.links.iter().enumerate() {
                            if !link
                                .label
                                .to_lowercase()
                                .contains(&self.filter.to_lowercase())
                            {
                                continue;
                            }
                            if ui
                                .add_enabled(
                                    self.can_navigate(),
                                    egui::Button::new(&link.label).wrap(),
                                )
                                .on_hover_text(&link.target)
                                .clicked()
                            {
                                action = Some(reader::Action::Open(index));
                            }
                        }
                    });
                }
            });
        if let Some(action) = action {
            self.action(action);
        }
    }

    pub(super) fn windows(&mut self, ctx: &egui::Context) {
        if self.settings_open {
            ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of("Settings"),
                egui::ViewportBuilder::default()
                    .with_title("Settings — HyperNet")
                    .with_inner_size([600.0, 400.0])
                    .with_min_inner_size([440.0, 320.0]),
                |ui, _| {
                    text_size(ui, self.preferences.text_scale);
                    if ui.input(|i| i.viewport().close_requested()) {
                        self.settings_open = false;
                    }
                    if ui.available_width() >= 560.0 * self.preferences.text_scale {
                        egui::Panel::left("SettingsCategories")
                            .exact_size(145.0)
                            .resizable(false)
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new("Appearance").strong());
                            });
                    }
                    egui::CentralPanel::default().show(ui, |ui| {
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            ui.heading("Appearance");
                            ui.add_space(16.0);
                            if preferences(ui, &mut self.preferences) {
                                self.settings_error = self
                                    .store
                                    .save(&self.preferences)
                                    .err()
                                    .map(|error| error.to_string());
                                ctx.request_repaint_of(egui::ViewportId::ROOT);
                                for name in
                                    ["Settings", "Help", "PageInformation", "SubmissionReview"]
                                {
                                    let id = egui::ViewportId::from_hash_of(name);
                                    ctx.request_repaint_of(id);
                                }
                            }
                            if let Some(error) = &self.settings_error {
                                ui.separator();
                                ui.colored_label(egui::Color32::LIGHT_RED, error);
                            }
                        });
                    });
                },
            );
        }
        if self.help_open {
            ctx.show_viewport_immediate(egui::ViewportId::from_hash_of("Help"),egui::ViewportBuilder::default().with_title("Help — HyperNet").with_inner_size([650.0,500.0]),|ui,_| {
                text_size(ui, self.preferences.text_scale);
                if ui.input(|i| i.viewport().close_requested()) { self.help_open=false; }
                egui::CentralPanel::default().show(ui,|ui| {
                    ui.heading("HyperNet Browser");
                    ui.add(egui::TextEdit::singleline(&mut self.help_filter).hint_text("Search help").char_limit(128));
                    ui.separator();
                    egui::ScrollArea::vertical().show(ui,|ui| {
                        for (title,text) in [
                            ("Keyboard","Ctrl+L  Address\nCtrl+R  Refresh\nAlt+Left  Back\nCtrl+,  Settings\nF1  Help\nTab / Shift+Tab  Move focus\nEnter / Space  Activate control\nClick Page or scroll box / Tab  Focus scrolling\nUp / Down  Scroll one line\nPageUp / PageDown  Scroll one view\nHome / End  Scroll to start / end"),
                            ("Pages","Catalogue lists approved Pages. Refresh checks current authority. Back returns to retained content. Page information shows publication details."),
                            ("Media and animation","Reveal downloads only the selected approved asset. Animation runs locally. Settings → Appearance → Animation applies to all pages and is saved across restarts."),
                            ("Forms","Review the recipient, values, storage and expiry before sending. Click or Tab to focus the review content, then use the scrolling keys to read it. Type SEND to confirm. Closing the review cancels submission."),
                            ("Markdown","Text supports inert formatting. Code is displayed literally. External links are display-only; images require an approved asset and explicit reveal."),
                            ("Connection","The selected network profile controls the route and privacy requirements. This window uses one profile. Pages cannot change credentials or destinations."),
                        ] {
                            if format!("{title} {text}").to_lowercase().contains(&self.help_filter.to_lowercase()) { ui.heading(title); ui.label(text); ui.add_space(12.0); }
                        }
                    });
                });
            });
        }
        if self.information_open {
            ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of("PageInformation"),
                egui::ViewportBuilder::default()
                    .with_title("Page information — HyperNet")
                    .with_inner_size([720.0, 420.0]),
                |ui, _| {
                    text_size(ui, self.preferences.text_scale);
                    if ui.input(|i| i.viewport().close_requested()) {
                        self.information_open = false;
                    }
                    egui::CentralPanel::default().show(ui, |ui| {
                        ui.heading("Page information");
                        ui.separator();
                        egui::ScrollArea::both().show(ui, |ui| {
                            if let Some(page) = &self.page {
                                for item in &page.metadata {
                                    ui.label(item);
                                }
                                ui.separator();
                                ui.label(&page.status);
                            }
                            if let Some(error) = &self.error {
                                ui.label(error);
                            }
                        });
                    });
                },
            );
        }
        self.confirmation_window(ctx);
    }

    fn confirmation_window(&mut self, ctx: &egui::Context) {
        let Some(confirmation) = &mut self.confirmation else {
            return;
        };
        let mut decision = None;
        ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("SubmissionReview"),
            egui::ViewportBuilder::default()
                .with_title("Review submission — HyperNet")
                .with_inner_size([760.0, 700.0])
                .with_min_inner_size([540.0, 440.0]),
            |ui, _| {
                text_size(ui, self.preferences.text_scale);
                if ui.input(|i| i.viewport().close_requested()) {
                    decision = Some(false);
                }
                egui::Panel::bottom("ReviewActions")
                    .resizable(false)
                    .min_size(review_actions_height(ui))
                    .show(ui, |ui| {
                        if let Some(action) = review_actions(ui, confirmation) {
                            decision = Some(action);
                        }
                    });
                egui::CentralPanel::default().show(ui, |ui| review_content(ui, confirmation));
            },
        );
        if let Some(decision) = decision {
            if let Some(confirmation) = self.confirmation.take() {
                let _ = confirmation.reply.send(decision);
            }
            self.busy = true;
        }
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Graphical/ChromeUnitTests.rs"]
mod tests;
