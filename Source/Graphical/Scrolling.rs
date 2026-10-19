// SPDX-License-Identifier: MIT
// Focused scroll regions preserve child controls and share keyboard navigation.
use eframe::egui::{self, Rect, Response, Sense, Stroke, StrokeKind, Ui};

pub(crate) fn reveal_focus(response: &Response) {
    if response.gained_focus() {
        response.scroll_to_me_animation(None, egui::style::ScrollAnimation::none());
    }
}

pub(crate) fn focus(ui: &Ui, rect: Rect, id: egui::Id, label: &str) -> Response {
    let response = ui
        .interact(rect, id, Sense::click())
        .on_hover_text("Click or Tab to focus; Up/Down, PageUp/PageDown, Home/End to scroll");
    response
        .widget_info(|| egui::WidgetInfo::labeled(egui::Role::ScrollView, ui.is_enabled(), label));
    if response.clicked() {
        response.request_focus();
    }
    response
}
pub(crate) fn keys<R>(
    ui: &Ui,
    response: &Response,
    output: &egui::scroll_area::ScrollAreaOutput<R>,
    step: f32,
    clicked: &mut bool,
) -> Option<f32> {
    if !*clicked && response.container_clicked() {
        let target = ui
            .ctx()
            .interaction_snapshot(|snapshot| snapshot.clicked)
            .and_then(|id| ui.ctx().read_response(id));
        if target.is_some_and(|target| target.id == response.id || !target.sense.is_focusable()) {
            response.request_focus();
            *clicked = true;
        }
    }
    if !response.has_focus() {
        return None;
    }
    let rect = output.inner_rect;
    ui.painter().rect_stroke(
        rect,
        0,
        Stroke::new(2.0, ui.visuals().selection.stroke.color),
        StrokeKind::Inside,
    );
    ui.memory_mut(|memory| {
        memory.set_focus_lock_filter(
            response.id,
            egui::EventFilter {
                vertical_arrows: true,
                ..Default::default()
            },
        );
    });
    let maximum = (output.content_size.y - rect.height()).max(0.0);
    let offset = output.state.clamped_offset().y;
    let page = (rect.height() - step).max(step);
    let next = ui.input_mut(|input| {
        if !input.modifiers.is_none() {
            return None;
        }
        for (key, next) in [
            (egui::Key::ArrowUp, offset - step),
            (egui::Key::ArrowDown, offset + step),
            (egui::Key::PageUp, offset - page),
            (egui::Key::PageDown, offset + page),
            (egui::Key::Home, 0.0),
            (egui::Key::End, maximum),
        ] {
            if input.consume_key(egui::Modifiers::NONE, key) {
                return Some(next.clamp(0.0, maximum));
            }
        }
        None
    });
    if next.is_some() {
        ui.ctx().request_repaint();
    }
    next
}
