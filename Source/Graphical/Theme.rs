// SPDX-License-Identifier: MIT
// Give native boxes one hard-edged outline without changing content or interaction geometry.
use eframe::egui::{
    self, Color32, CornerRadius, Shape, Ui,
    epaint::{PathShape, PathStroke},
};
use std::sync::Arc;

const CORNER_CUT: f32 = 5.0;
const MIN_BOX_SIDE: f32 = 3.0;

pub(super) fn apply(ctx: &egui::Context, style: &mut egui::Style) {
    style.visuals.window_corner_radius = CornerRadius::ZERO;
    style.visuals.menu_corner_radius = CornerRadius::ZERO;
    for widget in [
        &mut style.visuals.widgets.noninteractive,
        &mut style.visuals.widgets.inactive,
        &mut style.visuals.widgets.hovered,
        &mut style.visuals.widgets.active,
        &mut style.visuals.widgets.open,
    ] {
        widget.corner_radius = CornerRadius::ZERO;
    }
    style.visuals.handle_shape = egui::style::HandleShape::Rect { aspect_ratio: 0.75 };
    ctx.on_end_pass("HyperNet box outlines", Arc::new(finish));
}

fn finish(ui: &mut Ui) {
    let ctx = ui.ctx();
    let mut layers = ctx.memory(|memory| memory.layer_ids().collect::<Vec<_>>());
    if !layers.contains(&ui.layer_id()) {
        layers.push(ui.layer_id());
    }
    ctx.graphics_mut(|graphics| {
        for layer in layers {
            if let Some(list) = graphics.get_mut(layer) {
                for index in 0..list.next_idx().0 {
                    list.mutate_shape(egui::layers::ShapeIdx(index), |clipped| {
                        box_outline(&mut clipped.shape);
                    });
                }
            }
        }
    });
}

fn box_outline(shape: &mut Shape) {
    match shape {
        Shape::Vec(shapes) => {
            for shape in shapes {
                box_outline(shape);
            }
        }
        Shape::Rect(rectangle)
            if rectangle.brush.is_none()
                && rectangle.blur_width == 0.0
                && rectangle.angle == 0.0
                && rectangle.rect.is_finite()
                && rectangle.rect.width() >= MIN_BOX_SIDE
                && rectangle.rect.height() >= MIN_BOX_SIDE
                && (rectangle.fill != Color32::TRANSPARENT || !rectangle.stroke.is_empty()) =>
        {
            let rect = rectangle.rect;
            let cut = CORNER_CUT.min(rect.width() * 0.5).min(rect.height() * 0.5);
            let points = vec![
                rect.left_top(),
                egui::pos2(rect.right() - cut, rect.top()),
                egui::pos2(rect.right(), rect.top() + cut),
                rect.right_bottom(),
                rect.left_bottom(),
            ];
            let stroke = PathStroke::from(rectangle.stroke).with_kind(rectangle.stroke_kind);
            *shape = Shape::Path(PathShape::convex_polygon(points, rectangle.fill, stroke));
        }
        _ => {}
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Graphical/ThemeUnitTests.rs"]
mod tests;
