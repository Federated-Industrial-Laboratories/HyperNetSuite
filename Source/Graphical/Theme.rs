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
mod tests {
    use super::*;
    use egui::{Rect, Stroke, StrokeKind, TextureId, epaint::RectShape};

    #[test]
    fn corner_cut_preserves_fill_stroke_placement_and_nested_shape_order() {
        let rect = Rect::from_min_max(egui::pos2(10.0, 20.0), egui::pos2(110.0, 60.0));
        let fill = Color32::from_rgb(20, 30, 40);
        let stroke = Stroke::new(2.0, Color32::WHITE);
        for kind in [StrokeKind::Inside, StrokeKind::Middle, StrokeKind::Outside] {
            let mut shape = Shape::Vec(vec![
                Shape::Noop,
                RectShape::new(rect, 6, fill, stroke, kind).into(),
            ]);
            box_outline(&mut shape);
            let Shape::Vec(shapes) = shape else {
                panic!("shape grouping changed")
            };
            assert_eq!(shapes[0], Shape::Noop);
            let Shape::Path(path) = &shapes[1] else {
                panic!("box outline is absent")
            };
            assert_eq!(
                path.points,
                vec![
                    rect.left_top(),
                    egui::pos2(105.0, 20.0),
                    egui::pos2(110.0, 25.0),
                    rect.right_bottom(),
                    rect.left_bottom()
                ]
            );
            assert!(path.closed);
            assert_eq!(path.fill, fill);
            assert_eq!(path.stroke, PathStroke::from(stroke).with_kind(kind));
        }
    }

    #[test]
    fn image_brushes_shadows_rotations_and_thin_lines_are_unchanged() {
        let rect = Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(40.0, 30.0));
        let base = RectShape::filled(rect, 4, Color32::WHITE);
        let sources = [
            base.clone().with_texture(
                TextureId::User(1),
                Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(1.0, 1.0)),
            ),
            base.clone().with_blur_width(8.0),
            base.with_angle(0.2),
            RectShape::filled(
                Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(40.0, 1.0)),
                0,
                Color32::WHITE,
            ),
        ];
        for source in sources {
            let original = Shape::Rect(source);
            let mut converted = original.clone();
            box_outline(&mut converted);
            assert_eq!(converted, original);
        }
    }

    #[test]
    fn end_pass_hook_keeps_clip_rectangles_and_the_small_box_cut_bounded() {
        let ctx = egui::Context::default();
        apply(&ctx, &mut egui::Style::default());
        let clip = Rect::from_min_size(egui::pos2(20.0, 20.0), egui::vec2(80.0, 40.0));
        let rect = Rect::from_min_size(egui::pos2(25.0, 25.0), egui::vec2(6.0, 4.0));
        let output = ctx.run_ui(egui::RawInput::default(), |ui| {
            ui.painter()
                .with_clip_rect(clip)
                .rect_filled(rect, 3, Color32::WHITE);
        });
        let converted = output.shapes.iter().find(|shape| matches!(&shape.shape, Shape::Path(path) if path.points.first() == Some(&rect.left_top()))).expect("root layer box conversion");
        assert_eq!(converted.clip_rect, clip);
        let Shape::Path(path) = &converted.shape else {
            unreachable!()
        };
        assert_eq!(path.points[1], egui::pos2(29.0, 25.0));
        assert_eq!(path.points[2], egui::pos2(31.0, 27.0));
        output.drop_without_applying_deltas();
    }
}
