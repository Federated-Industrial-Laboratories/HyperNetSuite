// SPDX-License-Identifier: MIT
// Unit tests for PageRenderer.
use super::*;

#[test]
fn keyboard_scrolling_follows_page_box_and_text_field_focus() {
    fn frame(
        ctx: &egui::Context,
        renderer: &mut PageRenderer,
        document: &Document,
        view: &mut View,
        events: Vec<egui::Event>,
    ) -> egui::FullOutput {
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(600.0, 400.0))),
                events,
                ..Default::default()
            },
            |ui| {
                renderer.show(ui, document, view, &BTreeMap::new(), false);
            },
        );
        output.textures_delta.clear();
        output
    }
    fn focus(id: egui::accesskit::NodeId) -> egui::Event {
        egui::Event::AccessKitActionRequest(egui::accesskit::ActionRequest {
            action: egui::accesskit::Action::Focus,
            target_tree: egui::accesskit::TreeId::ROOT,
            target_node: id,
            data: None,
        })
    }
    fn key(key: egui::Key) -> egui::Event {
        egui::Event::Key {
            key,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        }
    }
    fn pointer(pos: Pos2, pressed: bool) -> Vec<egui::Event> {
        vec![
            egui::Event::PointerMoved(pos),
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            },
        ]
    }
    let source = format!(
        "HyperNetPage/2\n# Scrolling\n@ScrollBox {{\"id\":\"Details\",\"label\":\"Details\",\"rows\":2}}\n{}@End\n@Form {{\"id\":\"Feedback\",\"label\":\"Feedback\",\"profile\":\"HyperNetFormMail/1\",\"recipient\":\"{}\",\"owner\":\"{}\"}}\n@Field {{\"id\":\"Message\",\"label\":\"Message\",\"kind\":\"Text\",\"maxBytes\":100}}\n@Submit {{\"label\":\"Review\"}}\n@End\n{}: [Last](https://example.org/)\n",
        ": Box line\n\n".repeat(12),
        "01".repeat(32),
        "02".repeat(32),
        ": Page line\n\n".repeat(40)
    );
    let document = markup::parse(&source).unwrap();
    let ctx = egui::Context::default();
    ctx.enable_accesskit();
    let mut renderer = PageRenderer::default();
    let mut view = View::new();
    let output = frame(&ctx, &mut renderer, &document, &mut view, vec![]);
    let tree = output.platform_output.accesskit_update.as_ref().unwrap();
    let page = tree
        .nodes
        .iter()
        .find(|(_, node)| node.role() == egui::Role::ScrollView && node.label() == Some("Page"))
        .unwrap()
        .0;
    let nested = tree
        .nodes
        .iter()
        .find(|(_, node)| node.role() == egui::Role::ScrollView && node.label() == Some("Details"))
        .unwrap()
        .0;
    let field = tree
        .nodes
        .iter()
        .find(|(_, node)| node.role() == egui::Role::TextInput)
        .unwrap()
        .0;
    let last = tree
        .nodes
        .iter()
        .find(|(_, node)| node.role() == egui::Role::Link && node.label() == Some("Last"))
        .unwrap()
        .0;
    let text_position = |text| {
        let bounds = tree
            .nodes
            .iter()
            .filter(|(_, node)| node.role() == egui::Role::Label && node.value() == Some(text))
            .filter_map(|(_, node)| node.bounds())
            .min_by(|a, b| a.y0.total_cmp(&b.y0))
            .unwrap();
        Pos2::new(
            (bounds.x0 + bounds.x1) as f32 * 0.5,
            (bounds.y0 + bounds.y1) as f32 * 0.5,
        )
    };
    let box_text = text_position("Box line");
    let page_text = text_position("Page line");
    output.drop_without_applying_deltas();

    frame(
        &ctx,
        &mut renderer,
        &document,
        &mut view,
        pointer(box_text, true),
    )
    .drop_without_applying_deltas();
    let output = frame(
        &ctx,
        &mut renderer,
        &document,
        &mut view,
        pointer(box_text, false),
    );
    assert_eq!(
        ctx.memory(|memory| memory.focused())
            .map(|id| id.accesskit_id()),
        Some(nested),
        "box text at {box_text:?}; Page focus id {page:?}"
    );
    assert!(output.shapes.iter().any(|shape| matches!(&shape.shape,
        egui::Shape::Rect(rect) if rect.stroke.width == 2.0 && rect.stroke.color == ctx.global_style().visuals.selection.stroke.color)));
    output.drop_without_applying_deltas();
    frame(
        &ctx,
        &mut renderer,
        &document,
        &mut view,
        vec![key(egui::Key::End)],
    )
    .drop_without_applying_deltas();
    frame(&ctx, &mut renderer, &document, &mut view, vec![]).drop_without_applying_deltas();
    assert_eq!(view.offset, 0);
    assert!(view.scrolls.values().any(|offset| *offset > 0));
    let box_offsets = view.scrolls.clone();

    frame(
        &ctx,
        &mut renderer,
        &document,
        &mut view,
        pointer(page_text, true),
    )
    .drop_without_applying_deltas();
    frame(
        &ctx,
        &mut renderer,
        &document,
        &mut view,
        pointer(page_text, false),
    )
    .drop_without_applying_deltas();
    assert_eq!(
        ctx.memory(|memory| memory.focused())
            .map(|id| id.accesskit_id()),
        Some(page)
    );
    frame(
        &ctx,
        &mut renderer,
        &document,
        &mut view,
        vec![key(egui::Key::PageDown)],
    )
    .drop_without_applying_deltas();
    frame(&ctx, &mut renderer, &document, &mut view, vec![]).drop_without_applying_deltas();
    assert!(view.offset > 0);
    assert_eq!(view.scrolls, box_offsets);
    frame(
        &ctx,
        &mut renderer,
        &document,
        &mut view,
        vec![key(egui::Key::Home)],
    )
    .drop_without_applying_deltas();
    frame(
        &ctx,
        &mut renderer,
        &document,
        &mut view,
        vec![focus(field)],
    )
    .drop_without_applying_deltas();
    let offset = view.offset;
    frame(
        &ctx,
        &mut renderer,
        &document,
        &mut view,
        vec![key(egui::Key::End)],
    )
    .drop_without_applying_deltas();
    frame(&ctx, &mut renderer, &document, &mut view, vec![]).drop_without_applying_deltas();
    assert_eq!(view.offset, offset);
    assert_eq!(view.scrolls, box_offsets);
    assert!(renderer.keyboard_scrolls.is_empty());
    for _ in 0..2 {
        frame(
            &ctx,
            &mut renderer,
            &document,
            &mut view,
            vec![key(egui::Key::Tab)],
        )
        .drop_without_applying_deltas();
    }
    frame(&ctx, &mut renderer, &document, &mut view, vec![]).drop_without_applying_deltas();
    assert!(view.offset > 0, "Tab focus did not request scrolling");
    let output = frame(&ctx, &mut renderer, &document, &mut view, vec![]);
    assert_eq!(
        ctx.memory(|memory| memory.focused())
            .map(|id| id.accesskit_id()),
        Some(last)
    );
    let tree = output.platform_output.accesskit_update.as_ref().unwrap();
    let bounds = tree
        .nodes
        .iter()
        .find(|(id, _)| *id == last)
        .unwrap()
        .1
        .bounds()
        .unwrap();
    assert!(
        bounds.y0 >= 0.0 && bounds.y1 <= 400.0,
        "focused link remains outside view: {bounds:?}; Page offset {}",
        view.offset
    );
    assert!(view.offset > 0);
    output.drop_without_applying_deltas();
}

#[test]
fn paragraph_runs_render_multiline_markdown_without_changing_source() {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/Examples/GraphicalPage.txt"
    ));
    let document = markup::parse(source).unwrap();
    let original = serde_json::to_vec(&document).unwrap();
    let context = egui::Context::default();
    let mut renderer = PageRenderer::default();
    context
        .run_ui(egui::RawInput::default(), |ui| {
            renderer.show(ui, &document, &mut View::new(), &BTreeMap::new(), false);
        })
        .drop_without_applying_deltas();
    let parsed = format!("{:?}", renderer.markdown);
    assert!(parsed.contains("Table"));
    assert!(parsed.contains("List(Some(1))"));
    assert!(parsed.contains("Code"));
    assert_eq!(original, serde_json::to_vec(&document).unwrap());
}
#[test]
fn native_layout_accepts_current_document_vectors_at_narrow_and_wide_sizes() {
    let vectors: Vec<serde_json::Value> = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/Tests/MarkupVectors.json"
    )))
    .unwrap();
    let context = egui::Context::default();
    for vector in vectors.iter().filter(|value| value["valid"] == true) {
        let document = markup::parse(vector["body"].as_str().unwrap()).unwrap();
        let mut renderer = PageRenderer::default();
        let mut view = View::new();
        for width in [320.0, 960.0] {
            let input = egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(width, 600.0))),
                ..Default::default()
            };
            let output = context.run_ui(input, |ui| {
                assert!(
                    renderer
                        .show(ui, &document, &mut view, &BTreeMap::new(), false)
                        .is_none(),
                    "{}",
                    vector["name"]
                );
            });
            assert!(!output.shapes.is_empty());
            output.drop_without_applying_deltas();
        }
    }
}
#[test]
fn local_actions_cannot_bypass_animation_off_or_create_network_actions() {
    let document = markup::parse("HyperNetPage/2\n# Motion\n@Text {\"id\":\"Local\",\"value\":\"Text\",\"motion\":{\"preset\":\"TextFade\",\"durationMs\":1000}}\n=> https://example.org/ Reference\n").unwrap();
    let context = egui::Context::default();
    let mut renderer = PageRenderer::default();
    let mut view = View::new();
    let images = BTreeMap::new();
    context
        .run_ui(egui::RawInput::default(), |ui| {
            let mut frame = Render {
                renderer: &mut renderer,
                document: &document,
                view: &mut view,
                images: &images,
                animations: false,
                effect_keys: BTreeSet::new(),
                visible_effects: BTreeSet::new(),
                action: None,
                scroll_clicked: false,
            };
            frame.activate(
                &PageAction::Motion {
                    target: "Local".into(),
                    running: true,
                },
                ui,
            );
            assert!(frame.renderer.motion.is_empty());
            assert!(frame.action.is_none());
            frame.activate(
                &PageAction::Motion {
                    target: "Local".into(),
                    running: false,
                },
                ui,
            );
            assert_eq!(
                frame.renderer.motion.get(&document.nodes[0].key),
                Some(&false)
            );
            assert!(frame.action.is_none());
            frame.activate(&PageAction::Navigate { link: 0 }, ui);
            assert!(matches!(frame.action, Some(Action::Open(0))));
        })
        .drop_without_applying_deltas();
}
#[test]
fn only_visible_declared_effects_schedule_animation() {
    let document=markup::parse(&format!("HyperNetPage/2\n# Hidden motion\n{}@Text {{\"id\":\"Hidden\",\"value\":\"Text\",\"motion\":{{\"preset\":\"TextFade\",\"durationMs\":1000}}}}\n", "@Spacer {\"rows\":8}\n".repeat(5))).unwrap();
    let context = egui::Context::default();
    let mut renderer = PageRenderer::default();
    let mut view = View::new();
    for enabled in [true, false] {
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(600.0, 240.0))),
            ..Default::default()
        };
        context
            .run_ui(input, |ui| {
                renderer.show(ui, &document, &mut view, &BTreeMap::new(), enabled);
            })
            .drop_without_applying_deltas();
        assert!(renderer.visible_effects.is_empty());
    }
}
#[test]
fn animation_phase_is_continuous_cyclic_and_bounded() {
    assert_eq!(phase(0.0, 1000), 0.0);
    assert!((phase(1.25, 1000) - 0.25).abs() < 0.001);
    assert!((phase(1001.25, 1000) - 0.25).abs() < 0.001);
    assert!((0.0..=1.0).contains(&pulse(0.75)));
}
