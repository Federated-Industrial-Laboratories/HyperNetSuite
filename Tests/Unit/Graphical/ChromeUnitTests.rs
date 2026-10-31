// SPDX-License-Identifier: MIT
// Unit tests for Chrome.
use super::*;

fn accessible_name(tree: &egui::accesskit::TreeUpdate, node: &egui::accesskit::Node) -> String {
    node.label().map(str::to_owned).unwrap_or_else(|| {
        node.labelled_by()
            .iter()
            .filter_map(|id| {
                tree.nodes
                    .iter()
                    .find(|(other, _)| other == id)
                    .and_then(|(_, label)| label.value().or(label.label()))
            })
            .collect::<Vec<_>>()
            .join(" ")
    })
}

#[test]
fn enlarged_settings_keep_control_names_and_fit_narrow_window() {
    let ctx = egui::Context::default();
    theme(&ctx);
    ctx.enable_accesskit();
    let mut values = settings::Preferences {
        text_scale: 2.0,
        ..Default::default()
    };
    for _ in 0..2 {
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(440.0, 320.0),
                )),
                ..Default::default()
            },
            |ui| {
                text_size(ui, values.text_scale);
                egui::CentralPanel::default().show(ui, |ui| {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        ui.heading("Appearance");
                        ui.add_space(16.0);
                        assert!(!preferences(ui, &mut values));
                    });
                });
            },
        );
        output.textures_delta.clear();
        let tree = output.platform_output.accesskit_update.as_ref().unwrap();
        for (role, name) in [
            (egui::Role::CheckBox, "Animation"),
            (egui::Role::Slider, "Text size"),
            (egui::Role::CheckBox, "Page colours"),
        ] {
            let node = tree
                .nodes
                .iter()
                .map(|(_, node)| node)
                .find(|node| node.role() == role && accessible_name(tree, node) == name)
                .unwrap_or_else(|| panic!("missing control name: {name}"));
            let bounds = node.bounds().unwrap();
            assert!(bounds.x0 >= 0.0 && bounds.x1 <= 440.0, "{name}: {bounds:?}");
        }
        output.drop_without_applying_deltas();
    }
}

#[test]
fn enlarged_review_keeps_named_entry_and_actions_inside_minimum_window() {
    let ctx = egui::Context::default();
    theme(&ctx);
    ctx.enable_accesskit();
    let (reply, _receiver) = sync_channel(1);
    let mut confirmation = Confirmation {
        value: serde_json::Value::Null,
        reply,
        acknowledgement: String::new(),
        end_seen: false,
        scroll_offset: None,
    };
    let mut output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(540.0, 440.0),
            )),
            ..Default::default()
        },
        |ui| {
            text_size(ui, 2.0);
            egui::Panel::bottom("ReviewActions")
                .resizable(false)
                .min_size(review_actions_height(ui))
                .show(ui, |ui| {
                    assert_eq!(review_actions(ui, &mut confirmation), None);
                });
        },
    );
    output.textures_delta.clear();
    let tree = output.platform_output.accesskit_update.as_ref().unwrap();
    for (role, name) in [
        (egui::Role::TextInput, "Type SEND"),
        (egui::Role::Button, "Send"),
        (egui::Role::Button, "Cancel"),
    ] {
        let node = tree
            .nodes
            .iter()
            .map(|(_, node)| node)
            .find(|node| node.role() == role && accessible_name(tree, node) == name)
            .unwrap_or_else(|| panic!("missing control name: {name}"));
        let bounds = node.bounds().unwrap();
        assert!(
            bounds.x0 >= 0.0 && bounds.x1 <= 540.0 && bounds.y0 >= 0.0 && bounds.y1 <= 440.0,
            "{name}: {bounds:?}"
        );
    }
    output.drop_without_applying_deltas();
}

#[test]
fn long_review_keyboard_end_preserves_both_confirmation_gates() {
    fn frame(
        ctx: &egui::Context,
        confirmation: &mut Confirmation,
        events: Vec<egui::Event>,
    ) -> egui::FullOutput {
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(540.0, 440.0),
                )),
                events,
                ..Default::default()
            },
            |ui| {
                text_size(ui, 2.0);
                egui::Panel::bottom("ReviewActions")
                    .resizable(false)
                    .min_size(review_actions_height(ui))
                    .show(ui, |ui| {
                        assert_eq!(review_actions(ui, confirmation), None);
                    });
                egui::CentralPanel::default().show(ui, |ui| review_content(ui, confirmation));
            },
        );
        output.textures_delta.clear();
        output
    }
    fn send_disabled(output: &egui::FullOutput) -> bool {
        output
            .platform_output
            .accesskit_update
            .as_ref()
            .unwrap()
            .nodes
            .iter()
            .find(|(_, node)| node.role() == egui::Role::Button && node.label() == Some("Send"))
            .unwrap()
            .1
            .is_disabled()
    }
    let ctx = egui::Context::default();
    theme(&ctx);
    ctx.enable_accesskit();
    let (reply, receiver) = sync_channel(1);
    let mut confirmation = Confirmation {
        value: serde_json::json!({"values": "Review line\n".repeat(60)}),
        reply,
        acknowledgement: "SEND".into(),
        end_seen: false,
        scroll_offset: None,
    };
    let output = frame(&ctx, &mut confirmation, vec![]);
    assert!(!confirmation.end_seen);
    assert!(send_disabled(&output));
    let focus = output
        .platform_output
        .accesskit_update
        .as_ref()
        .unwrap()
        .nodes
        .iter()
        .find(|(_, node)| {
            node.role() == egui::Role::ScrollView && node.label() == Some("Submission review")
        })
        .unwrap()
        .0;
    output.drop_without_applying_deltas();
    frame(
        &ctx,
        &mut confirmation,
        vec![egui::Event::AccessKitActionRequest(
            egui::accesskit::ActionRequest {
                action: egui::accesskit::Action::Focus,
                target_tree: egui::accesskit::TreeId::ROOT,
                target_node: focus,
                data: None,
            },
        )],
    )
    .drop_without_applying_deltas();
    frame(
        &ctx,
        &mut confirmation,
        vec![egui::Event::Key {
            key: egui::Key::End,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        }],
    )
    .drop_without_applying_deltas();
    confirmation.acknowledgement.clear();
    let output = frame(&ctx, &mut confirmation, vec![]);
    assert!(confirmation.end_seen);
    assert!(send_disabled(&output));
    output.drop_without_applying_deltas();
    confirmation.acknowledgement = "SEND".into();
    let output = frame(&ctx, &mut confirmation, vec![]);
    assert!(!send_disabled(&output));
    assert!(receiver.try_recv().is_err());
    output.drop_without_applying_deltas();
}

#[test]
fn text_size_is_inherited_once_and_resets_from_context_style() {
    let ctx = egui::Context::default();
    theme(&ctx);
    let base = egui::TextStyle::Body.resolve(&ctx.global_style()).size;
    for scale in [2.0, 2.0, 1.0] {
        ctx.run_ui(egui::RawInput::default(), |ui| {
            text_size(ui, scale);
            assert_eq!(egui::TextStyle::Body.resolve(ui.style()).size, base * scale);
            ui.scope(|ui| {
                assert_eq!(egui::TextStyle::Body.resolve(ui.style()).size, base * scale);
                text_size(ui, scale);
                assert_eq!(egui::TextStyle::Body.resolve(ui.style()).size, base * scale);
            });
        })
        .drop_without_applying_deltas();
    }
    assert_eq!(
        egui::TextStyle::Body.resolve(&ctx.global_style()).size,
        base
    );
}
