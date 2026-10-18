// SPDX-License-Identifier: MIT
// Native layout and local controls for validated HyperPage documents.
#[path = "FormFields.rs"]
mod fields;
#[path = "Markdown.rs"]
mod markdown;
use crate::{
    markup::{
        self, BorderStyle, Colour, Document, Fit, Kind, Node, PageAction, Preset, ScrollDirection,
        Style, TextKind,
    },
    page_view::View,
    reader::Action,
};
use eframe::egui::{
    self, Align, Color32, Layout, Pos2, Rect, Response, RichText, Sense, Stroke, StrokeKind,
    TextureHandle, Ui, Vec2,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

const CELL_WIDTH: f32 = 8.0;
const LINE_HEIGHT: f32 = 18.0;
const MAX_VISIBLE_EFFECTS: usize = 8;
const FRAME_INTERVAL: Duration = Duration::from_millis(100);
#[derive(Default)]
pub struct PageRenderer {
    fields: fields::Fields,
    markdown: BTreeMap<usize, markdown::Markdown>,
    motion: BTreeMap<usize, bool>,
    scrolls: BTreeMap<usize, (f32, f32)>,
    scroll_request: BTreeMap<usize, ScrollDirection>,
    focus_request: Option<usize>,
    message: Option<String>,
    generation: u64,
    visible_effects: BTreeSet<usize>,
    text_scrolls: BTreeMap<usize, f32>,
    scroll_initialized: bool,
}
impl PageRenderer {
    pub fn reset(&mut self) {
        let generation = self.generation.wrapping_add(1);
        *self = Self {
            generation,
            ..Self::default()
        };
    }
    pub fn show(
        &mut self,
        ui: &mut Ui,
        document: &Document,
        view: &mut View,
        images: &BTreeMap<String, TextureHandle>,
        animations: bool,
    ) -> Option<Action> {
        let effect_keys = self
            .visible_effects
            .iter()
            .copied()
            .filter(|key| self.motion.get(key).copied().unwrap_or(true))
            .take(MAX_VISIBLE_EFFECTS)
            .collect();
        let mut frame = Render {
            renderer: self,
            document,
            view,
            images,
            animations,
            effect_keys,
            visible_effects: BTreeSet::new(),
            action: None,
        };
        let generation = frame.renderer.generation;
        ui.push_id(("HyperPage", generation), |ui| {
            ui.spacing_mut().item_spacing = Vec2::new(8.0, 6.0);
            let mut page_scroll = egui::ScrollArea::vertical()
                .id_salt("Page")
                .auto_shrink([false, false]);
            if !frame.renderer.scroll_initialized {
                page_scroll =
                    page_scroll.vertical_scroll_offset(frame.view.offset as f32 * line_height(ui));
                frame.renderer.scroll_initialized = true;
            }
            let output = page_scroll.show(ui, |ui| {
                ui.set_width(ui.available_width());
                if !document.title.is_empty() {
                    ui.label(
                        RichText::new(&document.title)
                            .size(body_size(ui) * 2.0)
                            .strong(),
                    );
                    ui.add_space(8.0);
                }
                frame.nodes(ui, &document.nodes, Style::default());
                if let Some(message) = &frame.renderer.message {
                    ui.colored_label(Color32::from_rgb(234, 139, 119), message);
                }
            });
            frame.view.offset = (output.state.clamped_offset().y / line_height(ui)) as usize;
        });
        if !frame.visible_effects.is_empty()
            && !ui
                .ctx()
                .input(|input| input.viewport().minimized.unwrap_or(false))
        {
            ui.ctx().request_repaint_after(FRAME_INTERVAL);
        }
        frame.renderer.visible_effects = frame.visible_effects;
        frame.action
    }
}
struct Render<'a> {
    renderer: &'a mut PageRenderer,
    document: &'a Document,
    view: &'a mut View,
    images: &'a BTreeMap<String, TextureHandle>,
    animations: bool,
    effect_keys: BTreeSet<usize>,
    visible_effects: BTreeSet<usize>,
    action: Option<Action>,
}
fn inherited(parent: Style, own: Style) -> Style {
    Style {
        colour: own.colour.or(parent.colour),
        bold: own.bold || parent.bold,
        border: own.border.or(parent.border),
    }
}
fn colour(value: Option<Colour>, fallback: Color32) -> Color32 {
    use Colour::*;
    let rgb = match value.unwrap_or(Default) {
        Default => return fallback,
        Black => [24, 26, 28],
        Red => [194, 93, 86],
        Green => [114, 161, 121],
        Yellow => [194, 165, 94],
        Blue => [104, 144, 185],
        Magenta => [168, 123, 174],
        Cyan => [108, 170, 174],
        White => [201, 205, 208],
        BrightBlack => [128, 134, 139],
        BrightRed => [235, 133, 121],
        BrightGreen => [155, 199, 158],
        BrightYellow => [224, 199, 131],
        BrightBlue => [146, 184, 220],
        BrightMagenta => [205, 165, 208],
        BrightCyan => [148, 207, 208],
        BrightWhite => [236, 239, 240],
    };
    Color32::from_rgb(rgb[0], rgb[1], rgb[2])
}
fn body_size(ui: &Ui) -> f32 {
    egui::TextStyle::Body.resolve(ui.style()).size
}
fn scale(ui: &Ui) -> f32 {
    body_size(ui) / 13.0
}
fn line_height(ui: &Ui) -> f32 {
    LINE_HEIGHT * scale(ui)
}
fn pulse(phase: f32) -> f32 {
    (phase * std::f32::consts::TAU).sin() * 0.5 + 0.5
}
fn phase(now: f64, duration_ms: u16) -> f32 {
    ((now * 1000.0).rem_euclid(f64::from(duration_ms.max(1))) / f64::from(duration_ms.max(1)))
        as f32
}
fn find<'a>(nodes: &'a [Node], target: &str) -> Option<&'a Node> {
    for node in nodes {
        if node.id.as_deref() == Some(target) {
            return Some(node);
        }
        if let Some(found) = find(&node.children, target) {
            return Some(found);
        }
    }
    None
}
fn plain_paragraph(node: &Node) -> bool {
    matches!(
        node.kind,
        Kind::Text {
            kind: TextKind::Paragraph,
            ..
        }
    ) && node.id.is_none()
        && node.motion.is_none()
        && node.style.colour.is_none()
        && !node.style.bold
        && node.style.border.is_none()
}
fn paragraph_source(nodes: &[Node]) -> String {
    nodes
        .iter()
        .filter_map(|node| match &node.kind {
            Kind::Text {
                text,
                kind: TextKind::Paragraph,
            } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}
impl Render<'_> {
    fn nodes(&mut self, ui: &mut Ui, nodes: &[Node], style: Style) {
        let mut remaining = nodes;
        while let Some(node) = remaining.first() {
            let count = remaining
                .iter()
                .take_while(|node| plain_paragraph(node))
                .count();
            if count > 1 {
                let source = paragraph_source(&remaining[..count]);
                let parsed = self
                    .renderer
                    .markdown
                    .entry(node.key)
                    .or_insert_with(|| markdown::Markdown::parse(&source));
                let text = markdown::TextStyle {
                    colour: if self.view.monochrome {
                        ui.visuals().text_color()
                    } else {
                        colour(style.colour, ui.visuals().text_color())
                    },
                    size: body_size(ui),
                    bold: style.bold,
                    italic: false,
                    strike: false,
                };
                ui.push_id(node.key, |ui| {
                    if let Some(action) =
                        parsed.show(ui, self.document, self.view, self.images, text)
                    {
                        self.action.get_or_insert(action);
                    }
                });
                remaining = &remaining[count..];
            } else {
                self.node(ui, node, style);
                remaining = &remaining[1..];
            }
        }
    }
    fn node(&mut self, ui: &mut Ui, node: &Node, parent: Style) {
        let style = inherited(parent, node.style);
        let effect = node
            .motion
            .filter(|_| {
                self.animations
                    && self.effect_keys.contains(&node.key)
                    && self.renderer.motion.get(&node.key).copied().unwrap_or(true)
            })
            .map(|effect| {
                (
                    effect.preset,
                    phase(ui.input(|i| i.time), effect.duration_ms),
                )
            });
        let result = ui.push_id(node.key, |ui| self.content(ui, node, style, effect));
        let response = result.inner.unwrap_or(result.response);
        let media_visible = match &node.kind {
            Kind::Image { asset, .. } => self
                .document
                .assets
                .iter()
                .find(|a| &a.id == asset)
                .is_some_and(|a| {
                    self.view.revealed.contains(&a.id)
                        && self.images.contains_key(&crate::graphical::image_key(a))
                }),
            _ => true,
        };
        if node.motion.is_some()
            && self.animations
            && media_visible
            && self.renderer.motion.get(&node.key).copied().unwrap_or(true)
            && ui.is_rect_visible(response.rect)
        {
            self.visible_effects.insert(node.key);
        }
        if response.has_focus() {
            self.view.focused = Some(node.key);
        }
        if self.renderer.focus_request == Some(node.key) {
            response.request_focus();
            response.scroll_to_me(Some(Align::Center));
            self.view.focused = Some(node.key);
            self.renderer.focus_request = None;
        }
    }
    fn content(
        &mut self,
        ui: &mut Ui,
        node: &Node,
        style: Style,
        effect: Option<(Preset, f32)>,
    ) -> Option<Response> {
        let mut text_colour = if self.view.monochrome {
            ui.visuals().text_color()
        } else {
            colour(style.colour, ui.visuals().text_color())
        };
        if let Some((Preset::ColourPulse, p)) = effect {
            text_colour = text_colour.gamma_multiply(0.65 + 0.35 * pulse(p));
        }
        let text_style = markdown::TextStyle {
            colour: text_colour,
            size: body_size(ui),
            bold: style.bold,
            italic: false,
            strike: false,
        };
        match &node.kind {
            Kind::Text { text, kind } => self.text(ui, node.key, text, *kind, text_style, effect),
            Kind::Column { padding, gap, .. } => {
                egui::Frame::new()
                    .inner_margin(i8::try_from(u16::from(*padding) * 4).unwrap_or(120))
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = f32::from(*gap) * 4.0;
                        self.nodes(ui, &node.children, style);
                    });
            }
            Kind::Row {
                min_child_columns,
                gap,
            } => {
                let gap = f32::from(*gap) * CELL_WIDTH * scale(ui);
                let width = ui.available_width().max(1.0);
                let minimum = f32::from(*min_child_columns) * CELL_WIDTH * scale(ui);
                let per_row = (((width + gap) / (minimum + gap).max(1.0)).floor() as usize).max(1);
                for children in node.children.chunks(per_row) {
                    let total: f32 = children
                        .iter()
                        .map(|child| match child.kind {
                            Kind::Column { weight, .. } => f32::from(weight),
                            _ => 1.0,
                        })
                        .sum();
                    let available =
                        (width - gap * children.len().saturating_sub(1) as f32).max(1.0);
                    ui.horizontal_top(|ui| {
                        ui.spacing_mut().item_spacing.x = gap;
                        for child in children {
                            let weight = match child.kind {
                                Kind::Column { weight, .. } => f32::from(weight),
                                _ => 1.0,
                            };
                            let width = available * weight / total.max(1.0);
                            ui.allocate_ui_with_layout(
                                Vec2::new(width, 0.0),
                                Layout::top_down(Align::Min),
                                |ui| {
                                    ui.set_width(width);
                                    self.node(ui, child, style);
                                },
                            );
                        }
                    });
                }
            }
            Kind::Panel { label, padding } => {
                let border = style.border.unwrap_or_default();
                let radius = if matches!(border, BorderStyle::Rounded) {
                    6
                } else {
                    0
                };
                let width = if matches!(border, BorderStyle::Heavy) {
                    2.0
                } else {
                    1.0
                };
                let mut border_colour = if self.view.monochrome {
                    Color32::from_gray(130)
                } else {
                    colour(style.colour, Color32::from_rgb(78, 85, 91))
                };
                if let Some((Preset::BorderEmphasis, p)) = effect {
                    border_colour = border_colour.gamma_multiply(0.7 + 0.6 * pulse(p));
                }
                let result = egui::Frame::new()
                    .fill(Color32::from_rgb(29, 32, 35))
                    .stroke(Stroke::new(width, border_colour))
                    .corner_radius(radius)
                    .inner_margin(i8::try_from(6 + u16::from(*padding) * 4).unwrap_or(120))
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        if !label.is_empty() {
                            ui.label(text_style.rich(label).strong());
                        }
                        self.nodes(ui, &node.children, style);
                    });
                if matches!(border, BorderStyle::Double) {
                    ui.painter().rect_stroke(
                        result.response.rect.shrink(3.0),
                        0,
                        Stroke::new(1.0, border_colour),
                        StrokeKind::Inside,
                    );
                }
            }
            Kind::ScrollBox { label, rows } => {
                ui.label(text_style.rich(label).strong());
                let row_height = line_height(ui);
                let height = f32::from(*rows) * row_height;
                let mut scroll = egui::ScrollArea::vertical()
                    .id_salt("Box")
                    .max_height(height)
                    .min_scrolled_height(height)
                    .auto_shrink([false, false]);
                if !self.renderer.scrolls.contains_key(&node.key) {
                    scroll = scroll.vertical_scroll_offset(
                        self.view
                            .scrolls
                            .get(&node.key)
                            .copied()
                            .unwrap_or_default() as f32
                            * row_height,
                    );
                }
                if let Some(direction) = self.renderer.scroll_request.remove(&node.key) {
                    let (offset, maximum) = self
                        .renderer
                        .scrolls
                        .get(&node.key)
                        .copied()
                        .unwrap_or_default();
                    let next = match direction {
                        ScrollDirection::Up => (offset - row_height).max(0.0),
                        ScrollDirection::Down => (offset + row_height).min(maximum),
                        ScrollDirection::Start => 0.0,
                        ScrollDirection::End => maximum,
                    };
                    scroll = scroll.vertical_scroll_offset(next);
                }
                let output = scroll.show(ui, |ui| self.nodes(ui, &node.children, style));
                let border = style.border.unwrap_or_default();
                let border_colour = if self.view.monochrome {
                    Color32::from_gray(130)
                } else {
                    colour(style.colour, Color32::from_rgb(78, 85, 91))
                };
                let width = if matches!(border, BorderStyle::Heavy) {
                    2.0
                } else {
                    1.0
                };
                ui.painter().rect_stroke(
                    output.inner_rect,
                    0,
                    Stroke::new(width, border_colour),
                    StrokeKind::Inside,
                );
                if matches!(border, BorderStyle::Double) {
                    ui.painter().rect_stroke(
                        output.inner_rect.shrink(3.0),
                        0,
                        Stroke::new(1.0, border_colour),
                        StrokeKind::Inside,
                    );
                }
                self.renderer.scrolls.insert(
                    node.key,
                    (
                        output.state.clamped_offset().y,
                        (output.content_size.y - output.inner_rect.height()).max(0.0),
                    ),
                );
                self.view.scrolls.insert(
                    node.key,
                    (output.state.clamped_offset().y / row_height) as usize,
                );
                let response = ui
                    .interact(
                        output.inner_rect,
                        ui.scope_id().with("ScrollFocus"),
                        Sense::focusable_noninteractive(),
                    )
                    .on_hover_text("Scroll with the wheel; focus for arrow keys, Home and End");
                response
                    .widget_info(|| egui::WidgetInfo::labeled(egui::Role::ScrollView, true, label));
                if response.has_focus() {
                    let direction = ui.input(|input| {
                        if input.key_pressed(egui::Key::ArrowUp) {
                            Some(ScrollDirection::Up)
                        } else if input.key_pressed(egui::Key::ArrowDown) {
                            Some(ScrollDirection::Down)
                        } else if input.key_pressed(egui::Key::Home) {
                            Some(ScrollDirection::Start)
                        } else if input.key_pressed(egui::Key::End) {
                            Some(ScrollDirection::End)
                        } else {
                            None
                        }
                    });
                    if let Some(direction) = direction {
                        self.renderer.scroll_request.insert(node.key, direction);
                        ui.ctx().request_repaint();
                    }
                }
                return Some(response);
            }
            Kind::Spacer { rows } => ui.add_space(f32::from(*rows) * line_height(ui)),
            Kind::Separator => {
                ui.separator();
            }
            Kind::Progress {
                label,
                value,
                maximum,
            } => {
                let progress = (*value as f32 / (*maximum).max(1) as f32).clamp(0.0, 1.0);
                let fill = if self.view.monochrome {
                    Color32::from_gray(150)
                } else {
                    colour(style.colour, Color32::from_rgb(103, 151, 158))
                };
                let response = ui.add(
                    egui::ProgressBar::new(progress)
                        .text(format!("{label}  {value}/{maximum}"))
                        .fill(fill),
                );
                if let Some((Preset::ProgressSweep, p)) = effect {
                    let filled = Rect::from_min_size(
                        response.rect.min,
                        Vec2::new(response.rect.width() * progress, response.rect.height()),
                    );
                    let x = filled.left() + (filled.width() + 20.0) * p - 20.0;
                    let highlight = Rect::from_min_size(
                        Pos2::new(x, filled.top()),
                        Vec2::new(20.0, filled.height()),
                    );
                    ui.painter()
                        .with_clip_rect(filled.intersect(ui.clip_rect()))
                        .rect_filled(highlight, 0, Color32::from_white_alpha(35));
                }
            }
            Kind::Button { label, action } => {
                let enabled =
                    !matches!(action, PageAction::Motion { running: true, .. }) || self.animations;
                let response = ui
                    .add_enabled(enabled, egui::Button::new(text_style.rich(label)))
                    .on_hover_text(self.action_description(action));
                if response.clicked() {
                    self.activate(action, ui);
                }
                return Some(response);
            }
            Kind::Form { label, .. } => {
                egui::Frame::new()
                    .stroke(Stroke::new(1.0, Color32::from_rgb(65, 72, 77)))
                    .inner_margin(8)
                    .show(ui, |ui| {
                        ui.label(text_style.rich(label).strong());
                        self.nodes(ui, &node.children, style);
                    });
            }
            Kind::Field { form, field } => {
                return Some(self.renderer.fields.show(
                    ui,
                    form,
                    field,
                    self.view,
                    ui.scope_id().with("Field"),
                ));
            }
            Kind::Image {
                asset,
                alt,
                rows,
                fit,
            } => {
                if let Some(asset) = self
                    .document
                    .assets
                    .iter()
                    .find(|manifest| &manifest.id == asset)
                {
                    let target = node.id.as_deref().unwrap_or_default();
                    if let Some(action) = image(
                        ui,
                        ImageView {
                            asset,
                            target,
                            alt,
                            height: f32::from(*rows) * line_height(ui),
                            fit: *fit,
                            motion: effect,
                        },
                        self.view,
                        self.images,
                    ) {
                        self.action.get_or_insert(action);
                    }
                }
            }
        }
        None
    }
    fn text(
        &mut self,
        ui: &mut Ui,
        key: usize,
        text: &str,
        kind: TextKind,
        style: markdown::TextStyle,
        effect: Option<(Preset, f32)>,
    ) {
        ui.scope(|ui| {
            if let Some((Preset::TextFade, p)) = effect {
                ui.multiply_opacity(0.65 + 0.35 * pulse(p));
            }
            let scroll_phase =
                effect.and_then(|(preset, p)| (preset == Preset::TextScroll).then_some(p));
            if kind == TextKind::Literal || scroll_phase.is_some() {
                let width = ui.available_width();
                let mut scroll = egui::ScrollArea::horizontal()
                    .id_salt("TextViewport")
                    .auto_shrink([false, true]);
                if let Some(p) = scroll_phase {
                    let maximum = self
                        .renderer
                        .text_scrolls
                        .get(&key)
                        .copied()
                        .unwrap_or_default();
                    scroll = scroll.horizontal_scroll_offset(maximum * pulse(p));
                }
                let output = scroll.show(ui, |ui| {
                    if kind != TextKind::Literal {
                        ui.set_width(width + 24.0 * scale(ui));
                    }
                    self.text_content(ui, key, text, kind, style);
                });
                self.renderer.text_scrolls.insert(
                    key,
                    (output.content_size.x - output.inner_rect.width()).max(0.0),
                );
            } else {
                self.text_content(ui, key, text, kind, style);
            }
        });
    }
    fn text_content(
        &mut self,
        ui: &mut Ui,
        key: usize,
        text: &str,
        kind: TextKind,
        mut style: markdown::TextStyle,
    ) {
        if kind == TextKind::Literal {
            ui.add(egui::Label::new(style.rich(text).monospace()).extend());
            return;
        }
        style.size *= match kind {
            TextKind::Heading2 => 1.7,
            TextKind::Heading3 => 1.4,
            _ => 1.0,
        };
        let parsed = self
            .renderer
            .markdown
            .entry(key)
            .or_insert_with(|| markdown::Markdown::parse(text));
        let mut render = |ui: &mut Ui| {
            if let Some(action) = parsed.show(ui, self.document, self.view, self.images, style) {
                self.action.get_or_insert(action);
            }
        };
        match kind {
            TextKind::Item => {
                ui.horizontal_top(|ui| {
                    ui.label("•");
                    ui.vertical(&mut render);
                });
            }
            TextKind::Quote => {
                let result = egui::Frame::new().inner_margin(8).show(ui, render);
                ui.painter().vline(
                    result.response.rect.left(),
                    result.response.rect.y_range(),
                    Stroke::new(2.0, style.colour),
                );
            }
            _ => render(ui),
        }
    }
    fn action_description(&self, action: &PageAction) -> String {
        match action {
            PageAction::Navigate { link } => self
                .document
                .links
                .get(*link)
                .map(|link| link.target.clone())
                .unwrap_or_else(|| "Unavailable destination".into()),
            PageAction::Submit { form } => format!("Review {form} before sending"),
            PageAction::Reveal { target } => format!("Retrieve approved media: {target}"),
            PageAction::Focus { target } => format!("Focus {target}"),
            PageAction::Scroll { target, direction } => format!("Scroll {target}: {direction:?}"),
            PageAction::Motion { target, running } => format!(
                "{} {target}",
                if *running {
                    "Start local animation for"
                } else {
                    "Pause local animation for"
                }
            ),
        }
    }
    fn activate(&mut self, action: &PageAction, ui: &Ui) {
        match action {
            PageAction::Navigate { link } if *link < self.document.links.len() => {
                self.action.get_or_insert(Action::Open(*link));
            }
            PageAction::Reveal { target } => {
                self.action.get_or_insert(Action::Reveal(target.clone()));
            }
            PageAction::Submit { form } => {
                if self
                    .document
                    .forms
                    .iter()
                    .find(|schema| &schema.id == form)
                    .is_some_and(|form| self.renderer.fields.ready(form, self.view))
                {
                    self.renderer.message = None;
                    self.action.get_or_insert(Action::Submit(form.clone()));
                } else {
                    self.renderer.message = Some(
                        "Complete required fields and correct invalid values before submitting"
                            .into(),
                    );
                }
            }
            PageAction::Focus { target } => {
                if let Some(node) = find(&self.document.nodes, target) {
                    self.renderer.focus_request = Some(node.key);
                    ui.ctx().request_repaint();
                }
            }
            PageAction::Scroll { target, direction } => {
                if let Some(node) = find(&self.document.nodes, target) {
                    self.renderer.scroll_request.insert(node.key, *direction);
                    ui.ctx().request_repaint();
                }
            }
            PageAction::Motion { target, running } => {
                if let Some(node) = find(&self.document.nodes, target)
                    && (!*running || self.animations)
                {
                    self.renderer.motion.insert(node.key, *running);
                    ui.ctx().request_repaint();
                }
            }
            _ => {}
        }
    }
}

pub(super) struct ImageView<'a> {
    pub asset: &'a markup::media::Asset,
    pub target: &'a str,
    pub alt: &'a str,
    pub height: f32,
    pub fit: Fit,
    pub motion: Option<(Preset, f32)>,
}
pub(super) fn image(
    ui: &mut Ui,
    image: ImageView<'_>,
    view: &View,
    images: &BTreeMap<String, TextureHandle>,
) -> Option<Action> {
    let ImageView {
        asset,
        target,
        alt,
        height,
        fit,
        motion,
    } = image;
    let key = crate::graphical::image_key(asset);
    let texture = view
        .revealed
        .contains(&asset.id)
        .then(|| images.get(&key))
        .flatten();
    if let Some(texture) = texture {
        let (rect, response) = ui.allocate_exact_size(
            Vec2::new(ui.available_width().max(1.0), height.clamp(18.0, 720.0)),
            Sense::hover(),
        );
        response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Image, true, alt));
        if ui.is_rect_visible(rect) {
            ui.painter()
                .rect_filled(rect, 0, Color32::from_rgb(20, 22, 24));
            let size = Vec2::new(asset.width as f32, asset.height as f32);
            let mut uv = Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0));
            let destination = if fit == Fit::Contain {
                let scale = (rect.width() / size.x).min(rect.height() / size.y);
                let fitted = size * scale;
                let mut center = rect.center();
                if let Some((Preset::ImagePan, p)) = motion {
                    center.x += (rect.width() - fitted.x) * 0.45 * (pulse(p) * 2.0 - 1.0);
                    center.y += (rect.height() - fitted.y) * 0.45 * (pulse(p) * 2.0 - 1.0);
                }
                Rect::from_center_size(center, fitted)
            } else {
                let scale = (rect.width() / size.x).max(rect.height() / size.y);
                let visible = rect.size() / (size * scale);
                let position = if let Some((Preset::ImagePan, p)) = motion {
                    pulse(p)
                } else {
                    0.5
                };
                let start = (Vec2::splat(1.0) - visible) * position;
                uv = Rect::from_min_size(Pos2::new(start.x, start.y), visible);
                rect
            };
            let tint = if let Some((Preset::ImageFade, p)) = motion {
                Color32::WHITE.gamma_multiply(0.65 + 0.35 * pulse(p))
            } else {
                Color32::WHITE
            };
            ui.painter()
                .with_clip_rect(rect.intersect(ui.clip_rect()))
                .image(texture.id(), destination, uv, tint);
        }
        response.on_hover_text(alt);
        None
    } else {
        egui::Frame::new()
            .fill(Color32::from_rgb(22, 25, 28))
            .inner_margin(8)
            .show(ui, |ui| {
                ui.label(alt);
                ui.button("Reveal image")
                    .on_hover_text(format!(
                        "{} · {} × {} · {} bytes",
                        asset.id, asset.width, asset.height, asset.bytes
                    ))
                    .clicked()
                    .then(|| Action::Reveal(target.to_owned()))
            })
            .inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paragraph_runs_render_multiline_markdown_without_changing_source() {
        let source = include_str!("../../Examples/GraphicalPage.txt");
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
        let vectors: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../../Tests/MarkupVectors.json")).unwrap();
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
}
