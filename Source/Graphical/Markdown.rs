// SPDX-License-Identifier: MIT
// Bounded CommonMark formatting with inert HTML and explicit navigation and asset actions.
use crate::{
    markup::{Document, media::Asset},
    page_view::View,
    reader::Action,
};
use eframe::egui::{self, RichText, Ui};
use pulldown_cmark::{Event, Options, Parser, Tag};
use std::collections::BTreeMap;

#[derive(Clone, Copy)]
pub(super) struct TextStyle {
    pub colour: egui::Color32,
    pub size: f32,
    pub bold: bool,
    pub italic: bool,
    pub strike: bool,
}
impl TextStyle {
    pub(super) fn rich(self, value: impl Into<String>) -> RichText {
        let mut text = RichText::new(value).color(self.colour).size(self.size);
        if self.bold {
            text = text.strong();
        }
        if self.italic {
            text = text.italics();
        }
        if self.strike {
            text = text.strikethrough();
        }
        text
    }
    fn strong(mut self) -> Self {
        self.bold = true;
        self
    }
    fn italics(mut self) -> Self {
        self.italic = true;
        self
    }
    fn strikethrough(mut self) -> Self {
        self.strike = true;
        self
    }
    fn size(mut self, size: f32) -> Self {
        self.size = size;
        self
    }
}

const MAX_EVENTS: usize = 8192;
const MAX_DEPTH: usize = 32;
#[derive(Clone, Debug)]
enum Group {
    Paragraph,
    Heading(u8),
    Code,
    Quote,
    List(Option<u64>),
    Item,
    Table,
    TableHead,
    TableRow,
    TableCell,
    Emphasis,
    Strong,
    Strike,
    Link(String),
    Image(String),
    Other,
}
#[derive(Clone, Debug)]
enum Element {
    Text(String),
    Code(String),
    Html(String),
    Break,
    Rule,
    Task(bool),
    Group(Group, Vec<Element>),
}
#[derive(Clone, Debug)]
pub(super) struct Markdown {
    elements: Vec<Element>,
}
fn group(tag: Tag<'_>) -> Group {
    match tag {
        Tag::Paragraph => Group::Paragraph,
        Tag::Heading { level, .. } => Group::Heading(level as u8),
        Tag::CodeBlock(_) => Group::Code,
        Tag::BlockQuote(_) => Group::Quote,
        Tag::List(start) => Group::List(start),
        Tag::Item => Group::Item,
        Tag::Table(_) => Group::Table,
        Tag::TableHead => Group::TableHead,
        Tag::TableRow => Group::TableRow,
        Tag::TableCell => Group::TableCell,
        Tag::Emphasis => Group::Emphasis,
        Tag::Strong => Group::Strong,
        Tag::Strikethrough => Group::Strike,
        Tag::Link { dest_url, .. } => Group::Link(dest_url.into_string()),
        Tag::Image { dest_url, .. } => Group::Image(dest_url.into_string()),
        _ => Group::Other,
    }
}
impl Markdown {
    pub(super) fn parse(source: &str) -> Self {
        let fallback = || Self {
            elements: vec![Element::Text(source.to_owned())],
        };
        if source.len() > crate::markup::MAX_BYTES {
            return fallback();
        }
        let mut stack = vec![(Group::Other, Vec::new())];
        let options =
            Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS;
        for (count, event) in Parser::new_ext(source, options).enumerate() {
            if count >= MAX_EVENTS {
                return fallback();
            }
            match event {
                Event::Start(tag) => {
                    if stack.len() >= MAX_DEPTH {
                        return fallback();
                    }
                    stack.push((group(tag), Vec::new()));
                }
                Event::End(_) => {
                    if stack.len() <= 1 {
                        return fallback();
                    }
                    let (kind, children) = stack.pop().expect("bounded parser group");
                    stack
                        .last_mut()
                        .expect("root group")
                        .1
                        .push(Element::Group(kind, children));
                }
                event => {
                    let value = match event {
                        Event::Text(value) => Element::Text(value.into_string()),
                        Event::Code(value)
                        | Event::InlineMath(value)
                        | Event::DisplayMath(value) => Element::Code(value.into_string()),
                        Event::Html(value) | Event::InlineHtml(value) => {
                            Element::Html(value.into_string())
                        }
                        Event::SoftBreak | Event::HardBreak => Element::Break,
                        Event::Rule => Element::Rule,
                        Event::TaskListMarker(value) => Element::Task(value),
                        Event::FootnoteReference(value) => Element::Text(format!("[{value}]")),
                        _ => continue,
                    };
                    stack.last_mut().expect("root group").1.push(value);
                }
            }
        }
        if stack.len() != 1 {
            return fallback();
        }
        Self {
            elements: stack.pop().expect("root group").1,
        }
    }
    pub(super) fn show(
        &self,
        ui: &mut Ui,
        document: &Document,
        view: &View,
        images: &BTreeMap<String, egui::TextureHandle>,
        text: TextStyle,
    ) -> Option<Action> {
        let mut renderer = Renderer {
            document,
            view,
            images,
            action: None,
        };
        renderer.blocks(ui, &self.elements, text);
        renderer.action
    }
}
pub(super) fn asset<'a>(document: &'a Document, destination: &str) -> Option<&'a Asset> {
    let id = destination.strip_prefix("asset:").unwrap_or(destination);
    document.assets.iter().find(|asset| asset.id == id)
}
fn plain(elements: &[Element], output: &mut String) {
    for element in elements {
        match element {
            Element::Text(value) | Element::Code(value) | Element::Html(value) => {
                output.push_str(value)
            }
            Element::Break => output.push('\n'),
            Element::Group(_, children) => plain(children, output),
            Element::Task(checked) => output.push_str(if *checked { "[x] " } else { "[ ] " }),
            Element::Rule => output.push_str("---"),
        }
    }
}
struct Renderer<'a> {
    document: &'a Document,
    view: &'a View,
    images: &'a BTreeMap<String, egui::TextureHandle>,
    action: Option<Action>,
}
impl Renderer<'_> {
    fn inline(&mut self, ui: &mut Ui, elements: &[Element], text: TextStyle, link: Option<&str>) {
        for element in elements {
            match element {
                Element::Text(value) | Element::Html(value) | Element::Code(value) => {
                    let rich = text.rich(value.clone());
                    let rich = if matches!(element, Element::Code(_) | Element::Html(_)) {
                        rich.monospace()
                    } else {
                        rich
                    };
                    if let Some(destination) = link {
                        let response = ui.link(rich).on_hover_text(destination);
                        super::scrolling::reveal_focus(&response);
                        if response.clicked() && self.action.is_none() {
                            self.action = Some(Action::Address(destination.to_owned()));
                        }
                    } else {
                        ui.add(egui::Label::new(rich).wrap());
                    }
                }
                Element::Break => {
                    ui.end_row();
                }
                Element::Task(value) => {
                    let mut value = *value;
                    ui.add_enabled(false, egui::Checkbox::without_text(&mut value));
                }
                Element::Rule => {
                    ui.separator();
                }
                Element::Group(kind, children) => match kind {
                    Group::Strong => self.inline(ui, children, text.strong(), link),
                    Group::Emphasis => self.inline(ui, children, text.italics(), link),
                    Group::Strike => self.inline(ui, children, text.strikethrough(), link),
                    Group::Link(destination) => self.inline(ui, children, text, Some(destination)),
                    Group::Image(destination) => {
                        let mut alt = String::new();
                        plain(children, &mut alt);
                        if let Some(asset) = asset(self.document, destination) {
                            if let Some(action) = super::image(
                                ui,
                                super::ImageView {
                                    asset,
                                    target: &format!("asset:{}", asset.id),
                                    alt: &alt,
                                    height: 120.0,
                                    fit: crate::markup::Fit::Contain,
                                    motion: None,
                                },
                                self.view,
                                self.images,
                            ) {
                                self.action.get_or_insert(action);
                            }
                        } else {
                            ui.label(text.rich(if alt.is_empty() {
                                "Image unavailable".to_owned()
                            } else {
                                alt
                            }));
                        }
                    }
                    _ => self.inline(ui, children, text, link),
                },
            }
        }
    }
    fn line(&mut self, ui: &mut Ui, children: &[Element], text: TextStyle) {
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            self.inline(ui, children, text, None);
        });
    }
    fn blocks(&mut self, ui: &mut Ui, elements: &[Element], text: TextStyle) {
        for (index, element) in elements.iter().enumerate() {
            ui.push_id(index, |ui| match element {
                Element::Group(kind, children) => match kind {
                    Group::Paragraph | Group::Other => self.line(ui, children, text),
                    Group::Heading(level) => {
                        ui.add_space(4.0);
                        self.line(
                            ui,
                            children,
                            text.strong().size(
                                text.size
                                    * match level {
                                        1 => 1.9,
                                        2 => 1.6,
                                        3 => 1.4,
                                        _ => 1.2,
                                    },
                            ),
                        );
                    }
                    Group::Code => {
                        let mut code = String::new();
                        plain(children, &mut code);
                        egui::Frame::new()
                            .fill(egui::Color32::from_rgb(20, 22, 24))
                            .inner_margin(8)
                            .show(ui, |ui| {
                                egui::ScrollArea::horizontal()
                                    .id_salt("Code")
                                    .show(ui, |ui| {
                                        ui.add(
                                            egui::Label::new(text.rich(code).monospace()).extend(),
                                        );
                                    });
                            });
                    }
                    Group::Quote => {
                        let result = egui::Frame::new()
                            .inner_margin(8)
                            .show(ui, |ui| self.blocks(ui, children, text));
                        ui.painter().vline(
                            result.response.rect.left(),
                            result.response.rect.y_range(),
                            egui::Stroke::new(2.0, ui.visuals().weak_text_color()),
                        );
                    }
                    Group::List(start) => {
                        for (item, child) in children.iter().enumerate() {
                            ui.horizontal_top(|ui| {
                                ui.label(
                                    text.rich(
                                        start
                                            .map(|n| format!("{}.", n.saturating_add(item as u64)))
                                            .unwrap_or_else(|| "•".into()),
                                    ),
                                );
                                ui.vertical(|ui| match child {
                                    Element::Group(Group::Item, children) => {
                                        self.blocks(ui, children, text)
                                    }
                                    _ => self.blocks(ui, std::slice::from_ref(child), text),
                                });
                            });
                        }
                    }
                    Group::Table => {
                        egui::ScrollArea::horizontal()
                            .id_salt("Table")
                            .show(ui, |ui| {
                                egui::Grid::new("TableCells")
                                    .striped(true)
                                    .spacing([12.0, 6.0])
                                    .show(ui, |ui| {
                                        for row in children {
                                            if let Element::Group(kind, cells) = row {
                                                for cell in cells {
                                                    if let Element::Group(
                                                        Group::TableCell,
                                                        values,
                                                    ) = cell
                                                    {
                                                        ui.vertical(|ui| {
                                                            ui.set_max_width(240.0);
                                                            self.line(
                                                                ui,
                                                                values,
                                                                if matches!(kind, Group::TableHead)
                                                                {
                                                                    text.strong()
                                                                } else {
                                                                    text
                                                                },
                                                            );
                                                        });
                                                    }
                                                }
                                                ui.end_row();
                                            }
                                        }
                                    });
                            });
                    }
                    _ => self.line(ui, children, text),
                },
                Element::Rule => {
                    ui.separator();
                }
                _ => self.line(ui, std::slice::from_ref(element), text),
            });
        }
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Graphical/MarkdownUnitTests.rs"]
mod tests;
