// SPDX-License-Identifier: MIT
// Bounded terminal-cell layout with responsive rows and independently clipped scrollboxes.
use crate::{
    borders::{BorderCell, Part},
    markup::{BorderStyle, Colour, Document, Kind, Node, PageAction, Style, TextKind},
};
use anyhow::{Result, ensure};
use std::{cell::Cell as Count, collections::BTreeMap, rc::Rc};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

pub const MAX_COLUMNS: usize = 300;
pub const MAX_ROWS: usize = 120;
pub const MAX_CELLS: usize = 262144;

#[derive(Clone)]
pub struct Cell {
    pub text: String,
    pub continuation: bool,
    pub style: Style,
    pub owner: Option<usize>,
    pub border: Option<BorderCell>,
}
pub struct Line {
    pub cells: Vec<Cell>,
    separator: bool,
    budget: Rc<Count<usize>>,
}
impl Drop for Line {
    fn drop(&mut self) {
        self.budget.set(self.budget.get() - self.cells.len());
    }
}
#[derive(Clone, Debug)]
pub struct Ancestor {
    pub key: usize,
    pub content_y: i64,
    pub rows: usize,
}
#[derive(Clone)]
pub enum ControlKind {
    ScrollBox,
    Field { form: String, field: String },
    Action(PageAction),
}
#[derive(Clone)]
pub struct Control {
    pub key: usize,
    pub label: String,
    pub kind: ControlKind,
    pub x: i64,
    pub y: i64,
    pub ancestors: Vec<Ancestor>,
}
#[derive(Clone, Debug)]
pub struct ScrollInfo {
    pub rows: usize,
    pub offset: usize,
    pub maximum: usize,
}
#[derive(Clone)]
pub struct Visual {
    pub key: usize,
    pub id: Option<String>,
    pub asset: Option<String>,
    pub fit: crate::markup::Fit,
    pub x: i64,
    pub y: i64,
    pub width: usize,
    pub rows: usize,
    pub top: i64,
    pub bottom: i64,
    pub effect: Option<crate::markup::Effect>,
}
#[derive(Default)]
pub struct Layout {
    pub lines: Vec<Line>,
    pub controls: Vec<Control>,
    pub scrolls: BTreeMap<usize, ScrollInfo>,
    pub ids: BTreeMap<String, usize>,
    pub visuals: Vec<Visual>,
}
struct Builder<'a> {
    budget: Rc<Count<usize>>,
    offsets: &'a BTreeMap<usize, usize>,
    values: &'a BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    ascii: bool,
}
pub fn safe_text(value: &str, ascii: bool) -> String {
    let mut output = String::new();
    for cluster in value.graphemes(true) {
        if cluster.width() == 0 || (ascii && !cluster.is_ascii()) {
            for ch in cluster.chars() {
                output.push_str(&format!("\\u{{{:x}}}", ch as u32));
            }
        } else {
            output.push_str(&crate::terminal_text(cluster, false));
        }
    }
    output
}
pub fn wrap(value: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut rows = Vec::new();
    let mut row = String::new();
    let mut used = 0;
    for cluster in value.graphemes(true) {
        let size = cluster.width();
        if used + size > width && !row.is_empty() {
            rows.push(std::mem::take(&mut row));
            used = 0;
        }
        if size > width {
            row.push('?');
            used += 1;
        } else {
            row.push_str(cluster);
            used += size;
        }
    }
    rows.push(row);
    rows
}
pub fn clipped(value: &str, width: usize) -> String {
    let mut text = String::new();
    let mut cells = 0;
    for cluster in value.graphemes(true) {
        let next = cluster.width();
        if cells + next > width {
            break;
        }
        text.push_str(cluster);
        cells += next;
    }
    text
}
fn inherited(parent: Style, own: Style) -> Style {
    Style {
        colour: own.colour.or(parent.colour),
        bold: own.bold || parent.bold,
        border: own.border.or(parent.border),
    }
}
impl Layout {
    fn metadata(&mut self, mut child: Layout, x: usize, y: usize) {
        for control in &mut child.controls {
            control.x += x as i64;
            control.y += y as i64;
        }
        for visual in &mut child.visuals {
            visual.x += x as i64;
            visual.y += y as i64;
            visual.top += y as i64;
            visual.bottom += y as i64;
        }
        self.visuals.append(&mut child.visuals);
        self.controls.append(&mut child.controls);
        self.scrolls.append(&mut child.scrolls);
        self.ids.append(&mut child.ids);
    }
}
impl Builder<'_> {
    fn line(&self, width: usize, style: Style) -> Result<Line> {
        ensure!(width > 0 && width <= MAX_COLUMNS, "invalid layout width");
        ensure!(
            self.budget.get().saturating_add(width) <= MAX_CELLS,
            "page layout exceeds the 262144-cell budget; use plain output"
        );
        self.budget.set(self.budget.get() + width);
        Ok(Line {
            cells: vec![
                Cell {
                    text: " ".into(),
                    continuation: false,
                    style,
                    owner: None,
                    border: None,
                };
                width
            ],
            budget: self.budget.clone(),
            separator: false,
        })
    }
    fn write(&self, line: &mut Line, start: usize, text: &str, style: Style, owner: Option<usize>) {
        let mut x = start;
        for cluster in text.graphemes(true) {
            let size = cluster.width();
            if size == 0 || x + size > line.cells.len() {
                break;
            }
            line.cells[x] = Cell {
                text: cluster.into(),
                continuation: false,
                style,
                owner,
                border: None,
            };
            for i in 1..size {
                line.cells[x + i] = Cell {
                    text: String::new(),
                    continuation: true,
                    style,
                    owner,
                    border: None,
                };
            }
            x += size;
        }
    }
    fn text(
        &self,
        value: &str,
        width: usize,
        style: Style,
        owner: Option<usize>,
    ) -> Result<Layout> {
        let mut block = Layout::default();
        for text in wrap(&safe_text(value, self.ascii), width) {
            let mut line = self.line(width, style)?;
            self.write(&mut line, 0, &text, style, owner);
            block.lines.push(line);
        }
        Ok(block)
    }
    fn flow(&self, nodes: &[Node], width: usize, style: Style, gap: usize) -> Result<Layout> {
        let mut block = Layout::default();
        for (index, node) in nodes.iter().enumerate() {
            if index != 0 {
                for _ in 0..gap {
                    block.lines.push(self.line(width, style)?);
                }
            }
            let mut child = self.node(node, width, style)?;
            let y = block.lines.len();
            block.lines.append(&mut child.lines);
            block.metadata(child, 0, y);
        }
        Ok(block)
    }
    fn inset(
        &self,
        mut child: Layout,
        width: usize,
        padding: usize,
        style: Style,
    ) -> Result<Layout> {
        if padding == 0 {
            return Ok(child);
        }
        let mut block = Layout::default();
        for _ in 0..padding {
            block.lines.push(self.line(width, style)?);
        }
        for line in child.lines.drain(..) {
            let mut row = self.line(width, style)?;
            let end = padding + line.cells.len();
            row.cells[padding..end].clone_from_slice(&line.cells);
            block.lines.push(row);
        }
        for _ in 0..padding {
            block.lines.push(self.line(width, style)?);
        }
        block.metadata(child, padding, padding);
        Ok(block)
    }
    fn row(
        &self,
        children: &[Node],
        width: usize,
        style: Style,
        minimum: usize,
        gap: usize,
    ) -> Result<Layout> {
        if children.is_empty() {
            return Ok(Layout::default());
        }
        let gaps = gap * children.len().saturating_sub(1);
        if minimum.saturating_mul(children.len()).saturating_add(gaps) > width {
            return self.flow(children, width, style, gap);
        }
        let weights: Vec<usize> = children
            .iter()
            .map(|n| match &n.kind {
                Kind::Column { weight, .. } => usize::from(*weight),
                _ => 1,
            })
            .collect();
        let total: usize = weights.iter().sum();
        ensure!(total > 0, "invalid row weights");
        let extra = width - gaps - minimum * children.len();
        let mut widths: Vec<_> = weights
            .iter()
            .map(|w| minimum + extra * w / total)
            .collect();
        let remaining = width - gaps - widths.iter().sum::<usize>();
        for value in widths.iter_mut().take(remaining) {
            *value += 1;
        }
        let mut children = children
            .iter()
            .zip(&widths)
            .map(|(n, w)| self.node(n, *w, style))
            .collect::<Result<Vec<_>>>()?;
        let height = children.iter().map(|c| c.lines.len()).max().unwrap_or(0);
        let mut block = Layout::default();
        for y in 0..height {
            let mut line = self.line(width, style)?;
            let mut x = 0;
            for (child, child_width) in children.iter().zip(&widths) {
                if let Some(row) = child.lines.get(y) {
                    line.cells[x..x + child_width].clone_from_slice(&row.cells);
                    if *child_width == width {
                        line.separator = row.separator;
                    }
                }
                x += child_width + gap;
            }
            block.lines.push(line);
        }
        let mut x = 0;
        for (mut child, child_width) in children.drain(..).zip(widths) {
            child.lines.clear();
            block.metadata(child, x, 0);
            x += child_width + gap;
        }
        Ok(block)
    }
    fn border_cell(
        &self,
        line: &mut Line,
        x: usize,
        node: &Node,
        part: Part,
        style: Style,
        owner: Option<usize>,
    ) {
        let border = BorderCell {
            key: node.key,
            style: if self.ascii {
                BorderStyle::Ascii
            } else {
                style.border.unwrap_or_default()
            },
            part,
        };
        self.write(line, x, border.glyph(false), style, owner);
        line.cells[x].border = Some(border);
    }
    fn border(
        &self,
        width: usize,
        label: &str,
        style: Style,
        node: &Node,
        bottom: bool,
        owner: Option<usize>,
    ) -> Result<Line> {
        let mut row = self.line(width, style)?;
        for x in 0..width {
            let part = match (width >= 3, x, bottom) {
                (true, 0, false) => Part::TopLeft,
                (true, 0, true) => Part::BottomLeft,
                (true, last, false) if last + 1 == width => Part::TopRight,
                (true, last, true) if last + 1 == width => Part::BottomRight,
                _ => Part::Horizontal,
            };
            self.border_cell(&mut row, x, node, part, style, owner);
        }
        if width > 4 && !label.is_empty() {
            self.write(
                &mut row,
                2,
                &clipped(&safe_text(label, self.ascii), width - 4),
                style,
                owner,
            );
        }
        Ok(row)
    }
    fn panel(
        &self,
        node: &Node,
        label: &str,
        padding: usize,
        width: usize,
        style: Style,
        scroll_rows: Option<usize>,
    ) -> Result<Layout> {
        let border = usize::from(width >= 3);
        let padding = padding.min(width.saturating_sub(3) / 2);
        let inner = width - border * 2 - padding * 2;
        let mut content = self.flow(&node.children, inner, style, 0)?;
        let rows = scroll_rows.unwrap_or(content.lines.len());
        let offset = scroll_rows
            .map(|_| {
                self.offsets
                    .get(&node.key)
                    .copied()
                    .unwrap_or(0)
                    .min(content.lines.len().saturating_sub(rows))
            })
            .unwrap_or(0);
        let owner = scroll_rows.map(|_| node.key);
        let mut block = Layout::default();
        block
            .lines
            .push(self.border(width, label, style, node, false, owner)?);
        for _ in 0..padding {
            let mut row = self.line(width, style)?;
            if border != 0 {
                self.border_cell(&mut row, 0, node, Part::Vertical, style, owner);
                self.border_cell(&mut row, width - 1, node, Part::Vertical, style, owner);
            }
            block.lines.push(row);
        }
        for y in 0..rows {
            let mut row = self.line(width, style)?;
            if border != 0 {
                self.border_cell(&mut row, 0, node, Part::Vertical, style, owner);
                self.border_cell(&mut row, width - 1, node, Part::Vertical, style, owner);
            }
            if let Some(line) = content.lines.get(offset + y) {
                let start = border + padding;
                row.cells[start..start + inner].clone_from_slice(&line.cells);
                if line.separator && border != 0 {
                    for cell in &mut row.cells[start..start + inner] {
                        if let Some(generated) = &mut cell.border {
                            generated.key = node.key;
                        }
                    }
                    self.border_cell(&mut row, 0, node, Part::LeftJoin, style, owner);
                    self.border_cell(&mut row, width - 1, node, Part::RightJoin, style, owner);
                    // A full-width divider crosses this panel's own padding only.
                    for x in (1..start).chain(start + inner..width - 1) {
                        self.border_cell(&mut row, x, node, Part::Horizontal, style, owner);
                    }
                }
            }
            block.lines.push(row);
        }
        for _ in 0..padding {
            let mut row = self.line(width, style)?;
            if border != 0 {
                self.border_cell(&mut row, 0, node, Part::Vertical, style, owner);
                self.border_cell(&mut row, width - 1, node, Part::Vertical, style, owner);
            }
            block.lines.push(row);
        }
        block
            .lines
            .push(self.border(width, "", style, node, true, owner)?);
        if scroll_rows.is_some() {
            for visual in &mut content.visuals {
                visual.y -= offset as i64;
                visual.top = (visual.top - offset as i64).max(0);
                visual.bottom = (visual.bottom - offset as i64).min(rows as i64);
            }
            for control in &mut content.controls {
                control.ancestors.push(Ancestor {
                    key: node.key,
                    content_y: control.y,
                    rows,
                });
                control.y -= offset as i64;
            }
            block.controls.push(Control {
                key: node.key,
                label: label.into(),
                kind: ControlKind::ScrollBox,
                x: 0,
                y: 0,
                ancestors: Vec::new(),
            });
            block.scrolls.insert(
                node.key,
                ScrollInfo {
                    rows,
                    offset,
                    maximum: content.lines.len().saturating_sub(rows),
                },
            );
            if let Some(id) = &node.id {
                block.ids.insert(id.clone(), node.key);
            }
        }
        content.lines.clear();
        block.metadata(content, border + padding, 1 + padding);
        Ok(block)
    }
    fn node(&self, node: &Node, width: usize, parent: Style) -> Result<Layout> {
        let mut style = inherited(parent, node.style);
        let mut block = match &node.kind {
            Kind::Text { text, kind } => {
                let prefix = match kind {
                    TextKind::Paragraph => "",
                    TextKind::Heading2 => "## ",
                    TextKind::Heading3 => "### ",
                    TextKind::Item => "- ",
                    TextKind::Quote => "> ",
                    TextKind::Literal => "| ",
                };
                style.bold |= matches!(kind, TextKind::Heading2 | TextKind::Heading3);
                self.text(&format!("{prefix}{text}"), width, style, None)
            }
            Kind::Column { padding, gap, .. } => {
                let padding = usize::from(*padding).min((width - 1) / 2);
                let content = self.flow(
                    &node.children,
                    width - padding * 2,
                    style,
                    usize::from(*gap),
                )?;
                self.inset(content, width, padding, style)
            }
            Kind::Row {
                min_child_columns,
                gap,
            } => self.row(
                &node.children,
                width,
                style,
                usize::from(*min_child_columns),
                usize::from(*gap),
            ),
            Kind::Form { label, .. } => self.panel(node, label, 0, width, style, None),
            Kind::Field { form, field } => {
                let value = self
                    .values
                    .get(form)
                    .and_then(|values| values.get(&field.id));
                let display = value
                    .map(|value| match value {
                        serde_json::Value::String(text) => text.clone(),
                        _ => value.to_string(),
                    })
                    .unwrap_or_else(|| "[unset]".into());
                let mut block = self.text(
                    &format!(
                        "{}{}: {}",
                        field.label,
                        if field.required { " *" } else { "" },
                        display
                    ),
                    width,
                    style,
                    Some(node.key),
                )?;
                block.controls.push(Control {
                    key: node.key,
                    label: field.label.clone(),
                    kind: ControlKind::Field {
                        form: form.clone(),
                        field: field.id.clone(),
                    },
                    x: 0,
                    y: 0,
                    ancestors: Vec::new(),
                });
                Ok(block)
            }
            Kind::Panel { label, padding } => {
                self.panel(node, label, usize::from(*padding), width, style, None)
            }
            Kind::ScrollBox { label, rows } => {
                ensure!(
                    *rows > 0 && usize::from(*rows) <= MAX_ROWS,
                    "invalid scrollbox viewport"
                );
                self.panel(node, label, 0, width, style, Some(usize::from(*rows)))
            }
            Kind::Image {
                asset,
                alt,
                rows,
                fit,
            } => {
                let mut block = self.text(&format!("[Image: {alt}]"), width, style, None)?;
                let top = block.lines.len();
                for _ in 0..*rows {
                    block.lines.push(self.line(width, style)?);
                }
                block.visuals.push(Visual {
                    key: node.key,
                    id: node.id.clone(),
                    asset: Some(asset.clone()),
                    fit: *fit,
                    x: 0,
                    y: top as i64,
                    width,
                    rows: usize::from(*rows),
                    top: top as i64,
                    bottom: (top + usize::from(*rows)) as i64,
                    effect: node.motion,
                });
                Ok(block)
            }
            Kind::Separator => {
                let mut block = Layout::default();
                let mut row = self.line(width, style)?;
                for x in 0..width {
                    self.border_cell(&mut row, x, node, Part::Horizontal, style, None);
                }
                row.separator = true;
                block.lines.push(row);
                Ok(block)
            }
            Kind::Spacer { rows } => {
                let mut block = Layout::default();
                for _ in 0..*rows {
                    block.lines.push(self.line(width, style)?);
                }
                Ok(block)
            }
            Kind::Progress {
                label,
                value,
                maximum,
            } => {
                ensure!(*maximum > 0 && value <= maximum, "invalid progress value");
                let mut block =
                    self.text(&format!("{label}: {value}/{maximum}"), width, style, None)?;
                let size = width.saturating_sub(2).min(40);
                let filled = (u64::from(*value) * size as u64 / u64::from(*maximum)) as usize;
                let mut bar = self.text(
                    &format!("[{}{}]", "#".repeat(filled), "-".repeat(size - filled)),
                    width,
                    style,
                    None,
                )?;
                block.lines.append(&mut bar.lines);
                Ok(block)
            }
            Kind::Button { label, action } => {
                let mut block = self.text(&format!("[ {label} ]"), width, style, Some(node.key))?;
                block.controls.push(Control {
                    key: node.key,
                    label: label.clone(),
                    kind: ControlKind::Action(action.clone()),
                    x: 0,
                    y: 0,
                    ancestors: Vec::new(),
                });
                Ok(block)
            }
        }?;
        if let Some(id) = &node.id {
            block.ids.insert(id.clone(), node.key);
        }
        if node.motion.is_some() && !matches!(node.kind, Kind::Image { .. }) {
            let rows = block.lines.len();
            block.visuals.push(Visual {
                key: node.key,
                id: node.id.clone(),
                asset: None,
                fit: crate::markup::Fit::Contain,
                x: 0,
                y: 0,
                width,
                rows,
                top: 0,
                bottom: rows as i64,
                effect: node.motion,
            });
        }
        Ok(block)
    }
}

pub fn build_with_values(
    document: &Document,
    columns: usize,
    offsets: &BTreeMap<usize, usize>,
    ascii: bool,
    values: &BTreeMap<String, BTreeMap<String, serde_json::Value>>,
) -> Result<Layout> {
    ensure!(
        (1..=MAX_COLUMNS).contains(&columns),
        "invalid layout viewport"
    );
    let builder = Builder {
        budget: Rc::new(Count::new(0)),
        offsets,
        values,
        ascii,
    };
    let mut result = builder.flow(
        &document.nodes,
        columns,
        Style {
            colour: Some(Colour::Default),
            bold: false,
            border: Some(BorderStyle::Light),
        },
        0,
    )?;
    result.controls.sort_by_key(|c| c.key);
    Ok(result)
}
#[cfg(test)]
#[path = "../../Tests/Unit/Presentation/PageLayoutUnitTests.rs"]
mod tests;

#[cfg(test)]
include!("../../Tests/Support/Presentation/PageLayout.rs");
