// SPDX-License-Identifier: MIT
// Bounded terminal-cell layout with responsive rows and independently clipped scrollboxes.
use crate::markup::{Colour, Document, Kind, Node, PageAction, Style, TextKind};
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
}
pub struct Line {
    pub cells: Vec<Cell>,
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
                    owner: None
                };
                width
            ],
            budget: self.budget.clone(),
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
            };
            for i in 1..size {
                line.cells[x + i] = Cell {
                    text: String::new(),
                    continuation: true,
                    style,
                    owner,
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
    fn border(
        &self,
        width: usize,
        label: &str,
        style: Style,
        owner: Option<usize>,
    ) -> Result<Line> {
        let mut row = self.line(width, style)?;
        self.write(
            &mut row,
            0,
            &format!("+{}+", "-".repeat(width.saturating_sub(2))),
            style,
            owner,
        );
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
        block.lines.push(self.border(width, label, style, owner)?);
        for _ in 0..padding {
            let mut row = self.line(width, style)?;
            if border != 0 {
                self.write(&mut row, 0, "|", style, owner);
                self.write(&mut row, width - 1, "|", style, owner);
            }
            block.lines.push(row);
        }
        for y in 0..rows {
            let mut row = self.line(width, style)?;
            if border != 0 {
                self.write(&mut row, 0, "|", style, owner);
                self.write(&mut row, width - 1, "|", style, owner);
            }
            if let Some(line) = content.lines.get(offset + y) {
                let start = border + padding;
                row.cells[start..start + inner].clone_from_slice(&line.cells);
            }
            block.lines.push(row);
        }
        for _ in 0..padding {
            let mut row = self.line(width, style)?;
            if border != 0 {
                self.write(&mut row, 0, "|", style, owner);
                self.write(&mut row, width - 1, "|", style, owner);
            }
            block.lines.push(row);
        }
        block.lines.push(self.border(width, "", style, owner)?);
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
            Kind::Separator => self.text(&"-".repeat(width), width, style, None),
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
#[cfg(test)]
pub fn build(
    document: &Document,
    columns: usize,
    offsets: &BTreeMap<usize, usize>,
    ascii: bool,
) -> Result<Layout> {
    build_with_values(document, columns, offsets, ascii, &BTreeMap::new())
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
        },
        0,
    )?;
    result.controls.sort_by_key(|c| c.key);
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn parse(source: &str) -> Document {
        crate::markup::parse(&format!("HyperNetPage/2\n# Layout\n{source}")).unwrap()
    }
    fn rows(layout: &Layout) -> Vec<String> {
        layout
            .lines
            .iter()
            .map(|l| l.cells.iter().map(|c| c.text.as_str()).collect::<String>())
            .collect()
    }
    #[test]
    fn images_are_clipped_to_every_scrollbox_and_alt_text_is_retained() {
        let asset = format!(
            r#"@Asset {{"id":"Picture","profile":"HyperNetRaster/1","width":1,"height":1,"bytes":3,"digest":"{}","hosts":["{}"],"copies":1}}"#,
            "0".repeat(64),
            "1".repeat(64)
        );
        let doc = parse(&format!(
            "{asset}\n@ScrollBox {{\"id\":\"Outer\",\"label\":\"Outer\",\"rows\":4}}\n: Above\n@ScrollBox {{\"id\":\"Inner\",\"label\":\"Inner\",\"rows\":6}}\n@Image {{\"id\":\"View\",\"asset\":\"Picture\",\"alt\":\"Red diagram\",\"rows\":8}}\n@End\n@End\n"
        ));
        let first = build(&doc, 40, &BTreeMap::new(), false).unwrap();
        let offsets = BTreeMap::from([(first.ids["Outer"], 2), (first.ids["Inner"], 3)]);
        let clipped = build(&doc, 40, &offsets, false).unwrap();
        let image = &clipped.visuals[0];
        assert!(image.top >= 1 && image.bottom <= 5);
        assert!(image.y < image.top && image.bottom - image.top <= 4);
        assert!(doc.lines.iter().any(|line| line.contains("Red diagram")));
    }
    #[test]
    fn weighted_rows_stack_and_preserve_unicode_cell_boundaries() {
        let doc = parse(
            "@Row {\"minChildColumns\":12,\"gap\":2}\n@Column {\"weight\":1}\n: LEFT 世界 cafe\u{301}\n@End\n@Column {\"weight\":3}\n: RIGHT 👩\u{200d}💻\n@End\n@End\n",
        );
        let wide = build(&doc, 60, &BTreeMap::new(), false).unwrap();
        let wide_rows = rows(&wide);
        assert!(
            wide_rows
                .iter()
                .any(|line| line.contains("LEFT") && line.contains("RIGHT"))
        );
        assert!(wide_rows.iter().all(|line| line.width() == 60));
        let narrow = build(&doc, 20, &BTreeMap::new(), false).unwrap();
        let narrow_rows = rows(&narrow);
        let left = narrow_rows
            .iter()
            .position(|line| line.contains("LEFT"))
            .unwrap();
        let right = narrow_rows
            .iter()
            .position(|line| line.contains("RIGHT"))
            .unwrap();
        assert!(right > left);
        assert!(narrow_rows.iter().all(|line| line.width() == 20));
        for width in 1..8 {
            let clipped = build(&doc, width, &BTreeMap::new(), false).unwrap();
            assert!(rows(&clipped).iter().all(|line| line.width() == width));
        }
    }
    #[test]
    fn panels_inherit_logical_colour_and_clip_nested_scroll_content() {
        let doc = parse(
            "@Panel {\"label\":\"Frame\",\"colour\":\"Cyan\",\"padding\":1}\n@ScrollBox {\"id\":\"Guide\",\"label\":\"Guide\",\"rows\":2}\n: FIRST\n: SECOND\n: HIDDEN\n@Text {\"value\":\"LAST\",\"colour\":\"BrightRed\",\"bold\":true}\n@End\n@End\n",
        );
        let layout = build(&doc, 30, &BTreeMap::new(), false).unwrap();
        let text = rows(&layout).join("\n");
        assert!(text.contains("FIRST") && !text.contains("HIDDEN"));
        let first_row = rows(&layout)
            .iter()
            .position(|line| line.contains("FIRST"))
            .unwrap();
        let first = layout.lines[first_row]
            .cells
            .iter()
            .find(|c| c.text == "F")
            .unwrap();
        assert_eq!(first.style.colour, Some(Colour::Cyan));
        let key = layout.ids["Guide"];
        let end = layout.scrolls[&key].maximum;
        drop(layout);
        let scrolled = build(&doc, 30, &BTreeMap::from([(key, end)]), false).unwrap();
        assert!(rows(&scrolled).join("\n").contains("LAST"));
        let last = scrolled
            .lines
            .iter()
            .flat_map(|l| &l.cells)
            .find(|c| c.text == "L")
            .unwrap();
        assert_eq!(last.style.colour, Some(Colour::BrightRed));
        assert!(last.style.bold);
        assert!(doc.lines.iter().any(|line| line.contains("HIDDEN")));
    }
    #[test]
    fn explicit_cell_budget_bounds_large_static_layouts() {
        let doc = parse(&"@Spacer {\"rows\":8}\n".repeat(250));
        assert!(build(&doc, 300, &BTreeMap::new(), false).is_err());
        let narrow = build(&doc, 40, &BTreeMap::new(), false).unwrap();
        assert_eq!(narrow.lines.len(), 2000);
        assert!(build(&doc, MAX_COLUMNS + 1, &BTreeMap::new(), false).is_err());
    }
}
