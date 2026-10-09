// SPDX-License-Identifier: MIT
// Viewer-owned focus and scroll state; page actions cannot select external operations.
use crate::{
    markup::{Document, PageAction, ScrollDirection},
    page_layout::{self, Control, ControlKind, Layout},
};
use anyhow::{Context, Result};
use std::collections::BTreeMap;

#[derive(Clone)]
pub struct View {
    pub offset: usize,
    pub focused: Option<usize>,
    pub scrolls: BTreeMap<usize, usize>,
    pub monochrome: bool,
    pub details: bool,
    pub details_offset: usize,
}
impl View {
    pub fn new() -> Self {
        Self {
            offset: 0,
            focused: None,
            scrolls: BTreeMap::new(),
            monochrome: std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()),
            details: false,
            details_offset: 0,
        }
    }
    pub fn selected<'a>(&self, layout: &'a Layout) -> Option<&'a Control> {
        self.focused
            .and_then(|key| layout.controls.iter().find(|control| control.key == key))
    }
    pub fn layout(
        &mut self,
        document: &Document,
        columns: usize,
        rows: usize,
        ascii: bool,
    ) -> Result<Layout> {
        let layout = page_layout::build(document, columns, &self.scrolls, ascii)?;
        for (key, info) in &layout.scrolls {
            self.scrolls.insert(*key, info.offset);
        }
        self.offset = self.offset.min(layout.lines.len().saturating_sub(rows));
        if self.focused.is_some() && self.selected(&layout).is_none() {
            self.focused = None;
        }
        Ok(layout)
    }
    pub fn reveal(
        &mut self,
        document: &Document,
        columns: usize,
        rows: usize,
        ascii: bool,
    ) -> Result<Layout> {
        // Each pass exposes one enclosing viewport; grammar depth bounds the number of passes.
        for _ in 0..9 {
            let layout = self.layout(document, columns, rows, ascii)?;
            let Some(control) = self.selected(&layout) else {
                return Ok(layout);
            };
            let mut changed = false;
            for ancestor in &control.ancestors {
                let info = layout
                    .scrolls
                    .get(&ancestor.key)
                    .context("missing enclosing viewport")?;
                let position = ancestor.content_y.max(0) as usize;
                let offset = if position < info.offset {
                    position
                } else if position >= info.offset.saturating_add(ancestor.rows) {
                    position.saturating_sub(ancestor.rows - 1)
                } else {
                    info.offset
                };
                let offset = offset.min(info.maximum);
                if offset != info.offset {
                    self.scrolls.insert(ancestor.key, offset);
                    changed = true;
                    break;
                }
            }
            if changed {
                continue;
            }
            let position = control.y.max(0) as usize;
            if position < self.offset {
                self.offset = position;
            } else if position >= self.offset.saturating_add(rows) {
                self.offset = position.saturating_sub(rows - 1);
            }
            self.offset = self.offset.min(layout.lines.len().saturating_sub(rows));
            return Ok(layout);
        }
        self.layout(document, columns, rows, ascii)
    }
    pub fn tab(&mut self, layout: &Layout, backwards: bool) {
        if layout.controls.is_empty() {
            self.focused = None;
            return;
        }
        let old = self
            .focused
            .and_then(|key| layout.controls.iter().position(|c| c.key == key));
        let length = layout.controls.len();
        let index = match (old, backwards) {
            (None, false) => 0,
            (None, true) => length - 1,
            (Some(index), false) => (index + 1) % length,
            (Some(index), true) => (index + length - 1) % length,
        };
        self.focused = Some(layout.controls[index].key);
    }
    pub fn scroll(
        &mut self,
        layout: &Layout,
        direction: ScrollDirection,
        amount: usize,
        page_rows: usize,
    ) {
        let target = self
            .selected(layout)
            .and_then(|control| match &control.kind {
                ControlKind::ScrollBox => Some(control.key),
                ControlKind::Action(_) => control.ancestors.first().map(|a| a.key),
            });
        if let Some(key) = target {
            self.scroll_box(layout, key, direction, amount);
        } else {
            self.offset = shift(
                self.offset,
                layout.lines.len().saturating_sub(page_rows),
                direction,
                amount,
            );
        }
    }
    fn scroll_box(
        &mut self,
        layout: &Layout,
        key: usize,
        direction: ScrollDirection,
        amount: usize,
    ) {
        if let Some(info) = layout.scrolls.get(&key) {
            self.scrolls
                .insert(key, shift(info.offset, info.maximum, direction, amount));
        }
    }
    pub fn page_amount(&self, layout: &Layout, fallback: usize) -> usize {
        self.selected(layout)
            .and_then(|control| match &control.kind {
                ControlKind::ScrollBox => layout.scrolls.get(&control.key),
                ControlKind::Action(_) => control
                    .ancestors
                    .first()
                    .and_then(|a| layout.scrolls.get(&a.key)),
            })
            .map(|info| info.rows)
            .unwrap_or(fallback)
    }
    pub fn activate(&mut self, layout: &Layout) -> Result<Option<usize>> {
        let Some(control) = self.selected(layout) else {
            return Ok(None);
        };
        let ControlKind::Action(action) = &control.kind else {
            return Ok(None);
        };
        match action {
            PageAction::Navigate { link } => Ok(Some(*link)),
            PageAction::Focus { target } => {
                self.focused = Some(*layout.ids.get(target).context("missing focus target")?);
                Ok(None)
            }
            PageAction::Scroll { target, direction } => {
                let key = *layout.ids.get(target).context("missing scroll target")?;
                self.scroll_box(layout, key, *direction, 1);
                Ok(None)
            }
        }
    }
}
pub fn shift(value: usize, maximum: usize, direction: ScrollDirection, amount: usize) -> usize {
    match direction {
        ScrollDirection::Up => value.saturating_sub(amount),
        ScrollDirection::Down => value.saturating_add(amount).min(maximum),
        ScrollDirection::Start => 0,
        ScrollDirection::End => maximum,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn focus_reveals_nested_viewports_and_local_actions_stay_in_document() {
        let document = crate::markup::parse("HyperNetPage/2\n# Focus\n@ScrollBox {\"id\":\"Outer\",\"label\":\"Outer\",\"rows\":3}\n: Before\n@ScrollBox {\"id\":\"Inner\",\"label\":\"Inner\",\"rows\":2}\n: One\n: Two\n: Three\n@Button {\"label\":\"Visible target\",\"action\":{\"kind\":\"Focus\",\"target\":\"Inner\"}}\n@End\n@End\n@Button {\"label\":\"Scroll to end\",\"action\":{\"kind\":\"Scroll\",\"target\":\"Inner\",\"direction\":\"End\"}}\n").unwrap();
        let mut view = View::new();
        let initial = view.layout(&document, 30, 12, false).unwrap();
        assert!(view.focused.is_none());
        let target = initial
            .controls
            .iter()
            .find(|c| c.label == "Visible target")
            .unwrap()
            .key;
        view.focused = Some(target);
        drop(initial);
        let revealed = view.reveal(&document, 30, 12, false).unwrap();
        let control = view.selected(&revealed).unwrap();
        assert!(control.y >= view.offset as i64 && control.y < (view.offset + 12) as i64);
        for ancestor in &control.ancestors {
            let info = &revealed.scrolls[&ancestor.key];
            assert!(ancestor.content_y >= info.offset as i64);
            assert!(ancestor.content_y < (info.offset + info.rows) as i64);
        }
        let inner = revealed.ids["Inner"];
        assert!(view.activate(&revealed).unwrap().is_none());
        assert_eq!(view.focused, Some(inner));
        view.tab(&revealed, true);
        assert_ne!(view.focused, Some(inner));
        let end = revealed
            .controls
            .iter()
            .find(|c| c.label == "Scroll to end")
            .unwrap()
            .key;
        view.focused = Some(end);
        assert!(view.activate(&revealed).unwrap().is_none());
        assert_eq!(view.scrolls[&inner], revealed.scrolls[&inner].maximum);
        drop(revealed);
        let narrow = view.reveal(&document, 14, 4, false).unwrap();
        assert_eq!(view.focused, Some(end));
        assert!(view.offset <= narrow.lines.len().saturating_sub(4));
    }
}
