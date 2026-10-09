// SPDX-License-Identifier: MIT
// Render validated text with fixed terminal controls and explicit link navigation.
use crate::markup::Document;
use anyhow::{Result, ensure};
use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute, queue,
    style::{Attribute, Print, ResetColor, SetAttribute, SetForegroundColor},
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::{
    io::{self, IsTerminal, Write},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
extern "C" fn interrupt(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::Relaxed);
}

pub enum Action {
    Quit,
    Open(usize),
    Refresh,
    Back,
}

struct Terminal {
    signals: Vec<(libc::c_int, libc::sigaction)>,
    raw: bool,
    alternate: bool,
}

impl Terminal {
    fn enter() -> Result<Self> {
        let mut guard = Self {
            signals: Vec::new(),
            raw: false,
            alternate: false,
        };
        INTERRUPTED.store(false, Ordering::Relaxed);
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = interrupt as *const () as usize;
            unsafe {
                libc::sigemptyset(&mut action.sa_mask);
            }
            ensure!(
                unsafe { libc::sigaction(signal, &action, &mut old) } == 0,
                "cannot install terminal signal handler"
            );
            guard.signals.push((signal, old));
        }
        terminal::enable_raw_mode()?;
        guard.raw = true;
        guard.alternate = true;
        execute!(io::stdout(), EnterAlternateScreen, Hide)?;
        Ok(guard)
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        if self.alternate {
            let _ = execute!(
                io::stdout(),
                SetAttribute(Attribute::Reset),
                ResetColor,
                Show,
                LeaveAlternateScreen
            );
        }
        if self.raw {
            let _ = terminal::disable_raw_mode();
        }
        for (signal, action) in &self.signals {
            unsafe {
                libc::sigaction(*signal, action, std::ptr::null_mut());
            }
        }
    }
}

pub fn text(value: &str, ascii: bool) -> String {
    crate::page_layout::safe_text(value, ascii)
}

fn colour(value: crate::markup::Colour) -> crossterm::style::Color {
    use crate::markup::Colour as C;
    use crossterm::style::Color as T;
    match value {
        C::Default => T::Reset,
        C::Black => T::Black,
        C::Red => T::DarkRed,
        C::Green => T::DarkGreen,
        C::Yellow => T::DarkYellow,
        C::Blue => T::DarkBlue,
        C::Magenta => T::DarkMagenta,
        C::Cyan => T::DarkCyan,
        C::White => T::Grey,
        C::BrightBlack => T::DarkGrey,
        C::BrightRed => T::Red,
        C::BrightGreen => T::Green,
        C::BrightYellow => T::Yellow,
        C::BrightBlue => T::Blue,
        C::BrightMagenta => T::Magenta,
        C::BrightCyan => T::Cyan,
        C::BrightWhite => T::White,
    }
}
fn chrome(out: &mut impl Write, x: u16, y: u16, value: &str, width: usize) -> Result<()> {
    queue!(
        out,
        SetAttribute(Attribute::Reset),
        ResetColor,
        MoveTo(x, y),
        Print(crate::page_layout::clipped(value, width))
    )?;
    Ok(())
}
fn paint(
    out: &mut impl Write,
    line: &crate::page_layout::Line,
    focused: Option<usize>,
    monochrome: bool,
) -> Result<()> {
    let mut previous = None;
    for cell in &line.cells {
        if cell.continuation {
            continue;
        }
        let state = (
            if monochrome {
                crate::markup::Colour::Default
            } else {
                cell.style.colour.unwrap_or_default()
            },
            cell.style.bold,
            cell.owner.is_some() && cell.owner == focused,
        );
        if previous != Some(state) {
            queue!(out, SetAttribute(Attribute::Reset), ResetColor)?;
            if !monochrome {
                queue!(out, SetForegroundColor(colour(state.0)))?;
            }
            if state.1 {
                queue!(out, SetAttribute(Attribute::Bold))?;
            }
            if state.2 {
                queue!(out, SetAttribute(Attribute::Reverse))?;
            }
            previous = Some(state);
        }
        queue!(out, Print(&cell.text))?;
    }
    queue!(out, SetAttribute(Attribute::Reset), ResetColor)?;
    Ok(())
}
fn selected_label(
    document: &Document,
    view: &crate::page_view::View,
    layout: &crate::page_layout::Layout,
    ascii: bool,
) -> String {
    use crate::{markup::PageAction, page_layout::ControlKind};
    let Some(control) = view.selected(layout) else {
        return "Page scroll | Tab selects a control".into();
    };
    let label = text(&control.label, ascii);
    match &control.kind {
        ControlKind::ScrollBox => {
            let info = &layout.scrolls[&control.key];
            format!(
                "ScrollBox: {label} | row {} of {}",
                info.offset + 1,
                info.maximum + 1
            )
        }
        ControlKind::Action(PageAction::Navigate { link }) => document
            .links
            .get(*link)
            .map(|link| format!("Navigate: {label} -> {}", text(&link.target, true)))
            .unwrap_or_else(|| "Invalid navigation control".into()),
        ControlKind::Action(PageAction::Focus { target }) => {
            format!("Focus: {label} -> {}", text(target, ascii))
        }
        ControlKind::Action(PageAction::Scroll { target, direction }) => {
            format!("Scroll: {label} -> {} {direction:?}", text(target, ascii))
        }
    }
}
pub fn show(document: &Document, metadata: &[String], tui: bool, ascii: bool) -> Result<Action> {
    let metadata: Vec<_> = metadata.iter().map(|line| text(line, ascii)).collect();
    if !tui
        || !io::stdin().is_terminal()
        || !io::stdout().is_terminal()
        || std::env::var("TERM").is_ok_and(|term| term == "dumb")
    {
        let mut out = io::stdout().lock();
        for line in &metadata {
            writeln!(out, "HyperNet: {line}")?;
        }
        writeln!(out, "--- Page content ---")?;
        for line in &document.lines {
            writeln!(out, "  | {}", text(line, ascii))?;
        }
        writeln!(out, "--- End page ---")?;
        return Ok(Action::Quit);
    }
    let _terminal = Terminal::enter()?;
    let mut out = io::stdout();
    let no_colour = std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty());
    let mut view = crate::page_view::View::new();
    let mut layout = crate::page_layout::Layout::default();
    let mut dirty = true;
    let mut reveal = true;
    let mut body_rows = 1;
    let mut detail_rows = Vec::new();
    let mut dimensions = None;
    loop {
        if INTERRUPTED.load(Ordering::Relaxed) {
            return Ok(Action::Quit);
        }
        // Some detached terminals do not deliver a resize event. Only a changed size redraws.
        let current_size = terminal::size()?;
        if dimensions != Some(current_size) {
            dimensions = Some(current_size);
            dirty = true;
            reveal = true;
        }
        if dirty {
            let (columns, rows) = current_size;
            let width =
                usize::from(columns.saturating_sub(1)).clamp(1, crate::page_layout::MAX_COLUMNS);
            let height = usize::from(rows).clamp(1, crate::page_layout::MAX_ROWS);
            queue!(
                out,
                SetAttribute(Attribute::Reset),
                ResetColor,
                Clear(ClearType::All),
                MoveTo(0, 0)
            )?;
            if columns < 20 || rows < 8 {
                chrome(&mut out, 0, 0, "Resize terminal; q exits", width)?;
            } else {
                body_rows = height - 6;
                let content_width = width - 4;
                layout.lines.clear();
                layout = if reveal {
                    view.reveal(document, content_width, body_rows, ascii)?
                } else {
                    view.layout(document, content_width, body_rows, ascii)?
                };
                detail_rows = metadata
                    .iter()
                    .flat_map(|line| crate::page_layout::wrap(line, content_width))
                    .collect();
                detail_rows.push(String::new());
                detail_rows.extend(crate::page_layout::wrap(
                    &format!(
                        "Selected control: {}",
                        selected_label(document, &view, &layout, ascii)
                    ),
                    content_width,
                ));
                view.details_offset = view
                    .details_offset
                    .min(detail_rows.len().saturating_sub(body_rows));
                chrome(
                    &mut out,
                    0,
                    0,
                    &format!("HyperNet Pages | {}", text(&document.title, ascii)),
                    width,
                )?;
                chrome(
                    &mut out,
                    0,
                    1,
                    metadata
                        .first()
                        .map(String::as_str)
                        .unwrap_or("Retained text; authority not rechecked"),
                    width,
                )?;
                let mode = if view.monochrome {
                    "monochrome"
                } else {
                    "terminal colours"
                };
                chrome(
                    &mut out,
                    0,
                    2,
                    &format!(
                        "--- {} | {mode} ---",
                        if view.details {
                            "Trusted publication details"
                        } else {
                            "Page content"
                        }
                    ),
                    width,
                )?;
                for y in 0..body_rows {
                    let row = (y + 3) as u16;
                    chrome(&mut out, 0, row, "| ", 2)?;
                    if view.details {
                        if let Some(line) = detail_rows.get(view.details_offset + y) {
                            chrome(&mut out, 2, row, line, content_width)?;
                        }
                    } else if let Some(line) = layout.lines.get(view.offset + y) {
                        queue!(out, MoveTo(2, row))?;
                        paint(&mut out, line, view.focused, view.monochrome)?;
                    }
                    chrome(&mut out, (width - 2) as u16, row, " |", 2)?;
                }
                let control = if view.details {
                    "Trusted metadata | i returns to the page".into()
                } else {
                    selected_label(document, &view, &layout, ascii)
                };
                chrome(&mut out, 0, (height - 3) as u16, &control, width)?;
                chrome(
                    &mut out,
                    0,
                    (height - 2) as u16,
                    "Tab focus | Enter act | arrows scroll | p page | i info | m mono | r refresh | b back | q quit",
                    width,
                )?;
            }
            out.flush()?;
            dirty = false;
            reveal = false;
        }
        let ready = match event::poll(Duration::from_millis(100)) {
            Ok(value) => value,
            Err(_) if INTERRUPTED.load(Ordering::Relaxed) => return Ok(Action::Quit),
            Err(error) => return Err(error.into()),
        };
        if !ready {
            continue;
        }
        match event::read()? {
            Event::Resize(_, _) => {
                dirty = true;
                reveal = true;
            }
            Event::Key(key) if key.kind != KeyEventKind::Release => {
                use crate::markup::ScrollDirection as Direction;
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(Action::Quit),
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(Action::Quit);
                    }
                    KeyCode::Char('r') => return Ok(Action::Refresh),
                    KeyCode::Char('b') => return Ok(Action::Back),
                    KeyCode::Char('i') => {
                        view.details = !view.details;
                        dirty = true;
                    }
                    KeyCode::Char('m') => {
                        view.monochrome = no_colour || !view.monochrome;
                        dirty = true;
                    }
                    KeyCode::Char('p') => {
                        view.focused = None;
                        dirty = true;
                    }
                    KeyCode::Tab | KeyCode::BackTab if !view.details => {
                        view.tab(
                            &layout,
                            key.code == KeyCode::BackTab
                                || key.modifiers.contains(KeyModifiers::SHIFT),
                        );
                        dirty = true;
                        reveal = true;
                    }
                    KeyCode::Enter if !view.details => {
                        let previous = view.focused;
                        if let Some(link) = view.activate(&layout)? {
                            ensure!(
                                link < document.links.len(),
                                "invalid page navigation control"
                            );
                            return Ok(Action::Open(link));
                        }
                        dirty = true;
                        reveal = view.focused != previous;
                    }
                    code => {
                        let amount = if matches!(code, KeyCode::PageUp | KeyCode::PageDown) {
                            if view.details {
                                body_rows
                            } else {
                                view.page_amount(&layout, body_rows)
                            }
                        } else {
                            1
                        };
                        let direction = match code {
                            KeyCode::Down | KeyCode::Char('j') | KeyCode::PageDown => {
                                Some(Direction::Down)
                            }
                            KeyCode::Up | KeyCode::Char('k') | KeyCode::PageUp => {
                                Some(Direction::Up)
                            }
                            KeyCode::Home | KeyCode::Char('g') => Some(Direction::Start),
                            KeyCode::End | KeyCode::Char('G') => Some(Direction::End),
                            _ => None,
                        };
                        if let Some(direction) = direction {
                            if view.details {
                                view.details_offset = crate::page_view::shift(
                                    view.details_offset,
                                    detail_rows.len().saturating_sub(body_rows),
                                    direction,
                                    amount,
                                );
                            } else {
                                view.scroll(&layout, direction, amount, body_rows);
                            }
                            dirty = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unicode_width::UnicodeWidthStr;
    #[test]
    fn unicode_wrap_preserves_boundaries_and_ascii_fallback() {
        let value = "世界 cafe\u{301} 👩\u{200d}💻";
        for width in 1..12 {
            assert!(
                crate::page_layout::wrap(value, width)
                    .iter()
                    .all(|line| line.width() <= width)
            );
        }
        assert_eq!(text("世界", true), "\\u{4e16}\\u{754c}");
        assert!(!text("\x1b]52;bad\x07", false).contains('\x1b'));
    }
}
