// SPDX-License-Identifier: MIT
// Render validated text with fixed terminal controls and explicit link navigation.
use crate::{markup::Document, terminal_input::Event};
use anyhow::{Result, ensure};
use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{KeyCode, KeyEventKind, KeyModifiers},
    execute, queue,
    style::{Attribute, Print, ResetColor, SetAttribute, SetForegroundColor},
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::{
    io::{self, IsTerminal, Write},
    sync::atomic::{AtomicBool, Ordering},
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
    Address(String),
    Catalogue,
    Next,
    Previous,
    Submit(String),
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
        execute!(
            io::stdout(),
            EnterAlternateScreen,
            Print("\x1b[?2004h"),
            Hide
        )?;
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
                Print("\x1b[?2004l"),
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
        ControlKind::Field { .. } => {
            format!("Field: {label} | Enter edits; values remain local until confirmation")
        }
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
        ControlKind::Action(PageAction::Submit { form }) => {
            format!("Review form: {label} | form {form}")
        }
        ControlKind::Action(PageAction::Focus { target }) => {
            format!("Focus: {label} -> {}", text(target, ascii))
        }
        ControlKind::Action(PageAction::Scroll { target, direction }) => {
            format!("Scroll: {label} -> {} {direction:?}", text(target, ascii))
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Preview,
    Page,
    Foreign,
    Catalogue,
}

fn prepare_layout(
    document: &Document,
    view: &mut crate::page_view::View,
    columns: usize,
    rows: usize,
    ascii: bool,
    reveal: bool,
) -> Result<crate::page_layout::Layout> {
    let mut next = view.clone();
    let layout = if reveal {
        next.reveal(document, columns, rows, ascii)?
    } else {
        next.layout(document, columns, rows, ascii)?
    };
    *view = next;
    Ok(layout)
}

pub(crate) fn preflight_at(
    document: &Document,
    view: &crate::page_view::View,
    dimensions: (u16, u16),
    ascii: bool,
) -> Result<()> {
    let (columns, rows) = dimensions;
    if columns >= 20 && rows >= 8 {
        let width = usize::from(columns.saturating_sub(1)).min(crate::page_layout::MAX_COLUMNS);
        let height = usize::from(rows).min(crate::page_layout::MAX_ROWS);
        prepare_layout(
            document,
            &mut view.clone(),
            width - 4,
            height - 6,
            ascii,
            false,
        )?;
    }
    Ok(())
}

fn save_field_value(
    document: &Document,
    view: &mut crate::page_view::View,
    editor: &crate::form_ui::Editor,
    value: Option<serde_json::Value>,
    dimensions: (u16, u16),
    ascii: bool,
) -> Result<()> {
    ensure!(
        dimensions.0 >= 20 && dimensions.1 >= 8,
        "Resize before saving this field"
    );
    let mut candidate = view.clone();
    let values = candidate
        .form_values
        .entry(editor.form.clone())
        .or_default();
    if let Some(value) = value {
        values.insert(editor.field.id.clone(), value);
    } else {
        values.remove(&editor.field.id);
    }
    ensure!(
        serde_json::to_vec(values)?.len() <= crate::markup::forms::MAX_VALUES_BYTES,
        "Combined values exceed the form byte limit"
    );
    preflight_at(document, &candidate, dimensions, ascii)?;
    *view = candidate;
    Ok(())
}

pub struct Session {
    terminal: Option<Terminal>,
    ascii: bool,
    monochrome: std::cell::Cell<bool>,
    input: std::cell::RefCell<crate::terminal_input::Input>,
}

impl Session {
    pub fn confirm_form(&self, review: &crate::forms::Review) -> Result<Option<bool>> {
        ensure!(
            self.interactive(),
            "form confirmation requires an interactive terminal"
        );
        let value = serde_json::to_string_pretty(review)?;
        ensure!(
            value.len() <= 32768,
            "form review exceeds the display bound"
        );
        let mut offset = 0usize;
        let mut seen_end = false;
        let mut confirmation = String::new();
        let mut dimensions = None;
        let mut dirty = true;
        let mut rows = Vec::new();
        let mut available = 1;
        loop {
            if INTERRUPTED.load(Ordering::Relaxed) {
                return Ok(None);
            }
            let size = terminal::size()?;
            if dimensions != Some(size) {
                dimensions = Some(size);
                dirty = true;
            }
            if dirty {
                let width =
                    usize::from(size.0.saturating_sub(1)).clamp(1, crate::page_layout::MAX_COLUMNS);
                let height = usize::from(size.1).clamp(1, crate::page_layout::MAX_ROWS);
                let mut out = io::stdout();
                queue!(
                    out,
                    SetAttribute(Attribute::Reset),
                    ResetColor,
                    Clear(ClearType::All),
                    MoveTo(0, 0)
                )?;
                if size.0 < 20 || size.1 < 8 {
                    chrome(&mut out, 0, 0, "Resize to review; Esc cancels", width)?;
                } else {
                    available = height - 4;
                    rows = value
                        .lines()
                        .flat_map(|line| crate::page_layout::wrap(&text(line, self.ascii), width))
                        .collect();
                    offset = offset.min(rows.len().saturating_sub(available));
                    seen_end |= offset + available >= rows.len();
                    chrome(&mut out, 0, 0, "Trusted form review | nothing sent", width)?;
                    chrome(
                        &mut out,
                        0,
                        1,
                        "Review every value and delivery policy. Esc cancels.",
                        width,
                    )?;
                    for (index, line) in rows.iter().skip(offset).take(available).enumerate() {
                        chrome(&mut out, 0, (index + 2) as u16, line, width)?;
                    }
                    chrome(
                        &mut out,
                        0,
                        (height - 2) as u16,
                        "Arrows/PgUp/PgDn/Home/End scroll; Ctrl-C quits",
                        width,
                    )?;
                    let prompt = if seen_end {
                        format!("Type SEND then Enter to confirm: {confirmation}")
                    } else {
                        "Read to the end before confirming".into()
                    };
                    chrome(&mut out, 0, (height - 1) as u16, &prompt, width)?;
                }
                out.flush()?;
                dirty = false;
            }
            let Some(event) = self.event()? else { continue };
            let Event::Key(key) = event else {
                confirmation.clear();
                dirty = true;
                continue;
            };
            match key.code {
                KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => return Ok(None),
                KeyCode::Esc | KeyCode::Char('q') => return Ok(Some(false)),
                KeyCode::Down => offset = offset.saturating_add(1),
                KeyCode::Up => offset = offset.saturating_sub(1),
                KeyCode::PageDown => offset = offset.saturating_add(available),
                KeyCode::PageUp => offset = offset.saturating_sub(available),
                KeyCode::Home => offset = 0,
                KeyCode::End => offset = rows.len().saturating_sub(available),
                KeyCode::Backspace => {
                    confirmation.pop();
                }
                KeyCode::Enter
                    if seen_end && confirmation == "SEND" && size.0 >= 20 && size.1 >= 8 =>
                {
                    return Ok(Some(true));
                }
                KeyCode::Char(ch)
                    if seen_end
                        && (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT)
                        && confirmation.len() < 4 =>
                {
                    confirmation.push(ch);
                }
                _ => {}
            }
            dirty = true;
        }
    }

    pub fn new(tui: bool, ascii: bool) -> Result<Self> {
        let interactive = tui
            && io::stdin().is_terminal()
            && io::stdout().is_terminal()
            && !std::env::var("TERM").is_ok_and(|term| term == "dumb");
        Ok(Self {
            terminal: if interactive {
                Some(Terminal::enter()?)
            } else {
                None
            },
            ascii,
            monochrome: std::cell::Cell::new(
                std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()),
            ),
            input: std::cell::RefCell::new(crate::terminal_input::Input::default()),
        })
    }

    pub fn interactive(&self) -> bool {
        self.terminal.is_some()
    }

    pub fn preflight(&self, document: &Document, view: &crate::page_view::View) -> Result<()> {
        if self.interactive() {
            preflight_at(document, view, terminal::size()?, self.ascii)?;
        }
        Ok(())
    }

    pub fn request<T, F>(&self, operation: F) -> Result<Option<T>>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        if !self.interactive() {
            return operation().map(Some);
        }
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        // Only one request runs at a time. Quitting drops the receiver and exits the session.
        let worker = std::thread::spawn(move || {
            let _ = sender.send(operation());
        });
        let mut size = None;
        loop {
            if INTERRUPTED.load(Ordering::Relaxed) {
                return Ok(None);
            }
            match receiver.try_recv() {
                Ok(result) => {
                    let _ = worker.join();
                    return result.map(Some);
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    anyhow::bail!("network operation stopped unexpectedly");
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
            let current = terminal::size()?;
            if size != Some(current) {
                let mut out = io::stdout();
                let row = current.1.saturating_sub(1);
                queue!(out, MoveTo(0, row), Clear(ClearType::CurrentLine))?;
                chrome(
                    &mut out,
                    0,
                    row,
                    "Status: Loading | q or Esc quits",
                    usize::from(current.0.saturating_sub(1)),
                )?;
                out.flush()?;
                size = Some(current);
            }
            if let Some(event) = self.event()? {
                if let Event::Key(key) = event
                    && key.kind != KeyEventKind::Release
                    && (matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
                        || (key.code == KeyCode::Char('c')
                            && key.modifiers.contains(KeyModifiers::CONTROL)))
                {
                    return Ok(None);
                }
            } else if INTERRUPTED.load(Ordering::Relaxed) {
                return Ok(None);
            }
        }
    }

    fn event(&self) -> Result<Option<Event>> {
        self.input.borrow_mut().poll()
    }

    pub fn show(
        &self,
        document: &Document,
        metadata: &[String],
        view: &mut crate::page_view::View,
        status: &str,
        mode: Mode,
    ) -> Result<Action> {
        let ascii = self.ascii;
        view.monochrome = self.monochrome.get();
        let metadata: Vec<_> = metadata.iter().map(|line| text(line, ascii)).collect();
        let status = bounded_status(status);
        if !self.interactive() {
            let mut out = io::stdout().lock();
            for line in &metadata {
                writeln!(out, "HyperNet: {line}")?;
            }
            let label = if mode == Mode::Catalogue {
                "Trusted catalogue"
            } else {
                "Page content"
            };
            writeln!(out, "--- {label} ---")?;
            for line in &document.lines {
                writeln!(out, "  | {}", text(line, ascii))?;
            }
            writeln!(
                out,
                "--- End {} ---",
                if mode == Mode::Catalogue {
                    "catalogue"
                } else {
                    "page"
                }
            )?;
            if !status.is_empty() {
                writeln!(out, "HyperNet: Status: {status}")?;
            }
            return Ok(Action::Quit);
        }
        let mut out = io::stdout();
        let no_colour = std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty());
        let mut layout = crate::page_layout::Layout::default();
        let mut dirty = true;
        let mut reveal = false;
        let mut body_rows = 1;
        let mut detail_rows = Vec::new();
        let mut dimensions = None;
        let mut editor: Option<AddressEditor> = None;
        let mut field_editor: Option<crate::form_ui::Editor> = None;
        let mut help = false;
        let mut input_status = String::new();
        let mut layout_error = None;
        loop {
            if INTERRUPTED.load(Ordering::Relaxed) {
                return Ok(Action::Quit);
            }
            // Some detached terminals do not deliver a resize event. Only a changed size redraws.
            let current_size = terminal::size()?;
            if dimensions != Some(current_size) {
                reveal = dimensions.is_some();
                dimensions = Some(current_size);
                dirty = true;
            }
            if dirty {
                let (columns, rows) = current_size;
                let width = usize::from(columns.saturating_sub(1))
                    .clamp(1, crate::page_layout::MAX_COLUMNS);
                let height = usize::from(rows).clamp(1, crate::page_layout::MAX_ROWS);
                queue!(
                    out,
                    SetAttribute(Attribute::Reset),
                    ResetColor,
                    Clear(ClearType::All),
                    MoveTo(0, 0)
                )?;
                if columns < 20 || rows < 8 {
                    chrome(&mut out, 0, 0, "Resize terminal; Ctrl-C exits", width)?;
                } else {
                    body_rows = height - 6;
                    let content_width = width - 4;
                    layout = crate::page_layout::Layout::default();
                    layout_error = match prepare_layout(
                        document,
                        view,
                        content_width,
                        body_rows,
                        ascii,
                        reveal,
                    ) {
                        Ok(next) => {
                            layout = next;
                            None
                        }
                        Err(error) => {
                            Some(bounded_status(&format!("Layout unavailable: {error:#}")))
                        }
                    };
                    detail_rows = metadata
                        .iter()
                        .flat_map(|line| crate::page_layout::wrap(line, content_width))
                        .collect();
                    detail_rows.push(String::new());
                    detail_rows.extend(crate::page_layout::wrap(
                        &format!(
                            "Selected control: {}",
                            selected_label(document, view, &layout, ascii)
                        ),
                        content_width,
                    ));
                    detail_rows.extend(crate::page_layout::wrap(
                        &format!("Status: {status}"),
                        content_width,
                    ));
                    if let Some(error) = &layout_error {
                        detail_rows.extend(crate::page_layout::wrap(error, content_width));
                    }
                    let recovery_rows: Vec<_> = layout_error
                        .iter()
                        .flat_map(|error| {
                            [
                                error.as_str(),
                                "The document is retained. Resize narrower or use plain output.",
                                if mode == Mode::Preview {
                                    "i details | ? help | q quit"
                                } else {
                                    "o address | c catalogue | b back | i details | ? help | q quit"
                                },
                            ]
                            .into_iter()
                            .flat_map(|line| crate::page_layout::wrap(line, content_width))
                        })
                        .collect();
                    if let Some(active) = &mut field_editor {
                        detail_rows = [crate::markup::forms::field_description(&active.field),
                            "Enter saves locally; Esc cancels; Ctrl-U clears; Ctrl-N inserts a newline; Ctrl-D omits an optional field; PgUp/PgDn scroll".into(),
                            format!("Value: {}", serde_json::to_string(&active.text)?), active.error.clone()]
                            .iter().flat_map(|line| crate::page_layout::wrap(&text(line, ascii), content_width)).collect();
                        active.scroll = active
                            .scroll
                            .min(detail_rows.len().saturating_sub(body_rows));
                    } else if help {
                        detail_rows = HELP
                            .iter()
                            .flat_map(|line| crate::page_layout::wrap(line, content_width))
                            .collect();
                    }
                    view.details_offset = view
                        .details_offset
                        .min(detail_rows.len().saturating_sub(body_rows));
                    chrome(
                        &mut out,
                        0,
                        0,
                        &format!(
                            "HyperNet {} | {}",
                            if mode == Mode::Preview {
                                "Pages"
                            } else {
                                "Browser"
                            },
                            text(&document.title, ascii)
                        ),
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
                    let colour_mode = if view.monochrome {
                        "monochrome"
                    } else {
                        "terminal colours"
                    };
                    chrome(
                        &mut out,
                        0,
                        2,
                        &format!(
                            "--- {} | {colour_mode} ---",
                            if field_editor.is_some() {
                                "Edit form field"
                            } else if help {
                                "Trusted browser help"
                            } else if view.details {
                                "Trusted publication details"
                            } else if layout_error.is_some() {
                                "Layout unavailable"
                            } else if mode == Mode::Catalogue {
                                "Trusted catalogue"
                            } else {
                                "Page content"
                            }
                        ),
                        width,
                    )?;
                    for y in 0..body_rows {
                        let row = (y + 3) as u16;
                        chrome(&mut out, 0, row, "| ", 2)?;
                        if let Some(active) = &field_editor {
                            if let Some(line) = detail_rows.get(active.scroll + y) {
                                chrome(&mut out, 2, row, line, content_width)?;
                            }
                        } else if view.details || help {
                            if let Some(line) = detail_rows.get(view.details_offset + y) {
                                chrome(&mut out, 2, row, line, content_width)?;
                            }
                        } else if layout_error.is_some() {
                            if let Some(line) = recovery_rows.get(y) {
                                chrome(&mut out, 2, row, line, content_width)?;
                            }
                        } else if let Some(line) = layout.lines.get(view.offset + y) {
                            queue!(out, MoveTo(2, row))?;
                            paint(&mut out, line, view.focused, view.monochrome)?;
                        }
                        chrome(&mut out, (width - 2) as u16, row, " |", 2)?;
                    }
                    let control = if let Some(active) = &field_editor {
                        format!("Editing field: {}", text(&active.field.label, ascii))
                    } else if help {
                        "Trusted help | ? returns".into()
                    } else if view.details {
                        "Trusted metadata | i returns to the page".into()
                    } else if layout_error.is_some() {
                        "Retained document | resize or use browser controls".into()
                    } else {
                        selected_label(document, view, &layout, ascii)
                    };
                    chrome(&mut out, 0, (height - 3) as u16, &control, width)?;
                    chrome(
                        &mut out,
                        0,
                        (height - 2) as u16,
                        if mode == Mode::Preview {
                            "? help | q quit | Tab/Enter controls | arrows scroll | i info | m mono"
                        } else if mode == Mode::Catalogue {
                            "? help | q quit | arrows/Enter | n next | p previous | o address"
                        } else {
                            "? help | q quit | o address | c catalogue | Tab/Enter | arrows"
                        },
                        width,
                    )?;
                }
                let footer = if let Some(active) = &field_editor {
                    if active.error.is_empty() {
                        "Field input is local; Enter saves, Escape cancels, Ctrl-C quits".into()
                    } else {
                        text(&active.error, ascii)
                    }
                } else if let Some(editor) = &editor {
                    let visible = width.saturating_sub(11);
                    let start = editor.value.len().saturating_sub(visible);
                    chrome(
                        &mut out,
                        0,
                        (height.saturating_sub(2)) as u16,
                        if input_status.is_empty() {
                            "Enter opens | Esc cancels | Backspace edits | Ctrl-U clears"
                        } else {
                            &input_status
                        },
                        width,
                    )?;
                    format!("Address: {}_", &editor.value[start..])
                } else if !input_status.is_empty() {
                    format!("Status: {input_status}")
                } else if let Some(error) = &layout_error {
                    format!("Status: {error}")
                } else {
                    format!("Status: {status}")
                };
                chrome(&mut out, 0, (height - 1) as u16, &footer, width)?;
                out.flush()?;
                dirty = false;
                reveal = false;
            }
            let Some(event) = self.event()? else {
                continue;
            };
            if let Some(active) = &mut field_editor {
                match active.input(&event) {
                    crate::form_ui::Edit::Quit => return Ok(Action::Quit),
                    crate::form_ui::Edit::Cancel => {
                        field_editor = None;
                    }
                    crate::form_ui::Edit::Save(value) => {
                        match save_field_value(document, view, active, value, current_size, ascii) {
                            Ok(()) => {
                                field_editor = None;
                                input_status = "Field saved locally; no submission sent".into();
                            }
                            Err(error) => {
                                active.error = bounded_status(&format!(
                                    "Field not saved: {error}; shorten the value or resize"
                                ))
                            }
                        }
                    }
                    crate::form_ui::Edit::Continue => {}
                }
                dirty = true;
                continue;
            }
            if let Some(active) = &mut editor {
                match active.input(&event) {
                Edit::Submit => return Ok(Action::Address(active.value.clone())),
                Edit::Quit => return Ok(Action::Quit),
                Edit::Cancel => { editor = None; input_status.clear(); }
                Edit::Rejected => input_status = "Address accepts at most 512 visible ASCII characters; controls are rejected".into(),
                Edit::Changed => input_status.clear(),
                Edit::Ignore => {}
            }
                dirty = true;
                continue;
            }
            match event {
                Event::Key(key) if key.kind != KeyEventKind::Release => {
                    use crate::markup::ScrollDirection as Direction;
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => return Ok(Action::Quit),
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            return Ok(Action::Quit);
                        }
                        KeyCode::Char('o') if mode != Mode::Preview => {
                            editor = Some(AddressEditor::default());
                            dirty = true;
                        }
                        KeyCode::Char('c') if mode != Mode::Preview => {
                            return Ok(Action::Catalogue);
                        }
                        KeyCode::Char('n') if mode == Mode::Catalogue => return Ok(Action::Next),
                        KeyCode::Char('p') if mode == Mode::Catalogue => {
                            return Ok(Action::Previous);
                        }
                        KeyCode::Char('r') if mode != Mode::Preview => return Ok(Action::Refresh),
                        KeyCode::Char('b') if mode != Mode::Preview => return Ok(Action::Back),
                        KeyCode::Char('?') => {
                            help = !help;
                            view.details_offset = 0;
                            dirty = true;
                        }
                        KeyCode::Char('i') => {
                            view.details = !view.details;
                            dirty = true;
                        }
                        KeyCode::Char('m') => {
                            view.monochrome = no_colour || !view.monochrome;
                            self.monochrome.set(view.monochrome);
                            dirty = true;
                        }
                        KeyCode::Char('p') if layout_error.is_none() => {
                            view.focused = None;
                            dirty = true;
                        }
                        KeyCode::Down | KeyCode::Up
                            if mode == Mode::Catalogue
                                && !view.details
                                && !help
                                && layout_error.is_none() =>
                        {
                            view.tab(&layout, key.code == KeyCode::Up);
                            dirty = true;
                            reveal = true;
                        }
                        KeyCode::Tab | KeyCode::BackTab
                            if !view.details && !help && layout_error.is_none() =>
                        {
                            view.tab(
                                &layout,
                                key.code == KeyCode::BackTab
                                    || key.modifiers.contains(KeyModifiers::SHIFT),
                            );
                            dirty = true;
                            reveal = true;
                        }
                        KeyCode::Enter if !view.details && !help && layout_error.is_none() => {
                            if let Some(control) = view.selected(&layout) {
                                if let crate::page_layout::ControlKind::Field { form, field } =
                                    &control.kind
                                {
                                    if mode != Mode::Page {
                                        input_status = "Form input requires an approved page on its native network".into();
                                    } else if let Some(spec) = document
                                        .forms
                                        .iter()
                                        .find(|value| &value.id == form)
                                        .and_then(|value| {
                                            value.fields.iter().find(|value| &value.id == field)
                                        })
                                    {
                                        field_editor = Some(crate::form_ui::Editor::new(
                                            form.clone(),
                                            spec.clone(),
                                            view.form_values
                                                .get(form)
                                                .and_then(|values| values.get(field)),
                                        ));
                                    }
                                    dirty = true;
                                    continue;
                                }
                                if let crate::page_layout::ControlKind::Action(
                                    crate::markup::PageAction::Submit { form },
                                ) = &control.kind
                                {
                                    if mode == Mode::Page {
                                        return Ok(Action::Submit(form.clone()));
                                    }
                                    input_status = "Form sending requires an approved page on its native network".into();
                                    dirty = true;
                                    continue;
                                }
                            }
                            let previous = view.focused;
                            if let Some(link) = view.activate(&layout)? {
                                ensure!(
                                    link < document.links.len(),
                                    "invalid page navigation control"
                                );
                                if mode != Mode::Preview {
                                    return Ok(Action::Open(link));
                                }
                                input_status = "Unapproved preview: navigation is disabled".into();
                            }
                            dirty = true;
                            reveal = view.focused != previous;
                        }
                        code => {
                            let amount = if matches!(code, KeyCode::PageUp | KeyCode::PageDown) {
                                if view.details || help {
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
                                if view.details || help {
                                    view.details_offset = crate::page_view::shift(
                                        view.details_offset,
                                        detail_rows.len().saturating_sub(body_rows),
                                        direction,
                                        amount,
                                    );
                                } else if layout_error.is_none() {
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
}

const HELP: &[&str] = &[
    "Browser: o edits an address; c fetches the configured native catalogue.",
    "Enter opens the selected control. Tab and Shift-Tab change focus.",
    "Pages: arrows, j/k, PageUp/PageDown, Home/End scroll. p returns focus to page scrolling.",
    "Catalogue: arrows select; n fetches the next batch; p returns to the previous retained batch.",
    "b returns through at most 16 retained views. r explicitly refreshes current authority.",
    "i shows complete trusted metadata, address, selected destination and status. Arrows scroll these details.",
    "m toggles monochrome; NO_COLOR always applies. ? closes help. q or Escape quits.",
    "Address editor: visible ASCII only, at most 512 characters. Enter opens; Escape cancels.",
    "Forms: Enter edits a field. Ctrl-U clears; Ctrl-N inserts a multiline newline; Ctrl-D omits an optional value.",
    "Submit prepares a separate trusted review. Read to its end, then type SEND and Enter to confirm.",
    "Only configured native or explicitly agreed federated pages can be fetched. HTTPS is displayed only.",
    "While Loading, q, Escape or Ctrl-C quits. Other input is discarded; no actions are queued.",
    "Quitting after explicit send confirmation cannot recall mail; inspect the encrypted outbox before retrying.",
    "Retained content is approved at fetch. Idle views never refresh authority or issue requests.",
    "Draft previews are unapproved and cannot navigate or send data.",
];

pub fn bounded_status(value: &str) -> String {
    text(value, false).chars().take(1024).collect()
}

#[derive(Default)]
struct AddressEditor {
    value: String,
}
#[derive(Debug, PartialEq, Eq)]
enum Edit {
    Submit,
    Quit,
    Cancel,
    Changed,
    Rejected,
    Ignore,
}
impl AddressEditor {
    fn append(&mut self, value: &str) -> Edit {
        if self.value.len().saturating_add(value.len()) > 512
            || value.bytes().any(|byte| !(33..127).contains(&byte))
        {
            return Edit::Rejected;
        }
        self.value.push_str(value);
        Edit::Changed
    }
    fn input(&mut self, event: &Event) -> Edit {
        match event {
            Event::Paste(value) => self.append(value),
            Event::Key(key) if key.kind != KeyEventKind::Release => match key.code {
                KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => Edit::Quit,
                KeyCode::Esc => Edit::Cancel,
                KeyCode::Enter => Edit::Submit,
                KeyCode::Char('u') if key.modifiers == KeyModifiers::CONTROL => {
                    self.value.clear();
                    Edit::Changed
                }
                KeyCode::Backspace => {
                    self.value.pop();
                    Edit::Changed
                }
                KeyCode::Char(value)
                    if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT =>
                {
                    self.append(&value.to_string())
                }
                _ => Edit::Rejected,
            },
            Event::Rejected => Edit::Rejected,
            _ => Edit::Ignore,
        }
    }
}

pub fn show(document: &Document, metadata: &[String], tui: bool, ascii: bool) -> Result<Action> {
    let session = Session::new(tui, ascii)?;
    session.show(
        document,
        metadata,
        &mut crate::page_view::View::new(),
        "",
        Mode::Preview,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use unicode_width::UnicodeWidthStr;
    #[test]
    fn oversized_field_save_preserves_the_view_and_editable_value() {
        let mut source = String::from("HyperNetPage/2\n# Forms\n");
        source.push_str(&"@Panel {\"label\":\"Panel\",\"padding\":4}\n".repeat(6));
        for index in 0..4 {
            source.push_str(&format!("@Form {{\"id\":\"F{index}\",\"label\":\"Form\",\"profile\":\"HyperNetFormMail/1\",\"recipient\":\"{}\",\"owner\":\"{}\"}}\n", "01".repeat(32), "02".repeat(32)));
            for field in 0..4 {
                source.push_str(&format!("@Field {{\"id\":\"T{field}\",\"label\":\"Text\",\"kind\":\"Text\",\"maxBytes\":2048}}\n"));
            }
            source.push_str("@Submit {\"label\":\"Review\"}\n@End\n");
        }
        source.push_str(&"@End\n".repeat(6));
        let document = crate::markup::parse(&source).unwrap();
        let mut view = crate::page_view::View::new();
        let long = serde_json::json!("x".repeat(2000));
        preflight_at(&document, &view, (80, 30), false).unwrap();
        let mut refused = false;
        'fields: for form in &document.forms {
            for field in &form.fields {
                let editor =
                    crate::form_ui::Editor::new(form.id.clone(), field.clone(), Some(&long));
                let previous = view.form_values.clone();
                if save_field_value(
                    &document,
                    &mut view,
                    &editor,
                    Some(long.clone()),
                    (80, 30),
                    false,
                )
                .is_err()
                {
                    refused = true;
                    assert_eq!(view.form_values, previous);
                    assert_eq!(editor.text.len(), 2000);
                    preflight_at(&document, &view, (80, 30), false).unwrap();
                    save_field_value(
                        &document,
                        &mut view,
                        &editor,
                        Some(serde_json::json!("Short")),
                        (80, 30),
                        false,
                    )
                    .unwrap();
                    assert_eq!(view.form_values[&form.id][&field.id], "Short");
                    break 'fields;
                }
                crate::markup::forms::validate_values(form, &view.form_values[&form.id]).unwrap();
            }
        }
        assert!(
            refused,
            "the fixture must reach the layout budget before the byte limit"
        );
    }
    #[test]
    fn resize_refusal_preserves_view_until_a_bounded_layout_can_resume() {
        let source = format!(
            "HyperNetPage/2\n# Budget\n{}",
            "@Spacer {\"rows\":8}\n".repeat(250)
        );
        let document = crate::markup::parse(&source).unwrap();
        let mut view = crate::page_view::View::new();
        view.offset = 17;
        view.details_offset = 5;
        let narrow = prepare_layout(&document, &mut view, 35, 18, false, false).unwrap();
        assert_eq!(narrow.lines.len(), 2000);
        drop(narrow);
        assert!(prepare_layout(&document, &mut view, 295, 18, false, true).is_err());
        assert_eq!(view.offset, 17);
        assert_eq!(view.details_offset, 5);
        let restored = prepare_layout(&document, &mut view, 35, 18, false, true).unwrap();
        assert_eq!(restored.lines.len(), 2000);
        assert_eq!(view.offset, 17);
        assert_eq!(view.details_offset, 5);
        // Plain output does not allocate a cell grid.
        assert!(document.lines.len() >= 250);
    }
    #[test]
    fn address_editor_rejects_controls_without_interpreting_shortcuts() {
        use crossterm::event::KeyEvent;
        let mut editor = AddressEditor::default();
        for character in "qrbo".chars() {
            assert_eq!(
                editor.input(&Event::Key(KeyEvent::new(
                    KeyCode::Char(character),
                    KeyModifiers::NONE
                ))),
                Edit::Changed
            );
        }
        assert_eq!(editor.value, "qrbo");
        assert_eq!(
            editor.input(&Event::Key(KeyEvent::new(
                KeyCode::Char('c'),
                KeyModifiers::CONTROL
            ))),
            Edit::Quit
        );
        assert_eq!(
            editor.input(&Event::Paste("bad\x03q".into())),
            Edit::Rejected
        );
        assert_eq!(editor.input(&Event::Paste("bad\nq".into())), Edit::Rejected);
        assert_eq!(editor.value, "qrbo");
        assert_eq!(editor.input(&Event::Paste("x".repeat(513))), Edit::Rejected);
        assert_eq!(
            editor.input(&Event::Key(KeyEvent::new(
                KeyCode::Char('u'),
                KeyModifiers::CONTROL
            ))),
            Edit::Changed
        );
        assert!(editor.value.is_empty());
        assert_eq!(editor.input(&Event::Paste("x".repeat(512))), Edit::Changed);
        assert_eq!(editor.append("x"), Edit::Rejected);
        assert_eq!(
            editor.input(&Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))),
            Edit::Cancel
        );
        assert_eq!(
            editor.input(&Event::Key(KeyEvent::new(
                KeyCode::Enter,
                KeyModifiers::NONE
            ))),
            Edit::Submit
        );
    }
    #[test]
    fn trusted_status_is_bounded_and_escapes_terminal_controls() {
        let status = bounded_status(&format!("{}\x1b]52;secret\x07", "x".repeat(1020)));
        assert!(status.chars().count() <= 1024);
        assert!(!status.contains('\x1b'));
        assert!(
            !bounded_status("bad\n\r\x1b\u{202e}")
                .chars()
                .any(char::is_control)
        );
    }
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
