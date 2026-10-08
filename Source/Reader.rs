// SPDX-License-Identifier: MIT
// Render validated text with fixed terminal controls and explicit link navigation.
use crate::markup::Document;
use anyhow::{Result, ensure};
use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute, queue,
    style::Print,
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::{
    io::{self, IsTerminal, Write},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

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
            let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
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

fn wrap(value: &str, width: usize) -> Vec<String> {
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

fn clipped(value: &str, width: usize) -> String {
    wrap(value, width).into_iter().next().unwrap_or_default()
}

pub fn show(document: &Document, metadata: &[String], tui: bool, ascii: bool) -> Result<Action> {
    let lines: Vec<_> = document
        .lines
        .iter()
        .map(|line| text(line, ascii))
        .collect();
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
        for line in lines {
            writeln!(out, "  | {line}")?;
        }
        writeln!(out, "--- End page ---")?;
        return Ok(Action::Quit);
    }
    let _terminal = Terminal::enter()?;
    let mut out = io::stdout();
    let mut offset = 0usize;
    let mut selected = 0usize;
    loop {
        if INTERRUPTED.load(Ordering::Relaxed) {
            return Ok(Action::Quit);
        }
        let (columns, rows) = terminal::size()?;
        let width = usize::from(columns.saturating_sub(1)).max(1);
        queue!(out, Clear(ClearType::All), MoveTo(0, 0))?;
        if columns < 20 || rows < 8 {
            queue!(out, Print(clipped("Resize terminal; q exits", width)))?;
        } else {
            let title = format!("HyperNet Pages | {}", text(&document.title, ascii));
            queue!(out, Print(clipped(&title, width)), MoveTo(0, 1))?;
            queue!(
                out,
                Print(clipped(
                    metadata
                        .first()
                        .map(String::as_str)
                        .unwrap_or("Retained text"),
                    width
                ))
            )?;
            let mut rendered = Vec::new();
            for line in metadata.iter().skip(1) {
                rendered.extend(wrap(&format!("Info: {line}"), width));
            }
            rendered.push("--- Page content ---".into());
            for line in &lines {
                rendered.extend(
                    wrap(line, width.saturating_sub(4).max(1))
                        .into_iter()
                        .map(|line| format!("  | {line}")),
                );
            }
            let visible = usize::from(rows - 5);
            offset = offset.min(rendered.len().saturating_sub(visible));
            for (index, line) in rendered.iter().skip(offset).take(visible).enumerate() {
                queue!(out, MoveTo(0, index as u16 + 2), Print(line))?;
            }
            let link = document
                .links
                .get(selected)
                .map(|link| {
                    format!(
                        "Link {}: {} -> {}",
                        selected + 1,
                        text(&link.label, ascii),
                        text(&link.target, true)
                    )
                })
                .unwrap_or_else(|| "No links".into());
            queue!(
                out,
                MoveTo(0, rows - 3),
                Print(clipped(&link, width)),
                MoveTo(0, rows - 2),
                Print(clipped(
                    "Arrows scroll | Tab selects | Enter follows | r refresh | b back | q quit",
                    width
                ))
            )?;
        }
        out.flush()?;
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        match event::read()? {
            Event::Key(key) if key.kind != KeyEventKind::Release => match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(Action::Quit),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Ok(Action::Quit);
                }
                KeyCode::Down | KeyCode::Char('j') => offset = offset.saturating_add(1),
                KeyCode::Up | KeyCode::Char('k') => offset = offset.saturating_sub(1),
                KeyCode::PageDown => {
                    offset = offset.saturating_add(usize::from(rows.saturating_sub(5)))
                }
                KeyCode::PageUp => {
                    offset = offset.saturating_sub(usize::from(rows.saturating_sub(5)))
                }
                KeyCode::Home | KeyCode::Char('g') => offset = 0,
                KeyCode::End | KeyCode::Char('G') => offset = usize::MAX,
                KeyCode::Tab if !document.links.is_empty() => {
                    selected = (selected + 1) % document.links.len()
                }
                KeyCode::BackTab if !document.links.is_empty() => {
                    selected = (selected + document.links.len() - 1) % document.links.len()
                }
                KeyCode::Enter if !document.links.is_empty() => return Ok(Action::Open(selected)),
                KeyCode::Char('r') => return Ok(Action::Refresh),
                KeyCode::Char('b') => return Ok(Action::Back),
                _ => {}
            },
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unicode_wrap_preserves_boundaries_and_ascii_fallback() {
        let text = "世界 cafe\u{301} 👩\u{200d}💻";
        for width in 2..12 {
            assert!(wrap(text, width).iter().all(|line| line.width() <= width));
        }
        assert_eq!(self::text("世界", true), "\\u{4e16}\\u{754c}");
        assert!(!self::text("\x1b]52;bad\x07", false).contains('\x1b'));
    }
}
