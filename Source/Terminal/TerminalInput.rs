// SPDX-License-Identifier: MIT
// Bound terminal input before decoding keys or inert address paste.
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

pub enum Event {
    Key(KeyEvent),
    Paste(String),
    Rejected,
}

#[derive(Default)]
pub struct Input {
    bytes: VecDeque<u8>,
    sequence: Vec<u8>,
    escape_at: Option<Instant>,
    paste: Option<Vec<u8>>,
    utf8: Vec<u8>,
    paste_end: usize,
    rejected: bool,
    control_string: bool,
    string_escape: bool,
}

fn key(code: KeyCode) -> Event {
    Event::Key(KeyEvent::new(code, KeyModifiers::NONE))
}
impl Input {
    pub fn poll(&mut self) -> Result<Option<Event>> {
        if self.bytes.is_empty() {
            let mut descriptor = libc::pollfd {
                fd: libc::STDIN_FILENO,
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut descriptor, 1, 100) };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    return Ok(None);
                }
                return Err(error.into());
            }
            if ready == 0 {
                if !self.utf8.is_empty() {
                    self.utf8.clear();
                    return Ok(Some(Event::Rejected));
                }
                if self
                    .escape_at
                    .is_some_and(|at| at.elapsed() >= Duration::from_millis(100))
                {
                    self.escape_at = None;
                    let escape_only = self.sequence == [27];
                    self.sequence.clear();
                    self.rejected = false;
                    return Ok(Some(if escape_only {
                        key(KeyCode::Esc)
                    } else {
                        Event::Rejected
                    }));
                }
                return Ok(None);
            }
            let mut buffer = [0; 1024];
            let count =
                unsafe { libc::read(libc::STDIN_FILENO, buffer.as_mut_ptr().cast(), buffer.len()) };
            if count == 0 {
                return Ok(Some(key(KeyCode::Esc)));
            }
            if count < 0 {
                let error = std::io::Error::last_os_error();
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) {
                    return Ok(None);
                }
                return Err(error.into());
            }
            self.bytes.extend(&buffer[..count as usize]);
        }
        while let Some(byte) = self.bytes.pop_front() {
            if let Some(event) = self.byte(byte) {
                return Ok(Some(event));
            }
        }
        Ok(None)
    }

    fn paste_byte(&mut self, byte: u8) -> Option<Event> {
        const END: &[u8] = b"\x1b[201~";
        if byte == END[self.paste_end] {
            self.paste_end += 1;
            if self.paste_end == END.len() {
                self.paste_end = 0;
                let value = self.paste.take().unwrap();
                return Some(if std::mem::take(&mut self.rejected) {
                    Event::Rejected
                } else {
                    match String::from_utf8(value) {
                        Ok(value) => Event::Paste(value),
                        Err(_) => Event::Rejected,
                    }
                });
            }
            return None;
        }
        if self.paste_end != 0 {
            self.rejected = true;
            self.paste_end = usize::from(byte == END[0]);
            if self.paste_end != 0 {
                return None;
            }
        }
        let value = self.paste.as_mut().unwrap();
        if (byte < 32 && byte != b'\n') || byte == 127 || value.len() == 2048 {
            self.rejected = true;
        } else if !self.rejected {
            value.push(byte);
        }
        None
    }

    fn byte(&mut self, byte: u8) -> Option<Event> {
        if self.paste.is_some() {
            return self.paste_byte(byte);
        }
        if self.control_string {
            if byte == 7 || (self.string_escape && byte == b'\\') {
                self.control_string = false;
                self.string_escape = false;
                return Some(Event::Rejected);
            }
            self.string_escape = byte == 27;
            return None;
        }
        if !self.sequence.is_empty() {
            if self.sequence == [27] && matches!(byte, b']' | b'P' | b'_' | b'^') {
                self.sequence.clear();
                self.escape_at = None;
                self.control_string = true;
                return None;
            }
            if self.sequence.len() < 16 {
                self.sequence.push(byte);
            } else {
                self.rejected = true;
            }
            if self.sequence == b"\x1b[200~" {
                self.sequence.clear();
                self.escape_at = None;
                self.paste = Some(Vec::new());
                self.rejected = false;
                return None;
            }
            let finished = if self.sequence.len() == 2 {
                byte != b'[' && byte != b'O'
            } else {
                (0x40..=0x7e).contains(&byte)
            };
            if !finished {
                return None;
            }
            self.escape_at = None;
            let result = if self.rejected {
                Event::Rejected
            } else {
                match self.sequence.as_slice() {
                    b"\x1b[A" | b"\x1bOA" => key(KeyCode::Up),
                    b"\x1b[B" | b"\x1bOB" => key(KeyCode::Down),
                    b"\x1b[C" | b"\x1bOC" => key(KeyCode::Right),
                    b"\x1b[D" | b"\x1bOD" => key(KeyCode::Left),
                    b"\x1b[H" | b"\x1bOH" | b"\x1b[1~" | b"\x1b[7~" => key(KeyCode::Home),
                    b"\x1b[F" | b"\x1bOF" | b"\x1b[4~" | b"\x1b[8~" => key(KeyCode::End),
                    b"\x1b[5~" => key(KeyCode::PageUp),
                    b"\x1b[6~" => key(KeyCode::PageDown),
                    b"\x1b[Z" => key(KeyCode::BackTab),
                    _ => Event::Rejected,
                }
            };
            self.sequence.clear();
            self.rejected = false;
            return Some(result);
        }
        if !self.utf8.is_empty() || byte >= 128 {
            if self.utf8.len() == 4 {
                self.utf8.clear();
                return Some(Event::Rejected);
            }
            self.utf8.push(byte);
            return match std::str::from_utf8(&self.utf8) {
                Ok(value) => {
                    let ch = value.chars().next().unwrap();
                    self.utf8.clear();
                    Some(if ch.is_control() {
                        Event::Rejected
                    } else {
                        key(KeyCode::Char(ch))
                    })
                }
                Err(error) if error.error_len().is_none() => None,
                Err(_) => {
                    self.utf8.clear();
                    Some(Event::Rejected)
                }
            };
        }
        Some(match byte {
            27 => {
                self.sequence.push(byte);
                self.escape_at = Some(Instant::now());
                return None;
            }
            b'\r' | b'\n' => key(KeyCode::Enter),
            b'\t' => key(KeyCode::Tab),
            8 | 127 => key(KeyCode::Backspace),
            14 => Event::Key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::CONTROL)),
            4 => Event::Key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL)),
            21 => Event::Key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL)),
            3 => Event::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            32..=126 => key(KeyCode::Char(char::from(byte))),
            _ => Event::Rejected,
        })
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Terminal/TerminalInputUnitTests.rs"]
mod tests;
