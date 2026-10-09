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
    paste: Option<String>,
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
                    Event::Paste(value)
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
        if !(33..127).contains(&byte) || value.len() == 512 {
            self.rejected = true;
        } else if !self.rejected {
            value.push(char::from(byte));
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
                self.paste = Some(String::new());
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
        Some(match byte {
            27 => {
                self.sequence.push(byte);
                self.escape_at = Some(Instant::now());
                return None;
            }
            b'\r' | b'\n' => key(KeyCode::Enter),
            b'\t' => key(KeyCode::Tab),
            8 | 127 => key(KeyCode::Backspace),
            21 => Event::Key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL)),
            3 => Event::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            32..=126 => key(KeyCode::Char(char::from(byte))),
            _ => Event::Rejected,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn feed(input: &mut Input, bytes: &[u8]) -> Vec<Event> {
        bytes.iter().filter_map(|byte| input.byte(*byte)).collect()
    }
    #[test]
    fn paste_is_atomic_bounded_and_never_shortcuts() {
        let mut input = Input::default();
        let events = feed(&mut input, b"\x1b[200~https://example.test/qr\x1b[201~");
        assert!(matches!(&events[..], [Event::Paste(value)] if value == "https://example.test/qr"));
        for payload in [
            vec![b'x'; 100_000],
            b"x\nq\x03r".to_vec(),
            b"x\x1b[5~q".to_vec(),
        ] {
            assert!(feed(&mut input, b"\x1b[200~").is_empty());
            assert!(feed(&mut input, &payload).is_empty());
            assert!(input.paste.as_ref().unwrap().len() <= 512);
            assert!(matches!(
                &feed(&mut input, b"\x1b[201~")[..],
                [Event::Rejected]
            ));
        }
        assert!(
            matches!(&feed(&mut input, b"q")[..], [Event::Key(key)] if key.code == KeyCode::Char('q'))
        );
    }
    #[test]
    fn fragmented_delimiters_produce_only_complete_events() {
        let encoded = b"\x1b[200~https://example.test/\x1b[201~";
        for split in 0..=encoded.len() {
            let mut input = Input::default();
            let mut events = feed(&mut input, &encoded[..split]);
            events.extend(feed(&mut input, &encoded[split..]));
            assert!(
                matches!(&events[..], [Event::Paste(value)] if value == "https://example.test/")
            );
        }
        for (encoded, code) in [
            (b"\x1bOA".as_slice(), KeyCode::Up),
            (b"\x1b[Z".as_slice(), KeyCode::BackTab),
            (b"\x1b[6~".as_slice(), KeyCode::PageDown),
        ] {
            let mut input = Input::default();
            let mut events = Vec::new();
            for byte in encoded {
                events.extend(feed(&mut input, &[*byte]));
            }
            assert!(matches!(&events[..], [Event::Key(key)] if key.code == code));
        }
    }
    #[test]
    fn unknown_escape_sequences_are_bounded_and_drained() {
        let mut input = Input::default();
        feed(&mut input, b"\x1b[");
        assert!(feed(&mut input, &vec![b'1'; 100_000]).is_empty());
        assert!(input.sequence.len() <= 16);
        assert!(matches!(&feed(&mut input, b"q")[..], [Event::Rejected]));
        assert!(
            matches!(&feed(&mut input, b"\x1b[A")[..], [Event::Key(key)] if key.code == KeyCode::Up)
        );
        assert!(feed(&mut input, b"\x1b]52;qr\n").is_empty());
        assert!(matches!(&feed(&mut input, b"\x07")[..], [Event::Rejected]));
    }
}
