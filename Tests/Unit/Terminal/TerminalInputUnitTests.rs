// SPDX-License-Identifier: MIT
// Unit tests for TerminalInput.
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
        assert!(input.paste.as_ref().unwrap().len() <= 2048);
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
fn unicode_and_multiline_paste_remain_inert_data() {
    let mut input = Input::default();
    let events = feed(&mut input, "\x1b[200~q\n世界 text\x1b[201~".as_bytes());
    assert!(matches!(&events[..],[Event::Paste(value)] if value=="q\n世界 text"));
    let events = feed(&mut input, "世界".as_bytes());
    assert!(
        matches!(&events[..],[Event::Key(a), Event::Key(b)] if a.code==KeyCode::Char('世') && b.code==KeyCode::Char('界'))
    );
}
#[test]
fn fragmented_delimiters_produce_only_complete_events() {
    let encoded = b"\x1b[200~https://example.test/\x1b[201~";
    for split in 0..=encoded.len() {
        let mut input = Input::default();
        let mut events = feed(&mut input, &encoded[..split]);
        events.extend(feed(&mut input, &encoded[split..]));
        assert!(matches!(&events[..], [Event::Paste(value)] if value == "https://example.test/"));
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
