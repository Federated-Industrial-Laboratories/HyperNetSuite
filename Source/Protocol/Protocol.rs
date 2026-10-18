// SPDX-License-Identifier: MIT
// Canonical fixed-width key and digest decoding.
use anyhow::{Result, bail};

pub fn hex_bytes<const N: usize>(text: &str) -> Result<[u8; N]> {
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!(
            "expected canonical lowercase hexadecimal value of {} bytes",
            N
        );
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(text, &mut bytes)?;
    Ok(bytes)
}
