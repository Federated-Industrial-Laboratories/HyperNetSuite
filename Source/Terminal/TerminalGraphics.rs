// SPDX-License-Identifier: MIT
// Generate terminal graphics from validated local pixels with explicit protocol selection.
use crate::{markup::Fit, media_import::Pixels};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::ValueEnum;
use std::{
    collections::VecDeque,
    io::Write,
    time::{Duration, Instant},
};
pub const MAX_OPERATION: usize = 2 * 1024 * 1024;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum Adapter {
    #[default]
    Off,
    /// Experimental Kitty graphics; native display qualification remains pending.
    Kitty,
    ITerm2,
    Sixel,
}
#[derive(Clone, Debug, Default, clap::Args)]
pub struct Options {
    /// Explicit terminal graphics protocol; unsupported terminals retain alt text.
    #[arg(long, value_enum, default_value_t = Adapter::Off)]
    pub graphics: Adapter,
    /// Verified cell width in pixels when the terminal omits pixel geometry.
    #[arg(long, requires = "graphics_cell_height")]
    pub graphics_cell_width: Option<u16>,
    /// Verified cell height in pixels when the terminal omits pixel geometry.
    #[arg(long, requires = "graphics_cell_width")]
    pub graphics_cell_height: Option<u16>,
}
#[derive(Clone, Copy)]
pub struct Geometry {
    pub width: u16,
    pub height: u16,
}
impl Options {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.graphics_cell_width.is_some() == self.graphics_cell_height.is_some(),
            "both cell dimensions are required"
        );
        for value in [self.graphics_cell_width, self.graphics_cell_height]
            .into_iter()
            .flatten()
        {
            ensure!(
                (1..=128).contains(&value),
                "cell dimensions must be between 1 and 128 pixels"
            );
        }
        Ok(())
    }
    pub fn geometry(&self) -> Option<Geometry> {
        if self.graphics == Adapter::Off
            || std::env::var_os("TMUX").is_some()
            || std::env::var_os("STY").is_some()
            || std::env::var_os("SSH_CONNECTION").is_some()
        {
            return None;
        }
        let term = std::env::var("TERM").unwrap_or_default();
        let program = std::env::var("TERM_PROGRAM").unwrap_or_default();
        let qualified = match self.graphics {
            Adapter::Off => false,
            Adapter::Kitty => term == "xterm-kitty",
            Adapter::ITerm2 => program == "WezTerm",
            Adapter::Sixel => {
                term.starts_with("xterm")
                    && term != "xterm-kitty"
                    && std::env::var("XTERM_VERSION").is_ok_and(|v| v.starts_with("XTerm("))
            }
        };
        if !qualified {
            return None;
        }
        if let (Some(width), Some(height)) = (self.graphics_cell_width, self.graphics_cell_height) {
            return Some(Geometry { width, height });
        }
        let mut size: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) } != 0
            || size.ws_col == 0
            || size.ws_row == 0
            || size.ws_xpixel == 0
            || size.ws_ypixel == 0
            || !size.ws_xpixel.is_multiple_of(size.ws_col)
            || !size.ws_ypixel.is_multiple_of(size.ws_row)
        {
            return None;
        }
        let width = size.ws_xpixel / size.ws_col;
        let height = size.ws_ypixel / size.ws_row;
        ((1..=128).contains(&width) && (1..=128).contains(&height))
            .then_some(Geometry { width, height })
    }
}
#[derive(Default)]
pub struct Budget {
    sent: VecDeque<(Instant, usize)>,
}
impl Budget {
    pub fn allow(&mut self, bytes: usize, now: Instant) -> bool {
        while self
            .sent
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) >= Duration::from_secs(1))
        {
            self.sent.pop_front();
        }
        if bytes > MAX_OPERATION
            || self
                .sent
                .iter()
                .map(|(_, n)| n)
                .sum::<usize>()
                .saturating_add(bytes)
                > MAX_OPERATION
        {
            return false;
        }
        self.sent.push_back((now, bytes));
        true
    }
}
pub fn cleanup(adapter: Adapter, ids: &[u32]) -> Vec<u8> {
    let mut output = Vec::new();
    if adapter == Adapter::Kitty {
        for id in ids {
            output.extend_from_slice(format!("\x1b_Ga=d,d=I,i={id},q=2\x1b\\").as_bytes());
        }
    }
    output
}
pub fn encode(adapter: Adapter, pixels: &Pixels, id: u32) -> Result<Vec<u8>> {
    pixels.validate()?;
    ensure!(id > 0, "invalid local image identity");
    let output = match adapter {
        Adapter::Off => Vec::new(),
        Adapter::Kitty => {
            let encoded = STANDARD.encode(&pixels.rgb);
            let mut output = Vec::new();
            let count = encoded.len().div_ceil(4096);
            for (index, chunk) in encoded.as_bytes().chunks(4096).enumerate() {
                let more = u8::from(index + 1 < count);
                if index == 0 {
                    write!(
                        output,
                        "\x1b_Ga=T,t=d,f=24,s={},v={},i={id},p={id},q=2,C=1,m={more};",
                        pixels.width, pixels.height
                    )?
                } else {
                    write!(output, "\x1b_Gm={more},q=2;")?
                }
                output.extend_from_slice(chunk);
                output.extend_from_slice(b"\x1b\\");
            }
            output
        }
        Adapter::ITerm2 => {
            use image::ImageEncoder;
            let mut png = Vec::new();
            image::codecs::png::PngEncoder::new(&mut png).write_image(
                &pixels.rgb,
                pixels.width,
                pixels.height,
                image::ExtendedColorType::Rgb8,
            )?;
            format!("\x1b]1337;File=size={};width={}px;height={}px;preserveAspectRatio=1;inline=1:{}\x07",png.len(),pixels.width,pixels.height,STANDARD.encode(png)).into_bytes()
        }
        Adapter::Sixel => sixel(pixels)?,
    };
    ensure!(
        output.len() <= MAX_OPERATION,
        "graphics operation exceeds 2 MiB"
    );
    Ok(output)
}
fn sixel(pixels: &Pixels) -> Result<Vec<u8>> {
    // Save private modes, anchor at the text cursor and isolate the palette.
    let mut output = format!(
        "\x1b[?80;1070s\x1b[?80l\x1b[?1070h\x1bP0;1;0q\"1;1;{};{}",
        pixels.width, pixels.height
    )
    .into_bytes();
    // A fixed 64-colour palette bounds both colour state and per-band work.
    for index in 0..64 {
        write!(
            output,
            "#{index};2;{};{};{}",
            ((index >> 4) & 3) * 100 / 3,
            ((index >> 2) & 3) * 100 / 3,
            (index & 3) * 100 / 3
        )?
    }
    let indices: Vec<u8> = pixels
        .rgb
        .chunks_exact(3)
        .map(|c| ((c[0] >> 6) << 4) | ((c[1] >> 6) << 2) | (c[2] >> 6))
        .collect();
    let width = pixels.width as usize;
    let height = pixels.height as usize;
    for y in (0..height).step_by(6) {
        let mut colours = [false; 64];
        for row in y..(y + 6).min(height) {
            for x in 0..width {
                colours[indices[row * width + x] as usize] = true
            }
        }
        let mut first = true;
        for (colour, used) in colours.iter().enumerate() {
            if !used {
                continue;
            }
            if !first {
                output.push(b'$')
            }
            first = false;
            write!(output, "#{colour}")?;
            let mut run = 0usize;
            let mut old = 0u8;
            for x in 0..=width {
                let mut bits = 0u8;
                if x < width {
                    for bit in 0..6 {
                        if y + bit < height && indices[(y + bit) * width + x] as usize == colour {
                            bits |= 1 << bit
                        }
                    }
                }
                let value = bits + 63;
                if x < width && (run == 0 || old == value) {
                    old = value;
                    run += 1;
                    continue;
                }
                if run > 3 {
                    write!(output, "!{run}{}", char::from(old))?
                } else {
                    output.extend(std::iter::repeat_n(old, run))
                }
                run = 1;
                old = value;
                ensure!(
                    output.len() + 32 <= MAX_OPERATION,
                    "Sixel output exceeds byte budget"
                );
            }
        }
        if y + 6 < height {
            output.push(b'-')
        }
    }
    output.extend_from_slice(b"\x1b\\\x1b[?80;1070r");
    Ok(output)
}
pub fn bounded_viewport(width: u32, height: u32) -> Option<(u32, u32)> {
    if width == 0 || height == 0 {
        return None;
    }
    let scale = (1024.0 / f64::from(width.max(height)))
        .min((262144.0 / (f64::from(width) * f64::from(height))).sqrt())
        .min(1.0);
    Some((
        (f64::from(width) * scale).floor().max(1.0) as u32,
        (f64::from(height) * scale).floor().max(1.0) as u32,
    ))
}
// Crop before encoding. No protocol can draw outside the supplied visible rectangle.
pub fn fit(
    pixels: &Pixels,
    width: u32,
    height: u32,
    fit: Fit,
    top: u32,
    bottom: u32,
    phase: Option<(crate::markup::Preset, f32)>,
) -> Result<Pixels> {
    pixels.validate()?;
    ensure!(
        width > 0
            && height > 0
            && width <= 1024
            && height <= 1024
            && u64::from(width) * u64::from(height) <= 262144,
        "graphics viewport exceeds pixel budget"
    );
    let mut ratio = if fit == Fit::Cover {
        (width as f64 / pixels.width as f64).max(height as f64 / pixels.height as f64)
    } else {
        (width as f64 / pixels.width as f64).min(height as f64 / pixels.height as f64)
    };
    let out_w = ((pixels.width as f64 * ratio).floor() as u32).clamp(1, width);
    let out_h = ((pixels.height as f64 * ratio).floor() as u32).clamp(1, height);
    let bottom = bottom.min(out_h);
    ensure!(top < bottom, "image is outside viewport");
    if phase.is_some_and(|(preset, _)| preset == crate::markup::Preset::ImagePan) {
        ratio *= 1.08;
    }
    let mut rgb = Vec::with_capacity(out_w as usize * (bottom - top) as usize * 3);
    let extra_x = (pixels.width as f64 - out_w as f64 / ratio).max(0.);
    let extra_y = (pixels.height as f64 - out_h as f64 / ratio).max(0.);
    let pan = phase
        .filter(|(preset, _)| *preset == crate::markup::Preset::ImagePan)
        .map(|(_, p)| f64::from(p))
        .unwrap_or(0.5);
    let fade = phase
        .filter(|(preset, _)| *preset == crate::markup::Preset::ImageFade)
        .map(|(_, p)| 0.65 + 0.35 * ((p * std::f32::consts::PI).sin()))
        .unwrap_or(1.0);
    for y in top..bottom {
        for x in 0..out_w {
            let sx = ((x as f64 / ratio + extra_x * pan) as u32).min(pixels.width - 1);
            let sy = ((y as f64 / ratio + extra_y * pan) as u32).min(pixels.height - 1);
            let start = (sy as usize * pixels.width as usize + sx as usize) * 3;
            for c in &pixels.rgb[start..start + 3] {
                rgb.push((f32::from(*c) * fade + 255. * (1. - fade)).round() as u8)
            }
        }
    }
    Ok(Pixels {
        width: out_w,
        height: bottom - top,
        rgb,
    })
}
#[cfg(test)]
#[path = "../../Tests/Unit/Terminal/TerminalGraphicsUnitTests.rs"]
mod tests;
