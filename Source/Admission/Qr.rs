// SPDX-License-Identifier: MIT
// QR import and export use the same bounded location parser as pasted invitations.
use super::location::Location;
use anyhow::{Result, ensure};
use image::{ImageBuffer, Luma};
use std::{
    fs::{File, OpenOptions},
    io::{Cursor, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};
const MAX_IMAGE_BYTES: usize = 4 * 1024 * 1024;
pub fn pixels(location: &Location) -> Result<ImageBuffer<Luma<u8>, Vec<u8>>> {
    let text = zeroize::Zeroizing::new(location.url(location.certificate_authority_pin.is_some())?);
    let code = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M)?;
    let side = code.width();
    let scale = 6usize;
    let size = (side + 8) * scale;
    ensure!(size <= 1024, "invitation QR exceeds display bound");
    Ok(ImageBuffer::from_fn(size as u32, size as u32, |x, y| {
        let (x, y) = (x as usize / scale, y as usize / scale);
        let black = x >= 4
            && y >= 4
            && x < side + 4
            && y < side + 4
            && code[(x - 4, y - 4)] == qrcode::Color::Dark;
        Luma([if black { 0 } else { 255 }])
    }))
}
pub fn write(location: &Location, path: &Path) -> Result<()> {
    let mut bytes = Cursor::new(Vec::new());
    pixels(location)?.write_to(&mut bytes, image::ImageFormat::Png)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    output.write_all(bytes.get_ref())?;
    output.sync_all()?;
    File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}
fn decode(bytes: &[u8]) -> Result<Location> {
    ensure!(bytes.len() <= MAX_IMAGE_BYTES, "QR image exceeds 4 MiB");
    let mut reader = image::ImageReader::new(Cursor::new(bytes)).with_guessed_format()?;
    ensure!(
        matches!(
            reader.format(),
            Some(image::ImageFormat::Png | image::ImageFormat::Jpeg)
        ),
        "QR import requires PNG or JPEG"
    );
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(2048);
    limits.max_image_height = Some(2048);
    limits.max_alloc = Some(32 * 1024 * 1024);
    reader.limits(limits);
    let image = reader.decode()?.into_luma8();
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(
        image.width() as usize,
        image.height() as usize,
        |x, y| image[(x as u32, y as u32)][0],
    );
    let grids = prepared.detect_grids();
    ensure!(
        !grids.is_empty() && grids.len() <= 8,
        "no unambiguous invitation QR found"
    );
    let mut decoded = None;
    for grid in grids {
        if let Ok((_, text)) = grid.decode() {
            let text = zeroize::Zeroizing::new(text);
            if let Ok(location) = Location::parse(&text) {
                ensure!(decoded.is_none(), "image contains more than one invitation");
                decoded = Some(location);
            }
        }
    }
    decoded.ok_or_else(|| anyhow::anyhow!("no supported invitation QR found"))
}
pub fn read(path: &Path) -> Result<Location> {
    let input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    ensure!(
        input.metadata()?.is_file() && input.metadata()?.len() <= MAX_IMAGE_BYTES as u64,
        "QR image must be a bounded regular file"
    );
    let mut bytes = Vec::new();
    input
        .take(MAX_IMAGE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    decode(&bytes)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn real_image_decoder_reads_exported_invitation_and_refuses_ambiguous_text() {
        let location = Location::parse("https://example.org/join#v=1&app=hrc").unwrap();
        let mut bytes = Cursor::new(Vec::new());
        pixels(&location)
            .unwrap()
            .write_to(&mut bytes, image::ImageFormat::Png)
            .unwrap();
        assert!(decode(bytes.get_ref()).unwrap() == location);
        assert!(decode(b"not an image").is_err());
    }
}
