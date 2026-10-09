// SPDX-License-Identifier: MIT
// Bound an isolated import and independently validate its canonical output.
use crate::markup::media::{self, Asset};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub const MAX_INPUT: usize = 16 * 1024 * 1024;
const MAX_OUTPUT: usize = 1024 * 1024;

#[derive(clap::Args)]
pub struct ImportArgs {
    /// PNG, JPEG or static SVG source. The original file is never published.
    #[arg(long)]
    pub input: PathBuf,
    /// New canonical raster or vector output file.
    #[arg(long)]
    pub output: PathBuf,
    /// New exact Asset declaration file.
    #[arg(long)]
    pub manifest: PathBuf,
    #[arg(long)]
    pub id: String,
    /// Consented media host identity; repeat for each intended host.
    #[arg(long, required = true)]
    pub host: Vec<String>,
    #[arg(long, default_value_t = 1)]
    pub copies: u16,
    /// Maximum output axis. The pixel budget can reduce both axes further.
    #[arg(long, default_value_t = 1024)]
    pub max_axis: u32,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportResult {
    pub asset: Asset,
    pub warnings: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WorkerHeader {
    pub profile: String,
    pub width: u32,
    pub height: u32,
    pub bytes: usize,
    pub warnings: Vec<String>,
}

pub fn import(args: &ImportArgs) -> Result<ImportResult> {
    ensure!(
        (1..=1024).contains(&args.max_axis),
        "max-axis must be between 1 and 1024"
    );
    ensure!(
        args.output != args.manifest,
        "output and manifest paths must differ"
    );
    let output = crate::transfer_files::Destination::open(&args.output)?;
    let manifest = crate::transfer_files::Destination::open(&args.manifest)?;
    let input = crate::transfer_files::read(&args.input, MAX_INPUT, false)?;
    ensure!(
        !input.is_empty() && input.len() <= MAX_INPUT,
        "import input exceeds 16 MiB or is empty"
    );
    let (header, bytes) = convert(&input, args.max_axis)?;
    let asset = Asset {
        id: args.id.clone(),
        profile: header.profile,
        width: header.width,
        height: header.height,
        bytes: bytes.len() as u64,
        digest: hex::encode(Sha256::digest(&bytes)),
        hosts: args.host.clone(),
        copies: args.copies,
    };
    media::validate_asset_bytes(&asset, &bytes).map_err(anyhow::Error::msg)?;
    let result = ImportResult {
        asset,
        warnings: header.warnings,
    };
    // Publish the complete asset first. A later manifest race must never delete another file.
    output.publish(&bytes)?;
    let mut metadata = serde_json::to_vec_pretty(&result.asset)?;
    metadata.push(b'\n');
    manifest.publish(&metadata)?;
    Ok(result)
}
pub(crate) fn convert(input: &[u8], max_axis: u32) -> Result<(WorkerHeader, Vec<u8>)> {
    ensure!(
        !input.is_empty() && input.len() <= MAX_INPUT,
        "invalid import size"
    );
    ensure!(
        (1..=1024).contains(&max_axis),
        "invalid import output bound"
    );
    worker(input, max_axis)
}
fn worker(input: &[u8], mode: u32) -> Result<(WorkerHeader, Vec<u8>)> {
    let mut child = Command::new(std::env::current_exe()?)
        .arg("--internal-media-worker")
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdin = child.stdin.take().context("missing worker input")?;
    let stdout = child.stdout.take().context("missing worker output")?;
    let input = input.to_vec();
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        stdin.write_all(&mode.to_le_bytes())?;
        stdin.write_all(&input)
    });
    let reader = std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let mut output = Vec::new();
        stdout
            .take((MAX_OUTPUT + 1) as u64)
            .read_to_end(&mut output)?;
        Ok(output)
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let write_result = writer
        .join()
        .map_err(|_| anyhow::anyhow!("import writer stopped"))?;
    let output = reader
        .join()
        .map_err(|_| anyhow::anyhow!("import reader stopped"))??;
    let Some(status) = status else {
        bail!("import exceeded the five-second wall deadline");
    };
    ensure!(
        status.success(),
        "import rejected or worker resource/confinement limit reached"
    );
    write_result?;
    ensure!(
        output.len() >= 4 && output.len() <= MAX_OUTPUT,
        "invalid worker output size"
    );
    let length = u32::from_le_bytes(output[..4].try_into()?) as usize;
    ensure!(
        length <= 8192 && 4 + length <= output.len(),
        "invalid worker header size"
    );
    let value: serde_json::Value = serde_json::from_slice(&output[4..4 + length])?;
    if let Some(error) = value.get("error").and_then(serde_json::Value::as_str) {
        ensure!(
            error.len() <= 1024 && error.chars().all(|c| !c.is_control()),
            "invalid worker error"
        );
        bail!("import refused: {error}");
    }
    let header: WorkerHeader = serde_json::from_value(value)?;
    ensure!(
        header.warnings.len() <= 32
            && header
                .warnings
                .iter()
                .all(|w| w.len() <= 128 && w.chars().all(|c| !c.is_control())),
        "invalid import report"
    );
    let bytes = output[4 + length..].to_vec();
    ensure!(bytes.len() == header.bytes, "worker output length mismatch");
    let asset = Asset {
        id: "Imported".into(),
        profile: header.profile.clone(),
        width: header.width,
        height: header.height,
        bytes: bytes.len() as u64,
        digest: hex::encode(Sha256::digest(&bytes)),
        hosts: vec!["0".repeat(64)],
        copies: 1,
    };
    media::validate_asset_bytes(&asset, &bytes).map_err(anyhow::Error::msg)?;
    Ok((header, bytes))
}

#[derive(Clone)]
pub struct Pixels {
    pub width: u32,
    pub height: u32,
    pub rgb: Vec<u8>,
}
impl Pixels {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=1024).contains(&self.width)
                && (1..=1024).contains(&self.height)
                && u64::from(self.width) * u64::from(self.height) <= 262144
                && self.rgb.len() == self.width as usize * self.height as usize * 3,
            "invalid pixel buffer"
        );
        Ok(())
    }
}
pub fn render_asset(asset: &Asset, bytes: &[u8]) -> Result<Pixels> {
    media::validate_asset_bytes(asset, bytes).map_err(anyhow::Error::msg)?;
    let rgb = if asset.profile == media::VECTOR_PROFILE {
        let (header, rendered) = worker(bytes, u32::MAX)?;
        ensure!(
            header.profile == media::RASTER_PROFILE
                && header.width == asset.width
                && header.height == asset.height,
            "vector renderer dimensions differ from manifest"
        );
        rendered
    } else {
        bytes.to_vec()
    };
    let pixels = Pixels {
        width: asset.width,
        height: asset.height,
        rgb,
    };
    pixels.validate()?;
    Ok(pixels)
}
pub(crate) fn render_vector(vector: &media::Vector) -> Result<Vec<u8>> {
    use media::PathCommand as C;
    use tiny_skia::{Color, FillRule, Paint, PathBuilder, Pixmap, Stroke, Transform};
    let mut pixmap = Pixmap::new(vector.width, vector.height).context("invalid vector viewport")?;
    pixmap.fill(Color::from_rgba8(
        vector.background[0],
        vector.background[1],
        vector.background[2],
        255,
    ));
    for geometry in &vector.paths {
        let mut builder = PathBuilder::new();
        let f = |v: i32| v as f32 / 1024.0;
        for command in &geometry.commands {
            match *command {
                C::Move { x, y } => builder.move_to(f(x), f(y)),
                C::Line { x, y } => builder.line_to(f(x), f(y)),
                C::Quad { x1, y1, x, y } => builder.quad_to(f(x1), f(y1), f(x), f(y)),
                C::Cubic {
                    x1,
                    y1,
                    x2,
                    y2,
                    x,
                    y,
                } => builder.cubic_to(f(x1), f(y1), f(x2), f(y2), f(x), f(y)),
                C::Close => builder.close(),
            }
        }
        let Some(path) = builder.finish() else {
            continue;
        };
        let mut paint = Paint {
            anti_alias: true,
            ..Paint::default()
        };
        if let Some(c) = geometry.fill {
            paint.set_color_rgba8(c[0], c[1], c[2], c[3]);
            let rule = match geometry.fill_rule {
                media::FillRule::NonZero => FillRule::Winding,
                media::FillRule::EvenOdd => FillRule::EvenOdd,
            };
            pixmap.fill_path(&path, &paint, rule, Transform::identity(), None);
        }
        if let Some(s) = &geometry.stroke {
            let c = s.colour;
            paint.set_color_rgba8(c[0], c[1], c[2], c[3]);
            pixmap.stroke_path(
                &path,
                &paint,
                &Stroke {
                    width: s.width as f32 / 1024.0,
                    ..Stroke::default()
                },
                Transform::identity(),
                None,
            );
        }
    }
    Ok(pixmap
        .data()
        .chunks_exact(4)
        .flat_map(|p| [p[0], p[1], p[2]])
        .collect())
}
