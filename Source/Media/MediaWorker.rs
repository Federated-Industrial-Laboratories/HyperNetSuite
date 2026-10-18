// SPDX-License-Identifier: MIT
// Decode bounded author input only after installing an irreversible syscall boundary.
#[path = "SvgImport.rs"]
mod svg_import;
use crate::media_import::{MAX_INPUT, WorkerHeader};
use anyhow::{Result, ensure};
use image::{DynamicImage, ImageDecoder};
use std::io::{Read, Write};

pub fn run() -> Result<()> {
    confine()?;
    let mut input = std::io::stdin().lock();
    let mut axis = [0u8; 4];
    input.read_exact(&mut axis)?;
    let axis = u32::from_le_bytes(axis);
    if axis == 0 {
        return probe();
    }
    let result = (|| -> Result<(WorkerHeader, Vec<u8>)> {
        ensure!(
            axis == u32::MAX || (1..=1024).contains(&axis),
            "invalid output dimension"
        );
        let mut bytes = Vec::new();
        input.take((MAX_INPUT + 1) as u64).read_to_end(&mut bytes)?;
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_INPUT,
            "input exceeds the encoded size bound"
        );
        if axis == u32::MAX {
            let vector = crate::markup::media::vector(&bytes).map_err(anyhow::Error::msg)?;
            let rgb = crate::media_import::render_vector(&vector)?;
            Ok((
                WorkerHeader {
                    profile: crate::markup::media::RASTER_PROFILE.into(),
                    width: vector.width,
                    height: vector.height,
                    bytes: rgb.len(),
                    warnings: Vec::new(),
                },
                rgb,
            ))
        } else {
            decode(&bytes, axis)
        }
    })();
    let mut out = std::io::stdout().lock();
    match result {
        Ok((header, bytes)) => {
            let header = serde_json::to_vec(&header)?;
            ensure!(
                header.len() <= 8192 && bytes.len() <= 786432,
                "invalid converted output"
            );
            out.write_all(&(header.len() as u32).to_le_bytes())?;
            out.write_all(&header)?;
            out.write_all(&bytes)?;
        }
        Err(error) => {
            let message: String = format!("{error}")
                .chars()
                .filter(|c| !c.is_control())
                .take(256)
                .collect();
            let header = serde_json::to_vec(&serde_json::json!({"error": message}))?;
            out.write_all(&(header.len() as u32).to_le_bytes())?;
            out.write_all(&header)?;
        }
    }
    out.flush()?;
    Ok(())
}
pub(crate) fn fitted(width: u32, height: u32, axis: u32) -> Result<(u32, u32)> {
    ensure!(
        width > 0 && height > 0 && u64::from(width) * u64::from(height) <= 16_000_000,
        "input exceeds 16 megapixels or has empty dimensions"
    );
    let scale = (axis as f64 / width.max(height) as f64)
        .min((262144.0 / (f64::from(width) * f64::from(height))).sqrt())
        .min(1.0);
    Ok((
        (f64::from(width) * scale).floor().max(1.0) as u32,
        (f64::from(height) * scale).floor().max(1.0) as u32,
    ))
}
fn decode(bytes: &[u8], axis: u32) -> Result<(WorkerHeader, Vec<u8>)> {
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(16_000_000);
    limits.max_image_height = Some(16_000_000);
    limits.max_alloc = Some(160 * 1024 * 1024);
    let (image, mut warnings) = if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        let decoder =
            image::codecs::png::PngDecoder::with_limits(std::io::Cursor::new(bytes), limits)?;
        ensure!(!decoder.is_apng()?, "animated PNG is unsupported");
        let dimensions = decoder.dimensions();
        fitted(dimensions.0, dimensions.1, axis)?;
        (
            DynamicImage::from_decoder(decoder)?,
            vec!["PNG metadata removed; transparency composited onto white".into()],
        )
    } else if bytes.starts_with(b"\xff\xd8") {
        let mut decoder = image::codecs::jpeg::JpegDecoder::new(std::io::Cursor::new(bytes))?;
        decoder.set_limits(limits)?;
        let dimensions = decoder.dimensions();
        fitted(dimensions.0, dimensions.1, axis)?;
        let orientation = decoder.orientation()?;
        let mut image = DynamicImage::from_decoder(decoder)?;
        image.apply_orientation(orientation);
        (
            image,
            vec!["JPEG metadata removed; orientation applied".into()],
        )
    } else {
        return svg_import::convert(bytes, axis);
    };
    let (width, height) = fitted(image.width(), image.height(), axis)?;
    // Sample directly from the decoded image to avoid allocating a second full-size raster.
    use image::GenericImageView;
    let mut rgb = Vec::with_capacity(width as usize * height as usize * 3);
    for y in 0..height {
        for x in 0..width {
            let p = image
                .get_pixel(
                    (u64::from(x) * u64::from(image.width()) / u64::from(width)) as u32,
                    (u64::from(y) * u64::from(image.height()) / u64::from(height)) as u32,
                )
                .0;
            for component in &p[..3] {
                rgb.push(
                    ((u32::from(*component) * u32::from(p[3])
                        + 255 * (255 - u32::from(p[3]))
                        + 127)
                        / 255) as u8,
                );
            }
        }
    }
    if image.width() != width || image.height() != height {
        warnings.push("Image reduced to the published pixel budget".into());
    }
    Ok((
        WorkerHeader {
            profile: "HyperNetRaster/1".into(),
            width,
            height,
            bytes: rgb.len(),
            warnings,
        },
        rgb,
    ))
}

#[cfg(target_os = "linux")]
fn confine() -> Result<()> {
    // These are freshly created pipes, not inherited files, sockets or terminal descriptors.
    for fd in [0, 1] {
        let mut status: libc::stat = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { libc::fstat(fd, &mut status) } == 0
                && status.st_mode & libc::S_IFMT == libc::S_IFIFO,
            "worker requires anonymous input/output pipes"
        );
    }
    ensure!(
        unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) } == 0,
        "cannot close inherited descriptors"
    );
    for (resource, ceiling) in [
        (libc::RLIMIT_AS, 256 * 1024 * 1024),
        (libc::RLIMIT_CPU, 2),
        (libc::RLIMIT_CORE, 0),
        (libc::RLIMIT_NOFILE, 3),
        (libc::RLIMIT_FSIZE, 1024 * 1024),
    ] {
        let limit = libc::rlimit {
            rlim_cur: ceiling,
            rlim_max: ceiling,
        };
        ensure!(
            unsafe { libc::setrlimit(resource, &limit) } == 0,
            "cannot restrict worker resources"
        );
    }
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "cannot disable worker dumps"
    );
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0,
        "cannot restrict worker privileges"
    );
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc00000b7;
    #[cfg(target_arch = "riscv64")]
    const ARCH: u32 = 0xc00000f3;
    #[cfg(target_arch = "powerpc64")]
    const ARCH: u32 = if cfg!(target_endian = "little") {
        0xc0000015
    } else {
        0x80000015
    };
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "powerpc64"
    )))]
    const ARCH: u32 = 0;
    ensure!(
        ARCH != 0,
        "import confinement is unavailable on this instruction set"
    );
    let stmt = |code, k| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |k, jt, jf| libc::sock_filter {
        code: 0x15,
        jt,
        jf,
        k,
    };
    const LOW_WORD: u32 = if cfg!(target_endian = "little") { 0 } else { 4 };
    const ALLOW: u32 = 0x7fff0000;
    const DENY: u32 = 0x00050000 | libc::EPERM as u32;
    let mut filter = vec![
        stmt(0x20, 4),
        jump(ARCH, 1, 0),
        stmt(0x06, 0x80000000),
        stmt(0x20, 0),
    ];
    // A default-deny allowlist prevents filesystem, network, process, ptrace and namespace access.
    // mmap cannot read a descriptor: only anonymous memory is allowed.
    filter.extend([
        jump(libc::SYS_mmap as u32, 0, 5),
        stmt(0x20, 40 + LOW_WORD),
        libc::sock_filter {
            code: 0x45,
            jt: 0,
            jf: 1,
            k: libc::MAP_ANONYMOUS as u32,
        },
        stmt(0x06, ALLOW),
        stmt(0x06, DENY),
        stmt(0x20, 0),
    ]);
    for (call, fd) in [(libc::SYS_read, 0u32), (libc::SYS_write, 1u32)] {
        filter.extend([
            jump(call as u32, 0, 4),
            stmt(0x20, 16 + LOW_WORD),
            jump(fd, 0, 1),
            stmt(0x06, ALLOW),
            stmt(0x06, DENY),
        ]);
    }
    for syscall in [
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_brk,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_mprotect,
        libc::SYS_madvise,
        libc::SYS_futex,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigaction,
        libc::SYS_clock_gettime,
        libc::SYS_getrandom,
        libc::SYS_sigaltstack,
    ] {
        filter.extend([jump(syscall as u32, 0, 1), stmt(0x06, ALLOW)]);
    }
    filter.push(stmt(0x06, DENY));
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_SECCOMP, 2, &program) } == 0,
        "cannot install worker syscall boundary"
    );
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn confine() -> Result<()> {
    anyhow::bail!("confined import requires Linux")
}
#[cfg(target_os = "linux")]
fn probe() -> Result<()> {
    use std::os::unix::net::UnixStream;
    let checks = [
        std::fs::File::open("/etc/passwd").is_err(),
        std::net::TcpListener::bind("127.0.0.1:0").is_err(),
        UnixStream::pair().is_err(),
        unsafe { libc::syscall(libc::SYS_clone, 0, 0, 0, 0, 0) } == -1,
        unsafe { libc::fcntl(3, libc::F_GETFD) } == -1,
    ];
    ensure!(
        checks.iter().all(|pass| *pass),
        "worker boundary probe failed"
    );
    std::io::stdout().write_all(b"{\"filesystemDenied\":true,\"networkDenied\":true,\"socketsDenied\":true,\"processDenied\":true,\"extraDescriptorsDenied\":true}\n")?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn probe() -> Result<()> {
    anyhow::bail!("confined import requires Linux")
}
