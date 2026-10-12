// SPDX-License-Identifier: MIT
// Operator clock health requires an explicit private source or independently pinned monitor.
use crate::{
    authority_challenge::{ClockHealth, Observation, boot_time_ms},
    transfer_files, trust_bootstrap, trust_wire as wire,
};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    ffi::CString,
    fs::File,
    io::Read,
    net::IpAddr,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub enum Source {
    Private {
        path: PathBuf,
    },
    Signed {
        path: PathBuf,
        monitor_key: [u8; 32],
        host_kernel_boot: String,
    },
}
impl Source {
    pub fn select(path: &Path, key: Option<&str>, boot: Option<&str>) -> Result<Self> {
        match (key, boot) {
            (None, None) => Ok(Self::Private { path: path.into() }),
            (Some(key), Some(boot)) => {
                let monitor_key = trust_bootstrap::hex32(key)?;
                wire::valid_key(&monitor_key)?;
                ensure!(valid_boot(boot), "invalid pinned host kernel boot");
                Ok(Self::Signed {
                    path: path.into(),
                    monitor_key,
                    host_kernel_boot: boot.into(),
                })
            }
            _ => anyhow::bail!("signed clock requires both monitor key and host kernel boot"),
        }
    }
    pub fn monitor_key(&self) -> Option<&[u8; 32]> {
        match self {
            Self::Private { .. } => None,
            Self::Signed { monitor_key, .. } => Some(monitor_key),
        }
    }
    pub fn health(&self) -> Result<ClockHealth> {
        match self {
            Self::Private { path } => health(path),
            Self::Signed {
                path,
                monitor_key,
                host_kernel_boot,
            } => {
                unshifted_clock()?;
                let bytes = read_opened_observation(open_observation(path, false)?, false)?;
                let health = signed(&bytes, *monitor_key, host_kernel_boot, moment()?)?;
                health.observe()?;
                Ok(health)
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Witness {
    version: u64,
    kernel_boot: String,
    sample_wall_ms: u64,
    sample_boot_ms: u64,
    valid_until_boot_ms: u64,
    maximum_error_ms: u64,
    source: IpAddr,
}
fn canonical_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "clock observation requires an absolute canonical path"
    );
    Ok(())
}
fn open_observation(path: &Path, private: bool) -> Result<File> {
    canonical_path(path)?;
    let parent = path.parent().context("clock parent absent")?;
    if private {
        for ancestor in parent.ancestors() {
            let meta = std::fs::symlink_metadata(ancestor)?;
            ensure!(
                meta.is_dir()
                    && (meta.uid() == 0 || meta.uid() == unsafe { libc::geteuid() })
                    && (meta.mode() & 0o022 == 0 || meta.uid() == 0 && meta.mode() & 0o1000 != 0),
                "clock ancestor permits replacement"
            );
        }
    }
    let directory = transfer_files::directory(parent)?;
    let name = CString::new(
        path.file_name()
            .context("clock file name absent")?
            .as_bytes(),
    )?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    ensure!(
        fd >= 0,
        "cannot open clock observation safely: {}",
        std::io::Error::last_os_error()
    );
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn read_opened_observation(file: File, private: bool) -> Result<Vec<u8>> {
    let metadata = file.metadata()?;
    // Atomic publication can unlink an observation after it was safely opened.
    // Its bytes must still pass the original clock authentication and expiry checks.
    ensure!(
        metadata.is_file() && metadata.nlink() <= 1 && metadata.len() <= 4096,
        "clock observation is not a bounded regular file"
    );
    if private {
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0,
            "private clock observation must be owned and mode 0600"
        );
    }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 4096,
        "clock observation grew beyond its bound"
    );
    Ok(bytes)
}
fn valid_boot(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
        && value
            .bytes()
            .any(|b| (b'1'..=b'9').contains(&b) || (b'a'..=b'f').contains(&b))
}
fn moment() -> Result<Observation> {
    Ok(Observation {
        boot_ms: boot_time_ms()?,
        wall_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .try_into()?,
    })
}
fn unshifted_report(value: &str) -> Result<()> {
    ensure!(
        value.len() <= 256 && value.is_ascii(),
        "invalid time namespace report"
    );
    let lines = value.lines().collect::<Vec<_>>();
    ensure!(lines.len() == 2, "unknown time namespace report");
    for (line, name) in lines.iter().zip(["monotonic", "boottime"]) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        ensure!(
            fields.as_slice() == [name, "0", "0"],
            "shifted time namespace is unsupported"
        );
    }
    Ok(())
}
fn unshifted_clock() -> Result<()> {
    let mut bytes = Vec::new();
    std::fs::File::open("/proc/self/timens_offsets")?
        .take(257)
        .read_to_end(&mut bytes)?;
    unshifted_report(std::str::from_utf8(&bytes)?)
}
impl Witness {
    fn health(&self, boot: &str, now: Observation) -> Result<ClockHealth> {
        ensure!(
            self.version == 1 && valid_boot(boot) && self.kernel_boot == boot,
            "clock observation belongs to another kernel boot"
        );
        ensure!(
            self.valid_until_boot_ms
                == self
                    .sample_boot_ms
                    .checked_add(1000)
                    .context("clock lifetime overflow")?
                && !self.source.is_unspecified()
                && !self.source.is_loopback(),
            "clock observation identity or lifetime differs"
        );
        ensure!(
            now.boot_ms >= self.sample_boot_ms && now.boot_ms < self.valid_until_boot_ms,
            "clock observation is stale"
        );
        let predicted = self
            .sample_wall_ms
            .checked_add(now.boot_ms - self.sample_boot_ms)
            .context("clock progression overflow")?;
        ensure!(
            self.maximum_error_ms
                .checked_add(now.wall_ms.abs_diff(predicted))
                .is_some_and(|v| v <= 250),
            "clock error exceeds the permitted bound"
        );
        ClockHealth::new(
            self.sample_wall_ms,
            self.sample_boot_ms,
            self.valid_until_boot_ms,
            self.maximum_error_ms,
        )
    }
}
fn signed(bytes: &[u8], key: [u8; 32], boot: &str, now: Observation) -> Result<ClockHealth> {
    ensure!(
        bytes.len() <= 4096,
        "signed clock observation exceeds its bound"
    );
    let (payload, signatures) = wire::envelope(bytes, 1)?;
    ensure!(
        signatures.len() == 1 && signatures[0].0 == key,
        "clock monitor signature differs from its pin"
    );
    let value = wire::decode(&payload)?;
    let fields = value.array(8)?;
    ensure!(
        fields[0].uint()? == 44 && fields[1].uint()? == 1,
        "unsupported signed clock observation"
    );
    let source: IpAddr = fields[7].text()?.parse()?;
    ensure!(
        source.to_string() == fields[7].text()?,
        "noncanonical signed clock source"
    );
    Witness {
        version: 1,
        kernel_boot: fields[2].text()?.into(),
        sample_wall_ms: fields[3].uint()?,
        sample_boot_ms: fields[4].uint()?,
        valid_until_boot_ms: fields[5].uint()?,
        maximum_error_ms: fields[6].uint()?,
        source,
    }
    .health(boot, now)
}
pub fn health(path: &Path) -> Result<ClockHealth> {
    let witness: Witness = serde_json::from_slice(&read_opened_observation(
        open_observation(path, true)?,
        true,
    )?)?;
    let kernel = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let health = witness.health(kernel.trim_end_matches('\n'), moment()?)?;
    health.observe()?;
    Ok(health)
}

#[cfg(test)]
#[path = "AuthorityClockTests.rs"]
mod tests;
