// SPDX-License-Identifier: MIT
// Client clock monitoring observes a trusted local chrony socket and never changes time.
use crate::{authority_clock, transfer_files as files};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Command as Process, Stdio},
    time::Duration,
};
#[path = "../Networks/ClientClockObservation.rs"]
mod observation;

#[derive(Subcommand)]
pub enum Command {
    /// Refresh private clock health from local authenticated chrony until cancelled.
    Monitor(Options),
    /// Produce one short-lived observation without changing the system clock.
    Observe(Options),
    /// Check the current local observation; old-boot and expired evidence refuses.
    Status {
        #[arg(long)]
        directory: PathBuf,
    },
}
#[derive(Args)]
pub struct Options {
    #[arg(long)]
    directory: PathBuf,
    /// Absolute trusted chronyc executable.
    #[arg(long, default_value = "/usr/bin/chronyc")]
    chronyc: PathBuf,
    /// Explicit local socket; no DNS, UDP or fallback destination is allowed.
    #[arg(long, default_value = "/run/chrony/chronyd.sock")]
    socket: PathBuf,
}
fn ancestors(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        let m = std::fs::symlink_metadata(ancestor)?;
        ensure!(
            m.is_dir()
                && (m.uid() == 0 || m.uid() == unsafe { libc::geteuid() })
                && m.mode() & 0o022 == 0,
            "clock dependency ancestor permits replacement"
        );
    }
    Ok(())
}
fn validate(o: &Options) -> Result<()> {
    ensure!(
        o.chronyc.is_absolute() && o.chronyc.canonicalize()? == o.chronyc,
        "chronyc must be an absolute canonical path"
    );
    let m = std::fs::symlink_metadata(&o.chronyc)?;
    ensure!(
        m.is_file()
            && m.mode() & 0o022 == 0
            && m.mode() & 0o111 != 0
            && (m.uid() == 0 || m.uid() == unsafe { libc::geteuid() }),
        "untrusted chronyc executable"
    );
    ancestors(o.chronyc.parent().context("chronyc parent absent")?)?;
    ensure!(
        o.socket.is_absolute() && o.socket.canonicalize()? == o.socket,
        "chrony requires one absolute canonical local socket"
    );
    let text = o.socket.to_str().context("invalid chrony socket")?;
    ensure!(
        !text.contains(',') && !text.chars().any(char::is_control),
        "chrony fallback prohibited"
    );
    let m = std::fs::symlink_metadata(&o.socket)?;
    ensure!(
        m.file_type().is_socket()
            && m.mode() & 0o002 == 0
            && (m.uid() == 0 || m.uid() == unsafe { libc::geteuid() }),
        "untrusted chrony socket"
    );
    ancestors(o.socket.parent().context("chrony parent absent")?)
}
fn query(o: &Options, command: &str, deadline: u64) -> Result<String> {
    ensure!(
        matches!(command, "tracking" | "sources" | "authdata" | "ntpdata"),
        "unsupported clock query"
    );
    crate::private_route_client::check_cancelled()?;
    ensure!(
        crate::authority_challenge::boot_time_ms()? < deadline,
        "chronyc observation deadline expired"
    );
    let mut child = Process::new(&o.chronyc)
        .args(["-n", "-c", "-h"])
        .arg(&o.socket)
        .arg(command)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let result = (|| -> Result<String> {
        let mut output = child.stdout.take().context("chronyc stdout absent")?;
        let fd = output.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        ensure!(
            flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0,
            "cannot bound chronyc output"
        );
        let mut bytes = Vec::new();
        loop {
            crate::private_route_client::check_cancelled()?;
            ensure!(
                crate::authority_challenge::boot_time_ms()? < deadline,
                "chronyc observation deadline expired"
            );
            let mut buffer = [0; 4096];
            match output.read(&mut buffer) {
                Ok(0) => {
                    if let Some(status) = child.try_wait()? {
                        ensure!(status.success(), "chronyc observation failed");
                        return Ok(String::from_utf8(bytes)?);
                    }
                }
                Ok(n) => {
                    bytes.extend_from_slice(&buffer[..n]);
                    ensure!(bytes.len() <= 16384, "chronyc output exceeds bound");
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e.into()),
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
    }
    let _ = child.wait();
    result
}
fn observe(o: &Options, directory: &std::fs::File) -> Result<()> {
    validate(o)?;
    let witness = observation::probe(|command, deadline| query(o, command, deadline))?;
    publish(directory, &witness, observation::moment)
}
fn publish(
    directory: &File,
    witness: &observation::Witness,
    mut now: impl FnMut() -> Result<observation::Moment>,
) -> Result<()> {
    witness.health(&observation::kernel_boot()?, now()?)?;
    let bytes = serde_json::to_vec(witness)?;
    ensure!(bytes.len() <= 4096, "clock observation exceeds its bound");
    let temporary = CString::new(format!("ClockPending{}", crate::random_hex::<16>()))?;
    let destination = c"ClockHealth.json";
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    ensure!(
        fd >= 0,
        "cannot create clock observation: {}",
        std::io::Error::last_os_error()
    );
    let mut file = unsafe { File::from_raw_fd(fd) };
    let result = (|| -> Result<()> {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(&bytes)?;
        // This short-lived observation needs atomic visibility, not crash durability.
        ensure!(
            unsafe {
                libc::renameat(
                    directory.as_raw_fd(),
                    temporary.as_ptr(),
                    directory.as_raw_fd(),
                    destination.as_ptr(),
                )
            } == 0,
            "cannot publish clock observation: {}",
            std::io::Error::last_os_error()
        );
        witness.health(&observation::kernel_boot()?, now()?)?;
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(directory.as_raw_fd(), temporary.as_ptr(), 0);
        }
    }
    result.context("clock observation could not be published")
}
pub fn run(command: Command) -> Result<()> {
    let (o, monitor) = match command {
        Command::Status { directory } => {
            authority_clock::health(&directory.join("ClockHealth.json"))?.observe()?;
            return crate::print_value(
                &serde_json::json!({"state":"ClockHealthy","localOnly":true}),
            );
        }
        Command::Observe(o) => (o, false),
        Command::Monitor(o) => (o, true),
    };
    let directory = files::private_directory(&o.directory)?;
    let _lock = files::profile_lock(&directory, OsStr::new("ClockHealth.json"))?;
    let mut previous = None;
    loop {
        crate::private_route_client::check_cancelled()?;
        let result = observe(&o, &directory);
        if !monitor {
            result?;
            return crate::print_value(
                &serde_json::json!({"state":"ClockHealthy","localOnly":true}),
            );
        }
        let healthy = result.is_ok();
        if previous != Some(healthy) {
            crate::print_value(
                &serde_json::json!({"state":if healthy {"ClockHealthy"} else {"ClockUnavailable"},"localOnly":true,
                    "bootMs":crate::authority_challenge::boot_time_ms()?}),
            )?;
            previous = Some(healthy);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(test)]
#[path = "PrivateRouteClockTests.rs"]
mod tests;
