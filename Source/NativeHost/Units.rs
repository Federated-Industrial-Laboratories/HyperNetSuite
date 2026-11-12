// SPDX-License-Identifier: Apache-2.0
// Native units retain exact commands and explicit online choice without service lifetime timers.
use super::engine::{self, Host};
use crate::admission::{host_service, protocol, runtime};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub fn name(directory: &Path, purpose: &str) -> Result<String> {
    ensure!(
        !purpose.is_empty()
            && purpose.len() <= 32
            && purpose
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'),
        "invalid native unit purpose"
    );
    Ok(format!(
        "hypernet-native-{}-{purpose}.service",
        &protocol::digest(directory.as_os_str().as_encoded_bytes())[..20]
    ))
}
fn quote(value: &str) -> Result<String> {
    ensure!(
        !value.chars().any(char::is_control),
        "invalid native unit argument"
    );
    Ok(format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    ))
}
fn target(directory: &Path, purpose: &str) -> Result<PathBuf> {
    Ok(host_service::config_root()?.join(name(directory, purpose)?))
}
fn owned(path: &Path) -> Result<()> {
    let info = std::fs::symlink_metadata(path)?;
    ensure!(
        info.is_file()
            && !info.file_type().is_symlink()
            && info.nlink() == 1
            && info.uid() == unsafe { libc::geteuid() }
            && info.mode() & 0o077 == 0,
        "native unit file is not private"
    );
    Ok(())
}
fn content(
    host: &Host<'_>,
    purpose: &str,
    executable: &Path,
    args: &[String],
    subordinate_ids: bool,
    controller: &Path,
) -> Result<String> {
    let mut command = vec![quote(&engine::text(executable)?)?];
    command.extend(args.iter().map(|s| quote(s)).collect::<Result<Vec<_>>>()?);
    Ok(format!(
        "[Unit]\nDescription=HyperNet native hosting\nAfter=network-online.target\nStartLimitIntervalSec=0\n\n[Service]\nType=exec\nExecCondition={} admission-host permitted --directory {}\nExecStart={}\nRestart={}\nRestartSec=5\nUMask=0077\nKillMode=mixed\nTimeoutStopSec=45\n{}\n[Install]\nWantedBy=default.target\n",
        quote(&engine::text(controller)?)?,
        quote(&engine::text(&host.c.root)?)?,
        command.join(" "),
        if host.c.hosting_end == crate::trust_validity::End::UntilWithdrawn
            || matches!(purpose, "clock" | "supervisor")
        {
            "on-failure"
        } else {
            "no"
        },
        if subordinate_ids {
            ""
        } else {
            "NoNewPrivileges=yes\n"
        }
    ))
}
pub fn ensure(
    host: &Host<'_>,
    purpose: &str,
    executable: &Path,
    args: &[String],
    subordinate_ids: bool,
) -> Result<()> {
    runtime::executable(executable)?;
    let content = content(
        host,
        purpose,
        executable,
        args,
        subordinate_ids,
        &host.c.suite,
    )?;
    let path = target(&host.c.root, purpose)?;
    if path.exists() {
        owned(&path)?;
        ensure!(
            crate::files::read_bounded(&path, true)? == content.as_bytes(),
            "review an installed-software successor before changing this native unit"
        );
    } else {
        let root = path.parent().context("native unit parent absent")?;
        let temporary = root.join(format!(".native-unit-{}", crate::random_hex::<16>()));
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)?;
            file.write_all(content.as_bytes())?;
            file.sync_all()?;
            std::fs::rename(&temporary, &path)?;
            File::open(root)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result?;
    }
    engine::raw(
        Path::new("/usr/bin/systemctl"),
        &engine::bytes(&["--user", "daemon-reload"]),
        host.cancel,
        host.end,
        "native unit reload",
    )?;
    engine::raw(
        Path::new("/usr/bin/systemctl"),
        &engine::bytes(&["--user", "enable", "--now", &name(&host.c.root, purpose)?]),
        host.cancel,
        host.end,
        "native unit start",
    )?;
    Ok(())
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Successor {
    pub purpose: String,
    before: String,
    after: String,
}
pub(super) fn exists(root: &Path, purpose: &str) -> Result<bool> {
    match std::fs::symlink_metadata(target(root, purpose)?) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn inactive(host: &Host<'_>, purpose: &str) -> Result<()> {
    let bytes = engine::raw(
        Path::new("/usr/bin/systemctl"),
        &engine::bytes(&[
            "--user",
            "show",
            "--property=ActiveState,UnitFileState",
            &name(&host.c.root, purpose)?,
        ]),
        host.cancel,
        host.end,
        "stopped controller update",
    )?;
    let fields: std::collections::BTreeMap<_, _> = std::str::from_utf8(&bytes)?
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();
    ensure!(
        matches!(fields.get("ActiveState"), Some(&"inactive" | &"failed"))
            && fields.get("UnitFileState") == Some(&"disabled"),
        "disable and stop the exact native unit before controller update"
    );
    Ok(())
}
pub(super) fn successor(
    host: &Host<'_>,
    purpose: &str,
    executable: &Path,
    args: &[String],
    controller: &Path,
    resume: bool,
) -> Result<Successor> {
    let path = target(&host.c.root, purpose)?;
    owned(&path)?;
    inactive(host, purpose)?;
    let subordinate = !matches!(purpose, "clock" | "hrc");
    let before = content(host, purpose, executable, args, subordinate, &host.c.suite)?;
    let after = content(
        host,
        purpose,
        if executable == host.c.suite {
            controller
        } else {
            executable
        },
        args,
        subordinate,
        controller,
    )?;
    let current = crate::files::read_bounded(&path, true)?;
    ensure!(
        current == before.as_bytes() || resume && current == after.as_bytes(),
        "native unit differs from its exact standard command"
    );
    Ok(Successor {
        purpose: purpose.into(),
        before,
        after,
    })
}
pub(super) fn apply_successor(host: &Host<'_>, change: &Successor) -> Result<()> {
    inactive(host, &change.purpose)?;
    replace_exact(
        &target(&host.c.root, &change.purpose)?,
        &change.before,
        &change.after,
    )
}
fn replace_exact(path: &Path, before: &str, after: &str) -> Result<()> {
    owned(path)?;
    let current = crate::files::read_bounded(path, true)?;
    if current == after.as_bytes() {
        return Ok(());
    }
    ensure!(
        current == before.as_bytes(),
        "native unit changed during controller update"
    );
    crate::native_installation::files::publish(path, after.as_bytes())
}
pub(super) fn reload(host: &Host<'_>) -> Result<()> {
    engine::raw(
        Path::new("/usr/bin/systemctl"),
        &engine::bytes(&["--user", "daemon-reload"]),
        host.cancel,
        host.end,
        "stopped native unit update",
    )?;
    Ok(())
}
pub fn active(host: &Host<'_>, purpose: &str) -> Result<bool> {
    let name = name(&host.c.root, purpose)?;
    Ok(engine::raw(
        Path::new("/usr/bin/systemctl"),
        &engine::bytes(&["--user", "is-active", &name]),
        host.cancel,
        host.end,
        "native unit status",
    )
    .is_ok_and(|b| b == b"active\n"))
}
pub fn stop(host: &Host<'_>, purpose: &str) -> Result<()> {
    stop_owned(&host.c.root, purpose, host.cancel, host.end)
}
pub fn stop_owned(
    root: &Path,
    purpose: &str,
    cancel: &std::sync::atomic::AtomicBool,
    end: std::time::Instant,
) -> Result<()> {
    let path = target(root, purpose)?;
    if !path.exists() {
        return Ok(());
    }
    owned(&path)?;
    engine::raw(
        Path::new("/usr/bin/systemctl"),
        &engine::bytes(&["--user", "disable", "--now", &name(root, purpose)?]),
        cancel,
        end,
        "native unit stop",
    )?;
    Ok(())
}
impl Host<'_> {
    pub fn unit(&self, purpose: &str, executable: &Path, args: &[String]) -> Result<()> {
        ensure(
            self,
            purpose,
            executable,
            args,
            !matches!(purpose, "clock" | "hrc"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_unit_successor_retries_partial_publication_and_refuses_unreviewed_content() {
        let root = std::env::temp_dir().join(format!(
            "hypernet-unit-update-{}",
            crate::random_hex::<16>()
        ));
        crate::admission::saved::create_directory(&root).unwrap();
        let result = (|| -> Result<()> {
            let a = root.join("one.service");
            let b = root.join("two.service");
            crate::native_installation::files::exact(&a, b"old one")?;
            crate::native_installation::files::exact(&b, b"old two")?;
            replace_exact(&a, "old one", "new one")?;
            // Retry after only the first reviewed unit was published.
            replace_exact(&a, "old one", "new one")?;
            replace_exact(&b, "old two", "new two")?;
            assert_eq!(crate::files::read_bounded(&b, true)?, b"new two");
            assert!(replace_exact(&b, "unreviewed", "other command").is_err());
            std::fs::remove_file(&a)?;
            std::os::unix::fs::symlink(&b, &a)?;
            assert!(replace_exact(&a, "new two", "other command").is_err());
            Ok(())
        })();
        std::fs::remove_dir_all(&root).unwrap();
        result.unwrap();
    }
}
