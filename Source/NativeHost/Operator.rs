// SPDX-License-Identifier: Apache-2.0
// Fixed native owner commands use an isolated mapped identity and bounded named exports.
use super::{engine::*, files};
use crate::admission::host_isolation;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::Read,
    path::{Path, PathBuf},
};

pub fn podman(host: &Host<'_>, arguments: &[String]) -> Result<Vec<u8>> {
    raw(
        Path::new("/usr/bin/podman"),
        arguments,
        host.cancel,
        host.end,
        &host.state.phase,
    )
}
pub fn mapped_ids(host: &Host<'_>) -> Result<(u32, u32)> {
    let mut ids = Vec::new();
    for (file, owner) in [
        ("uid_map", unsafe { libc::geteuid() }),
        ("gid_map", unsafe { libc::getegid() }),
    ] {
        let bytes = podman(
            host,
            &bytes(&["unshare", "/usr/bin/cat", &format!("/proc/self/{file}")]),
        )?;
        ids.push(host_isolation::mapped_identity(&bytes, owner, 1001)?);
    }
    Ok((ids[0], ids[1]))
}
fn mapped_write(
    host: &Host<'_>,
    parent: &Path,
    name: &str,
    operation: &str,
    input: &[u8],
) -> Result<()> {
    ensure!(
        parent.starts_with(&host.c.root),
        "mapped state escapes host directory"
    );
    let arguments = bytes(&[
        "run",
        "--interactive",
        "--rm",
        "--pull=never",
        "--network=none",
        "--userns=nomap",
        "--user=1000:1000",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--read-only",
        "--pids-limit=32",
        "--memory=134217728",
        "--cpus=1",
        "--log-driver=none",
        "--volume",
        &format!(
            "{}:/HyperNetSuite:ro,nosuid,nodev",
            host_isolation::argument(&host.c.suite)?
        ),
        "--volume",
        &format!(
            "{}:/Input:rw,nosuid,nodev",
            host_isolation::argument(parent)?
        ),
        "--entrypoint=/HyperNetSuite",
        &host.state.image,
        "admission-host",
        operation,
        "--directory",
        "/Input",
        "--name",
        name,
    ]);
    let arguments: Vec<std::ffi::OsString> = arguments.iter().map(Into::into).collect();
    let result = crate::admission::helper::output(
        Path::new("/usr/bin/podman"),
        &arguments,
        input,
        host.cancel,
        std::time::Duration::from_secs(60),
    )?;
    ensure!(
        serde_json::from_slice::<Value>(&result)?["status"] == "Ready",
        "mapped input preparation failed"
    );
    Ok(())
}
pub fn directory(host: &Host<'_>, path: &Path) -> Result<()> {
    ensure!(
        path.starts_with(&host.c.root),
        "mapped state escapes host directory"
    );
    let parent = path.parent().context("mapped parent absent")?;
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .context("mapped name absent")?;
    if parent != host.c.root {
        if podman(
            host,
            &bytes(&[
                "unshare",
                "/usr/bin/stat",
                "-c",
                "%F %u:%a",
                "--",
                &text(path)?,
            ]),
        )
        .is_ok_and(|m| m == b"directory 1001:700\n")
        {
            return Ok(());
        }
        return mapped_write(host, parent, name, "mapped-directory", &[]);
    }
    if !path.exists() {
        files::directory(path)?;
    }
    let metadata = podman(
        host,
        &bytes(&[
            "unshare",
            "/usr/bin/stat",
            "-c",
            "%F %u:%a",
            "--",
            &text(path)?,
        ]),
    )?;
    if metadata == b"directory 1001:700\n" {
        return Ok(());
    }
    ensure!(metadata == b"directory 0:700\n", "mapped directory differs");
    // Until this exact handoff, only the owner can enter this new private directory.
    podman(
        host,
        &bytes(&[
            "unshare",
            "/usr/bin/chown",
            "--no-dereference",
            "1001:1001",
            "--",
            &text(path)?,
        ]),
    )?;
    Ok(())
}
pub fn copy(host: &Host<'_>, source: &Path, destination: &Path) -> Result<()> {
    ensure!(
        source.starts_with(&host.c.root) && destination.starts_with(&host.c.root),
        "mapped input escapes host directory"
    );
    let input = zeroize::Zeroizing::new(files::public_file(source, 1_048_576)?);
    if podman(
        host,
        &bytes(&[
            "unshare",
            "/usr/bin/stat",
            "-c",
            "%F %u:%a:%h",
            "--",
            &text(destination)?,
        ]),
    )
    .is_ok_and(|m| m == b"regular file 1001:600:1\n")
        && podman(
            host,
            &bytes(&[
                "unshare",
                "/usr/bin/cmp",
                "--",
                &text(source)?,
                &text(destination)?,
            ]),
        )
        .is_ok()
    {
        return Ok(());
    }
    mapped_write(
        host,
        destination.parent().context("mapped parent absent")?,
        destination
            .file_name()
            .and_then(|v| v.to_str())
            .context("mapped input name absent")?,
        "mapped-input",
        &input,
    )
}
fn export(host: &Host<'_>, source: &Path, destination: &Path) -> Result<()> {
    let metadata = podman(
        host,
        &bytes(&[
            "unshare",
            "/usr/bin/stat",
            "-c",
            "%F %u:%h",
            "--",
            &text(source)?,
        ]),
    )?;
    ensure!(
        metadata == b"regular file 1001:1\n",
        "mapped output metadata differs"
    );
    let value = podman(
        host,
        &bytes(&["unshare", "/usr/bin/cat", "--", &text(source)?]),
    )?;
    ensure!(value.len() <= 1_048_576, "mapped result exceeds bound");
    files::exact_file(destination, &value)
}
pub fn online(host: &Host<'_>, who: &str) -> Result<Vec<String>> {
    let mut a = host.trust()?;
    a.extend(bytes(&[
        "--directory",
        &text(&host.p(&format!("{who}Floor")))?,
        "--clock-witness",
        &text(&host.p("Native/Clock/Public/ClockHealth.cbor"))?,
        "--key",
        &text(&host.p(&format!("Keys/{who}.json")))?,
        "--socket",
        &text(&host.p("A1/Launch/State/Control/Control.sock"))?,
    ]));
    Ok(a)
}
pub fn operator(host: &Host<'_>, who: &str, arguments: &[String]) -> Result<Value> {
    ensure!(
        ["Administrator", "ServiceOwner"].contains(&who)
            || (who.starts_with("Manager")
                && who.len() <= 40
                && who.bytes().all(|c| c.is_ascii_alphanumeric())),
        "unsupported native operator"
    );
    let allowed = match arguments.first().map(String::as_str) {
        Some("authority-inspection") => matches!(
            arguments.get(1).map(String::as_str),
            Some(
                "initialise"
                    | "context"
                    | "stream-status"
                    | "delegate-grant"
                    | "invite-member"
                    | "admit-member"
                    | "deployments"
                    | "applications"
                    | "admission"
            )
        ),
        Some("applications") => matches!(
            arguments.get(1).map(String::as_str),
            Some("delegate" | "context" | "offer" | "register")
        ),
        Some("routes") => matches!(
            arguments.get(1).map(String::as_str),
            Some("register" | "issue" | "invite")
        ),
        Some("streams") => matches!(
            arguments.get(1).map(String::as_str),
            Some("register" | "lookup")
        ),
        Some("pages") => matches!(
            arguments.get(1).map(String::as_str),
            Some("host" | "author" | "submit" | "inspect" | "review-sign" | "review" | "content")
        ),
        _ => false,
    };
    ensure!(allowed, "unsupported native owner command");
    let root = host.p(&format!("Op{who}"));
    for path in [&root, &root.join("Inputs"), &root.join("Output")] {
        directory(host, path)?;
    }
    copy(
        host,
        &host.p(&format!("Keys/{who}.json")),
        &root.join("Identity.json"),
    )?;
    let mut converted = Vec::new();
    let mut output: Option<(PathBuf, PathBuf)> = None;
    for (index, arg) in arguments.iter().enumerate() {
        if arg == &text(&host.p(&format!("{who}Floor")))? {
            converted.push("/Operator/Floor".into());
        } else if arg == &text(&host.p(&format!("Keys/{who}.json")))? {
            converted.push("/Operator/Identity.json".into());
        } else if arg == &text(&host.p("Native/Clock/Public/ClockHealth.cbor"))? {
            converted.push("/Clock/ClockHealth.cbor".into());
        } else if arg == &text(&host.p("A1/Launch/State/Control/Control.sock"))? {
            converted.push("/Authority/Control.sock".into());
        } else if arg == &text(&host.p("PageStore/Launch/State/Control/Control.sock"))? {
            converted.push("/Content/Control.sock".into());
        } else if index > 0 && arguments[index - 1] == "--progress-directory" {
            ensure!(
                Path::new(arg).starts_with(&host.c.root),
                "native progress escapes host"
            );
            converted.push(format!("/Operator/Progress-{}", digest(arg.as_bytes())));
        } else if index > 0
            && (arguments[index - 1] == "--output"
                || (arguments[index - 1] == "--receipt"
                    && arguments
                        .iter()
                        .any(|a| a == "admit-member" || a == "register")))
        {
            ensure!(output.is_none(), "multiple native output paths");
            let path = PathBuf::from(arg);
            ensure!(
                path.starts_with(&host.c.root),
                "native output escapes retained host"
            );
            let name = digest(arg.as_bytes());
            converted.push(format!("/Operator/Output/{name}"));
            output = Some((path, root.join("Output").join(name)));
        } else if Path::new(arg).is_absolute() {
            let path = Path::new(arg);
            ensure!(
                path.starts_with(&host.c.root),
                "native input escapes retained host"
            );
            let data = files::public_file(path, 1_048_576)?;
            let name = digest(&data);
            copy(host, path, &root.join("Inputs").join(&name))?;
            converted.push(format!("/Operator/Inputs/{name}"));
        } else {
            converted.push(arg.clone());
        }
    }
    if converted.iter().any(|v| v == "--clock-witness") {
        converted.extend(bytes(&[
            "--clock-monitor-key",
            &host.monitor()?,
            "--host-kernel-boot",
            "CurrentHost",
        ]));
    }
    if let Some((destination, source)) = &output
        && podman(
            host,
            &bytes(&["unshare", "/usr/bin/test", "-f", &text(source)?]),
        )
        .is_ok()
    {
        export(host, source, destination)?;
        return Ok(json!({"status":"RecoveredNativeOutput"}));
    }
    let mut command = bytes(&[
        "run",
        "--rm",
        "--pull=never",
        "--network=none",
        "--userns=nomap",
        "--user=1000:1000",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--read-only",
        "--pids-limit=64",
        "--memory=268435456",
        "--cpus=1",
        "--log-driver=none",
        "--workdir=/Operator",
        "--entrypoint=/HyperNetSuite",
    ]);
    for (path, target, mode) in [
        (host.c.suite.clone(), "/HyperNetSuite", "ro"),
        (root, "/Operator", "rw"),
        (host.p("Native/Clock/Public"), "/Clock", "ro"),
        (host.p("A1/Launch/State/Control"), "/Authority", "ro"),
    ] {
        command.extend(bytes(&[
            "--volume",
            &format!(
                "{}:{target}:{mode},nosuid,nodev",
                host_isolation::argument(&path)?
            ),
        ]));
    }
    if arguments.first().is_some_and(|s| s == "pages")
        && host.p("PageStore/Launch/State/Control").is_dir()
    {
        command.extend(bytes(&[
            "--volume",
            &format!(
                "{}:/Content:ro,nosuid,nodev",
                host_isolation::argument(&host.p("PageStore/Launch/State/Control"))?
            ),
        ]));
    }
    command.push(host.state.image.clone());
    command.extend(converted);
    let result = if arguments.first().is_some_and(|s| s == "pages")
        && arguments.get(1).is_some_and(|s| s == "inspect")
    {
        podman(host, &command)?;
        json!({"status":"PageInspectionSaved"})
    } else {
        invoke(
            Path::new("/usr/bin/podman"),
            &command,
            host.cancel,
            host.end,
            &host.state.phase,
        )?
    };
    if let Some((destination, source)) = output {
        export(host, &source, &destination)?;
    }
    Ok(result)
}
pub fn initialise(host: &Host<'_>, who: &str) -> Result<()> {
    if podman(
        host,
        &bytes(&[
            "unshare",
            "/usr/bin/test",
            "-d",
            &text(&host.p(&format!("Op{who}/Floor")))?,
        ]),
    )
    .is_err()
    {
        let mut a = bytes(&[
            "authority-inspection",
            "initialise",
            "--requester",
            &string(&host.state.results[who], "publicKey")?,
        ]);
        a.extend(host.trust()?);
        a.extend(bytes(&[
            "--directory",
            &text(&host.p(&format!("{who}Floor")))?,
            "--clock-witness",
            &text(&host.p("Native/Clock/Public/ClockHealth.cbor"))?,
        ]));
        operator(host, who, &a)?;
    }
    Ok(())
}
pub fn authority_ready(host: &Host<'_>) -> Result<Value> {
    initialise(host, "Administrator")?;
    // Stream status verifies a current quorum without replacing unfinished owner work.
    let mut a = bytes(&["authority-inspection", "stream-status"]);
    a.extend(online(host, "Administrator")?);
    let value = operator(host, "Administrator", &a)?;
    ensure!(
        value["status"] == "StreamStatus",
        "authority readiness response differs"
    );
    Ok(value)
}
pub fn record_reference(value: &Value, kind: u64) -> Result<String> {
    let records = value["result"][3]
        .as_array()
        .context("native records absent")?;
    let r = records
        .iter()
        .find(|r| r[0].as_u64() == Some(kind))
        .context("native record absent")?;
    Ok(format!(
        "{}:{}:{}",
        string(&r[1], "hex")?,
        r[2].as_u64().context("native generation absent")?,
        string(&r[3], "hex")?
    ))
}

// Retired public exports can be removed only through the confined mapped owner.
pub fn retire_export(host: &Host<'_>, who: &str, destination: &Path) -> Result<()> {
    ensure!(
        matches!(who, "Administrator") && destination.starts_with(host.p("ReceiverClient")),
        "unexpected retired export"
    );
    let name = digest(text(destination)?.as_bytes());
    mapped_write(
        host,
        &host.p(&format!("Op{who}/Output")),
        &name,
        "mapped-remove",
        &[],
    )?;
    files::remove(destination)
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub enum ExportKind {
    Input,
    Output,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredExport {
    pub kind: ExportKind,
    pub name: String,
    pub sha256: String,
}
fn valid_exports(entries: &[RetiredExport]) -> Result<()> {
    ensure!(
        !entries.is_empty() && entries.len() <= 4,
        "retired export batch exceeds bound"
    );
    for e in entries {
        ensure!(
            crate::admission::protocol::identifier(&e.name)
                && crate::admission::protocol::identifier(&e.sha256),
            "retired export identity differs"
        );
    }
    Ok(())
}
pub fn retire_exports(host: &Host<'_>, who: &str, entries: &[RetiredExport]) -> Result<()> {
    ensure!(
        who.starts_with("Manager")
            && who.len() <= 40
            && who.bytes().all(|c| c.is_ascii_alphanumeric()),
        "retired exports require an activation manager"
    );
    valid_exports(entries)?;
    let root = host.p(&format!("Op{who}"));
    let arguments = bytes(&[
        "run",
        "--interactive",
        "--rm",
        "--pull=never",
        "--network=none",
        "--userns=nomap",
        "--user=1000:1000",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--read-only",
        "--pids-limit=32",
        "--memory=134217728",
        "--cpus=1",
        "--log-driver=none",
        "--volume",
        &format!(
            "{}:/HyperNetSuite:ro,nosuid,nodev",
            host_isolation::argument(&host.c.suite)?
        ),
        "--volume",
        &format!(
            "{}:/Inputs:rw,nosuid,nodev",
            host_isolation::argument(&root.join("Inputs"))?
        ),
        "--volume",
        &format!(
            "{}:/Output:rw,nosuid,nodev",
            host_isolation::argument(&root.join("Output"))?
        ),
        "--entrypoint=/HyperNetSuite",
        &host.state.image,
        "admission-host",
        "mapped-retire",
        "--inputs",
        "/Inputs",
        "--outputs",
        "/Output",
    ]);
    let arguments: Vec<std::ffi::OsString> = arguments.iter().map(Into::into).collect();
    let result = crate::admission::helper::output(
        Path::new("/usr/bin/podman"),
        &arguments,
        &serde_json::to_vec(entries)?,
        host.cancel,
        std::time::Duration::from_secs(60),
    )?;
    ensure!(
        serde_json::from_slice::<Value>(&result)?["status"] == "Ready",
        "export retirement failed"
    );
    Ok(())
}
fn retire_checked(inputs: &Path, outputs: &Path, entries: &[RetiredExport]) -> Result<()> {
    crate::admission::private::directory(inputs)?;
    crate::admission::private::directory(outputs)?;
    valid_exports(entries)?;
    // Check the whole batch before deleting; exact missing files support interrupted retries.
    let mut paths = Vec::new();
    for e in entries {
        let path = match e.kind {
            ExportKind::Input => inputs,
            ExportKind::Output => outputs,
        }
        .join(&e.name);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                ensure!(
                    digest(&files::read(&path, 1_048_576)?) == e.sha256,
                    "retired export changed"
                );
                paths.push(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    for path in paths {
        files::remove(&path)?;
    }
    Ok(())
}
pub fn retire_input(inputs: &Path, outputs: &Path) -> Result<()> {
    let mut input = Vec::new();
    std::io::stdin().take(4097).read_to_end(&mut input)?;
    ensure!(input.len() <= 4096, "retired export request exceeds bound");
    let entries: Vec<RetiredExport> = serde_json::from_slice(&input)?;
    retire_checked(inputs, outputs, &entries)?;
    crate::print_value(&json!({"status":"Ready"}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retired_exports_check_complete_batch_and_resume_exact_missing_files() {
        let root =
            std::env::temp_dir().join(format!("hypernet-exports-{}", crate::random_hex::<16>()));
        files::directory(&root).unwrap();
        let outcome = (|| -> Result<()> {
            let inputs = root.join("Inputs");
            let outputs = root.join("Output");
            files::directory(&inputs)?;
            files::directory(&outputs)?;
            let a = RetiredExport {
                kind: ExportKind::Input,
                name: digest(b"receipt"),
                sha256: digest(b"receipt"),
            };
            let b = RetiredExport {
                kind: ExportKind::Output,
                name: digest(b"request path"),
                sha256: digest(b"request"),
            };
            files::exact_file(&inputs.join(&a.name), b"receipt")?;
            files::exact_file(&outputs.join(&b.name), b"changed")?;
            let entries = [a.clone(), b.clone()];
            assert!(retire_checked(&inputs, &outputs, &entries).is_err());
            assert_eq!(files::read(&inputs.join(&a.name), 32)?, b"receipt");
            files::remove(&outputs.join(&b.name))?;
            files::exact_file(&outputs.join(&b.name), b"request")?;
            // An interrupted batch has already removed one exact export.
            files::remove(&inputs.join(&a.name))?;
            retire_checked(&inputs, &outputs, &entries)?;
            retire_checked(&inputs, &outputs, &entries)?;
            assert!(!outputs.join(&b.name).exists());
            let sentinel = root.join("Identity.json");
            files::exact_file(&sentinel, b"retained native state")?;
            std::os::unix::fs::symlink(&sentinel, inputs.join(&a.name))?;
            assert!(retire_checked(&inputs, &outputs, &entries).is_err());
            std::fs::remove_file(inputs.join(&a.name))?;
            std::fs::hard_link(&sentinel, inputs.join(&a.name))?;
            assert!(retire_checked(&inputs, &outputs, &entries).is_err());
            std::fs::remove_file(inputs.join(&a.name))?;
            assert_eq!(files::read(&sentinel, 64)?, b"retained native state");
            let escape = RetiredExport {
                kind: ExportKind::Input,
                name: "../Identity.json".into(),
                sha256: digest(b"retained native state"),
            };
            assert!(retire_checked(&inputs, &outputs, &[escape]).is_err());
            Ok(())
        })();
        std::fs::remove_dir_all(&root).unwrap();
        outcome.unwrap();
    }
}
