// SPDX-License-Identifier: MIT
// Desktop activation carries private invitations over the user bus and helper stdin, never process arguments.
use super::{
    desktop, helper,
    location::{Application, Location},
    runtime,
};
use anyhow::{Result, ensure};
use serde_json::json;
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::Write,
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{SyncSender, sync_channel},
    },
    time::Duration,
};
use zeroize::Zeroize;
const NAME: &str = "org.federatedindustrial.HyperNetSuite";
const OBJECT: &str = "/org/federatedindustrial/HyperNetSuite";
struct Request {
    location: Option<String>,
}
impl Drop for Request {
    fn drop(&mut self) {
        self.location.zeroize();
    }
}
struct Launcher {
    sender: SyncSender<Request>,
    busy: Arc<AtomicBool>,
}
impl Launcher {
    fn queue(&self, location: Option<String>) -> zbus::fdo::Result<()> {
        if location
            .as_ref()
            .is_some_and(|s| Location::parse(s).is_err())
        {
            return Err(zbus::fdo::Error::InvalidArgs(
                "A valid HyperNet server invitation is required".into(),
            ));
        }
        if self
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(zbus::fdo::Error::LimitsExceeded(
                "A HyperNet join window is already open".into(),
            ));
        }
        if self.sender.try_send(Request { location }).is_err() {
            self.busy.store(false, Ordering::Release);
            return Err(zbus::fdo::Error::Failed("Join launcher unavailable".into()));
        }
        Ok(())
    }
}
#[zbus::interface(name = "org.freedesktop.Application")]
impl Launcher {
    fn activate(
        &self,
        _platform_data: HashMap<String, zbus::zvariant::OwnedValue>,
    ) -> zbus::fdo::Result<()> {
        self.queue(None)
    }
    fn open(
        &self,
        mut uris: Vec<String>,
        _platform_data: HashMap<String, zbus::zvariant::OwnedValue>,
    ) -> zbus::fdo::Result<()> {
        if uris.len() != 1 {
            return Err(zbus::fdo::Error::InvalidArgs(
                "Open one server invitation at a time".into(),
            ));
        }
        self.queue(uris.pop())
    }
    fn activate_action(
        &self,
        _action_name: String,
        _parameter: Vec<zbus::zvariant::OwnedValue>,
        _platform_data: HashMap<String, zbus::zvariant::OwnedValue>,
    ) -> zbus::fdo::Result<()> {
        Err(zbus::fdo::Error::NotSupported(
            "Use the HyperNet join window".into(),
        ))
    }
}
fn launch(request: &Request, stop: &AtomicBool) -> Result<()> {
    let requested = request
        .location
        .as_ref()
        .map(|s| Location::parse(s))
        .transpose()?
        .map_or(Application::Native, |l| l.application);
    let hrc = if requested == Application::Hrc {
        desktop::discover("hrc")
    } else {
        None
    };
    let application = if hrc.is_some() {
        Application::Hrc
    } else {
        Application::Native
    };
    let executable = std::env::current_exe()?.canonicalize()?;
    let mut args = vec![
        "join".into(),
        "desktop".into(),
        "--application".into(),
        application.name().into(),
    ];
    if let Some(hrc) = &hrc {
        args.push("--hrc-executable".into());
        args.push(hrc.as_os_str().into());
    }
    let result = helper::interactive(
        &executable,
        &args,
        &json!({"location":request.location}),
        stop,
    )?;
    ensure!(
        result.get("status").and_then(serde_json::Value::as_str) == Some("Joined"),
        "server join did not complete"
    );
    if let Some(hrc) = hrc {
        let path = result
            .get("hrcProfile")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("joined chat profile absent"))?;
        super::private::directory(Path::new(path))?;
        Command::new(hrc)
            .args(["gui", "--profile", path])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()?;
    }
    Ok(())
}
pub fn serve(stop: Arc<AtomicBool>) -> Result<serde_json::Value> {
    let (sender, receiver) = sync_channel(1);
    let busy = Arc::new(AtomicBool::new(false));
    let _connection = zbus::blocking::connection::Builder::session()?
        .name(NAME)?
        .max_queued(4)
        .serve_at(
            OBJECT,
            Launcher {
                sender,
                busy: busy.clone(),
            },
        )?
        .build()?;
    let mut idle = 0;
    while !stop.load(Ordering::Acquire) {
        match receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(request) => {
                let _ = launch(&request, &stop);
                busy.store(false, Ordering::Release);
                idle = 0;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                idle += 1;
                if idle >= 240 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    Ok(json!({"status":"DesktopActivationStopped"}))
}
fn directory(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "desktop data path must be absolute");
    let mut missing = vec![];
    let mut current = path;
    while !current.exists() {
        missing.push(current.to_owned());
        current = current
            .parent()
            .ok_or_else(|| anyhow::anyhow!("desktop data parent absent"))?;
    }
    for path in missing.into_iter().rev() {
        std::fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    ensure!(
        path.canonicalize()? == path,
        "desktop data path must be canonical"
    );
    for parent in path.ancestors() {
        let m = std::fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir()
                && (m.uid() == 0 || m.uid() == unsafe { libc::geteuid() })
                && (m.mode() & 0o022 == 0 || (m.uid() == 0 && m.mode() & 0o1000 != 0)),
            "desktop data directory permits replacement"
        );
    }
    let m = std::fs::metadata(path)?;
    ensure!(
        m.uid() == unsafe { libc::geteuid() },
        "desktop data directory is not owned"
    );
    Ok(())
}
fn metadata(path: &Path, text: &str) -> Result<()> {
    let parent = path.parent().unwrap();
    directory(parent)?;
    if let Ok(m) = std::fs::symlink_metadata(path) {
        ensure!(
            m.is_file()
                && m.nlink() == 1
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o022 == 0,
            "desktop registration file is not owned"
        );
    }
    let temporary = parent.join(format!(".hypernet-{}", crate::random_hex::<16>()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}
fn quoted(path: &Path, desktop: bool) -> Result<String> {
    let path = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("desktop executable path is not UTF-8"))?;
    ensure!(
        !path.chars().any(char::is_control),
        "desktop executable path contains controls"
    );
    let value = path
        .replace('\\', "\\\\\\\\")
        .replace('"', "\\\"")
        .replace('`', "\\`")
        .replace('$', "\\$");
    let value = if desktop {
        value.replace('%', "%%")
    } else {
        value
    };
    Ok(format!("\"{value}\""))
}
pub fn install() -> Result<serde_json::Value> {
    let executable = std::env::current_exe()?.canonicalize()?;
    runtime::executable(&executable)?;
    let base = std::env::var_os("XDG_DATA_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .ok_or_else(|| anyhow::anyhow!("desktop data directory unavailable"))?;
    let desktop = base.join("applications").join(format!("{NAME}.desktop"));
    let service = base.join("dbus-1/services").join(format!("{NAME}.service"));
    let service_executable = quoted(&executable, false)?;
    let executable = quoted(&executable, true)?;
    metadata(
        &desktop,
        &format!(
            "[Desktop Entry]\nType=Application\nVersion=1.0\nName=HyperNet\nComment=Join servers and read HyperNet Pages\nExec={executable} join desktop\nDBusActivatable=true\nTerminal=false\nCategories=Network;\nMimeType=x-scheme-handler/hypernet-join;\nStartupNotify=true\n"
        ),
    )?;
    metadata(
        &service,
        &format!(
            "[D-BUS Service]\nName={NAME}\nExec={service_executable} join activation-service\n"
        ),
    )?;
    let mut mime = Command::new("/usr/bin/xdg-mime")
        .args([
            "default",
            &format!("{NAME}.desktop"),
            "x-scheme-handler/hypernet-join",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let until = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = mime.try_wait()? {
            ensure!(
                status.success(),
                "desktop files installed but default link handler could not be registered"
            );
            break;
        }
        if std::time::Instant::now() >= until {
            let _ = mime.kill();
            let _ = mime.wait();
            anyhow::bail!("desktop handler registration timed out");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Ok(
        json!({"status":"DesktopInstalled","desktop":desktop,"service":service,"privateInvitationsInArguments":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn activation_bounds_urls_and_never_replaces_an_open_review() {
        let (sender, receiver) = sync_channel(1);
        let busy = Arc::new(AtomicBool::new(false));
        let launcher = Launcher {
            sender,
            busy: busy.clone(),
        };
        assert!(launcher.queue(Some("file:///tmp/program".into())).is_err());
        assert!(!busy.load(Ordering::Acquire));
        launcher
            .queue(Some("https://server.example/join".into()))
            .unwrap();
        assert!(
            launcher
                .queue(Some("https://other.example/join".into()))
                .is_err()
        );
        assert_eq!(
            receiver.try_recv().unwrap().location.as_deref(),
            Some("https://server.example/join")
        );
    }
}
