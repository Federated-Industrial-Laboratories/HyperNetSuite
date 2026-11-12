// SPDX-License-Identifier: MIT
// The setup window installs a fixed local coordinated release through the native signature and rollback verifiers.
use super::{helper, saved};
use anyhow::{Result, ensure};
use eframe::egui;
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, sync_channel},
    },
    time::Duration,
};
pub fn directory() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|s| PathBuf::from(s).join(".local/state")))
        .ok_or_else(|| anyhow::anyhow!("local state directory unavailable"))?;
    ensure!(base.is_absolute(), "local state directory must be absolute");
    Ok(base.join("HyperNetSuite/Installation"))
}
pub fn release_directory() -> Result<PathBuf> {
    Ok(std::env::current_exe()?
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| anyhow::anyhow!("installed package directory unavailable"))?
        .join("Packages"))
}
pub fn inspect(stop: &AtomicBool) -> Result<Value> {
    let directory = directory()?;
    let bytes = helper::output(
        &std::env::current_exe()?.canonicalize()?,
        &[
            "native-installation".into(),
            "inspect".into(),
            "--directory".into(),
            directory.into_os_string(),
            "--json".into(),
        ],
        &[],
        stop,
        Duration::from_secs(60),
    )?;
    Ok(serde_json::from_slice(&bytes)?)
}
pub fn install(release: &Path, stop: &AtomicBool) -> Result<Value> {
    let directory = directory()?;
    let mut missing = vec![];
    let mut at = directory.parent().unwrap();
    while !at.exists() {
        missing.push(at.to_owned());
        at = at
            .parent()
            .ok_or_else(|| anyhow::anyhow!("installation parent absent"))?;
    }
    for path in missing.into_iter().rev() {
        saved::create_directory(&path)?;
    }
    let bytes = helper::output(
        &std::env::current_exe()?.canonicalize()?,
        &[
            "native-installation".into(),
            "install".into(),
            "--release-directory".into(),
            release.as_os_str().into(),
            "--directory".into(),
            directory.into_os_string(),
            "--json".into(),
        ],
        &[],
        stop,
        Duration::from_secs(1800),
    )?;
    let _: Value = serde_json::from_slice(&bytes)?;
    inspect(stop)
}
struct Job {
    receiver: Receiver<Result<Value, String>>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Job {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
struct Window {
    release: String,
    picker: super::folder_picker::Picker,
    job: Option<Job>,
    result: Arc<Mutex<Option<Value>>>,
    error: Option<String>,
    stop: Arc<AtomicBool>,
}
impl eframe::App for Window {
    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if let Some(path) = self.picker.show(&ctx) {
            self.release = path.display().to_string();
        }
        if self.stop.load(Ordering::Acquire) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        if let Some(result) = self.job.as_ref().and_then(|j| j.receiver.try_recv().ok()) {
            self.job = None;
            match result {
                Ok(value) => {
                    if let Ok(mut result) = self.result.lock() {
                        *result = Some(value);
                    }
                }
                Err(e) => self.error = Some(e),
            }
        }
        egui::CentralPanel::default().show(ui,|ui|{egui::ScrollArea::vertical().show(ui,|ui|{ui.heading("Install or repair HyperNet");ui.label("Install the coordinated Core and Suite packages for this user. The installer checks the pinned publisher, each signature, compatible versions and rollback policy before making them available.");ui.label("Your saved identities, server permissions and unfinished operations are retained.");
        if let Some(error)=&self.error{ui.colored_label(egui::Color32::from_rgb(245,130,110),error);}
        if self.job.is_some(){ui.horizontal(|ui|{ui.spinner();ui.label("Verifying and installing packages…");if ui.button("Cancel").clicked()&&let Some(job)=&self.job{job.stop.store(true,Ordering::Release);}});return;}
        ui.label("Coordinated release folder");ui.horizontal(|ui|{ui.add(egui::TextEdit::singleline(&mut self.release).desired_width(520.0));if ui.button("Browse").clicked(){self.picker.choose(PathBuf::from(&self.release),&ctx);}});ui.small("The release supplies its Packages folder. A server invitation cannot choose packages, programs or signing keys.");
        if ui.button("Install / verify packages").clicked(){let path=PathBuf::from(&self.release);let(send,receiver)=sync_channel(1);let stop=Arc::new(AtomicBool::new(false));let flag=stop.clone();let context=ctx.clone();let worker=std::thread::spawn(move||{let _=send.send(install(&path,&flag).map_err(|e|format!("{e:#}")));context.request_repaint();});self.job=Some(Job{receiver,stop,worker:Some(worker)});}
        if let Ok(result)=self.result.lock()&&result.is_some(){ui.label("Signed installation verified. Return to joining or hosting to continue.");}
        ui.separator();ui.label("System prerequisites");ui.label("Python 3 and chrony are supplied by your Linux distribution. Hosting also needs rootless Podman. Use the software manager if a requirement is missing. Joining uses a private time observer and does not change your system clock.");ui.label("Installing packages does not start a public server or enable new firewall rules.");if ui.button("Return").clicked(){ctx.send_viewport_cmd(egui::ViewportCommand::Close);}
    });});
        if self.job.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
}
pub fn run(stop: Arc<AtomicBool>) -> Result<Value> {
    let result = Arc::new(Mutex::new(None));
    let output = result.clone();
    let release = release_directory()?.display().to_string();
    eframe::run_native(
        "HyperNet setup",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_title("HyperNet setup")
                .with_inner_size([700.0, 530.0]),
            renderer: eframe::Renderer::Glow,
            persist_window: false,
            ..Default::default()
        },
        Box::new(move |cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(Window {
                release,
                picker: Default::default(),
                job: None,
                result: output,
                error: None,
                stop,
            }))
        }),
    )
    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let installed = result
        .lock()
        .map_err(|_| anyhow::anyhow!("installation result unavailable"))?
        .take();
    Ok(json!({"status":"Closed","installation":installed}))
}
