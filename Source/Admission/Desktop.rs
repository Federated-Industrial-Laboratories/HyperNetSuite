// SPDX-License-Identifier: MIT
// The common desktop join flow reviews server permissions before admitting locally generated identities.
use super::{
    agents, client, local,
    location::{Application, Location},
    protocol, runtime, saved,
};
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
use zeroize::Zeroize;

fn root() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|s| PathBuf::from(s).join(".local/state")))
        .ok_or_else(|| anyhow::anyhow!("local state directory unavailable"))?;
    ensure!(base.is_absolute(), "local state directory must be absolute");
    let root = base.join("HyperNetSuite/Servers");
    let mut missing = vec![];
    let mut current = root.as_path();
    while !current.exists() {
        missing.push(current.to_owned());
        current = current
            .parent()
            .ok_or_else(|| anyhow::anyhow!("local state parent unavailable"))?;
    }
    for path in missing.into_iter().rev() {
        saved::create_directory(&path)?;
    }
    super::private::directory(&root)?;
    Ok(root)
}
pub fn discover(name: &str) -> Option<PathBuf> {
    let sibling = std::env::current_exe().ok()?.parent()?.join(name);
    let search = std::env::var_os("PATH").unwrap_or_default();
    let paths =
        std::iter::once(sibling).chain(std::env::split_paths(&search).map(|p| p.join(name)));
    paths
        .filter_map(|p| p.canonicalize().ok())
        .find(|p| runtime::executable(p).is_ok())
}
fn defaults(application: Application) -> runtime::Configuration {
    runtime::Configuration {
        core: if application == Application::Hrc {
            discover("HyperNet")
        } else {
            None
        },
        chronyc: discover("chronyc").unwrap_or_else(|| "/usr/bin/chronyc".into()),
        chronyd: Some(discover("chronyd").unwrap_or_else(|| "/usr/sbin/chronyd".into())),
        ..Default::default()
    }
}
fn entries(root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = vec![];
    for entry in std::fs::read_dir(root)?.take(65) {
        let e = entry?;
        ensure!(paths.len() < 64, "saved-server capacity reached");
        ensure!(
            e.file_type()?.is_dir() && e.file_name().to_str().is_some_and(protocol::identifier),
            "unexpected file in saved server list"
        );
        super::private::directory(&e.path())?;
        paths.push(e.path());
    }
    paths.sort();
    Ok(paths)
}
fn directory(root: &Path, location: &Location) -> Result<PathBuf> {
    let mut public = location.clone();
    public.invitation = None;
    public.secret = None;
    for path in entries(root)? {
        let file = path.join("Draft.json");
        if file.try_exists()? {
            let prior: String = saved::read(&file)?;
            let prior = Location::parse(&prior)?;
            if prior.origin == public.origin && prior.identity_pin == public.identity_pin {
                return Ok(path);
            }
        }
    }
    ensure!(entries(root)?.len() < 64, "saved-server capacity reached");
    let directory = root.join(crate::random_hex::<32>());
    saved::create_directory(&directory)?;
    saved::replace(&directory.join("Draft.json"), &public.url(false)?)?;
    Ok(directory)
}
struct Prepared {
    directory: PathBuf,
    metadata: protocol::Metadata,
    runtime: Option<runtime::Runtime>,
    configuration: runtime::Configuration,
}
enum Output {
    Prepared(Box<Prepared>),
    Joined(Value),
    Location(String),
    Updated,
    Installed(Value),
    Closed,
}
struct Job {
    receiver: Receiver<Result<Output, String>>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Job {
    fn new(
        ctx: &egui::Context,
        work: impl FnOnce(&AtomicBool) -> Result<Output> + Send + 'static,
    ) -> Self {
        let (send, receiver) = sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let cancelled = stop.clone();
        let context = ctx.clone();
        let worker = std::thread::spawn(move || {
            let result = work(&cancelled).map_err(|e| format!("{e:#}"));
            let _ = send.send(result);
            context.request_repaint();
        });
        Self {
            receiver,
            stop,
            worker: Some(worker),
        }
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}
struct Window {
    application: Application,
    executable: Option<PathBuf>,
    root: PathBuf,
    location: String,
    name: String,
    password: String,
    configuration: runtime::Configuration,
    prepared: Option<Box<Prepared>>,
    job: Option<Job>,
    error: Option<String>,
    message: String,
    saved: Vec<(PathBuf, String, bool)>,
    selected: Option<PathBuf>,
    result: Arc<Mutex<Option<Value>>>,
    closed: Arc<AtomicBool>,
    qr_path: String,
}
impl Drop for Window {
    fn drop(&mut self) {
        self.password.zeroize();
        self.location.zeroize();
    }
}
fn prepare(
    directory: PathBuf,
    location: String,
    configuration: runtime::Configuration,
    stop: &AtomicBool,
) -> Result<Output> {
    {
        let _ = saved::Session::open(&directory)?;
    }
    let file = directory.join("Runtime.json");
    let configuration = if file.try_exists()? {
        let mut retained = local::configuration(&directory, &file)?;
        if !local::owned(&directory)? {
            if retained
                .core
                .as_ref()
                .is_none_or(|p| runtime::executable(p).is_err())
                && let Some(core) = configuration
                    .core
                    .as_ref()
                    .filter(|p| runtime::executable(p).is_ok())
            {
                retained.core = Some(core.clone());
            }
            if runtime::executable(&retained.chronyc).is_err()
                && runtime::executable(&configuration.chronyc).is_ok()
            {
                retained.chronyc = configuration.chronyc.clone();
            }
            if retained.chrony_socket.is_none()
                && retained
                    .chronyd
                    .as_ref()
                    .is_none_or(|p| runtime::executable(p).is_err())
                && let Some(chronyd) = configuration
                    .chronyd
                    .as_ref()
                    .filter(|p| runtime::executable(p).is_ok())
            {
                retained.chronyd = Some(chronyd.clone());
            }
            saved::replace(&file, &retained)?;
        }
        retained
    } else {
        saved::replace(&file, &configuration)?;
        configuration
    };
    let mut runtime = if local::owned(&directory)? {
        None
    } else {
        Some(runtime::Runtime::start(&directory, &configuration, stop)?)
    };
    if let Some(runtime) = &mut runtime {
        agents::wait_clock(runtime, stop)?;
    }
    let metadata = if directory.join("Server.json").try_exists()? {
        let session = saved::Session::open(&directory)?;
        let state = session.state()?;
        let requested = Location::parse(&location)?;
        ensure!(
            state.metadata.origin == requested.origin.as_str()
                && requested.identity_pin.is_none_or(|pin| hex::encode(pin)
                    == protocol::digest(
                        &hex::decode(&state.metadata.signing_key).unwrap_or_default()
                    )),
            "saved server identity differs from this link"
        );
        state.metadata
    } else {
        let preview = client::run(&directory, &client::Command::Preview { location }, stop)?;
        serde_json::from_value(
            preview
                .get("server")
                .ok_or_else(|| anyhow::anyhow!("server preview absent"))?
                .clone(),
        )?
    };
    Ok(Output::Prepared(Box::new(Prepared {
        directory,
        metadata,
        runtime,
        configuration,
    })))
}
fn join(
    mut prepared: Box<Prepared>,
    location: String,
    name: String,
    mut password: String,
    application: Application,
    executable: Option<PathBuf>,
    stop: &AtomicBool,
) -> Result<Output> {
    let path = prepared.directory.join("Runtime.json");
    if prepared.directory.join("Server.json").try_exists()?
        && saved::read::<saved::State>(&prepared.directory.join("Server.json"))?
            .installed
            .is_some()
    {
        local::desire(&prepared.directory, true)?;
        drop(prepared.runtime.take());
        runtime::ensure_running(&prepared.directory, &path, stop)?;
        return Ok(Output::Joined(local::joined(&prepared.directory, &path)?));
    }
    let location = Location::parse(&location)?;
    if application == Application::Hrc {
        use unicode_segmentation::UnicodeSegmentation;
        ensure!(
            !name.is_empty()
                && name.len() <= 64
                && name.graphemes(true).count() <= 32
                && !name.chars().any(char::is_control),
            "chat display name must fit 64 UTF-8 bytes and 32 characters, without control characters"
        );
    }
    let options = if application == Application::Hrc {
        let runtime = prepared
            .runtime
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("unfinished chat join is owned by another window"))?;
        let rooms = prepared
            .metadata
            .permissions
            .hrc
            .as_ref()
            .and_then(|v| v.pointer("/policy/rooms"))
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("server rooms absent"))?
            .clone();
        Some(client::HrcOptions {
            executable: executable.ok_or_else(|| anyhow::anyhow!("chat executable unavailable"))?,
            companion: runtime.ipc.clone(),
            clock: runtime.hrc_clock.clone().ok_or_else(|| {
                anyhow::anyhow!("install HyperNet Core for the signed chat clock")
            })?,
            classification: json!({"kind":"person"}),
            rooms,
            allow_initiate: false,
            allow_agent_replies: false,
            successor: false,
        })
    } else {
        None
    };
    client::run(
        &prepared.directory,
        &client::Command::Prepare {
            location: location.url(false)?,
            display_name: name,
            minimum_route: 0,
            hrc: options,
        },
        stop,
    )?;
    let admission = if let Some(secret) = &location.secret {
        Some(protocol::Admission::Invite {
            secret: secret.clone(),
        })
    } else if !password.is_empty() {
        Some(protocol::Admission::Password {
            password: std::mem::take(&mut password),
        })
    } else if prepared
        .metadata
        .permissions
        .modes
        .contains(&super::store::Mode::Public)
    {
        Some(protocol::Admission::Public)
    } else {
        None
    };
    password.zeroize();
    let result = client::run(
        &prepared.directory,
        &client::Command::Connect { admission },
        stop,
    )?;
    ensure!(
        result.get("status").and_then(Value::as_str) == Some("Joined"),
        "Join is incomplete: {}. Retry with the same saved server.",
        result
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("Pending")
    );
    drop(prepared.runtime.take());
    runtime::ensure_running(&prepared.directory, &path, stop)?;
    Ok(Output::Joined(local::joined(&prepared.directory, &path)?))
}
impl Window {
    fn refresh(&mut self) {
        let result = entries(&self.root).and_then(|entries| {
            entries
                .into_iter()
                .filter(|d| d.join("Server.json").exists())
                .map(|d| {
                    let s: saved::State = saved::read(&d.join("Server.json"))?;
                    Ok((d, s.metadata.name, s.desired_online))
                })
                .collect::<Result<Vec<_>>>()
        });
        match result {
            Ok(s) => self.saved = s,
            Err(e) => self.error = Some(e.to_string()),
        }
    }
    fn preview(&mut self, ctx: &egui::Context) {
        self.prepared = None;
        self.error = None;
        let result = Location::parse(&self.location).and_then(|l| directory(&self.root, &l));
        match result {
            Ok(directory) => {
                let location = self.location.clone();
                let configuration = self.configuration.clone();
                self.message = "Checking the server and preparing your local connection…".into();
                self.job = Some(Job::new(ctx, move |stop| {
                    prepare(directory, location, configuration, stop)
                }));
            }
            Err(e) => self.error = Some(e.to_string()),
        }
    }
    fn import(&mut self, ctx: &egui::Context, path: PathBuf) {
        self.job = Some(Job::new(ctx, move |_| {
            Ok(Output::Location(super::qr::read(&path)?.url(false)?))
        }));
    }
}
impl eframe::App for Window {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if self.closed.load(Ordering::Acquire) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        if let Some(result) = self.job.as_ref().and_then(|j| j.receiver.try_recv().ok()) {
            self.job = None;
            match result {
                Ok(Output::Prepared(prepared)) => {
                    self.configuration = prepared.configuration.clone();
                    if prepared.directory.join("Server.json").exists()
                        && let Ok(state) =
                            saved::read::<saved::State>(&prepared.directory.join("Server.json"))
                    {
                        self.name = state.display_name;
                    }
                    self.prepared = Some(prepared);
                    self.message.clear();
                }
                Ok(Output::Joined(value)) => {
                    if let Ok(mut result) = self.result.lock() {
                        *result = Some(value);
                    }
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                Ok(Output::Location(location)) => {
                    self.location.zeroize();
                    self.location = location;
                    self.prepared = None;
                    self.error = None;
                    self.message = "Invitation imported. Review the server to continue.".into();
                }
                Ok(Output::Installed(value)) => {
                    if let Some(core) = value.get("coreExecutable").and_then(Value::as_str) {
                        let path = PathBuf::from(core);
                        if runtime::executable(&path).is_ok() {
                            self.configuration.core = Some(path);
                        }
                    }
                    self.message = "Signed native installation verified.".into();
                }
                Ok(Output::Closed) => {
                    self.message.clear();
                }
                Ok(Output::Updated) => {
                    self.refresh();
                    self.message = "Saved choice updated.".into();
                }
                Err(error) => {
                    self.error = Some(error);
                    self.refresh();
                    self.message.clear();
                }
            }
        }
        let dropped = ctx.input(|i| i.raw.dropped_files.first().map(|f| f.path().to_owned()));
        if self.job.is_none()
            && let Some(path) = dropped
        {
            self.import(&ctx, path);
        }
        egui::CentralPanel::default().show(ui,|ui|{
            ui.heading(if self.application==Application::Hrc{"Join HyperNet RelayChat"}else{"Join HyperNet"});
            ui.label("Open a server link, import its QR code, or enter its address. Your keys stay on this device.");ui.add_space(12.0);
            if let Some(error)=&self.error {ui.colored_label(egui::Color32::from_rgb(245,130,110),error);ui.label("Your saved keys and unfinished operations have been retained. Correct the cause and retry.");ui.add_space(8.0);}
            if self.job.is_some(){ui.horizontal(|ui|{ui.spinner();ui.label(&self.message);if ui.button("Cancel").clicked() && let Some(job)=&self.job{job.stop.store(true,Ordering::Release);}});return;}
            if !self.message.is_empty(){ui.label(&self.message);}
            if self.prepared.is_none() {
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Install / repair components").clicked() {
                        self.job = Some(Job::new(&ctx, move |stop| {
                            let result = super::helper::interactive(&std::env::current_exe()?.canonicalize()?, &["join".into(), "setup-desktop".into()], &Value::Null, stop)?;
                            Ok(result.get("installation").filter(|v| !v.is_null()).cloned().map_or(Output::Closed, Output::Installed))
                        }));
                    }
                    if ui.button("Create / manage a server").clicked() {
                        let hrc = self.executable.clone();
                        self.job = Some(Job::new(&ctx, move |stop| {
                            let mut args = vec!["join".into(), "host-desktop".into()];
                            if let Some(hrc) = hrc { args.push("--hrc-executable".into()); args.push(hrc.into_os_string()); }
                            super::helper::interactive(&std::env::current_exe()?.canonicalize()?, &args, &Value::Null, stop)?;
                            Ok(Output::Closed)
                        }));
                    }
                });
            }
            ui.add_enabled_ui(self.prepared.is_none(),|ui|{ui.label("Server address or private invitation");ui.add(egui::TextEdit::singleline(&mut self.location).desired_width(f32::INFINITY).hint_text("https://server.example/join or hypernet-join://…"));
                ui.horizontal(|ui|{if ui.button("Review server").clicked(){self.preview(&ctx);}ui.label("You can also drop a QR image here.");});
                ui.collapsing("Import a QR image",|ui|{ui.horizontal(|ui|{ui.text_edit_singleline(&mut self.qr_path);if ui.button("Import image").clicked(){self.import(&ctx,PathBuf::from(&self.qr_path));}});});
            });
            if let Some(prepared)=&self.prepared {
                ui.separator();ui.heading(&prepared.metadata.name);ui.label(&prepared.metadata.origin);
                ui.label(match prepared.metadata.permissions.access {super::store::End::UntilRemoved=>"Access lasts until you or the host remove it.",super::store::End::Expires{..}=>"This server grants time-limited access."});
                if prepared.metadata.permissions.reader{ui.label("Read the server's approved Pages.");}
                if self.application==Application::Hrc{ui.label("Join the advertised community rooms and send messages.");}
                ui.label("This membership cannot create rooms, moderate users, publish Pages or host services.");
                if prepared.metadata.permissions.agents{ui.label("After joining, you may approve separately keyed Agents within the host's limits.");}
                ui.label("Display name");ui.add(egui::TextEdit::singleline(&mut self.name).char_limit(128));
                let needs_password=prepared.metadata.permissions.modes.contains(&super::store::Mode::Password) && Location::parse(&self.location).is_ok_and(|l|l.secret.is_none());
                if needs_password{ui.label("Server password");ui.add(egui::TextEdit::singleline(&mut self.password).password(true).char_limit(128));}
                let valid=!self.name.trim().is_empty()&&(!needs_password||!self.password.is_empty()||prepared.directory.join("Server.json").exists());
                ui.horizontal(|ui|{
                    if ui.add_enabled(valid,egui::Button::new("Join / reconnect")).clicked(){let prepared=self.prepared.take().unwrap();let location=self.location.clone();let name=self.name.trim().to_owned();let password=std::mem::take(&mut self.password);let application=self.application;let executable=self.executable.clone();self.message="Joining with your saved local keys…".into();self.job=Some(Job::new(&ctx,move|stop|join(prepared,location,name,password,application,executable,stop)));}
                    if ui.button("Back").clicked(){self.prepared=None;self.password.zeroize();}
                });
            }else{
                ui.collapsing("Saved servers",|ui|{
                    egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| { for (directory,name,online) in &self.saved {if ui.selectable_label(self.selected.as_ref()==Some(directory),format!("{} · {}",name,if *online{"Reconnect enabled"}else{"Offline"})).clicked(){self.selected=Some(directory.clone());}} });
                    if let Some(directory)=self.selected.clone(){ui.horizontal(|ui|{
                        if ui.button("Open / reconnect").clicked(){match saved::read::<saved::State>(&directory.join("Server.json")){Ok(state)=>{self.location=state.location;let location=self.location.clone();let configuration=self.configuration.clone();self.message="Opening saved server…".into();self.job=Some(Job::new(&ctx,move|stop|prepare(directory.clone(),location,configuration,stop)));},Err(e)=>self.error=Some(e.to_string())}}
                        if ui.button("Stay offline").clicked(){let directory=self.selected.clone().unwrap();self.job=Some(Job::new(&ctx,move |_|{local::desire(&directory,false)?;Ok(Output::Updated)}));}
                    });}
                });
            }
            ui.separator();ui.collapsing("Advanced connection tools",|ui|{
                ui.label("Manual bootstrap files and finite leases remain available through the existing network and authority commands. A server link cannot choose programs or system settings.");
                ui.label("Local clock tools (used without changing system time)");
                for (label,path) in [("chronyc",&mut self.configuration.chronyc),("chronyd",self.configuration.chronyd.get_or_insert_with(||"/usr/sbin/chronyd".into()))]{let mut value=path.display().to_string();ui.horizontal(|ui|{ui.label(label);if ui.text_edit_singleline(&mut value).changed(){*path=PathBuf::from(&value);}});}
                if self.application==Application::Hrc {let mut value=self.configuration.core.as_ref().map(|p|p.display().to_string()).unwrap_or_default();ui.horizontal(|ui|{ui.label("HyperNet Core");if ui.text_edit_singleline(&mut value).changed(){self.configuration.core=Some(value.into());}});}
                ui.label("The packaged setup installs these prerequisites. Use Repair installation if a tool is missing.");
            });
        });
        if self.job.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
}
pub fn run(
    application: Application,
    executable: Option<PathBuf>,
    location: Option<String>,
    stop: Arc<AtomicBool>,
) -> Result<Value> {
    ensure!(
        application != Application::Hrc || executable.is_some(),
        "chat application executable required"
    );
    if let Some(executable) = &executable {
        runtime::executable(executable)?;
    }
    let root = root()?;
    let result = Arc::new(Mutex::new(None));
    let output = result.clone();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Join HyperNet")
            .with_app_id("HyperNetJoin")
            .with_inner_size([740.0, 700.0])
            .with_min_inner_size([560.0, 460.0]),
        renderer: eframe::Renderer::Glow,
        persist_window: false,
        ..Default::default()
    };
    eframe::run_native(
        "Join HyperNet",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            let mut window = Window {
                application,
                executable,
                root,
                location: location.unwrap_or_default(),
                name: String::new(),
                password: String::new(),
                configuration: defaults(application),
                prepared: None,
                job: None,
                error: None,
                message: String::new(),
                saved: vec![],
                selected: None,
                result: output,
                closed: stop,
                qr_path: String::new(),
            };
            window.refresh();
            if application == Application::Hrc && window.configuration.core.is_none() && super::installation::directory().is_ok_and(|p|p.exists()) {
                window.message = "Checking the installed native components…".into();
                window.job = Some(Job::new(&cc.egui_ctx, |stop| Ok(Output::Installed(super::installation::inspect(stop)?))));
            }
            if application==Application::Native && Location::parse(&window.location).is_ok_and(|l|l.application==Application::Hrc) {
                window.message="This window joins read-only Pages. Install RelayChat to join the chat service too.".into();
            }
            Ok(Box::new(window))
        }),
    )
    .map_err(|e| anyhow::anyhow!("cannot open join window: {e}"))?;
    result
        .lock()
        .map_err(|_| anyhow::anyhow!("join result unavailable"))?
        .take()
        .ok_or_else(|| anyhow::anyhow!("join cancelled; saved keys and progress retained"))
}
