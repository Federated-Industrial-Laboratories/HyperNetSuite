// SPDX-License-Identifier: MIT
// The hosting window reviews resources and permissions and keeps private invitations local until explicitly shared.
use super::{desktop, hosting, location::Location, protocol, qr, saved, store};
use anyhow::Result;
use eframe::egui;
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, sync_channel},
    },
    time::Duration,
};
use zeroize::Zeroize;
struct Job {
    receiver: Receiver<Result<Value, String>>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Job {
    fn new(
        ctx: &egui::Context,
        work: impl FnOnce(&AtomicBool) -> Result<Value> + Send + 'static,
    ) -> Self {
        let (send, receiver) = sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let ctx = ctx.clone();
        let worker = std::thread::spawn(move || {
            let result = work(&flag).map_err(|e| format!("{e:#}"));
            let _ = send.send(result);
            ctx.request_repaint();
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
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn root() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|s| PathBuf::from(s).join(".local/state")))
        .ok_or_else(|| anyhow::anyhow!("user state directory unavailable"))?;
    let path = base.join("HyperNetSuite/Hosts");
    let mut missing = vec![];
    let mut at = path.as_path();
    while !at.exists() {
        missing.push(at.to_owned());
        at = at
            .parent()
            .ok_or_else(|| anyhow::anyhow!("state parent unavailable"))?;
    }
    for p in missing.into_iter().rev() {
        saved::create_directory(&p)?;
    }
    super::private::directory(&path)?;
    Ok(path)
}
fn address() -> String {
    unsafe {
        let mut first = std::ptr::null_mut();
        if libc::getifaddrs(&mut first) != 0 {
            return String::new();
        }
        let mut at = first;
        let mut address = String::new();
        while !at.is_null() {
            let item = &*at;
            if !item.ifa_addr.is_null()
                && (*item.ifa_addr).sa_family as i32 == libc::AF_INET
                && item.ifa_flags & libc::IFF_LOOPBACK as u32 == 0
            {
                let a = &*(item.ifa_addr as *const libc::sockaddr_in);
                address = std::net::Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes()).to_string();
                break;
            }
            at = item.ifa_next;
        }
        libc::freeifaddrs(first);
        address
    }
}
fn packages() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| {
            p.parent()
                .and_then(Path::parent)
                .map(|p| p.join("Packages").display().to_string())
        })
        .unwrap_or_default()
}
struct Window {
    root: PathBuf,
    directory: PathBuf,
    hosts: Vec<PathBuf>,
    selected: Option<PathBuf>,
    hrc: Option<PathBuf>,
    name: String,
    nickname: String,
    motd: String,
    address: String,
    origin: String,
    tls_mode: u8,
    certificate_email: String,
    certificate_terms: bool,
    challenge_port: u16,
    certificate_path: String,
    certificate_key: String,
    join_port: u16,
    relay_port: u16,
    authority_port: u16,
    subnet: u8,
    mode: store::Mode,
    password: String,
    participants: u64,
    agents: bool,
    agent_limit: u8,
    same_organisation: bool,
    access_permanent: bool,
    access_days: u32,
    hosting_permanent: bool,
    hosting_days: u32,
    memory_mib: u64,
    state_mib: u64,
    cpu: u64,
    connection_mib: u64,
    installation: PathBuf,
    release: String,
    picker: super::folder_picker::Picker,
    configuration: Option<hosting::Configuration>,
    preview: Option<Value>,
    status: Option<Value>,
    job: Option<Job>,
    error: Option<String>,
    notice: String,
    link: String,
    instructions: String,
    texture: Option<egui::TextureHandle>,
    export_path: String,
    invite_uses: u32,
    invite_days: u32,
    invite_permanent: bool,
    rotation_password: String,
    confirm_withdraw: bool,
    remove: Option<String>,
    stop: Arc<AtomicBool>,
}
impl Drop for Window {
    fn drop(&mut self) {
        self.password.zeroize();
        self.rotation_password.zeroize();
        self.link.zeroize();
        self.instructions.zeroize();
    }
}
impl Window {
    fn refresh_hosts(&mut self) {
        self.hosts = std::fs::read_dir(&self.root)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                e.file_type().ok().filter(|t| t.is_dir()).and_then(|_| {
                    e.file_name()
                        .to_str()
                        .filter(|s| {
                            protocol::identifier(s) && e.path().join("HostingSetup.json").exists()
                        })
                        .map(|_| e.path())
                })
            })
            .take(33)
            .collect();
        self.hosts.sort();
        if self.hosts.len() > 32 {
            self.error = Some("Saved host capacity reached.".into());
        }
    }
    fn call(&mut self, ctx: &egui::Context, request: hosting::Request) {
        let directory = self.directory.clone();
        self.job = Some(Job::new(ctx, move |stop| {
            hosting::request(&directory, request, stop)
        }));
    }
    fn configuration(&self) -> Result<hosting::Configuration> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as u64;
        let end = |permanent, days: u32| {
            if permanent {
                json!({"untilWithdrawn":1})
            } else {
                json!(now.saturating_add(u64::from(days) * 86400000))
            }
        };
        let ip: std::net::Ipv4Addr = self.address.parse()?;
        let chronyc = desktop::discover("chronyc").ok_or_else(|| {
            anyhow::anyhow!(
                "Install chrony using your distribution's software manager, then retry."
            )
        })?;
        let chronyd = desktop::discover("chronyd").ok_or_else(|| {
            anyhow::anyhow!(
                "Install chrony using your distribution's software manager, then retry."
            )
        })?;
        let origin = if self.origin.trim().is_empty() {
            format!("https://{}:{}/", ip, self.join_port)
        } else {
            Location::parse(self.origin.trim())?.origin.to_string()
        };
        let tls=match self.tls_mode {
            0=>super::host_tls::Configuration::Private,
            1=>super::host_tls::Configuration::Acme {certbot:desktop::discover("certbot").ok_or_else(||anyhow::anyhow!("Install Certbot5.10 or newer for automatic public certificates, or select Native links."))?,email:self.certificate_email.trim().into(),challenge_port:self.challenge_port,terms_accepted:self.certificate_terms},
            _=>super::host_tls::Configuration::Managed {certificate:self.certificate_path.trim().into(),key:self.certificate_key.trim().into()},
        };
        Ok(hosting::Configuration{version:1,tls,installation:self.installation.clone(),origin,listen:format!("{ip}:{}",self.join_port).parse()?,mode:self.mode,podman:desktop::discover("podman").ok_or_else(||anyhow::anyhow!("Install rootless Podman using your distribution's software manager, then retry."))?,native:json!({"name":self.name.trim(),"advertisedAddress":ip,"bindAddress":ip,"relayPort":self.relay_port,"authorityFirstPort":self.authority_port,"subnetOctet":self.subnet,"sameOrganisation":self.same_organisation,"accessEnd":end(self.access_permanent,self.access_days),"hostingEnd":end(self.hosting_permanent,self.hosting_days),"maximumParticipants":self.participants,"clock":{"chronyc":chronyc,"socket":null,"chronyd":chronyd,"timeServer":"time.cloudflare.com"},"resources":{"memoryBytesPerRole":self.memory_mib*1048576,"stateBytesPerRole":self.state_mib*1048576,"cpuQuotaPerRole":self.cpu*1000,"pidsPerRole":128,"connectionBytes":self.connection_mib*1048576,"connectionSeconds":3600,"relayConnections":128,"endpointConnections":64},"hrc":self.hrc.as_ref().map(|p|json!({"executable":p,"nickname":self.nickname.trim(),"motd":self.motd,"agentsEnabled":self.agents,"maxAgentsPerOperator":self.agent_limit}))})})
    }
    fn begin_review(&mut self, ctx: &egui::Context) {
        match self.configuration() {
            Ok(configuration) => {
                self.configuration = Some(configuration.clone());
                self.call(ctx, hosting::Request::Preview { configuration });
            }
            Err(e) => self.error = Some(e.to_string()),
        }
    }
    fn show_link(&mut self, ctx: &egui::Context, link: String, instructions: String) {
        self.link.zeroize();
        self.instructions.zeroize();
        self.link = link;
        self.instructions = instructions;
        self.texture = None;
        if let Ok(location) = Location::parse(&self.link)
            && let Ok(pixels) = qr::pixels(&location)
        {
            let size = [pixels.width() as usize, pixels.height() as usize];
            let image = egui::ColorImage::from_gray(size, pixels.as_raw());
            self.texture = Some(ctx.load_texture(
                "Private server invitation",
                image,
                egui::TextureOptions::NEAREST,
            ));
        }
    }
    fn install(&mut self, ctx: &egui::Context) {
        let release = PathBuf::from(&self.release);
        self.job = Some(Job::new(ctx, move |stop| {
            Ok(
                json!({"status":"InstallationComplete","installation":super::installation::install(&release,stop)?}),
            )
        }));
    }

    fn setup(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.heading("Create a server");
        ui.label("Share a link or QR code. People generate their own keys and join with the permissions you choose.");
        ui.label("Server name");
        ui.text_edit_singleline(&mut self.name);
        ui.label("This computer's reachable IPv4 address");
        ui.text_edit_singleline(&mut self.address);
        ui.small("For Internet access, use an address assigned to this server and allow the reviewed ports in its firewall. A home LAN address reaches only that LAN unless your network provides forwarding.");
        ui.horizontal(|ui| {
            ui.label("Joining");
            ui.selectable_value(&mut self.mode, store::Mode::InviteOnly, "Invite only");
            ui.selectable_value(&mut self.mode, store::Mode::Password, "Password");
            ui.selectable_value(&mut self.mode, store::Mode::Public, "Public");
        });
        if self.mode == store::Mode::Password {
            ui.label("Server password (12 to 128 bytes)");
            ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
        }
        if self.mode == store::Mode::Public {
            ui.label("Anyone who knows this server address can join within your capacity and permissions.");
        }
        ui.collapsing("How people open the link", |ui| {
            ui.radio_value(&mut self.tls_mode,0,"Native links (private TLS authority)");
            ui.radio_value(&mut self.tls_mode,1,"Public HTTPS with automatic certificates");
            ui.radio_value(&mut self.tls_mode,2,"Use certificates managed by another tool");
            match self.tls_mode {
                0=>{ui.small("The app verifies the private authority from your link. QR codes open the native app. No certificate authority is contacted.");},
                1=>{
                    ui.label("Certificate contact email");ui.text_edit_singleline(&mut self.certificate_email);
                    ui.horizontal(|ui|{ui.label("Certificate challenge port");ui.add(egui::DragValue::new(&mut self.challenge_port).range(1025..=65535));});
                    ui.small("Forward public TCP80 to this challenge port on this computer. Keep that forwarding for automatic renewal. The challenge listener is isolated and serves only temporary validation tokens.");
                    ui.hyperlink_to("Read Let's Encrypt subscriber terms","https://letsencrypt.org/repository/");
                    ui.checkbox(&mut self.certificate_terms,"I accept the certificate authority's terms and disclosure of my server address in public certificates.");
                    ui.small("Certbot5.10 or newer is required. The certificate authority receives the contact email and server address.");
                },
                _=>{
                    ui.label("Certificate chain PEM file");ui.text_edit_singleline(&mut self.certificate_path);
                    ui.label("Private-key PEM file");ui.text_edit_singleline(&mut self.certificate_key);
                    ui.small("Use private files readable by your account. Your certificate manager renews them; the host checks for changes every minute. Keep the same paths.");
                },
            }
        });
        ui.checkbox(&mut self.access_permanent, "Access until removed");
        if !self.access_permanent {
            ui.horizontal(|ui| {
                ui.label("Access days");
                ui.add(egui::DragValue::new(&mut self.access_days).range(1..=3650));
            });
        }
        ui.checkbox(
            &mut self.hosting_permanent,
            "Run until stopped or withdrawn",
        );
        if !self.hosting_permanent {
            ui.horizontal(|ui| {
                ui.label("Hosting consent days");
                ui.add(egui::DragValue::new(&mut self.hosting_days).range(1..=3650));
            });
        }
        ui.horizontal(|ui| {
            ui.label("Participants, including you");
            ui.add(
                egui::DragValue::new(&mut self.participants)
                    .range(2..=if self.hrc.is_some() { 32 } else { 64 }),
            );
        });
        ui.label("Ordinary users can read Pages and, when chat is enabled, join the welcome room and send messages. Room creation, moderation, publication and hosting are off.");
        if self.hrc.is_some() {
            ui.label("Your owner nickname");
            ui.text_edit_singleline(&mut self.nickname);
            ui.label("Welcome message");
            ui.text_edit_multiline(&mut self.motd);
            ui.checkbox(
                &mut self.agents,
                "Allow separately keyed Agents with their operator's consent",
            );
            if self.agents {
                ui.horizontal(|ui| {
                    ui.label("Agents per operator");
                    ui.add(egui::DragValue::new(&mut self.agent_limit).range(1..=8));
                });
            }
        }
        ui.checkbox(
            &mut self.same_organisation,
            "I operate this server's relay and destinations in the same organisation.",
        );
        ui.small(
            "This topology does not provide independent operators or independent fault domains.",
        );
        ui.collapsing("Resources and connection settings",|ui|{ui.horizontal(|ui|{ui.label("Memory per native role (MiB)");ui.add(egui::DragValue::new(&mut self.memory_mib).range(256..=8192));});ui.horizontal(|ui|{ui.label("State per native role (MiB)");ui.add(egui::DragValue::new(&mut self.state_mib).range(1024..=1048576));});ui.horizontal(|ui|{ui.label("CPU per native role (%)");ui.add(egui::DragValue::new(&mut self.cpu).range(10..=800));});ui.horizontal(|ui|{ui.label("Bytes per connection (MiB)");ui.add(egui::DragValue::new(&mut self.connection_mib).range(1..=1024));});for(label,port)in[("Join HTTPS port",&mut self.join_port),("Relay port",&mut self.relay_port),("First authority port",&mut self.authority_port)]{ui.horizontal(|ui|{ui.label(label);ui.add(egui::DragValue::new(port).range(1025..=65530));});}ui.horizontal(|ui|{ui.label("Private subnet start");ui.add(egui::DragValue::new(&mut self.subnet).range(1..=251));});ui.label("Optional HTTPS origin with the same joining port");ui.text_edit_singleline(&mut self.origin);ui.small("The shared native link pins the server's private TLS authority. Browsers need a publicly trusted certificate to open HTTPS without a certificate warning.");});
        ui.collapsing("Install or repair signed native packages",|ui|{ui.label("Use the coordinated release's Packages folder. The installer checks the pinned publisher, signatures and rollback rules before installing Core and Suite together.");ui.horizontal(|ui|{ui.add(egui::TextEdit::singleline(&mut self.release).desired_width(520.0));if ui.button("Browse").clicked(){self.picker.choose(PathBuf::from(&self.release),ctx);}});if ui.button("Install / verify packages").clicked(){self.install(ctx);}ui.small(self.installation.display().to_string());ui.small("Podman, chrony and Python 3 come from your distribution's software manager. The native package installer reports any missing system requirements.");});
        if ui
            .add_enabled(
                self.same_organisation && !self.name.trim().is_empty(),
                egui::Button::new("Review server setup"),
            )
            .clicked()
        {
            self.begin_review(ctx);
        }
    }
    fn review(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.heading("Review this server");
        let configuration = self.configuration.as_ref().unwrap();
        ui.label(format!("{} at {}", self.name, configuration.origin));
        ui.label(format!(
            "{} participant places, including your owner account.",
            self.participants
        ));
        ui.label(if self.access_permanent {
            "Members keep access until removed."
        } else {
            "Member access ends at the reviewed finite expiry."
        });
        ui.label(if self.hosting_permanent{"This computer will keep hosting across service restarts until you stop it or withdraw consent."}else{"Hosting stops when the reviewed consent expires."});
        ui.label("The public listener has a separate local identity and 128 MiB memory limit. Native authority keys, your owner account and private service state are not mounted into it.");
        if self
            .preview
            .as_ref()
            .and_then(|v| v.get("startsAfterLogout"))
            .and_then(Value::as_bool)
            != Some(true)
        {
            ui.label("Unattended user services are currently disabled. Hosting may stop after logout until you enable them in the dashboard.");
        }
        if let Some(tls) = self.preview.as_ref().and_then(|v| v.get("tls")) {
            ui.label(
                tls.get("connection")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            );
            if let Some(text) = tls.get("requirement").and_then(Value::as_str) {
                ui.label(text);
            }
            if let Some(text) = tls.get("disclosure").and_then(Value::as_str) {
                ui.label(text);
            }
        }
        ui.collapsing("Exact native requirements and exposure", |ui| {
            if let Some(v) = self.preview.as_ref().and_then(|v| v.get("native")) {
                ui.monospace(serde_json::to_string_pretty(v).unwrap_or_default());
            }
        });
        ui.horizontal(|ui| {
            if ui.button("Create and start server").clicked() {
                let configuration = self.configuration.clone().unwrap();
                let review_digest = self
                    .preview
                    .as_ref()
                    .and_then(|v| v.get("reviewDigest"))
                    .and_then(Value::as_str)
                    .unwrap()
                    .to_owned();
                let password = if self.password.is_empty() {
                    None
                } else {
                    Some(std::mem::take(&mut self.password))
                };
                self.call(
                    ctx,
                    hosting::Request::Create {
                        configuration,
                        review_digest,
                        password,
                    },
                );
            }
            if ui.button("Back").clicked() {
                self.preview = None;
            }
        });
    }
    fn dashboard(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let status = self.status.as_ref().unwrap().clone();
        let state = status
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("NeedsAttention");
        ui.heading("Server dashboard");
        ui.label(format!("Status: {state}"));
        if let Some(reason) = status.pointer("/native/reason").and_then(Value::as_str) {
            ui.label(reason);
        }
        if status.get("setupIncomplete").and_then(Value::as_bool) == Some(true) {
            ui.label("The original setup is retained but not complete. Start / resume continues it with the same keys and reviewed settings.");
        }
        if state == "Running" {
            ui.label("Native hosting and the joining endpoint are ready from this host. Verify the shared link once from another connection before inviting others.");
        }
        if status
            .pointer("/certificateRefresh/healthy")
            .and_then(Value::as_bool)
            == Some(false)
        {
            ui.colored_label(egui::Color32::LIGHT_RED,"Certificate refresh failed. Check the selected files or TCP80 forwarding. Existing certificates keep their normal expiry.");
        }
        ui.horizontal(|ui| {
            if ui.button("Refresh status").clicked() {
                self.call(ctx, hosting::Request::Status);
            }
            if ui.button("Start / resume").clicked() {
                self.call(ctx, hosting::Request::Start);
            }
            if ui.button("Stop hosting").clicked() {
                self.call(ctx, hosting::Request::Stop);
            }
        });
        if status.get("startsAfterLogout").and_then(Value::as_bool) != Some(true) {
            ui.label("To host after logout and reboot, enable unattended user services. Your desktop may ask for administrator authentication.");
            if ui.button("Enable unattended hosting").clicked() {
                self.call(ctx, hosting::Request::EnableUnattended);
            }
        }
        let admission = status.get("admission").filter(|v| !v.is_null());
        if let Some(admission) = admission {
            let mut enabled = admission
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let old = enabled;
            ui.checkbox(&mut enabled, "Accept new joins");
            if enabled != old {
                let mode = serde_json::from_value(
                    admission
                        .get("mode")
                        .cloned()
                        .unwrap_or(json!("inviteOnly")),
                )
                .unwrap_or(store::Mode::InviteOnly);
                self.call(
                    ctx,
                    hosting::Request::Admin {
                        action: super::control::Admin::Configure { enabled, mode },
                    },
                );
            }
            ui.small("Pausing new joins keeps existing members and their access.");
            ui.horizontal(|ui| {
                ui.label("Joining mode");
                ui.selectable_value(&mut self.mode, store::Mode::InviteOnly, "Invite only");
                ui.selectable_value(&mut self.mode, store::Mode::Password, "Password");
                ui.selectable_value(&mut self.mode, store::Mode::Public, "Public");
                if ui.button("Apply mode").clicked() {
                    self.call(
                        ctx,
                        hosting::Request::Admin {
                            action: super::control::Admin::Configure {
                                enabled,
                                mode: self.mode,
                            },
                        },
                    );
                }
            });
            ui.collapsing("Set or rotate server password",|ui|{ui.add(egui::TextEdit::singleline(&mut self.rotation_password).password(true));if ui.button("Set password").clicked(){let password=std::mem::take(&mut self.rotation_password);self.call(ctx,hosting::Request::Admin{action:super::control::Admin::Password{password}});}ui.small("The new password affects future password joins. Existing members retain their access. Select Password mode separately.");});
            ui.separator();
            ui.heading("Share access");
            ui.horizontal(|ui| {
                ui.label("Invitation uses");
                ui.add(egui::DragValue::new(&mut self.invite_uses).range(1..=10000));
                ui.checkbox(&mut self.invite_permanent, "No invitation expiry");
                if !self.invite_permanent {
                    ui.label("Days");
                    ui.add(egui::DragValue::new(&mut self.invite_days).range(1..=365));
                }
            });
            if ui.button("Create private invitation").clicked() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let end = if self.invite_permanent {
                    store::End::UntilRemoved
                } else {
                    store::End::Expires {
                        expires_ms: now + u64::from(self.invite_days) * 86400000,
                    }
                };
                self.call(
                    ctx,
                    hosting::Request::Invite {
                        end,
                        maximum_uses: self.invite_uses,
                    },
                );
            }
            if ui.button("Show public connection link").clicked() {
                self.show_link(
                    ctx,
                    status
                        .get("link")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .into(),
                    status
                        .get("instructions")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .into(),
                );
            }
            ui.collapsing("Existing invitations", |ui| {
                if let Some(items) = admission.get("invitations").and_then(Value::as_array) {
                    for i in items {
                        let id = i.get("id").and_then(Value::as_str).unwrap_or("");
                        ui.horizontal(|ui| {
                            ui.label(format!(
                                "{}: {} / {} uses",
                                id.get(..12).unwrap_or(id),
                                i.get("uses").unwrap_or(&Value::Null),
                                i.get("maximumUses").unwrap_or(&Value::Null)
                            ));
                            if i.get("enabled").and_then(Value::as_bool) == Some(true)
                                && ui.button("Disable").clicked()
                            {
                                self.call(
                                    ctx,
                                    hosting::Request::Admin {
                                        action: super::control::Admin::DisableInvite {
                                            id: id.into(),
                                        },
                                    },
                                );
                            }
                        });
                    }
                }
                ui.small("Disabling an invitation does not remove people who already joined.");
            });
            ui.separator();
            ui.heading("Members");
            if let Some(removal) = admission.get("removal").filter(|v| !v.is_null()) {
                ui.label("A removal is still being completed. Access is being closed across chat and native services.");
                if let Some(attempt) = removal.get("attempt").and_then(Value::as_str)
                    && ui.button("Continue removal").clicked()
                {
                    self.call(
                        ctx,
                        hosting::Request::Admin {
                            action: super::control::Admin::Revoke {
                                attempt: attempt.into(),
                            },
                        },
                    );
                }
            }
            if let Some(members) = admission.get("members").and_then(Value::as_array) {
                for m in members {
                    let name = m
                        .get("displayName")
                        .and_then(Value::as_str)
                        .unwrap_or("Participant");
                    let attempt = m.get("attempt").and_then(Value::as_str).unwrap_or("");
                    ui.horizontal(|ui| {
                        ui.label(name);
                        ui.small(m.get("phase").and_then(Value::as_str).unwrap_or(""));
                        if ui.button("Remove").clicked() {
                            self.remove = Some(attempt.into());
                        }
                    });
                }
            }
            if let Some(attempt) = self.remove.clone() {
                ui.label("Remove this participant and their scoped Agents? Existing local history is kept. Their native and chat access will be retired.");
                ui.horizontal(|ui| {
                    if ui.button("Confirm removal").clicked() {
                        self.remove = None;
                        self.call(
                            ctx,
                            hosting::Request::Admin {
                                action: super::control::Admin::Revoke { attempt },
                            },
                        );
                    }
                    if ui.button("Cancel removal").clicked() {
                        self.remove = None;
                    }
                });
            }
        }
        ui.separator();
        ui.collapsing("Owner and diagnostics", |ui| {
            if let Some(owner)=status.pointer("/native/owner/hrcProfile").and_then(Value::as_str) {
                ui.label("Your separate owner profile provides room moderation and device controls in RelayChat.");
                if let Some(executable)=&self.hrc && ui.button("Open owner chat").clicked() {
                    use std::os::unix::process::CommandExt;
                    let result=(||->Result<()>{
                        super::runtime::executable(executable)?;
                        super::private::directory(Path::new(owner))?;
                        std::process::Command::new(executable).args(["gui","--profile",owner]).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).process_group(0).spawn()?;
                        Ok(())
                    })();
                    if let Err(e)=result { self.error=Some(e.to_string()); }
                }
            }
            if ui.button("Open welcome Page").clicked() {
                let directory=self.directory.clone();
                self.job=Some(Job::new(ctx,move|stop|super::pages::open_owner(&directory,super::pages::Input{location:None},stop)));
            }
            if ui.button("Export redacted diagnosis").clicked() { self.call(ctx,hosting::Request::Diagnose); }
            ui.checkbox(&mut self.confirm_withdraw,"Withdraw this host's consent and close its native services");
            if ui.add_enabled(self.confirm_withdraw,egui::Button::new("Withdraw hosting consent")).clicked() { self.call(ctx,hosting::Request::Withdraw); }
            ui.small("Stopping retains the host for an ordinary restart. Withdrawal changes the native consent and requires a fresh review to host again.");
        });
    }
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
            self.notice.clear();
            match result {
                Err(error) => {
                    self.error = Some(error);
                    self.refresh_hosts();
                }
                Ok(value) => {
                    self.error = None;
                    match value.get("status").and_then(Value::as_str).unwrap_or(""){
                    "Preview"=>self.preview=Some(value),
                    "Running"|"Stopped"|"NeedsAttention"=>{self.preview=None;if let Some(mode)=value.pointer("/admission/mode").and_then(|v|serde_json::from_value(v.clone()).ok()){self.mode=mode;}self.status=Some(value);self.refresh_hosts();},
                    "InvitationCreated"=>self.show_link(&ctx,value.get("link").and_then(Value::as_str).unwrap_or_default().into(),value.get("instructions").and_then(Value::as_str).unwrap_or_default().into()),
                    "InstallationComplete"=>self.notice="Signed native installation verified. Review your server setup to continue.".into(),
                    "HostingDiagnosis"=>{let file=self.directory.join("Diagnosis.json");match saved::replace(&file,&value){Ok(())=>self.notice=format!("Redacted diagnosis saved to {}",file.display()),Err(e)=>self.error=Some(e.to_string())}},
                    "refused"=>self.error=Some(format!("Host action refused: {}",value.get("code").and_then(Value::as_str).unwrap_or("Unavailable"))),
                    "RemovalPending"=>{self.notice="Removal is still in progress; continue it from the member list.".into();self.call(&ctx,hosting::Request::Status);},
                    _=>{self.notice="Host setting saved.".into();if self.status.is_some(){self.call(&ctx,hosting::Request::Status);}}
                }
                }
            }
        }
        egui::CentralPanel::default().show(ui,|ui|{egui::ScrollArea::vertical().show(ui,|ui|{
            ui.heading("HyperNet hosting");
            if let Some(error)=&self.error{ui.colored_label(egui::Color32::from_rgb(245,130,110),error);ui.small("Saved keys, policy and unfinished operations are retained. Correct the cause and resume.");}
            if !self.notice.is_empty(){ui.label(&self.notice);}
            if self.job.is_some(){ui.horizontal(|ui|{ui.spinner();ui.label("Applying the reviewed operation…");if ui.button("Cancel").clicked()&&let Some(job)=&self.job{job.stop.store(true,Ordering::Release);}});return;}
            ui.collapsing("Saved servers",|ui|{for path in &self.hosts{if ui.selectable_label(self.selected.as_ref()==Some(path),saved::read::<Value>(&path.join("HostingSetup.json")).ok().and_then(|v|v.pointer("/configuration/native/name").and_then(Value::as_str).map(str::to_owned)).unwrap_or_else(||"Unfinished server setup".into())).clicked(){self.selected=Some(path.clone());}}
if let Some(path)=self.selected.clone()&&ui.button("Open dashboard").clicked(){self.directory=path;self.call(&ctx,hosting::Request::Status);}
if ui.button("Create another server").clicked(){self.directory=self.root.join(crate::random_hex::<32>());self.selected=None;self.configuration=None;self.preview=None;self.status=None;self.mode=store::Mode::InviteOnly;self.password.zeroize();self.agents=false;self.link.zeroize();self.instructions.zeroize();self.texture=None;self.same_organisation=false;self.error=None;}
});
            if self.status.is_none() && self.directory.join("HostingSetup.json").exists() {
                ui.horizontal(|ui|{if ui.button("Resume retained setup").clicked(){self.call(&ctx,hosting::Request::Resume);}
if ui.button("Stop retained setup").clicked(){self.call(&ctx,hosting::Request::Stop);}});
            }
            if self.status.is_some(){self.dashboard(ui,&ctx);}else if self.preview.is_some(){self.review(ui,&ctx);}else{self.setup(ui,&ctx);}
            if !self.link.is_empty(){ui.separator();ui.heading("Connection details");ui.add(egui::Label::new(&self.link).wrap().selectable(true));ui.horizontal(|ui|{if ui.button("Copy link").clicked(){ctx.copy_text(self.link.clone());}
if ui.button("Copy connection instructions").clicked(){ctx.copy_text(self.instructions.clone());}
if ui.button("Hide invitation").clicked(){self.link.zeroize();self.instructions.zeroize();self.texture=None;}});if let Some(texture)=&self.texture{ui.image((texture.id(),egui::vec2(320.0,320.0)));}ui.horizontal(|ui|{ui.text_edit_singleline(&mut self.export_path);if ui.button("Save QR image").clicked(){match Location::parse(&self.link).and_then(|l|qr::write(&l,Path::new(&self.export_path))){Ok(())=>self.notice="QR image saved privately.".into(),Err(e)=>self.error=Some(e.to_string())}}});ui.small("A private invitation is a credential. Share it only with its intended recipients. Clipboard history may retain copied invitations.");}
        });});
        if self.job.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
}
pub fn run(hrc: Option<PathBuf>, stop: Arc<AtomicBool>) -> Result<Value> {
    if let Some(path) = &hrc {
        super::runtime::executable(path)?;
    }
    let root = root()?;
    let directory = root.join(crate::random_hex::<32>());
    let installation = root.parent().unwrap().join("Installation");
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("HyperNet hosting")
            .with_inner_size([860.0, 820.0])
            .with_min_inner_size([600.0, 500.0]),
        renderer: eframe::Renderer::Glow,
        persist_window: false,
        ..Default::default()
    };
    eframe::run_native(
        "HyperNet hosting",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            let mut window = Window {
                root,
                directory,
                hosts: vec![],
                selected: None,
                hrc,
                name: "My HyperNet server".into(),
                nickname: "Owner".into(),
                motd: "Welcome to our server".into(),
                address: address(),
                origin: String::new(),
                tls_mode: 0,
                certificate_email: String::new(),
                certificate_terms: false,
                challenge_port: 8080,
                certificate_path: String::new(),
                certificate_key: String::new(),
                join_port: 25445,
                relay_port: 25443,
                authority_port: 25450,
                subnet: 220,
                mode: store::Mode::InviteOnly,
                password: String::new(),
                participants: 16,
                agents: false,
                agent_limit: 2,
                same_organisation: false,
                access_permanent: true,
                access_days: 30,
                hosting_permanent: true,
                hosting_days: 30,
                memory_mib: 512,
                state_mib: 1024,
                cpu: 100,
                connection_mib: 256,
                installation,
                release: packages(),
                picker: Default::default(),
                configuration: None,
                preview: None,
                status: None,
                job: None,
                error: None,
                notice: String::new(),
                link: String::new(),
                instructions: String::new(),
                texture: None,
                export_path: String::new(),
                invite_uses: 1,
                invite_days: 7,
                invite_permanent: false,
                rotation_password: String::new(),
                confirm_withdraw: false,
                remove: None,
                stop,
            };
            window.refresh_hosts();
            Ok(Box::new(window))
        }),
    )
    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok(json!({"status":"Closed"}))
}
