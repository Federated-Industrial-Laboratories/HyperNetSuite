// SPDX-License-Identifier: MIT
// Native transfer controls review immutable metadata before serialized background operations.
use crate::{
    authority_domains::transfer::{Agreement, Offer},
    transfers::application::{
        self, AcceptanceReview, Application, Draft, Host, Local, Request, Response,
    },
};
use anyhow::Result;
use eframe::egui;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{Receiver, SyncSender, sync_channel},
    },
};
#[path = "TransferFiles.rs"]
mod files;
#[path = "TransferTime.rs"]
mod time;
#[path = "TransferViews.rs"]
mod views;
use super::common::{self, Appearance};

struct Progress {
    done: AtomicU64,
    total: AtomicU64,
    pause: AtomicBool,
}
struct Review {
    title: &'static str,
    action: &'static str,
    request: Request,
    offer: Option<Offer>,
    fields: Vec<(&'static str, String)>,
    acknowledged: bool,
    acknowledgement: &'static str,
}
#[derive(Clone, Copy, PartialEq)]
enum View {
    Outbox,
    Incoming,
    Outgoing,
    Compose,
}
struct Form {
    file: String,
    recipient: String,
    age: String,
    label: String,
    duration: time::Duration,
}
struct Transfers {
    sender: SyncSender<Request>,
    receiver: Receiver<Result<Response, String>>,
    appearance: Appearance,
    progress: Arc<Progress>,
    local: Option<Local>,
    offers: Vec<Agreement>,
    next: Option<String>,
    hosts: Vec<Host>,
    hosts_next: Option<String>,
    selected: Option<Agreement>,
    retained: Option<Offer>,
    view: View,
    form: Form,
    review: Option<Review>,
    host: String,
    destination: String,
    shorter_acceptance: bool,
    acceptance_duration: time::Duration,
    host_lifetime: Option<u64>,
    output: String,
    inspect: String,
    status: String,
    error: Option<String>,
    busy: bool,
    stopped: bool,
    transfer_busy: bool,
    last_request: Option<Request>,
    picker: Option<files::Picker>,
}
pub(crate) fn run(arguments: application::Arguments) -> Result<()> {
    common::run("HyperNet Transfers", move |cc| {
        let (sender, requests) = sync_channel(1);
        let (results, receiver) = sync_channel(1);
        let progress = Arc::new(Progress {
            done: AtomicU64::new(0),
            total: AtomicU64::new(0),
            pause: AtomicBool::new(false),
        });
        let worker_progress = progress.clone();
        let ctx = cc.egui_ctx.clone();
        std::thread::Builder::new()
            .name("HyperNetTransfers".into())
            .spawn(move || {
                let mut app = match Application::open(arguments) {
                    Ok(app) => app,
                    Err(error) => {
                        let _ = results.send(Err(format!("{error:#}")));
                        ctx.request_repaint();
                        return;
                    }
                };
                while let Ok(request) = requests.recv() {
                    let result = app
                        .execute(request, |done, total| {
                            worker_progress.done.store(done, Ordering::Relaxed);
                            worker_progress.total.store(total, Ordering::Relaxed);
                            ctx.request_repaint();
                            anyhow::ensure!(
                                !worker_progress.pause.load(Ordering::Relaxed),
                                "Transfer paused. Resume the same transfer to continue."
                            );
                            crate::private_route_client::check_cancelled()
                        })
                        .map_err(|error| format!("{error:#}"));
                    if results.send(result).is_err() {
                        break;
                    }
                    ctx.request_repaint();
                }
            })?;
        let mut app = Transfers {
            sender,
            receiver,
            appearance: Appearance::new(),
            progress,
            local: None,
            offers: vec![],
            next: None,
            hosts: vec![],
            hosts_next: None,
            selected: None,
            retained: None,
            view: View::Outbox,
            form: Form {
                file: String::new(),
                recipient: String::new(),
                age: String::new(),
                label: String::new(),
                duration: time::Duration::default(),
            },
            review: None,
            host: String::new(),
            destination: "Downloads".into(),
            shorter_acceptance: false,
            acceptance_duration: time::Duration::default(),
            host_lifetime: None,
            output: String::new(),
            inspect: String::new(),
            status: "Opening transfer vault".into(),
            error: None,
            busy: false,
            stopped: false,
            transfer_busy: false,
            last_request: None,
            picker: None,
        };
        app.submit(Request::Local);
        Ok(Box::new(app))
    })
}
impl Transfers {
    fn submit(&mut self, request: Request) {
        if self.busy || self.stopped {
            return;
        }
        self.transfer_busy = matches!(
            request,
            Request::Send(_) | Request::Receive { .. } | Request::Recover { .. }
        );
        self.progress.done.store(0, Ordering::Relaxed);
        self.progress.total.store(0, Ordering::Relaxed);
        self.progress.pause.store(false, Ordering::Relaxed);
        match self.sender.try_send(request.clone()) {
            Ok(()) => {
                self.busy = true;
                self.error = None;
                self.last_request = Some(request);
                self.status = "Working".into();
            }
            Err(_) => {
                self.error = Some(
                    "The transfer worker is unavailable. Close and reopen the application.".into(),
                );
                self.stopped = true;
            }
        }
    }
    fn messages(&mut self) {
        while let Ok(result) = self.receiver.try_recv() {
            self.busy = false;
            self.transfer_busy = false;
            self.status = "Ready".into();
            match result {
                Err(error) => {
                    self.status = "Operation stopped".into();
                    self.error = Some(error);
                }
                Ok(Response::Local(local)) => {
                    self.local = Some(local);
                }
                Ok(Response::Offers { offers, next }) => {
                    self.offers = offers;
                    self.next = next;
                    self.selected = None;
                }
                Ok(Response::Hosts { hosts, next }) => {
                    self.hosts = hosts;
                    self.hosts_next = next;
                }
                Ok(Response::Agreement(agreement)) => {
                    self.inspect = hex::encode(agreement.offer.id);
                    self.retained = None;
                    if let Some(row) = self
                        .offers
                        .iter_mut()
                        .find(|row| row.offer.id == agreement.offer.id)
                    {
                        *row = (*agreement).clone();
                    }
                    self.selected = Some(*agreement);
                }
                Ok(Response::Prepared(offer)) => {
                    let offer = *offer;
                    self.retained = Some(offer.clone());
                    if let Some(local) = &mut self.local {
                        local.offers.push(offer.clone());
                    }
                    self.publish_review(offer);
                }
                Ok(Response::Done(message)) => {
                    self.status = message;
                }
            }
        }
    }
    fn publish_review(&mut self, offer: Offer) {
        self.review = Some(Review { title: "Publish offer", action: "Publish", request: Request::Publish(offer.clone()), offer: Some(offer),
            fields: vec![("Visibility", "The authority receives participant identities, label, size and expiry. File content stays encrypted.".into())],
            acknowledged: false, acknowledgement: "I independently verified this participant and age encryption key." });
    }
    fn simple_review(
        &mut self,
        title: &'static str,
        action: &'static str,
        request: Request,
        offer: Option<Offer>,
        impact: &'static str,
    ) {
        self.review = Some(Review {
            title,
            action,
            request,
            offer,
            fields: vec![("Effect", impact.into())],
            acknowledged: false,
            acknowledgement: "Confirm this operation.",
        });
    }
    fn refresh(&mut self) {
        match self.view {
            View::Outbox => self.submit(Request::Local),
            View::Incoming => self.submit(Request::List {
                action: 19,
                after: None,
            }),
            View::Outgoing => self.submit(Request::List {
                action: 18,
                after: None,
            }),
            View::Compose => {}
        }
    }
    fn toolbar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("TransfersToolbar").show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.add_enabled_ui(!self.busy && self.review.is_none(), |ui| {
                    for (view, label) in [
                        (View::Outbox, "Local outbox"),
                        (View::Incoming, "Received offers"),
                        (View::Outgoing, "Sent offers"),
                        (View::Compose, "New transfer"),
                    ] {
                        if ui.selectable_label(self.view == view, label).clicked() {
                            self.view = view;
                            self.selected = None;
                            self.retained = None;
                            self.refresh();
                        }
                    }
                    if ui
                        .button("Refresh")
                        .on_hover_text("Refresh the selected list")
                        .clicked()
                    {
                        self.refresh();
                    }
                });
                if ui.button("Settings").on_hover_text("Ctrl+, ").clicked() {
                    self.appearance.settings_open = true;
                }
                if ui.button("Help").on_hover_text("F1").clicked() {
                    self.appearance.help_open = true;
                }
            });
        });
    }
    fn status(&mut self, ui: &mut egui::Ui) {
        egui::Panel::bottom("TransfersStatus").show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                if self.busy {
                    ui.spinner();
                }
                ui.label(&self.status);
                if self.transfer_busy {
                    let done = self.progress.done.load(Ordering::Relaxed);
                    let total = self.progress.total.load(Ordering::Relaxed);
                    if total > 0 {
                        ui.add(
                            egui::ProgressBar::new(done as f32 / total as f32)
                                .text(format!("{done} / {total} bytes"))
                                .desired_width(240.0),
                        );
                    }
                    if ui
                        .button("Pause")
                        .on_hover_text("Finish the current request, then retain progress")
                        .clicked()
                    {
                        self.progress.pause.store(true, Ordering::Relaxed);
                        self.status = "Pausing after current request".into();
                    }
                }
            });
        });
    }
    fn confirmation(&mut self, ctx: &egui::Context) {
        let Some(review) = &mut self.review else {
            return;
        };
        let mut open = true;
        let mut decision = None;
        egui::Window::new(review.title)
            .open(&mut open)
            .collapsible(false)
            .default_width(680.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .max_height(520.0)
                    .show(ui, |ui| {
                        if let Some(offer) = &review.offer {
                            views::display_offer(ui, offer);
                        }
                        if let Request::Accept(acceptance) = &review.request {
                            time::field(ui, "Acceptance expires", acceptance.expires);
                        }
                        for (label, value) in &review.fields {
                            views::field(ui, label, value);
                        }
                        ui.separator();
                        ui.checkbox(&mut review.acknowledged, review.acknowledgement);
                        ui.horizontal(|ui| {
                            if ui
                                .add_enabled(review.acknowledged, egui::Button::new(review.action))
                                .clicked()
                            {
                                decision = Some(true);
                            }
                            if ui.button("Back").clicked() {
                                decision = Some(false);
                            }
                        });
                    });
            });
        if decision == Some(true) {
            let review = self.review.take().expect("open review");
            self.submit(review.request);
        } else if decision == Some(false) || !open {
            self.review = None;
        }
    }
    fn picker(&mut self, ctx: &egui::Context) {
        if let Some(picker) = &mut self.picker {
            let mut open = true;
            if let Some(path) = picker.show(ctx, &mut open) {
                if picker.save {
                    self.output = path;
                } else {
                    self.form.file = path;
                }
                open = false;
            }
            if !open {
                self.picker = None;
            }
        }
    }
}
impl eframe::App for Transfers {
    fn logic(&mut self, _: &egui::Context, _: &mut eframe::Frame) {
        self.messages();
    }
    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        self.messages();
        self.appearance.apply(ui);
        self.toolbar(ui);
        self.status(ui);
        let enabled = !self.busy && !self.stopped && self.review.is_none() && self.picker.is_none();
        egui::CentralPanel::default().show(ui, |ui| {
            if let Some(error) = &self.error {
                ui.colored_label(egui::Color32::LIGHT_RED, error);
                if ui
                    .add_enabled(
                        enabled && self.last_request.is_some(),
                        egui::Button::new("Retry exact operation"),
                    )
                    .clicked()
                    && let Some(request) = self.last_request.clone()
                {
                    self.submit(request);
                }
                ui.separator();
            }
            ui.add_enabled_ui(enabled, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    self.content(ui);
                });
            });
        });
        let ctx = ui.ctx().clone();
        self.confirmation(&ctx);
        self.picker(&ctx);
        self.appearance.windows(&ctx, "Transfers", &[
            ("Send", "Create a transfer vault, choose a file and enter independently verified participant and age keys. Prepare encrypts and retains the exact file locally. Review and publish the offer. After the recipient accepts a store, select Upload."),
            ("Receive", "Refresh received offers or inspect an identifier. Select a consenting store with an approved route, destination label and duration; review acceptance. Once uploaded, choose a new output path and download. Existing files are never replaced."),
            ("Recovery", "Pause retains acknowledged chunks. Resume Upload or Download after an interruption. Retry exact operation reconciles the original intent; changing a pending request is refused. Unpublished offers remain in Local outbox."),
            ("Keys and grants", "Sending uses capability 18; receiving uses 19. Supply the matching grants at launch. Transfer age keys are separate from account signing keys and must be authenticated independently. The application never chooses a replacement route."),
            ("Remove data", "Cancel prevents future transfer effects. Delete removes selected-store ciphertext; do this before cancellation if needed. Forget removes only local retained data. Previously disclosed copies and backups cannot be erased by these operations."),
        ]);
    }
}
impl Drop for Transfers {
    fn drop(&mut self) {
        crate::private_route_client::request_cancel();
    }
}
