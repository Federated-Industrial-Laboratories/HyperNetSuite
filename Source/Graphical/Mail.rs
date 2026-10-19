// SPDX-License-Identifier: MIT
// Native Mail owns presentation while a serial worker owns the encrypted mailbox workflow.
use super::*;
use crate::graphical::{
    common::{self, Appearance},
    scrolling,
};
use eframe::egui;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, SyncSender},
};
#[path = "MailViews.rs"]
mod views;

pub(super) fn run(arguments: Arguments) -> Result<()> {
    let selected = arguments.mailbox.clone().unwrap_or_default();
    common::run("HyperNet Mail", move |cc| {
        let (requests, commands) = mpsc::sync_channel(1);
        let (responses, events) = mpsc::sync_channel(1);
        let closed = Arc::new(AtomicBool::new(false));
        let stop = closed.clone();
        let context = cc.egui_ctx.clone();
        std::thread::Builder::new()
            .name("HyperNetMail".into())
            .spawn(move || {
                let mut application = match Application::open(&arguments) {
                    Ok(application) => application,
                    Err(error) => {
                        let _ = responses.send(Err(format!("{error:#}")));
                        context.request_repaint();
                        return;
                    }
                };
                let initial = application
                    .execute(Request::Refresh)
                    .map_err(|error| format!("{error:#}"));
                if responses.send(initial).is_err() {
                    return;
                }
                context.request_repaint();
                while !stop.load(Ordering::Acquire) {
                    match commands.recv_timeout(std::time::Duration::from_millis(200)) {
                        Ok(request) => {
                            if stop.load(Ordering::Acquire) {
                                break;
                            }
                            let result = application
                                .execute(request)
                                .map_err(|error| format!("{error:#}"));
                            if responses.send(result).is_err() {
                                break;
                            }
                            context.request_repaint();
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            })?;
        Ok(Box::new(Mail {
            requests,
            events,
            closed,
            appearance: Appearance::new(),
            overview: Overview::default(),
            selected,
            store: String::new(),
            folder: Folder::Inbox,
            inbox: None,
            letter: None,
            draft: Draft::default(),
            review: None,
            contact_address: String::new(),
            contact_owner: String::new(),
            contact_checked: false,
            deletion: None,
            busy: true,
            error: None,
            status: "Opening vault".into(),
            active: None,
            failed: None,
        }))
    })
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Folder {
    Inbox,
    Archive,
    Outbox,
    Contacts,
    Compose,
}
struct Mail {
    requests: SyncSender<Request>,
    events: Receiver<Result<Response, String>>,
    closed: Arc<AtomicBool>,
    appearance: Appearance,
    overview: Overview,
    selected: String,
    store: String,
    folder: Folder,
    inbox: Option<Inbox>,
    letter: Option<crypto::Letter>,
    draft: Draft,
    review: Option<Box<Review>>,
    contact_address: String,
    contact_owner: String,
    contact_checked: bool,
    deletion: Option<views::Deletion>,
    busy: bool,
    error: Option<String>,
    status: String,
    active: Option<Request>,
    failed: Option<Request>,
}
impl Mail {
    fn request(&mut self, request: Request) {
        if self.busy || self.closed.load(Ordering::Acquire) {
            return;
        }
        match self.requests.try_send(request.clone()) {
            Ok(()) => {
                self.active = Some(request);
                self.failed = None;
                self.busy = true;
                self.error = None;
                self.status = "Working".into();
            }
            Err(_) => {
                self.error = Some("Mail session is unavailable; reopen the application".into())
            }
        }
    }
    fn events(&mut self) {
        loop {
            let result = match self.events.try_recv() {
                Ok(result) => result,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    if self.busy {
                        self.busy = false;
                        self.failed = self.active.take();
                        self.error =
                            Some("Mail worker disconnected; reopen the application".into());
                    }
                    break;
                }
            };
            self.busy = false;
            match result {
                Ok(response) => {
                    self.active = None;
                    self.failed = None;
                    self.overview = response.overview;
                    self.status = response.status;
                    self.error = None;
                    if self.selected.is_empty() {
                        self.selected = self
                            .overview
                            .mailboxes
                            .first()
                            .map(|b| b.label.clone())
                            .unwrap_or_default();
                    }
                    if self.store.is_empty() {
                        self.store = self
                            .overview
                            .mailboxes
                            .iter()
                            .find(|b| b.label == self.selected)
                            .and_then(|b| {
                                b.stores.iter().find(|s| self.overview.stores.contains(s))
                            })
                            .cloned()
                            .or_else(|| self.overview.stores.first().cloned())
                            .unwrap_or_default();
                    }
                    match response.detail {
                        Detail::None => {}
                        Detail::Inbox(inbox) => {
                            self.inbox = Some(inbox);
                            self.letter = None;
                        }
                        Detail::Letter(letter) => self.letter = Some(*letter),
                        Detail::Composed(message) => {
                            self.folder = Folder::Outbox;
                            self.status = format!("Draft {} saved", views::short(&message));
                            self.draft = Draft::default();
                        }
                        Detail::Review(review) => self.review = Some(review),
                    }
                }
                Err(error) => {
                    self.failed = self.active.take();
                    self.error = Some(error);
                    self.status = "Operation stopped".into();
                }
            }
        }
    }
    fn inbox(&mut self, after: Option<String>) {
        self.request(Request::Inbox {
            mailbox: self.selected.clone(),
            store: self.store.clone(),
            after,
        });
    }
    fn shutdown(&self) {
        self.closed.store(true, Ordering::Release);
        crate::private_route_client::request_cancel();
    }
}
impl eframe::App for Mail {
    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        self.events();
        self.appearance.apply(ui);
        let context = ui.ctx().clone();
        self.toolbar(ui);
        egui::Panel::bottom("MailStatus").show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                if self.busy {
                    ui.spinner();
                }
                ui.label(&self.status);
            });
        });
        self.sidebar(ui);
        egui::CentralPanel::default().show(ui, |ui| {
            if let Some(error) = &self.error {
                ui.colored_label(egui::Color32::LIGHT_RED, error);
                ui.separator();
            }
            if !self.busy
                && self.failed.is_some()
                && ui.button("Retry exact operation").clicked()
                && let Some(request) = self.failed.clone()
            {
                self.request(request);
            }
            ui.add_enabled_ui(
                !self.busy && self.review.is_none() && self.deletion.is_none(),
                |ui| {
                    self.content(ui);
                },
            );
        });
        self.confirmations(&context);
        self.appearance.windows(&context, "HyperNet Mail", &[
            ("Accounts", "Select an existing mailbox from the encrypted vault. Network profiles, mailbox enrolment and storage permissions are configured with the Suite CLI."),
            ("Inbox", "Refresh retrieves message identifiers from the selected store. Open decrypts one message and saves it in the local archive. Receive keys publishes four one-use keys for new mail."),
            ("Contacts", "Verify the recipient owner key through an independent channel. A displayed address or network directory is not independent identity verification."),
            ("Sending", "Compose saves a local draft. Review binds its content, recipient revision and selected store. Send requires explicit confirmation. Stored copies are storage acknowledgements, not read receipts."),
            ("Recovery", "After an interrupted send, select the same message and store in Outbox, then Review and Send. The original ciphertext and request are resumed. Never create a replacement to resolve an uncertain send."),
            ("Deletion", "Delete stored copy affects only the selected store. Delete local copy affects only the encrypted archive. Neither removes another reader's retained copy."),
            ("Keyboard", "Tab and Shift+Tab move focus. Enter activates buttons. Focus a scroll region for Up/Down, PageUp/PageDown, Home/End. Ctrl+, opens Settings; F1 opens Help."),
        ]);
        if context.input(|input| input.viewport().close_requested()) {
            self.shutdown();
        }
    }
    fn on_exit(&mut self, _: Option<&eframe::glow::Context>) {
        self.shutdown();
    }
}
