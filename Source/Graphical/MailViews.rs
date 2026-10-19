// SPDX-License-Identifier: MIT
// Mail controls display explicit recipients, storage destinations and irreversible actions.
use super::*;
pub(super) struct Deletion {
    remote: bool,
    mailbox: String,
    store: String,
    message: String,
}
pub(super) fn short(value: &str) -> String {
    value.chars().take(16).collect()
}
fn expiry(seconds: u64) -> String {
    let Ok(time) = libc::time_t::try_from(seconds) else {
        return "Invalid expiry".into();
    };
    let mut value: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::gmtime_r(&time, &mut value) }.is_null() {
        return "Invalid expiry".into();
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02} UTC",
        value.tm_year + 1900,
        value.tm_mon + 1,
        value.tm_mday,
        value.tm_hour,
        value.tm_min
    )
}
fn field(ui: &mut egui::Ui, label: &str, value: &mut String, limit: usize) -> bool {
    let label = ui.label(label);
    let response = ui
        .add(
            egui::TextEdit::singleline(value)
                .char_limit(limit)
                .desired_width(f32::INFINITY),
        )
        .labelled_by(label.id);
    scrolling::reveal_focus(&response);
    response.changed()
}
fn identifier(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(label);
    ui.add(
        egui::Label::new(egui::RichText::new(value).monospace())
            .wrap()
            .selectable(true),
    );
}
fn scroll<R>(ui: &mut egui::Ui, name: &str, content: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let id = ui.make_persistent_id(name);
    let focus = scrolling::focus(ui, ui.available_rect_before_wrap(), id.with("Focus"), name);
    let offset = ui.ctx().data_mut(|data| data.remove_temp::<f32>(id));
    let mut area = egui::ScrollArea::vertical().id_salt(name);
    if let Some(offset) = offset {
        area = area.vertical_scroll_offset(offset);
    }
    let output = area.show(ui, content);
    if let Some(offset) = scrolling::keys(
        ui,
        &focus,
        &output,
        ui.text_style_height(&egui::TextStyle::Body),
        &mut false,
    ) {
        ui.ctx().data_mut(|data| data.insert_temp(id, offset));
    }
    output.inner
}
impl Mail {
    pub(super) fn toolbar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("MailToolbar").show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.heading("Mail");
                if ui
                    .add_enabled(
                        !self.busy && self.review.is_none() && self.deletion.is_none(),
                        egui::Button::new("Reload vault"),
                    )
                    .clicked()
                {
                    self.request(Request::Refresh);
                }
                if ui.button("Settings").clicked() {
                    self.appearance.settings_open = true;
                }
                if ui.button("Help").clicked() {
                    self.appearance.help_open = true;
                }
            });
        });
    }
    pub(super) fn sidebar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::left("MailFolders")
            .default_size(190.0)
            .min_size(145.0)
            .show(ui, |ui| {
                ui.add_enabled_ui(
                    !self.busy && self.review.is_none() && self.deletion.is_none(),
                    |ui| {
                        let before = self.selected.clone();
                        egui::ComboBox::from_label("Mailbox")
                            .selected_text(if self.selected.is_empty() {
                                "Select"
                            } else {
                                &self.selected
                            })
                            .show_ui(ui, |ui| {
                                for mailbox in &self.overview.mailboxes {
                                    ui.selectable_value(
                                        &mut self.selected,
                                        mailbox.label.clone(),
                                        &mailbox.label,
                                    );
                                }
                            });
                        if before != self.selected {
                            self.inbox = None;
                            self.letter = None;
                            self.store = self
                                .overview
                                .mailboxes
                                .iter()
                                .find(|b| b.label == self.selected)
                                .and_then(|b| {
                                    b.stores.iter().find(|s| self.overview.stores.contains(s))
                                })
                                .cloned()
                                .unwrap_or_default();
                        }
                        if let Some(mailbox) = self
                            .overview
                            .mailboxes
                            .iter()
                            .find(|b| b.label == self.selected)
                        {
                            ui.label(if mailbox.private {
                                "Private mailbox"
                            } else {
                                "Distributed mailbox"
                            });
                            ui.label(short(&mailbox.address))
                                .on_hover_text(&mailbox.address);
                        }
                        ui.separator();
                        for (folder, title) in [
                            (Folder::Inbox, "Inbox"),
                            (Folder::Archive, "Archive"),
                            (Folder::Outbox, "Outbox"),
                            (Folder::Contacts, "Contacts"),
                            (Folder::Compose, "Compose"),
                        ] {
                            if ui
                                .selectable_value(&mut self.folder, folder, title)
                                .clicked()
                            {
                                self.letter = None;
                            }
                        }
                        ui.separator();
                        if ui
                            .button("Receive keys")
                            .on_hover_text("Publish four one-use receive keys for this mailbox")
                            .clicked()
                        {
                            self.request(Request::Refill {
                                mailbox: self.selected.clone(),
                            });
                        }
                    },
                );
            });
    }
    fn store(&mut self, ui: &mut egui::Ui) {
        let previous = self.store.clone();
        egui::ComboBox::from_label("Store")
            .selected_text(if self.store.is_empty() {
                "Select".into()
            } else {
                short(&self.store)
            })
            .show_ui(ui, |ui| {
                for store in &self.overview.stores {
                    ui.selectable_value(&mut self.store, store.clone(), short(store))
                        .on_hover_text(store);
                }
            })
            .response
            .on_hover_text(&self.store);
        if self.store != previous {
            self.inbox = None;
            self.letter = None;
        }
    }
    pub(super) fn content(&mut self, ui: &mut egui::Ui) {
        if self.overview.mailboxes.is_empty() {
            ui.label("No mailbox in this vault");
            return;
        }
        if self.letter.is_some() {
            self.message(ui);
            return;
        }
        match self.folder {
            Folder::Inbox => self.inbox_view(ui),
            Folder::Archive => self.archive_view(ui),
            Folder::Outbox => self.outbox_view(ui),
            Folder::Contacts => self.contacts(ui),
            Folder::Compose => self.compose_view(ui),
        }
    }
    fn inbox_view(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.heading("Inbox");
            self.store(ui);
            if ui.button("Refresh").clicked() {
                self.inbox(None);
            }
            if self.inbox.as_ref().is_some_and(|i| i.next.is_some())
                && ui.button("Next page").clicked()
            {
                self.inbox(self.inbox.as_ref().and_then(|i| i.next.clone()));
            }
        });
        ui.separator();
        let mut request = None;
        let mut deletion = None;
        scroll(ui, "Inbox messages", |ui| {
            if let Some(inbox) = &self.inbox {
                if inbox.messages.is_empty() {
                    ui.label("No messages");
                }
                for message in &inbox.messages {
                    ui.push_id(&message.id, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            if ui
                                .button(format!("Open {}", short(&message.id)))
                                .on_hover_text(&message.id)
                                .clicked()
                            {
                                request = Some(Request::Read {
                                    mailbox: self.selected.clone(),
                                    store: self.store.clone(),
                                    message: message.id.clone(),
                                });
                            }
                            ui.label(format!("{} bytes", message.bytes.unwrap_or(0)));
                            ui.label(expiry(message.expires));
                            if ui.button("Delete stored copy").clicked() {
                                deletion = Some(Deletion {
                                    remote: true,
                                    mailbox: self.selected.clone(),
                                    store: self.store.clone(),
                                    message: message.id.clone(),
                                });
                            }
                        });
                        ui.separator();
                    });
                }
            } else {
                ui.label("Refresh to list stored messages");
            }
        });
        if let Some(request) = request {
            self.request(request);
        }
        if let Some(deletion) = deletion {
            self.deletion = Some(deletion);
        }
    }
    fn archive_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Local archive");
        ui.separator();
        let mut request = None;
        let mut deletion = None;
        scroll(ui, "Archived messages", |ui| {
            let messages: Vec<_> = self
                .overview
                .archive
                .iter()
                .filter(|m| m.mailbox == self.selected)
                .collect();
            if messages.is_empty() {
                ui.label("No archived messages");
            }
            for message in messages {
                ui.push_id(&message.id, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        if ui
                            .button(
                                message
                                    .subject
                                    .as_deref()
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or("No subject"),
                            )
                            .clicked()
                        {
                            request = Some(Request::ArchiveRead {
                                message: message.id.clone(),
                            });
                        }
                        if ui.button("Delete local copy").clicked() {
                            deletion = Some(Deletion {
                                remote: false,
                                mailbox: self.selected.clone(),
                                store: self.store.clone(),
                                message: message.id.clone(),
                            });
                        }
                    });
                    if let Some(sender) = &message.sender {
                        ui.label(short(sender)).on_hover_text(sender);
                    }
                    ui.separator();
                });
            }
        });
        if let Some(request) = request {
            self.request(request);
        }
        if let Some(deletion) = deletion {
            self.deletion = Some(deletion);
        }
    }
    fn outbox_view(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.heading("Outbox");
            self.store(ui);
        });
        ui.separator();
        let mut request = None;
        scroll(ui, "Outgoing messages", |ui| {
            let messages: Vec<_> = self
                .overview
                .outbox
                .iter()
                .filter(|m| m.mailbox == self.selected)
                .collect();
            if messages.is_empty() {
                ui.label("No outgoing messages");
            }
            for message in messages {
                ui.push_id(&message.message, |ui| {
                    ui.strong(if message.subject.is_empty() {
                        "No subject"
                    } else {
                        &message.subject
                    });
                    ui.label(short(&message.recipient))
                        .on_hover_text(&message.recipient);
                    ui.horizontal_wrapped(|ui| {
                        ui.label(format!(
                            "{} · {} of {} stored copies",
                            message.state,
                            message.copies,
                            message
                                .required_copies
                                .map(|n| n.to_string())
                                .unwrap_or_else(|| "?".into())
                        ));
                        if ui.button("Review / retry").clicked() {
                            request = Some(Request::Review {
                                message: message.message.clone(),
                                store: self.store.clone(),
                            });
                        }
                    });
                    ui.separator();
                });
            }
        });
        if let Some(request) = request {
            self.request(request);
        }
    }
    fn compose_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Compose");
        ui.separator();
        scroll(ui, "Compose message", |ui| {
            field(ui, "Recipient address", &mut self.draft.recipient, 64);
            field(ui, "Subject", &mut self.draft.subject, 512);
            let label = ui.label("Message");
            let response = ui
                .add(
                    egui::TextEdit::multiline(&mut self.draft.body)
                        .char_limit(32768)
                        .desired_rows(14)
                        .desired_width(f32::INFINITY),
                )
                .labelled_by(label.id);
            scrolling::reveal_focus(&response);
            ui.horizontal_wrapped(|ui| {
                let label = ui.label("Expires after (hours)");
                ui.add(egui::DragValue::new(&mut self.draft.retention_hours).range(1..=168))
                    .labelled_by(label.id);
                if ui.button("Save draft").clicked() {
                    self.request(Request::Compose {
                        mailbox: self.selected.clone(),
                        draft: self.draft.clone(),
                    });
                }
            });
        });
    }
    fn contacts(&mut self, ui: &mut egui::Ui) {
        ui.heading("Contacts");
        ui.separator();
        scroll(ui, "Contacts and verification", |ui| {
            let changed = field(ui, "Recipient address", &mut self.contact_address, 64)
                | field(ui, "Owner public key", &mut self.contact_owner, 64);
            if changed {
                self.contact_checked = false;
            }
            ui.checkbox(
                &mut self.contact_checked,
                "I verified this owner key independently",
            );
            if ui
                .add_enabled(self.contact_checked, egui::Button::new("Verify contact"))
                .clicked()
            {
                self.request(Request::VerifyContact {
                    mailbox: self.selected.clone(),
                    address: self.contact_address.clone(),
                    owner: self.contact_owner.clone(),
                });
                self.contact_checked = false;
            }
            ui.separator();
            for contact in &self.overview.contacts {
                identifier(ui, "Address", &contact.address);
                identifier(ui, "Verified owner", &contact.owner);
                ui.label(format!("Revision {}", contact.generation));
                ui.separator();
            }
        });
    }
    fn message(&mut self, ui: &mut egui::Ui) {
        if ui.button("Back to messages").clicked() {
            self.letter = None;
            return;
        }
        let letter = self.letter.as_ref().unwrap();
        scroll(ui, "Message content", |ui| {
            ui.heading(if letter.subject.is_empty() {
                "No subject"
            } else {
                &letter.subject
            });
            identifier(ui, "From", &letter.route.sender_address);
            identifier(ui, "To", &letter.route.recipient_address);
            ui.separator();
            ui.add(egui::Label::new(&letter.body).wrap().selectable(true));
        });
    }
    pub(super) fn confirmations(&mut self, ctx: &egui::Context) {
        let mut decision = None;
        if let Some(review) = &self.review {
            let mut open = true;
            egui::Window::new("Review message")
                .open(&mut open)
                .default_width(720.0)
                .default_height(600.0)
                .show(ctx, |ui| {
                    self.appearance.apply(ui);
                    ui.horizontal_wrapped(|ui| {
                        if ui
                            .add_enabled(!self.busy, egui::Button::new("Send to selected store"))
                            .clicked()
                        {
                            decision = Some(true);
                        }
                        if ui.button("Cancel").clicked() {
                            decision = Some(false);
                        }
                    });
                    ui.separator();
                    scroll(ui, "Message review", |ui| {
                        identifier(ui, "From", &review.sender);
                        identifier(ui, "To", &review.recipient);
                        identifier(ui, "Verified owner", &review.consent.recipient_owner);
                        ui.label(format!(
                            "Recipient revision {}",
                            review.consent.recipient_generation
                        ));
                        identifier(ui, "Selected store", &review.consent.store);
                        ui.label(format!(
                            "Required copies: {} · Expires: {}",
                            review.consent.required_copies,
                            expiry(review.expires)
                        ));
                        ui.separator();
                        ui.strong(&review.subject);
                        ui.add(egui::Label::new(&review.body).wrap().selectable(true));
                    });
                });
            if !open {
                decision = Some(false);
            }
        }
        if let Some(send) = decision {
            let review = self.review.take().unwrap();
            if send {
                self.request(Request::Send { review });
            }
        }
        let mut deletion = None;
        if let Some(intent) = &self.deletion {
            let mut open = true;
            egui::Window::new(if intent.remote {
                "Delete stored copy"
            } else {
                "Delete local copy"
            })
            .open(&mut open)
            .show(ctx, |ui| {
                self.appearance.apply(ui);
                identifier(ui, "Mailbox", &intent.mailbox);
                identifier(ui, "Message", &intent.message);
                if intent.remote {
                    identifier(ui, "Store", &intent.store);
                } else {
                    ui.label("Permanently delete this device's readable copy? Stored ciphertext cannot restore it.");
                }
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .add_enabled(!self.busy, egui::Button::new("Delete"))
                        .clicked()
                    {
                        deletion = Some(true);
                    }
                    if ui.button("Cancel").clicked() {
                        deletion = Some(false);
                    }
                });
            });
            if !open {
                deletion = Some(false);
            }
        }
        if let Some(delete) = deletion {
            let intent = self.deletion.take().unwrap();
            if delete {
                self.request(if intent.remote {
                    Request::RemoteDelete {
                        mailbox: intent.mailbox,
                        store: intent.store,
                        message: intent.message,
                    }
                } else {
                    Request::ArchiveDelete {
                        message: intent.message,
                    }
                });
                self.inbox = None;
            }
        }
    }
}
