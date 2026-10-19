// SPDX-License-Identifier: MIT
// Transfer views expose exact recipient, storage and output choices before confirmation.
use super::*;
pub(super) fn field(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(egui::RichText::new(label).strong());
    ui.add(egui::Label::new(value).wrap().selectable(true));
    ui.add_space(5.0);
}
pub(super) fn display_offer(ui: &mut egui::Ui, offer: &Offer) {
    field(ui, "Transfer", &hex::encode(offer.id));
    field(ui, "Label", &offer.label);
    field(ui, "Sender", &hex::encode(offer.sender));
    field(ui, "Recipient", &hex::encode(offer.recipient));
    field(ui, "Recipient age key", &offer.encryption_key);
    field(ui, "File bytes", &offer.file_bytes.to_string());
    field(ui, "Ciphertext bytes", &offer.payload_bytes.to_string());
    field(ui, "Ciphertext digest", &hex::encode(offer.payload_digest));
    time::field(ui, "Offer expires", offer.expires);
}
fn input(ui: &mut egui::Ui, label: &str, value: &mut String) {
    let label = ui.label(label);
    let response = ui
        .add(egui::TextEdit::singleline(value).desired_width(f32::INFINITY))
        .labelled_by(label.id);
    super::super::scrolling::reveal_focus(&response);
}
impl Transfers {
    pub(super) fn content(&mut self, ui: &mut egui::Ui) {
        if self.local.is_none() {
            ui.heading("Transfer vault");
            ui.horizontal(|ui| {
                if ui.button("Open existing vault").clicked() { self.submit(Request::Local); }
                if ui.button("Create vault").clicked() { self.simple_review("Create transfer vault", "Create", Request::Initialise, None,
                    "Create a new encrypted vault and independent age key at the launch paths. Existing state is never replaced."); }
            });
            return;
        }
        if let Some(pending) = self.local.as_ref().and_then(|local| local.pending.clone()) {
            ui.heading("Retained operation");
            field(ui, &pending.operation, &pending.transfer);
            if pending.needs_output {
                input(ui, "New output path", &mut self.output);
                if ui.button("Choose output…").clicked() {
                    self.picker = Some(files::Picker::new(true, &self.output));
                }
            }
            if ui
                .add_enabled(
                    !pending.needs_output || !self.output.is_empty(),
                    egui::Button::new("Review recovery"),
                )
                .clicked()
            {
                let output = pending.needs_output.then(|| PathBuf::from(&self.output));
                let mut fields = pending.fields;
                if let Some(output) = &output {
                    fields.push(("New output", output.display().to_string()));
                }
                self.review = Some(Review {
                    title: "Recover retained operation",
                    action: "Recover",
                    request: Request::Recover {
                        digest: pending.digest,
                        output,
                    },
                    offer: None,
                    fields,
                    acknowledged: false,
                    acknowledgement: "Reconcile this exact previously authorized operation.",
                });
            }
            ui.separator();
        }
        if self.view == View::Compose {
            self.compose(ui);
            return;
        }
        ui.horizontal(|ui| {
            let label = ui.label("Transfer ID");
            let response = ui
                .add(egui::TextEdit::singleline(&mut self.inspect).desired_width(470.0))
                .labelled_by(label.id);
            super::super::scrolling::reveal_focus(&response);
            if ui.button("Inspect").clicked() {
                self.submit(Request::Inspect(self.inspect.clone()));
            }
        });
        ui.separator();
        if self.view == View::Outbox {
            ui.collapsing("My transfer identity", |ui| {
                if let Some(local) = &self.local {
                    field(ui, "Participant", &local.participant);
                    field(ui, "Public age key", &local.recipient_age);
                }
            });
            let offers = self
                .local
                .as_ref()
                .map(|local| local.offers.clone())
                .unwrap_or_default();
            if offers.is_empty() {
                ui.label("No locally retained offers");
            }
            for offer in offers {
                let name = format!(
                    "{}  |  {} bytes  |  {}",
                    offer.label,
                    offer.file_bytes,
                    &hex::encode(offer.id)[..12]
                );
                if ui
                    .selectable_label(
                        self.retained.as_ref().is_some_and(|v| v.id == offer.id),
                        name,
                    )
                    .clicked()
                {
                    self.retained = Some(offer);
                    self.selected = None;
                }
            }
        } else {
            if self.offers.is_empty() {
                ui.label("No offers on this page");
            }
            for agreement in self.offers.clone() {
                let offer = &agreement.offer;
                let status = if agreement.cancelled {
                    "Cancelled"
                } else if agreement.acceptance.is_some() {
                    "Accepted"
                } else {
                    "Awaiting acceptance"
                };
                let name = format!(
                    "{}  |  {} bytes  |  {status}",
                    offer.label, offer.file_bytes
                );
                if ui
                    .selectable_label(
                        self.selected
                            .as_ref()
                            .is_some_and(|v| v.offer.id == offer.id),
                        name,
                    )
                    .clicked()
                {
                    self.inspect = hex::encode(offer.id);
                    self.selected = Some(agreement);
                    self.retained = None;
                }
            }
            ui.horizontal(|ui| {
                if ui.button("First page").clicked() {
                    self.refresh();
                }
                if ui
                    .add_enabled(self.next.is_some(), egui::Button::new("Next page"))
                    .clicked()
                {
                    self.submit(Request::List {
                        action: if self.view == View::Incoming { 19 } else { 18 },
                        after: self.next.clone(),
                    });
                }
            });
        }
        ui.separator();
        if let Some(offer) = self.retained.clone() {
            self.retained_view(ui, offer);
        }
        if let Some(agreement) = self.selected.clone() {
            self.agreement_view(ui, agreement);
        }
    }
    fn compose(&mut self, ui: &mut egui::Ui) {
        ui.heading("New transfer");
        input(ui, "File", &mut self.form.file);
        if ui.button("Choose file…").clicked() {
            self.picker = Some(files::Picker::new(false, &self.form.file));
        }
        input(ui, "Recipient participant key", &mut self.form.recipient);
        input(ui, "Recipient age key", &mut self.form.age);
        input(ui, "Public label", &mut self.form.label);
        self.form
            .duration
            .control(ui, "OfferDuration", "Available for");
        if ui
            .button("Prepare offer")
            .on_hover_text("Encrypt and retain the exact file locally, then review publication")
            .clicked()
        {
            match time::now().and_then(|now| self.form.duration.expiry(now)) {
                Ok(expires) => self.submit(Request::Prepare(Draft {
                    file: PathBuf::from(&self.form.file),
                    recipient: self.form.recipient.clone(),
                    recipient_age: self.form.age.clone(),
                    label: self.form.label.clone(),
                    expires,
                })),
                Err(error) => self.error = Some(error.to_string()),
            }
        }
    }
    fn retained_view(&mut self, ui: &mut egui::Ui, offer: Offer) {
        ui.heading(&offer.label);
        ui.horizontal_wrapped(|ui| {
            if ui.button("Review publication").clicked() { self.publish_review(offer.clone()); }
            if ui.button("Inspect agreement").clicked() { self.submit(Request::Inspect(hex::encode(offer.id))); }
            if ui.button("Forget local data").clicked() { self.simple_review("Forget local data", "Forget", Request::Forget(hex::encode(offer.id)), Some(offer.clone()),
                "Remove this participant's retained ciphertext. An unfinished upload cannot resume without it. Network and store state remain unchanged."); }
        });
        display_offer(ui, &offer);
    }
    fn agreement_view(&mut self, ui: &mut egui::Ui, agreement: Agreement) {
        let current = &agreement.offer;
        let transfer = hex::encode(current.id);
        let participant = self
            .local
            .as_ref()
            .map(|local| local.participant.as_str())
            .unwrap_or("");
        let sender = hex::encode(current.sender) == participant;
        let recipient = hex::encode(current.recipient) == participant;
        ui.heading(&current.label);
        if agreement.cancelled {
            ui.colored_label(egui::Color32::LIGHT_RED, "Cancelled");
        }
        ui.horizontal_wrapped(|ui| {
            if ui.button("Refresh agreement").clicked() { self.submit(Request::Inspect(transfer.clone())); }
            if !agreement.cancelled && ui.button("Cancel transfer").clicked() { self.simple_review("Cancel transfer", "Cancel transfer", Request::Cancel(transfer.clone()), Some(current.clone()),
                "Prevent future store operations. Cancellation does not erase remote or local data. Delete stored ciphertext first if required."); }
            if ui.button("Forget local data").clicked() { self.simple_review("Forget local data", "Forget", Request::Forget(transfer.clone()), Some(current.clone()),
                "Remove this participant's retained ciphertext and partial download. Network and store state remain unchanged."); }
        });
        if let Some(acceptance) = &agreement.acceptance {
            field(ui, "Accepted store", &hex::encode(acceptance.service.id));
            field(ui, "Destination label", &acceptance.destination);
            time::field(ui, "Acceptance expires", acceptance.expires);
            ui.horizontal_wrapped(|ui| {
                if ui.add_enabled(!agreement.cancelled, egui::Button::new("Store status")).clicked() { self.submit(Request::Status(transfer.clone())); }
                if sender && ui.add_enabled(!agreement.cancelled, egui::Button::new("Upload / resume")).clicked() {
                    self.simple_review("Upload encrypted file", "Upload", Request::Send(transfer.clone()), Some(current.clone()), "Upload the retained encrypted file to the recipient's accepted store.");
                    if let Some(review) = &mut self.review { review.fields.push(("Store", hex::encode(acceptance.service.id))); }
                }
                if recipient && ui.add_enabled(!agreement.cancelled, egui::Button::new("Delete stored data")).clicked() {
                    self.simple_review("Delete stored data", "Delete", Request::Delete(transfer.clone()), Some(current.clone()), "Delete ciphertext at the accepted store. This does not erase local copies or backups.");
                    if let Some(review) = &mut self.review { review.fields.push(("Store", hex::encode(acceptance.service.id))); }
                }
            });
            if recipient && !agreement.cancelled {
                input(ui, "New output path", &mut self.output);
                ui.horizontal(|ui| {
                    if ui.button("Choose output…").clicked() { self.picker = Some(files::Picker::new(true, &self.output)); }
                    if ui.add_enabled(!self.output.is_empty(), egui::Button::new("Download / resume")).clicked() {
                        self.simple_review("Download file", "Download", Request::Receive { agreement: agreement.clone(), output: PathBuf::from(&self.output) }, Some(current.clone()),
                            "Download, authenticate and decrypt into a new private file. Existing paths and symbolic links are refused. File content is never executed.");
                        if let Some(review) = &mut self.review { review.fields.push(("New output", self.output.clone())); review.fields.push(("Store", hex::encode(acceptance.service.id))); }
                    }
                });
            }
        } else if recipient && !agreement.cancelled {
            self.acceptance(ui, &agreement);
        } else if sender && !agreement.cancelled {
            ui.label("Awaiting recipient acceptance");
        }
        ui.separator();
        display_offer(ui, current);
    }
    fn acceptance(&mut self, ui: &mut egui::Ui, agreement: &Agreement) {
        ui.heading("Accept offer");
        ui.horizontal(|ui| {
            if ui.button("Find stores").clicked() {
                self.submit(Request::Stores { after: None });
            }
            if ui
                .add_enabled(self.hosts_next.is_some(), egui::Button::new("More stores"))
                .clicked()
            {
                self.submit(Request::Stores {
                    after: self.hosts_next.clone(),
                });
            }
        });
        for host in &self.hosts {
            let compatible = !host.withdrawn
                && host.route.is_some()
                && host.maximum_payload >= agreement.offer.payload_bytes;
            let label = format!(
                "{}…  |  {} bytes capacity  |  {} bytes per file",
                &host.service[..16],
                host.state_bytes,
                host.maximum_payload
            );
            if ui
                .add_enabled(
                    compatible,
                    egui::Button::selectable(self.host == host.service, label),
                )
                .on_hover_text(format!(
                    "Store: {}\nRoute: {}\nMaximum lifetime: {}",
                    host.service,
                    host.route.as_deref().unwrap_or("Unavailable"),
                    time::duration(host.maximum_lifetime_ms)
                ))
                .clicked()
            {
                self.host = host.service.clone();
                self.host_lifetime = Some(host.maximum_lifetime_ms);
            }
        }
        if !self.host.is_empty() {
            field(ui, "Selected store", &self.host);
        }
        input(ui, "Destination label", &mut self.destination);
        ui.radio_value(&mut self.shorter_acceptance, false, "Until offer expires");
        ui.radio_value(&mut self.shorter_acceptance, true, "Shorter duration");
        if self.shorter_acceptance {
            self.acceptance_duration
                .control(ui, "AcceptanceDuration", "Available for");
        }
        let expiry = time::now().and_then(|now| {
            let lifetime = self
                .host_lifetime
                .ok_or_else(|| anyhow::anyhow!("select a store"))?;
            let shorter = self
                .shorter_acceptance
                .then(|| self.acceptance_duration.expiry(now))
                .transpose()?;
            time::acceptance(now, agreement.offer.expires, lifetime, shorter)
        });
        if let Some(lifetime) = self.host_lifetime {
            ui.label(format!(
                "Selected store limit: {}",
                time::duration(lifetime)
            ));
            match &expiry {
                Ok(expires) => time::field(ui, "Acceptance ends", *expires),
                Err(error) => {
                    ui.colored_label(egui::Color32::LIGHT_RED, error.to_string());
                }
            }
        }
        if ui
            .add_enabled(expiry.is_ok(), egui::Button::new("Review acceptance"))
            .clicked()
            && let Ok(expires) = expiry
        {
            let review = AcceptanceReview {
                agreement: agreement.clone(),
                service: self.host.clone(),
                destination: self.destination.clone(),
                expires,
            };
            self.review = Some(Review {
                title: "Accept transfer",
                action: "Accept",
                request: Request::Accept(review),
                offer: Some(agreement.offer.clone()),
                fields: vec![
                    ("Selected store", self.host.clone()),
                    ("Destination label", self.destination.clone()),
                ],
                acknowledged: false,
                acknowledgement: "Accept this exact offer and encrypted storage location.",
            });
        }
    }
}
