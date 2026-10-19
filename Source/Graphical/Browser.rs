// SPDX-License-Identifier: MIT
// Native browser chrome owns presentation; the existing browser owns network authority.
use crate::{markup, page_view, reader};
use anyhow::{Result, ensure};
use eframe::egui;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, SyncSender, sync_channel},
    },
};

#[path = "Chrome.rs"]
mod chrome;
#[path = "Common.rs"]
pub(crate) mod common;
#[path = "PageRenderer.rs"]
mod renderer;
#[path = "Scrolling.rs"]
pub(crate) mod scrolling;
#[path = "Session.rs"]
mod session;
#[path = "Settings.rs"]
pub(crate) mod settings;
#[path = "Theme.rs"]
mod theme;
#[path = "Transfers.rs"]
pub(crate) mod transfers;
pub use session::Session;
use session::{Message, Page};

pub fn image_key(asset: &markup::media::Asset) -> String {
    format!(
        "{}:{}x{}:{}",
        asset.profile, asset.width, asset.height, asset.digest
    )
}

pub fn run(work: impl FnOnce(crate::viewer::Session) -> Result<()> + Send + 'static) -> Result<()> {
    let closed = Arc::new(AtomicBool::new(false));
    let app_closed = closed.clone();
    let outcome = Arc::new(std::sync::Mutex::new(None));
    let worker_outcome = outcome.clone();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("HyperNet Browser")
            .with_app_id("HyperNetBrowser")
            .with_inner_size([1180.0, 800.0])
            .with_min_inner_size([620.0, 420.0]),
        renderer: eframe::Renderer::Glow,
        persist_window: false,
        ..Default::default()
    };
    let result = eframe::run_native(
        "HyperNet Browser",
        options,
        Box::new(move |cc| {
            chrome::theme(&cc.egui_ctx);
            let (sender, receiver) = sync_channel(1);
            let session = Session {
                sender: sender.clone(),
                context: cc.egui_ctx.clone(),
                closed: app_closed.clone(),
            };
            let context = cc.egui_ctx.clone();
            std::thread::Builder::new()
                .name("HyperNetBrowser".into())
                .spawn(move || {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        work(crate::viewer::Session::Graphical(session))
                    }))
                    .unwrap_or_else(|_| {
                        Err(anyhow::anyhow!("browser operation stopped unexpectedly"))
                    })
                    .map_err(|error| format!("{error:#}"));
                    if let Ok(mut outcome) = worker_outcome.lock() {
                        *outcome = Some(result.clone());
                    }
                    let _ = sender.send(Message::Finished(result));
                    context.request_repaint();
                })?;
            Ok(Box::new(Browser::new(receiver, app_closed)))
        }),
    );
    closed.store(true, Ordering::Release);
    crate::private_route_client::request_cancel();
    result.map_err(|error| anyhow::anyhow!("cannot open graphical browser: {error}"))?;
    if let Some(Err(error)) = outcome.lock().ok().and_then(|mut result| result.take()) {
        anyhow::bail!("{error}");
    }
    Ok(())
}

struct Confirmation {
    value: serde_json::Value,
    reply: SyncSender<bool>,
    acknowledgement: String,
    end_seen: bool,
    scroll_offset: Option<f32>,
}

struct Browser {
    receiver: Receiver<Message>,
    closed: Arc<AtomicBool>,
    page: Option<Box<Page>>,
    renderer: renderer::PageRenderer,
    fingerprint: Vec<u8>,
    images: BTreeMap<String, egui::TextureHandle>,
    image_bytes: usize,
    busy: bool,
    finished: bool,
    error: Option<String>,
    confirmation: Option<Confirmation>,
    address: String,
    focus_address: bool,
    sidebar: bool,
    filter: String,
    settings_open: bool,
    help_open: bool,
    information_open: bool,
    help_filter: String,
    preferences: settings::Preferences,
    store: settings::Store,
    settings_error: Option<String>,
}

impl Browser {
    fn new(receiver: Receiver<Message>, closed: Arc<AtomicBool>) -> Self {
        let (store, preferences, settings_error) = settings::Store::load();
        Self {
            receiver,
            closed,
            page: None,
            renderer: Default::default(),
            fingerprint: Vec::new(),
            images: BTreeMap::new(),
            image_bytes: 0,
            busy: true,
            finished: false,
            error: None,
            confirmation: None,
            address: String::new(),
            focus_address: false,
            sidebar: false,
            filter: String::new(),
            settings_open: false,
            help_open: false,
            information_open: false,
            help_filter: String::new(),
            preferences,
            store,
            settings_error,
        }
    }

    fn messages(&mut self, ctx: &egui::Context) {
        while let Ok(message) = self.receiver.try_recv() {
            match message {
                Message::Busy => {
                    self.busy = true;
                    self.error = None;
                }
                Message::Page(mut page) => {
                    ctx.send_viewport_cmd_to(
                        egui::ViewportId::ROOT,
                        egui::ViewportCommand::Title(format!("{} — HyperNet", page.document.title)),
                    );
                    let fingerprint = serde_json::to_vec(&(&page.document, page.view.instance))
                        .unwrap_or_default();
                    if self.fingerprint != fingerprint {
                        self.renderer.reset();
                        self.fingerprint = fingerprint;
                        self.filter.clear();
                    }
                    if let Some(address) = page
                        .metadata
                        .iter()
                        .find(|value| value.starts_with("hypernet://"))
                    {
                        self.address = address.clone();
                    } else {
                        self.address.clear();
                    }
                    page.view.monochrome = self.preferences.monochrome;
                    self.page = Some(page);
                    self.busy = false;
                    self.error = None;
                }
                Message::Image(asset, pixels, reply) => {
                    let result = self.install_image(ctx, &asset, pixels);
                    let _ = reply.send(result);
                }
                Message::Confirm(value, reply) => {
                    self.confirmation = Some(Confirmation {
                        value,
                        reply,
                        acknowledgement: String::new(),
                        end_seen: false,
                        scroll_offset: None,
                    });
                    self.busy = false;
                }
                Message::Finished(result) => {
                    self.busy = false;
                    self.finished = true;
                    if let Err(error) = result {
                        self.error = Some(error);
                    }
                }
            }
        }
    }

    fn install_image(
        &mut self,
        ctx: &egui::Context,
        asset: &markup::media::Asset,
        pixels: crate::media_import::Pixels,
    ) -> Result<()> {
        pixels.validate()?;
        let key = image_key(asset);
        if self.images.contains_key(&key) {
            return Ok(());
        }
        let bytes = pixels.rgb.len() / 3 * 4;
        // Thirty-two MiB holds all assets from several pages without an unbounded GPU cache.
        if self.image_bytes + bytes > 32 * 1024 * 1024 {
            let active = self
                .page
                .as_ref()
                .map(|page| {
                    page.document
                        .assets
                        .iter()
                        .map(image_key)
                        .collect::<std::collections::BTreeSet<_>>()
                })
                .unwrap_or_default();
            self.images.retain(|key, _| active.contains(key));
            self.image_bytes = self
                .images
                .values()
                .map(|image| image.size()[0] * image.size()[1] * 4)
                .sum();
        }
        ensure!(
            self.image_bytes + bytes <= 32 * 1024 * 1024,
            "image cache is full"
        );
        let image = egui::ColorImage::from_rgb(
            [pixels.width as usize, pixels.height as usize],
            &pixels.rgb,
        );
        self.images.insert(
            key,
            ctx.load_texture("Approved media", image, egui::TextureOptions::LINEAR),
        );
        self.image_bytes += bytes;
        Ok(())
    }

    fn action(&mut self, action: reader::Action) {
        if self.busy || self.confirmation.is_some() || self.finished {
            return;
        }
        if let Some(page) = &mut self.page
            && let Some(reply) = page.reply.take()
        {
            let _ = reply.send((action, page.view.clone()));
            self.busy = true;
        }
    }

    fn can_navigate(&self) -> bool {
        !self.busy
            && !self.finished
            && self.confirmation.is_none()
            && self
                .page
                .as_ref()
                .is_some_and(|page| page.mode != reader::Mode::Preview)
    }

    fn keyboard(&mut self, ctx: &egui::Context) {
        let command = egui::Modifiers::CTRL;
        if ctx.input_mut(|i| i.consume_key(command, egui::Key::L)) {
            self.focus_address = true;
        }
        if ctx.input_mut(|i| i.consume_key(command, egui::Key::Comma)) {
            self.settings_open = true;
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::F1)) {
            self.help_open = true;
        }
        if self.can_navigate() {
            if ctx.input_mut(|i| i.consume_key(command, egui::Key::R)) {
                self.action(reader::Action::Refresh);
            }
            if ctx.input_mut(|i| i.consume_key(egui::Modifiers::ALT, egui::Key::ArrowLeft)) {
                self.action(reader::Action::Back);
            }
        }
    }

    fn shutdown(&mut self) {
        self.closed.store(true, Ordering::Release);
        crate::private_route_client::request_cancel();
        self.confirmation.take();
        if let Some(page) = &mut self.page {
            page.reply.take();
        }
    }
}

impl eframe::App for Browser {
    fn logic(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        self.messages(ctx);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.messages(&ctx);
        self.keyboard(&ctx);
        chrome::text_size(ui, self.preferences.text_scale);
        self.toolbar(ui);
        self.status_bar(ui);
        self.sidebar(ui);
        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .inner_margin(20.0)
                    .fill(egui::Color32::from_rgb(20, 23, 26)),
            )
            .show(ui, |ui| {
                if let Some(error) = &self.error {
                    ui.colored_label(egui::Color32::from_rgb(239, 150, 133), "Unable to continue");
                    ui.label(error);
                }
                if let Some(page) = &mut self.page {
                    page.view.monochrome = self.preferences.monochrome;
                    let enabled = !self.busy && !self.finished && self.confirmation.is_none();
                    let action = ui
                        .add_enabled_ui(enabled, |ui| {
                            self.renderer.show(
                                ui,
                                &page.document,
                                &mut page.view,
                                &self.images,
                                self.preferences.animations && enabled,
                            )
                        })
                        .inner;
                    if let Some(action) = action {
                        self.action(action);
                    }
                } else if self.busy {
                    ui.vertical_centered(|ui| {
                        ui.add_space(80.0);
                        ui.spinner();
                        ui.label("Connecting");
                    });
                }
            });
        self.windows(&ctx);
        if ctx.input(|i| i.viewport().close_requested()) {
            self.shutdown();
        }
    }

    fn on_exit(&mut self, _: Option<&eframe::glow::Context>) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cache_identity_includes_profile_dimensions_and_digest() {
        let asset = markup::media::Asset {
            id: "Image".into(),
            profile: markup::media::RASTER_PROFILE.into(),
            width: 2,
            height: 1,
            bytes: 6,
            digest: "a".repeat(64),
            hosts: vec!["b".repeat(64)],
            copies: 1,
        };
        let mut other = asset.clone();
        other.id = "Alias".into();
        assert_eq!(image_key(&asset), image_key(&other));
        other.digest = "c".repeat(64);
        assert_ne!(image_key(&asset), image_key(&other));
        other = asset.clone();
        other.width = 1;
        other.height = 2;
        assert_ne!(image_key(&asset), image_key(&other));
        other = asset.clone();
        other.profile = markup::media::VECTOR_PROFILE.into();
        assert_ne!(image_key(&asset), image_key(&other));
    }
}
