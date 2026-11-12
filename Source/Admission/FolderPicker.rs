// SPDX-License-Identifier: MIT
// A bounded background folder chooser keeps package selection local and explicit.
use eframe::egui;
use std::{
    path::PathBuf,
    sync::mpsc::{Receiver, sync_channel},
    time::Duration,
};
pub struct Picker {
    directory: PathBuf,
    entries: Vec<PathBuf>,
    pending: Option<Receiver<Result<Vec<PathBuf>, String>>>,
    error: Option<String>,
    pub open: bool,
}
impl Default for Picker {
    fn default() -> Self {
        Self {
            directory: "/".into(),
            entries: vec![],
            pending: None,
            error: None,
            open: false,
        }
    }
}
impl Picker {
    pub fn choose(&mut self, path: PathBuf, ctx: &egui::Context) {
        self.open = true;
        let mut directory = if path.is_absolute() {
            path
        } else {
            std::env::current_dir().unwrap_or_else(|_| "/".into())
        };
        while !directory.is_dir() {
            if !directory.pop() {
                directory = "/".into();
                break;
            }
        }
        self.navigate(directory, ctx);
    }
    fn navigate(&mut self, directory: PathBuf, ctx: &egui::Context) {
        self.directory = directory.clone();
        self.entries.clear();
        self.error = None;
        let (sender, receiver) = sync_channel(1);
        let context = ctx.clone();
        std::thread::spawn(move || {
            let result = (|| -> std::io::Result<Vec<PathBuf>> {
                let mut entries = std::fs::read_dir(directory)?
                    .take(2048)
                    .filter_map(Result::ok)
                    .filter_map(|e| e.file_type().ok().filter(|t| t.is_dir()).map(|_| e.path()))
                    .take(256)
                    .collect::<Vec<_>>();
                entries.sort();
                Ok(entries)
            })()
            .map_err(|_| "This folder cannot be read. Choose another folder.".into());
            let _ = sender.send(result);
            context.request_repaint();
        });
        self.pending = Some(receiver);
    }
    pub fn show(&mut self, ctx: &egui::Context) -> Option<PathBuf> {
        if !self.open {
            return None;
        }
        if let Some(result) = self.pending.as_ref().and_then(|r| r.try_recv().ok()) {
            self.pending = None;
            match result {
                Ok(entries) => self.entries = entries,
                Err(error) => self.error = Some(error),
            }
        }
        let mut open = self.open;
        let mut chosen = None;
        let mut navigate = None;
        let mut cancel = false;
        egui::Window::new("Choose the coordinated Packages folder").open(&mut open).default_size([560.0,420.0]).show(ctx,|ui|{
            ui.add(egui::Label::new(self.directory.display().to_string()).wrap());
            if let Some(error)=&self.error {ui.colored_label(egui::Color32::LIGHT_RED,error);}
            ui.horizontal(|ui|{
                if ui.add_enabled(self.directory.parent().is_some(),egui::Button::new("Up")).clicked(){navigate=self.directory.parent().map(PathBuf::from);}
                if ui.add_enabled(self.pending.is_none(),egui::Button::new("Choose this folder")).clicked(){chosen=Some(self.directory.clone());}
                if ui.button("Cancel").clicked(){cancel=true;}
            });
            if self.pending.is_some(){ui.spinner();}
            egui::ScrollArea::vertical().max_height(340.0).show(ui,|ui|{
                for entry in &self.entries {
                    if ui.button(entry.file_name().unwrap_or_default().to_string_lossy()).clicked(){navigate=Some(entry.clone());}
                }
            });
            ui.small("Choose the Packages folder containing Core and Suite. At most256 folders are shown; the path can also be entered in the setup window.");
        });
        if let Some(path) = navigate {
            self.navigate(path, ctx);
        }
        self.open = open && !cancel && chosen.is_none();
        if self.pending.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        chosen
    }
}
