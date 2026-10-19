// SPDX-License-Identifier: MIT
// A bounded directory page keeps file selection responsive without opening or executing content.
use eframe::egui;
use std::{
    path::PathBuf,
    sync::mpsc::{Receiver, sync_channel},
};

struct Entry {
    path: PathBuf,
    directory: bool,
}
struct Listing {
    entries: Vec<Entry>,
    more: bool,
}
pub(super) struct Picker {
    pub save: bool,
    directory: PathBuf,
    address: String,
    name: String,
    page: usize,
    entries: Vec<Entry>,
    more: bool,
    loading: Option<Receiver<Result<Listing, String>>>,
    error: Option<String>,
}
impl Picker {
    pub(super) fn new(save: bool, current: &str) -> Self {
        let path = PathBuf::from(current);
        let directory = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")));
        let mut result = Self {
            save,
            address: directory.display().to_string(),
            directory,
            name: if save {
                path.file_name()
                    .and_then(|v| v.to_str())
                    .unwrap_or("")
                    .into()
            } else {
                String::new()
            },
            page: 0,
            entries: vec![],
            more: false,
            loading: None,
            error: None,
        };
        result.load();
        result
    }
    fn load(&mut self) {
        let (sender, receiver) = sync_channel(1);
        let path = self.directory.clone();
        let page = self.page;
        self.loading = Some(receiver);
        self.error = None;
        std::thread::spawn(move || {
            let result = (|| -> anyhow::Result<Listing> {
                let _directory = crate::transfer_files::directory(&path)?;
                let mut iter = std::fs::read_dir(&path)?.skip(page * 256);
                let mut entries = vec![];
                for entry in iter.by_ref().take(256) {
                    let entry = entry?;
                    let kind = entry.file_type()?;
                    if kind.is_file() || kind.is_dir() {
                        entries.push(Entry {
                            path: entry.path(),
                            directory: kind.is_dir(),
                        });
                    }
                }
                entries.sort_by(|a, b| b.directory.cmp(&a.directory).then(a.path.cmp(&b.path)));
                Ok(Listing {
                    entries,
                    more: iter.next().is_some(),
                })
            })()
            .map_err(|e| e.to_string());
            let _ = sender.send(result);
        });
    }
    pub(super) fn show(&mut self, ctx: &egui::Context, open: &mut bool) -> Option<String> {
        if let Some(receiver) = &self.loading {
            match receiver.try_recv() {
                Ok(result) => {
                    self.loading = None;
                    match result {
                        Ok(list) => {
                            self.entries = list.entries;
                            self.more = list.more;
                        }
                        Err(e) => self.error = Some(e),
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.loading = None;
                    self.error = Some("Directory listing stopped".into());
                }
                Err(_) => ctx.request_repaint_after(std::time::Duration::from_millis(100)),
            }
        }
        let mut selected = None;
        let mut next_dir = None;
        let mut load = false;
        egui::Window::new(if self.save {
            "Save file"
        } else {
            "Choose file"
        })
        .open(open)
        .default_width(650.0)
        .default_height(440.0)
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(self.loading.is_none(), egui::Button::new("Parent"))
                    .clicked()
                {
                    next_dir = self.directory.parent().map(PathBuf::from);
                }
                ui.add(
                    egui::TextEdit::singleline(&mut self.address)
                        .hint_text("Directory")
                        .desired_width(390.0),
                );
                if ui
                    .add_enabled(self.loading.is_none(), egui::Button::new("Open directory"))
                    .clicked()
                {
                    next_dir = Some(PathBuf::from(&self.address));
                }
            });
            if let Some(e) = &self.error {
                ui.colored_label(egui::Color32::LIGHT_RED, e);
            }
            egui::ScrollArea::vertical()
                .max_height(300.0)
                .show(ui, |ui| {
                    for entry in &self.entries {
                        let name = entry.path.file_name().unwrap_or_default().to_string_lossy();
                        let label = if entry.directory {
                            format!("[+] {name}")
                        } else {
                            name.into_owned()
                        };
                        if ui
                            .add_enabled(self.loading.is_none(), egui::Button::new(label))
                            .clicked()
                        {
                            if entry.directory {
                                next_dir = Some(entry.path.clone());
                            } else if self.save {
                                self.name = entry
                                    .path
                                    .file_name()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                                    .into_owned();
                            } else {
                                selected = Some(entry.path.display().to_string());
                            }
                        }
                    }
                });
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        self.page > 0 && self.loading.is_none(),
                        egui::Button::new("Previous"),
                    )
                    .clicked()
                {
                    self.page -= 1;
                    load = true;
                }
                if ui
                    .add_enabled(
                        self.more && self.loading.is_none(),
                        egui::Button::new("Next"),
                    )
                    .clicked()
                {
                    self.page += 1;
                    load = true;
                }
                if self.loading.is_some() {
                    ui.spinner();
                }
            });
            if self.save {
                ui.horizontal(|ui| {
                    ui.label("New filename");
                    ui.text_edit_singleline(&mut self.name);
                    let valid = !self.name.is_empty()
                        && matches!(
                            std::path::Path::new(&self.name)
                                .components()
                                .collect::<Vec<_>>()
                                .as_slice(),
                            [std::path::Component::Normal(_)]
                        )
                        && !matches!(self.name.as_str(), "." | "..");
                    if ui
                        .add_enabled(valid, egui::Button::new("Select path"))
                        .clicked()
                    {
                        selected = Some(self.directory.join(&self.name).display().to_string());
                    }
                });
            }
        });
        if let Some(path) = next_dir {
            self.directory = path;
            self.address = self.directory.display().to_string();
            self.page = 0;
            load = true;
        }
        if load {
            self.load();
        }
        selected
    }
}
