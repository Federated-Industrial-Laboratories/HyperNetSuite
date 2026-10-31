// SPDX-License-Identifier: MIT
// Persist only graphical preferences through private descriptor-relative files.
use crate::authority_files as files;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Component, Path, PathBuf},
};

const MAX_BYTES: usize = 4096;
const FILE_NAME: &str = "Settings.json";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Preferences {
    pub animations: bool,
    pub text_scale: f32,
    pub monochrome: bool,
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            animations: false,
            text_scale: 1.0,
            monochrome: false,
        }
    }
}
impl Preferences {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.text_scale.is_finite() && (0.75..=2.0).contains(&self.text_scale),
            "text scale must be between 0.75 and 2.0"
        );
        Ok(())
    }
}

pub struct Store {
    directory: Option<File>,
    blocked: Option<String>,
}
impl Store {
    pub fn load() -> (Self, Preferences, Option<String>) {
        Self::load_directory(configuration_directory(
            std::env::var_os("XDG_CONFIG_HOME"),
            std::env::var_os("HOME"),
        ))
    }

    fn load_directory(path: Result<PathBuf>) -> (Self, Preferences, Option<String>) {
        let loaded = (|| {
            let path = path?;
            create_directories(&path)?;
            let directory = files::private_directory(&path)?;
            let _lock = files::profile_lock(&directory, OsStr::new(FILE_NAME))?;
            let preferences = read(&directory)?.unwrap_or_default();
            Ok::<_, anyhow::Error>((directory, preferences))
        })();
        match loaded {
            Ok((directory, preferences)) => (
                Self {
                    directory: Some(directory),
                    blocked: None,
                },
                preferences,
                None,
            ),
            Err(error) => {
                let message = format!(
                    "Settings could not be loaded: {error:#}. Saving is disabled; repair the settings path or file and reopen the application."
                );
                (
                    Self {
                        directory: None,
                        blocked: Some(message.clone()),
                    },
                    Preferences::default(),
                    Some(message),
                )
            }
        }
    }

    pub fn save(&self, preferences: &Preferences) -> Result<()> {
        if let Some(message) = &self.blocked {
            anyhow::bail!("{message}");
        }
        preferences.validate()?;
        let directory = self.directory.as_ref().context("settings unavailable")?;
        let metadata = directory.metadata()?;
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0,
            "settings directory must remain private and owned by the current user"
        );
        let _lock = files::profile_lock(directory, OsStr::new(FILE_NAME))?;
        // Refuse a file that became corrupt or unsafe after this window opened.
        let replace = read(directory)
            .context("settings changed or became unsafe; saving was refused")?
            .is_some();
        let bytes = serde_json::to_vec_pretty(preferences)?;
        ensure!(bytes.len() <= MAX_BYTES, "settings exceed the size limit");
        files::atomic_at(directory, OsStr::new(FILE_NAME), &bytes, replace)
            .context("cannot save settings")
    }
}

fn missing(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}
fn read(directory: &File) -> Result<Option<Preferences>> {
    let bytes = match files::read_at(directory, OsStr::new(FILE_NAME), MAX_BYTES, true) {
        Ok(bytes) => bytes,
        Err(error) if missing(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    let preferences: Preferences =
        serde_json::from_slice(&bytes).context("invalid settings document")?;
    preferences.validate()?;
    Ok(Some(preferences))
}
fn configuration_directory(xdg: Option<OsString>, home: Option<OsString>) -> Result<PathBuf> {
    let base = match xdg.filter(|value| !value.is_empty()) {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(
            home.filter(|value| !value.is_empty())
                .context("HOME is unset and XDG_CONFIG_HOME is unavailable")?,
        )
        .join(".config"),
    };
    ensure!(base.is_absolute(), "settings base must be an absolute path");
    Ok(base.join("HyperNetSuite"))
}
fn create_directories(path: &Path) -> Result<File> {
    ensure!(
        path.is_absolute()
            && path.as_os_str().as_bytes().len() <= MAX_BYTES
            && path.components().count() <= 64
            && path.components().all(|part| matches!(
                part,
                Component::RootDir | Component::Normal(_) | Component::CurDir
            )),
        "settings directory path is invalid or too long"
    );
    match files::directory(path) {
        Ok(directory) => Ok(directory),
        Err(error) if missing(&error) => {
            create_directories(path.parent().context("settings directory has no parent")?)?;
            match files::create_directory(path) {
                Ok(directory) => Ok(directory),
                // Another instance may have created the same directory.
                Err(error) => files::directory(path).with_context(|| error.to_string()),
            }
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Graphical/SettingsUnitTests.rs"]
mod tests;
