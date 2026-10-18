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
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::var_os("HYPERNET_TEST_DIRECTORY")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    std::env::var_os("XDG_STATE_HOME")
                        .map(PathBuf::from)
                        .unwrap_or_else(|| {
                            PathBuf::from(std::env::var_os("HOME").unwrap()).join(".local/state")
                        })
                        .join("HyperNetSuite/Tests")
                });
            create_directories(&root).unwrap();
            files::private_directory(&root).unwrap();
            let path = root.join(format!("GraphicalSettings{}", crate::random_hex::<16>()));
            files::create_directory(&path).unwrap();
            Self(path)
        }
        fn directory(&self) -> PathBuf {
            self.0.join("Preferences")
        }
        fn load(&self) -> (Store, Preferences, Option<String>) {
            Store::load_directory(Ok(self.directory()))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn private_preferences_roundtrip_and_atomic_update() {
        let fixture = Fixture::new();
        let (store, defaults, warning) = fixture.load();
        assert!(warning.is_none());
        assert_eq!(defaults, Preferences::default());
        let first = Preferences {
            animations: true,
            text_scale: 1.25,
            monochrome: true,
        };
        store.save(&first).unwrap();
        let path = fixture.directory().join(FILE_NAME);
        assert_eq!(
            fs::metadata(fixture.directory()).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fixture.load().1, first);
        let json: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"animations": true, "textScale": 1.25, "monochrome": true})
        );
        store.save(&defaults).unwrap();
        assert_eq!(fixture.load().1, defaults);
        for scale in [f32::NAN, f32::INFINITY, 0.74, 2.01] {
            assert!(
                store
                    .save(&Preferences {
                        text_scale: scale,
                        ..defaults.clone()
                    })
                    .is_err()
            );
            assert_eq!(fixture.load().1, defaults);
        }
    }

    #[test]
    fn corrupt_settings_remain_unchanged_and_save_blocked_until_reopen() {
        for contents in [
            b"{".to_vec(),
            br#"{"animations":false,"textScale":1,"monochrome":false,"network":"private"}"#
                .to_vec(),
            br#"{"animations":false,"animations":true,"textScale":1,"monochrome":false}"#.to_vec(),
            br#"{"animations":false,"textScale":0,"monochrome":false}"#.to_vec(),
            br#"{"animations":false}"#.to_vec(),
            vec![b' '; MAX_BYTES + 1],
        ] {
            let fixture = Fixture::new();
            let (initial, _, _) = fixture.load();
            let path = fixture.directory().join(FILE_NAME);
            files::write_new(&path, &contents).unwrap();
            assert!(initial.save(&Preferences::default()).is_err());
            let (blocked, defaults, warning) = fixture.load();
            assert!(warning.unwrap().contains("Saving is disabled"));
            assert_eq!(defaults, Preferences::default());
            assert!(blocked.save(&defaults).is_err());
            assert_eq!(fs::read(&path).unwrap(), contents);
            fs::remove_file(&path).unwrap();
            assert!(blocked.save(&defaults).is_err());
            fixture.load().0.save(&defaults).unwrap();
        }
    }

    #[test]
    fn unsafe_paths_and_links_cannot_change_another_file() {
        let fixture = Fixture::new();
        let target = fixture.0.join("Target.json");
        let original = serde_json::to_vec(&Preferences::default()).unwrap();
        files::write_new(&target, &original).unwrap();
        let (store, _, _) = fixture.load();
        let settings = fixture.directory().join(FILE_NAME);
        for hard_link in [false, true] {
            if hard_link {
                fs::hard_link(&target, &settings).unwrap();
            } else {
                symlink(&target, &settings).unwrap();
            }
            assert!(fixture.load().2.is_some());
            assert!(store.save(&Preferences::default()).is_err());
            assert_eq!(fs::read(&target).unwrap(), original);
            fs::remove_file(&settings).unwrap();
        }
        let linked = fixture.0.join("Linked");
        symlink(fixture.directory(), &linked).unwrap();
        let (blocked, defaults, warning) = Store::load_directory(Ok(linked.join("Child")));
        assert!(warning.is_some());
        assert!(blocked.save(&defaults).is_err());
        assert!(!fixture.directory().join("Child").exists());
        assert!(create_directories(&fixture.0.join("Missing/../Wrong")).is_err());
        assert!(!fixture.0.join("Missing").exists());
        files::write_new(&settings, &original).unwrap();
        fs::set_permissions(&settings, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(fixture.load().2.is_some());
        assert!(store.save(&defaults).is_err());
        fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(fixture.directory(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(fixture.load().2.is_some());
        assert!(store.save(&defaults).is_err());
        assert_eq!(fs::read(&target).unwrap(), original);
    }

    #[test]
    fn configuration_path_uses_only_absolute_explicit_bases() {
        let xdg = PathBuf::from("/Private/Configuration");
        let home = PathBuf::from("/Private/Home");
        assert_eq!(
            configuration_directory(Some(xdg.clone().into()), Some(home.clone().into())).unwrap(),
            xdg.join("HyperNetSuite")
        );
        for xdg in [None, Some(OsString::new())] {
            assert_eq!(
                configuration_directory(xdg, Some(home.clone().into())).unwrap(),
                home.join(".config/HyperNetSuite")
            );
        }
        assert!(configuration_directory(Some("Relative".into()), Some(home.into())).is_err());
        assert!(configuration_directory(None, None).is_err());
    }
}
