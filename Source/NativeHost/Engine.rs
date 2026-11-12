// SPDX-License-Identifier: Apache-2.0
// Adapted from RelayChat's resumable native host journal and reviewed command orchestration.
use super::configuration::Configuration;
use crate::admission::{helper, host_service, private, protocol, runtime, saved};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::File,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
pub fn text(path: &Path) -> Result<String> {
    let value = path.to_str().context("native host path is not UTF-8")?;
    ensure!(
        path.is_absolute() && !value.chars().any(char::is_control),
        "invalid native host path"
    );
    Ok(value.into())
}
pub fn bytes(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).into()).collect()
}
pub fn string(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(Into::into)
        .with_context(|| format!("native result field {key} absent"))
}
pub fn number(value: &Value, key: &str) -> Result<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .with_context(|| format!("native result number {key} absent"))
}
pub fn public_read(path: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&crate::files::read_bounded(
        path, false,
    )?)?)
}
pub fn read(path: &Path) -> Result<Value> {
    saved::read(path)
}
pub fn write(path: &Path, value: &impl Serialize) -> Result<()> {
    saved::replace(path, value)
}
pub fn digest(bytes: &[u8]) -> String {
    protocol::digest(bytes)
}
pub fn random() -> Result<String> {
    Ok(crate::random_hex::<32>())
}
pub fn check(cancel: &AtomicBool, end: Instant) -> Result<()> {
    ensure!(
        !cancel.load(Ordering::Acquire),
        "native hosting cancelled; exact progress retained"
    );
    ensure!(
        Instant::now() < end,
        "native hosting request timed out; resume the retained setup"
    );
    Ok(())
}
pub fn raw(
    program: &Path,
    args: &[String],
    cancel: &AtomicBool,
    end: Instant,
    phase: &str,
) -> Result<Vec<u8>> {
    check(cancel, end)?;
    let duration = end
        .checked_duration_since(Instant::now())
        .context("native hosting request timed out")?
        .min(Duration::from_secs(180));
    let args: Vec<OsString> = args.iter().map(Into::into).collect();
    helper::output(program, &args, &[], cancel, duration)
        .with_context(|| format!("native host phase {phase}"))
}
pub fn invoke(
    program: &Path,
    args: &[String],
    cancel: &AtomicBool,
    end: Instant,
    phase: &str,
) -> Result<Value> {
    Ok(serde_json::from_slice(&raw(
        program, args, cancel, end, phase,
    )?)?)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Installation {
    pub directory: PathBuf,
    pub core: PathBuf,
    pub suite: PathBuf,
    pub image: String,
    pub selection: Value,
}
impl Installation {
    pub fn inspect(directory: &Path, cancel: &AtomicBool) -> Result<Self> {
        private::directory(directory)?;
        let current = std::env::current_exe()?.canonicalize()?;
        let selection = invoke(
            &current,
            &bytes(&[
                "native-installation",
                "inspect",
                "--directory",
                &text(directory)?,
                "--json",
            ]),
            cancel,
            Instant::now() + Duration::from_secs(180),
            "installed package verification",
        )?;
        ensure!(
            selection.get("format").and_then(Value::as_str) == Some("HyperNetNativeInstallation/1")
                && selection.get("status").and_then(Value::as_str) == Some("Ready"),
            "verified native installation is unavailable"
        );
        let core = PathBuf::from(string(&selection, "coreExecutable")?);
        let suite = PathBuf::from(string(&selection, "suiteExecutable")?);
        runtime::executable(&core)?;
        runtime::executable(&suite)?;
        let image = string(&selection, "coreImage")?;
        ensure!(
            image
                .strip_prefix("sha256:")
                .is_some_and(protocol::identifier),
            "installed image identity differs"
        );
        for product in ["core", "suite"] {
            ensure!(
                selection
                    .pointer(&format!("/packages/{product}/version"))
                    .and_then(Value::as_str)
                    == Some("0.11.0"),
                "native host requires the coordinated release"
            );
        }
        ensure!(
            binary_digest(&current)? == binary_digest(&suite)?,
            "run native hosting from the reviewed installed Suite"
        );
        Ok(Self {
            directory: directory.into(),
            core,
            suite,
            image,
            selection,
        })
    }
}
pub fn binary_digest(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    runtime::executable(path)?;
    let mut file = File::open(path)?;
    ensure!(
        file.metadata()?.len() <= 536_870_912,
        "native executable exceeds bound"
    );
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(hex::encode(hash.finalize()))
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Selection {
    pub root: PathBuf,
    pub recovery_directory: PathBuf,
    pub core: PathBuf,
    pub suite: PathBuf,
    pub installation: PathBuf,
    pub configuration: Configuration,
}
impl std::ops::Deref for Selection {
    type Target = Configuration;
    fn deref(&self) -> &Configuration {
        &self.configuration
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Journal {
    pub format: String,
    pub configuration_digest: String,
    pub review_digest: String,
    pub configuration: Configuration,
    pub installation_directory: PathBuf,
    pub installation: Value,
    pub hrc_digest: Option<String>,
    pub image: String,
    pub created_ms: u64,
    pub phase: String,
    pub ids: BTreeMap<String, String>,
    pub results: BTreeMap<String, Value>,
    pub artifacts: BTreeMap<String, String>,
    pub completed: bool,
    pub desired_running: bool,
    pub withdrawn: bool,
}
pub struct Host<'a> {
    pub c: Selection,
    pub cancel: &'a AtomicBool,
    pub end: Instant,
    pub state: Journal,
    _lock: File,
}
impl<'a> Host<'a> {
    pub fn open(
        root: &Path,
        installation: Installation,
        c: Configuration,
        cancel: &'a AtomicBool,
        review: Option<&str>,
    ) -> Result<Self> {
        c.validate()?;
        saved::create_directory(root)?;
        let lock = host_service::lock(root, "Operation.lock")?;
        let configuration_digest = protocol::digest_value(&c)?;
        let existing = root.join("Hosting.json").exists();
        let state: Journal = if existing {
            let state: Journal = saved::read(&root.join("Hosting.json"))?;
            ensure!(
                state.format == "HyperNetNativeHost/1"
                    && state.configuration_digest == configuration_digest
                    && protocol::digest_value(&state.configuration)? == configuration_digest
                    && state.installation_directory == installation.directory
                    && state.installation == installation.selection
                    && state.hrc_digest
                        == c.hrc
                            .as_ref()
                            .map(|h| binary_digest(&h.executable))
                            .transpose()?,
                "resume the exact reviewed host and installed software"
            );
            state
        } else {
            let review = review.context("native host setup is absent")?;
            ensure!(
                std::fs::read_dir(root)?.count() == 1,
                "new native host directory is not empty"
            );
            Journal {
                format: "HyperNetNativeHost/1".into(),
                configuration_digest,
                review_digest: review.into(),
                configuration: c.clone(),
                installation_directory: installation.directory.clone(),
                installation: installation.selection,
                hrc_digest: c
                    .hrc
                    .as_ref()
                    .map(|h| binary_digest(&h.executable))
                    .transpose()?,
                image: installation.image,
                created_ms: now()? / 1000 * 1000,
                phase: "Preparing".into(),
                ids: BTreeMap::new(),
                results: BTreeMap::new(),
                artifacts: BTreeMap::new(),
                completed: false,
                desired_running: true,
                withdrawn: false,
            }
        };
        ensure!(
            state.ids.len() <= 2048
                && state.results.len() <= 2048
                && state.artifacts.len() <= 2048
                && state.phase.len() <= 128
                && !state.phase.chars().any(char::is_control),
            "native host journal exceeds bound"
        );
        let c = Selection {
            root: root.into(),
            recovery_directory: root.join("Recovery"),
            core: installation.core,
            suite: installation.suite,
            installation: installation.directory,
            configuration: c,
        };
        let host = Self {
            c,
            cancel,
            end: Instant::now() + Duration::from_secs(1500),
            state,
            _lock: lock,
        };
        host.verify_artifacts()?;
        if !existing {
            host.save()?;
        }
        Ok(host)
    }
    pub fn retained(root: &Path, cancel: &'a AtomicBool) -> Result<Self> {
        private::directory(root)?;
        let lock = host_service::lock(root, "Operation.lock")?;
        let state: Journal = saved::read(&root.join("Hosting.json"))?;
        ensure!(
            state.format == "HyperNetNativeHost/1"
                && protocol::digest_value(&state.configuration)? == state.configuration_digest,
            "retained host configuration differs"
        );
        state.configuration.validate()?;
        let c = Selection {
            root: root.into(),
            recovery_directory: root.join("Recovery"),
            core: PathBuf::from(string(&state.installation, "coreExecutable")?),
            suite: PathBuf::from(string(&state.installation, "suiteExecutable")?),
            installation: state.installation_directory.clone(),
            configuration: state.configuration.clone(),
        };
        ensure!(
            c.core.is_absolute() && c.suite.is_absolute() && c.installation.is_absolute(),
            "retained installation paths differ"
        );
        Ok(Self {
            c,
            cancel,
            end: Instant::now() + Duration::from_secs(1500),
            state,
            _lock: lock,
        })
    }
    pub fn save(&self) -> Result<()> {
        write(&self.p("Hosting.json"), &self.state)
    }
    pub fn phase(&mut self, phase: &str) -> Result<()> {
        if self.state.phase == phase {
            return Ok(());
        }
        self.state.phase = phase.into();
        self.save()
    }
    pub fn p(&self, name: &str) -> PathBuf {
        self.c.root.join(name)
    }
    pub fn dir(&self, name: &str) -> Result<PathBuf> {
        let p = self.p(name);
        ensure!(
            p.starts_with(&self.c.root)
                && !Path::new(name).components().any(|c| matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::RootDir
                )),
            "native directory escapes host root"
        );
        let mut at = self.c.root.clone();
        for part in Path::new(name).components() {
            at.push(part.as_os_str());
            saved::create_directory(&at)?;
        }
        Ok(p)
    }
    pub fn id(&mut self, name: &str) -> Result<String> {
        if let Some(id) = self.state.ids.get(name) {
            return Ok(id.clone());
        }
        ensure!(
            self.state.ids.len() < 2048,
            "native host identifier capacity reached"
        );
        let id = random()?;
        self.state.ids.insert(name.into(), id.clone());
        self.save()?;
        Ok(id)
    }
    pub fn remember(&mut self, name: &str, value: Value) -> Result<Value> {
        if self.state.results.get(name) == Some(&value) {
            return Ok(value);
        }
        ensure!(
            self.state.results.contains_key(name) || self.state.results.len() < 2048,
            "native host result capacity reached"
        );
        self.state.results.insert(name.into(), value.clone());
        self.save()?;
        Ok(value)
    }
    pub fn remembered(&self, name: &str) -> Option<Value> {
        self.state.results.get(name).cloned()
    }
    pub fn core(&self, args: &[String]) -> Result<Value> {
        let result = invoke(&self.c.core, args, self.cancel, self.end, &self.state.phase)?;
        ensure!(
            result.get("ok") != Some(&Value::Bool(false)),
            "native Core operation refused"
        );
        Ok(result)
    }
    pub fn suite(&self, args: &[String]) -> Result<Value> {
        invoke(
            &self.c.suite,
            args,
            self.cancel,
            self.end,
            &self.state.phase,
        )
    }
    pub fn artifact(&mut self, path: &Path) -> Result<()> {
        ensure!(
            path.starts_with(&self.c.root),
            "host artifact escapes retained state"
        );
        let key = text(path)?;
        let hash = digest(&super::files::public_file(path, 8_388_608)?);
        ensure!(
            self.state
                .artifacts
                .get(&key)
                .is_none_or(|old| old == &hash),
            "retained native artifact changed"
        );
        ensure!(
            self.state.artifacts.contains_key(&key) || self.state.artifacts.len() < 2048,
            "host artifact capacity reached"
        );
        if self.state.artifacts.get(&key) == Some(&hash) {
            return Ok(());
        }
        self.state.artifacts.insert(key, hash);
        self.save()
    }
    pub fn verify_artifacts(&self) -> Result<()> {
        for (path, hash) in &self.state.artifacts {
            let path = Path::new(path);
            ensure!(
                path.starts_with(&self.c.root)
                    && digest(&super::files::public_file(path, 8_388_608)?) == *hash,
                "retained native artifact changed"
            );
        }
        Ok(())
    }
    pub fn immutable_json(&mut self, path: &Path, value: &Value) -> Result<()> {
        let content = serde_json::to_vec(value)?;
        if path.exists() {
            ensure!(
                super::files::read(path, 8_388_608)? == content,
                "retained native input changed"
            );
        } else {
            super::files::exact_file(path, &content)?;
        }
        self.artifact(path)
    }
    pub fn bootstrap(&self) -> Result<Value> {
        self.remembered("bootstrap")
            .context("native bootstrap is absent")
    }
    pub fn bootstrap_file_digest(&self) -> Result<String> {
        self.state
            .artifacts
            .get(&text(&self.p("Network/Bootstrap.cbor"))?)
            .cloned()
            .context("bootstrap digest absent")
    }
    pub fn trust(&self) -> Result<Vec<String>> {
        Ok(bytes(&[
            "--bootstrap",
            &text(&self.p("Network/Bootstrap.cbor"))?,
            "--bootstrap-digest",
            &self.bootstrap_file_digest()?,
        ]))
    }
    pub fn root_grant(&self) -> Result<String> {
        string(
            &self.bootstrap()?["genesisGovernance"]["rootGrants"][0]["record"],
            "id",
        )
    }
    pub fn monitor(&self) -> Result<String> {
        string(
            self.state
                .results
                .get("clock")
                .context("native clock absent")?,
            "publicKey",
        )
    }
    pub fn wait(&self, mut probe: impl FnMut() -> Result<()>, seconds: u64) -> Result<()> {
        let end = self.end.min(Instant::now() + Duration::from_secs(seconds));
        loop {
            check(self.cancel, end)?;
            match probe() {
                Ok(()) => return Ok(()),
                Err(error) if Instant::now() >= end => return Err(error),
                Err(_) => {}
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

pub fn end_arguments(end: crate::trust_validity::End) -> Vec<String> {
    match end {
        crate::trust_validity::End::At(value) => bytes(&["--expires-ms", &value.to_string()]),
        crate::trust_validity::End::UntilWithdrawn => bytes(&["--until-withdrawn"]),
    }
}
