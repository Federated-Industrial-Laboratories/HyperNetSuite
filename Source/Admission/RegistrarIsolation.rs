// SPDX-License-Identifier: MIT
// A separate mapped registrar receives scoped authority artifacts and authenticated sockets only.
use super::{
    control, helper,
    host_isolation::{Container, argument, mapped_identity},
    protocol, registrar, saved, store,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::Duration,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mount {
    source: PathBuf,
    target: PathBuf,
    read_only: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Native {
    namespace_uid: u32,
    namespace_gid: u32,
    pub host_uid: u32,
    host_gid: u32,
    pub configuration: PathBuf,
    pub descriptor_key_file: PathBuf,
    mounts: Vec<Mount>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Hrc {
    executable: PathBuf,
    state_directory: PathBuf,
    bridge_directory: PathBuf,
    host_uid: u32,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrarContainer {
    pub native: Native,
    pub hrc: Option<Hrc>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Initial {
    pub configuration: registrar::Configuration,
    pub maximum_members: usize,
    pub access: store::End,
    pub mode: store::Mode,
    pub password: Option<super::password::Verifier>,
}
pub fn initialise(directory: &Path, initial: Initial) -> Result<Value> {
    super::private::directory(directory)?;
    ensure!(
        initial.configuration.directory == directory,
        "registrar state path differs"
    );
    initial.configuration.validate()?;
    let path = directory.join("Registrar.json");
    if path.exists() {
        let old: registrar::Configuration = saved::read(&path)?;
        ensure!(
            serde_json::to_value(old)? == serde_json::to_value(&initial.configuration)?,
            "retained registrar configuration differs"
        );
    } else {
        saved::replace(&path, &initial.configuration)?;
    }
    if !directory.join("Admission.json").exists() {
        let mut state = store::State::new(initial.maximum_members, initial.access)?;
        state.mode = initial.mode;
        state.password = initial.password;
        state.enabled = true;
        store::Locked::create(directory, state)?;
    }
    let registrar = registrar::Registrar::open(initial.configuration)?;
    Ok(json!({"status":"RegistrarConfigured","identityPin":registrar.identity_pin()}))
}
impl RegistrarContainer {
    fn validate(&self, edge: &Container) -> Result<()> {
        ensure!(
            self.native.namespace_uid == 1001
                && self.native.namespace_gid == 1001
                && self.native.host_uid != edge.edge_uid
                && self.native.host_uid != unsafe { libc::geteuid() }
                && self.native.host_uid != 0
                && self.native.host_gid != unsafe { libc::getegid() }
                && self.native.configuration == Path::new("/Native/Registrar.json")
                && self.native.descriptor_key_file == Path::new("/Native/Descriptor.key"),
            "native registrar isolation differs"
        );
        let targets = [("/Native", false), ("/Authority", true), ("/Clock", true)];
        ensure!(
            self.native.mounts.len() == targets.len(),
            "unexpected registrar mount"
        );
        for (target, read_only) in targets {
            let matches: Vec<_> = self
                .native
                .mounts
                .iter()
                .filter(|m| m.target == Path::new(target))
                .collect();
            ensure!(
                matches.len() == 1 && matches[0].read_only == read_only,
                "registrar mount permissions differ"
            );
            argument(&matches[0].source)?;
            let meta = std::fs::symlink_metadata(&matches[0].source)?;
            ensure!(
                meta.is_dir() && !meta.file_type().is_symlink() && meta.mode() & 0o022 == 0,
                "registrar mount must not permit replacement"
            );
        }
        if let Some(hrc) = &self.hrc {
            super::runtime::executable(&hrc.executable)?;
            ensure!(
                hrc.host_uid == self.native.host_uid,
                "HRC registrar identity differs"
            );
            for path in [&hrc.state_directory, &hrc.bridge_directory] {
                argument(path)?;
                let m = std::fs::symlink_metadata(path)?;
                ensure!(
                    m.is_dir() && !m.file_type().is_symlink() && m.mode() & 0o022 == 0,
                    "HRC admission mount differs"
                );
            }
        }
        Ok(())
    }
    fn transfer_empty(
        &self,
        edge: &Container,
        name: &str,
        mode: u32,
        stop: &AtomicBool,
    ) -> Result<()> {
        let root = edge.directory.join(name);
        if !root.exists() {
            saved::create_directory(&root)?;
        }
        let m = std::fs::symlink_metadata(&root)?;
        ensure!(
            m.is_dir()
                && !m.file_type().is_symlink()
                && m.mode() & 0o022 == 0
                && (m.uid() == unsafe { libc::geteuid() } || m.uid() == self.native.host_uid),
            "isolated state ownership differs"
        );
        if m.uid() == unsafe { libc::geteuid() } {
            ensure!(
                std::fs::read_dir(&root)?.next().is_none(),
                "initial isolated state is not empty"
            );
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(mode))?;
            edge.command(
                &[
                    "unshare".into(),
                    "/usr/bin/chown".into(),
                    "--".into(),
                    "1001:1001".into(),
                    root.into_os_string(),
                ],
                stop,
            )?;
        } else {
            ensure!(
                m.mode() & 0o777 == mode,
                "isolated state permissions differ"
            );
        }
        Ok(())
    }
    fn base(&self, edge: &Container) -> Result<Vec<OsString>> {
        self.validate(edge)?;
        let mut args: Vec<OsString> = [
            "run",
            "--rm",
            "--pull=never",
            "--read-only",
            "--network=none",
            "--user=1001:1001",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=32",
            "--memory=268435456",
            "--cpus=1",
            "--ulimit=nofile=128:128",
            "--log-driver=none",
            "--workdir=/Registrar",
            "--entrypoint=/HyperNetSuite",
        ]
        .into_iter()
        .map(Into::into)
        .collect();
        let mut mounts = vec![
            (edge.suite.clone(), "/HyperNetSuite".into(), true),
            (edge.directory.join("Registrar"), "/Registrar".into(), false),
            (edge.directory.join("Bridge"), "/Bridge".into(), false),
        ];
        mounts.extend(
            self.native
                .mounts
                .iter()
                .map(|m| (m.source.clone(), m.target.clone(), m.read_only)),
        );
        if let Some(hrc) = &self.hrc {
            mounts.extend([
                (hrc.executable.clone(), "/Hrc".into(), true),
                (hrc.state_directory.clone(), "/HrcAdmission".into(), true),
                (hrc.bridge_directory.clone(), "/HrcBridge".into(), true),
            ]);
        }
        for (source, target, read_only) in mounts {
            args.extend([
                "--volume".into(),
                format!(
                    "{}:{}:{},nosuid,nodev",
                    argument(&source)?,
                    argument(&target)?,
                    if read_only { "ro" } else { "rw" }
                )
                .into(),
            ]);
        }
        Ok(args)
    }
    pub fn prepare(&self, edge: &Container, initial: Initial, stop: &AtomicBool) -> Result<String> {
        self.validate(edge)?;
        for (file, owner, expected) in [
            (
                "/proc/self/uid_map",
                unsafe { libc::geteuid() },
                self.native.host_uid,
            ),
            (
                "/proc/self/gid_map",
                unsafe { libc::getegid() },
                self.native.host_gid,
            ),
        ] {
            let map = edge.command(
                &["unshare".into(), "/usr/bin/cat".into(), file.into()],
                stop,
            )?;
            ensure!(
                mapped_identity(&map, owner, 1001)? == expected,
                "retained registrar identity mapping differs"
            );
        }
        self.transfer_empty(edge, "Registrar", 0o700, stop)?;
        self.transfer_empty(edge, "Bridge", 0o711, stop)?;
        let mut args = self.base(edge)?;
        args.extend([
            "--interactive".into(),
            edge.image.clone().into(),
            "join".into(),
            "registrar-configuration".into(),
            "--directory".into(),
            "/Registrar".into(),
        ]);
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&initial)?);
        let response: Value = serde_json::from_slice(&helper::output(
            &edge.podman,
            &args,
            &bytes,
            stop,
            Duration::from_secs(30),
        )?)?;
        ensure!(
            response.get("status").and_then(Value::as_str) == Some("RegistrarConfigured"),
            "registrar setup incomplete"
        );
        Ok(response
            .get("identityPin")
            .and_then(Value::as_str)
            .filter(|s| protocol::identifier(s))
            .ok_or_else(|| anyhow::anyhow!("registrar identity absent"))?
            .into())
    }
    pub fn launch_arguments(&self, edge: &Container) -> Result<Vec<OsString>> {
        let mut args = self.base(edge)?;
        args.extend([
            "--name".into(),
            format!("{}-registrar", edge.name()).into(),
            "--label".into(),
            format!(
                "org.hypernet.admission={}",
                protocol::digest(edge.directory.as_os_str().as_encoded_bytes())
            )
            .into(),
            edge.image.clone().into(),
            "join".into(),
            "registrar".into(),
            "--config".into(),
            "/Registrar/Registrar.json".into(),
        ]);
        Ok(args)
    }
    pub fn stop(&self, edge: &Container, stop: &AtomicBool) -> Result<()> {
        edge.stop_named(&format!("{}-registrar", edge.name()), stop)
    }
    pub fn owner(&self, edge: &Container, action: control::Admin) -> Result<Value> {
        control::owner_at(
            &edge.directory.join("Bridge/Admission.sock"),
            self.native.host_uid,
            action,
        )
    }
}
