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

#[derive(Clone)]
struct Directory {
    path: PathBuf,
    owner: u32,
    group: u32,
    mode: u32,
}
impl Directory {
    fn new(path: PathBuf, owner: u32, mode: u32) -> Self {
        Self {
            path,
            owner,
            group: owner,
            mode,
        }
    }
    fn check(&self, metadata: &Metadata) -> Result<()> {
        ensure!(
            metadata.mode & libc::S_IFMT == libc::S_IFDIR
                && metadata.mode & 0o7777 == self.mode
                && metadata.owner == self.owner
                && metadata.group == self.group,
            "registrar mount directory ownership, type or permissions differ"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Metadata {
    device: u64,
    inode: u64,
    mode: u32,
    owner: u32,
    group: u32,
}
fn parse_metadata(bytes: &[u8], count: usize) -> Result<Vec<Metadata>> {
    ensure!(
        count <= 7 && bytes.len() <= 4096,
        "registrar mount metadata exceeds bound"
    );
    let rows = std::str::from_utf8(bytes)?
        .lines()
        .map(|line| {
            let fields = line.split(':').collect::<Vec<_>>();
            ensure!(fields.len() == 5, "registrar mount metadata is incomplete");
            Ok(Metadata {
                device: fields[0].parse()?,
                inode: fields[1].parse()?,
                mode: u32::from_str_radix(fields[2], 16)?,
                owner: fields[3].parse()?,
                group: fields[4].parse()?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        rows.len() == count,
        "registrar mount metadata count differs"
    );
    Ok(rows)
}
fn mapped_metadata(podman: &Path, directories: &[Directory]) -> Result<Vec<Metadata>> {
    ensure!(
        !directories.is_empty() && directories.len() <= 7,
        "registrar mount count differs"
    );
    // The owner cannot traverse native 0700 mapped state. stat without -L inspects
    // the final entry in that namespace without following a substituted symlink.
    let mut args: Vec<OsString> = [
        "unshare",
        "/usr/bin/stat",
        "--printf",
        "%d:%i:%f:%u:%g\n",
        "--",
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    for directory in directories {
        args.push(argument(&directory.path)?.into());
    }
    let bytes = helper::output(
        podman,
        &args,
        &[],
        &AtomicBool::new(false),
        Duration::from_secs(30),
    )?;
    let metadata = parse_metadata(&bytes, directories.len())?;
    for (directory, metadata) in directories.iter().zip(&metadata) {
        directory.check(metadata)?;
    }
    Ok(metadata)
}
pub struct Bindings {
    podman: PathBuf,
    directories: Vec<Directory>,
    metadata: Vec<Metadata>,
}
impl Bindings {
    fn capture(podman: &Path, directories: Vec<Directory>) -> Result<Self> {
        let metadata = mapped_metadata(podman, &directories)?;
        Ok(Self {
            podman: podman.into(),
            directories,
            metadata,
        })
    }
    pub fn require_current(&self) -> Result<()> {
        self.check_current(&mapped_metadata(&self.podman, &self.directories)?)
    }
    fn check_current(&self, current: &[Metadata]) -> Result<()> {
        ensure!(
            current.len() == self.directories.len(),
            "registrar mount metadata count differs"
        );
        for (directory, metadata) in self.directories.iter().zip(current) {
            directory.check(metadata)?;
        }
        ensure!(
            current == self.metadata.as_slice(),
            "native control mount changed; restart public joining"
        );
        Ok(())
    }
}
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
    pub fn bindings(&self, edge: &Container) -> Result<Bindings> {
        self.validate(edge)?;
        let mut directories = vec![
            Directory::new(edge.directory.join("Registrar"), 1001, 0o700),
            Directory::new(edge.directory.join("Bridge"), 1001, 0o711),
        ];
        directories.extend(self.directories());
        Bindings::capture(&edge.podman, directories)
    }
    fn directories(&self) -> Vec<Directory> {
        let mut directories = self
            .native
            .mounts
            .iter()
            .map(|mount| {
                if mount.target == Path::new("/Clock") {
                    Directory::new(mount.source.clone(), 0, 0o755)
                } else {
                    Directory::new(mount.source.clone(), 1001, 0o700)
                }
            })
            .collect::<Vec<_>>();
        if let Some(hrc) = &self.hrc {
            directories.extend([
                Directory::new(hrc.state_directory.clone(), 1001, 0o700),
                Directory::new(hrc.bridge_directory.clone(), 0, 0o711),
            ]);
        }
        directories
    }
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
        }
        if let Some(hrc) = &self.hrc {
            super::runtime::executable(&hrc.executable)?;
            ensure!(
                hrc.host_uid == self.native.host_uid,
                "HRC registrar identity differs"
            );
            for path in [&hrc.state_directory, &hrc.bridge_directory] {
                argument(path)?;
            }
        }
        mapped_metadata(&edge.podman, &self.directories())?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;
    struct TemporaryDirectory(PathBuf);
    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn replaced_control_directory_requires_a_new_bind_mount() {
        let root = TemporaryDirectory(std::env::temp_dir().join(format!(
            "HyperNetRegistrarBindings-{}",
            crate::random_hex::<16>()
        )));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root.0)
            .unwrap();
        let control = root.0.join("Control");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&control)
            .unwrap();
        let read = |path: &Path| -> Result<Metadata> {
            let meta = std::fs::symlink_metadata(path)?;
            Ok(Metadata {
                device: meta.dev(),
                inode: meta.ino(),
                mode: meta.mode(),
                owner: meta.uid(),
                group: meta.gid(),
            })
        };
        let spec = Directory {
            path: control.clone(),
            owner: unsafe { libc::geteuid() },
            group: unsafe { libc::getegid() },
            mode: 0o700,
        };
        let bindings = Bindings {
            podman: "/usr/bin/podman".into(),
            directories: vec![spec.clone()],
            metadata: vec![read(&control).unwrap()],
        };
        std::fs::write(
            control.join("Current"),
            b"new socket entries remain visible",
        )
        .unwrap();
        bindings.check_current(&[read(&control).unwrap()]).unwrap();
        std::fs::rename(&control, root.0.join("Previous")).unwrap();
        assert!(read(&control).is_err());
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&control)
            .unwrap();
        assert!(bindings.check_current(&[read(&control).unwrap()]).is_err());
        let refreshed = Bindings {
            podman: "/usr/bin/podman".into(),
            directories: vec![spec],
            metadata: vec![read(&control).unwrap()],
        };
        refreshed.check_current(&[read(&control).unwrap()]).unwrap();
        std::fs::remove_dir(&control).unwrap();
        std::os::unix::fs::symlink(root.0.join("Previous"), &control).unwrap();
        assert!(refreshed.check_current(&[read(&control).unwrap()]).is_err());
    }
    #[test]
    fn mapped_private_mount_metadata_preserves_ownership_and_inode_checks() {
        let directories = vec![
            Directory::new("/Host/Authority/Launch/State/Control".into(), 1001, 0o700),
            Directory::new("/Host/Clock/Public".into(), 0, 0o755),
            Directory::new("/Host/Bridge".into(), 1001, 0o711),
            Directory::new("/Runtime/HrcBridge".into(), 0, 0o711),
        ];
        let metadata = parse_metadata(b"2050:101:41c0:1001:1001\n2050:102:41ed:0:0\n2050:103:41c9:1001:1001\n2050:104:41c9:0:0\n", directories.len()).unwrap();
        let bindings = Bindings {
            podman: "/usr/bin/podman".into(),
            directories,
            metadata: metadata.clone(),
        };
        bindings.check_current(&metadata).unwrap();
        for replacement in [
            Metadata {
                mode: libc::S_IFLNK | 0o777,
                ..metadata[0].clone()
            },
            Metadata {
                mode: libc::S_IFDIR | 0o720,
                ..metadata[0].clone()
            },
            Metadata {
                mode: libc::S_IFDIR | 0o755,
                ..metadata[0].clone()
            },
            Metadata {
                owner: 0,
                ..metadata[0].clone()
            },
            Metadata {
                group: 0,
                ..metadata[0].clone()
            },
            Metadata {
                inode: 201,
                ..metadata[0].clone()
            },
            Metadata {
                device: 2051,
                ..metadata[0].clone()
            },
        ] {
            let mut changed = metadata.clone();
            changed[0] = replacement;
            assert!(bindings.check_current(&changed).is_err());
        }
        assert!(bindings.check_current(&metadata[..3]).is_err());
        assert!(parse_metadata(b"2050:101:41c0:1001:1001\n", 2).is_err());
        assert!(parse_metadata(b"2050:101:invalid:1001:1001\n", 1).is_err());
        assert!(parse_metadata(&[b'0'; 4097], 1).is_err());
    }
}
