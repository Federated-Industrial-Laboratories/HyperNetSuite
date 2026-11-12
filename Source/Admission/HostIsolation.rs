// SPDX-License-Identifier: MIT
// The public listener receives a separate rootless identity and only its TLS state and authenticated bridge.
use super::{certificates, edge, helper, location::Location, protocol, runtime, saved};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    ffi::OsString,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::Duration,
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Container {
    pub podman: PathBuf,
    pub suite: PathBuf,
    pub image: String,
    pub directory: PathBuf,
    pub edge_uid: u32,
    pub listen: std::net::SocketAddr,
}
pub(super) fn argument(path: &Path) -> Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("container path is not UTF-8"))?;
    ensure!(
        path.is_absolute() && !value.contains([':', ',', '\n', '\r']),
        "unsupported container path"
    );
    Ok(value.into())
}
pub(super) fn mapped_identity(bytes: &[u8], owner: u32, namespace_id: u32) -> Result<u32> {
    let text = std::str::from_utf8(bytes)?;
    let mut mapped = None;
    let mut owner_mapped = false;
    ensure!(text.len() <= 4096, "container identity map exceeds bound");
    for line in text.lines() {
        let fields = line
            .split_whitespace()
            .map(str::parse::<u64>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(
            fields.len() == 3 && fields[2] > 0,
            "invalid container identity map"
        );
        let end = fields[0]
            .checked_add(fields[2])
            .ok_or_else(|| anyhow::anyhow!("identity map overflow"))?;
        if fields[0] == 0 {
            owner_mapped = fields[1] == u64::from(owner);
        }
        if fields[0] <= u64::from(namespace_id) && end > u64::from(namespace_id) {
            ensure!(mapped.is_none(), "ambiguous container identity map");
            mapped = Some(u32::try_from(
                fields[1] + u64::from(namespace_id) - fields[0],
            )?);
        }
    }
    let uid =
        mapped.ok_or_else(|| anyhow::anyhow!("rootless subordinate identities unavailable"))?;
    ensure!(
        owner != 0 && owner_mapped && uid != owner && uid != 0,
        "public listener needs a separate rootless identity"
    );
    Ok(uid)
}
impl Container {
    pub fn new(
        directory: &Path,
        podman: PathBuf,
        suite: PathBuf,
        image: String,
        listen: std::net::SocketAddr,
        stop: &AtomicBool,
    ) -> Result<Self> {
        super::private::directory(directory)?;
        runtime::executable(&podman)?;
        runtime::executable(&suite)?;
        ensure!(
            image
                .strip_prefix("sha256:")
                .is_some_and(protocol::identifier),
            "installed image identity is invalid"
        );
        let bytes = helper::output(
            &podman,
            &[
                "unshare".into(),
                "/usr/bin/cat".into(),
                "/proc/self/uid_map".into(),
            ],
            &[],
            stop,
            Duration::from_secs(30),
        )?;
        let edge_uid = mapped_identity(&bytes, unsafe { libc::geteuid() }, 1)?;
        Ok(Self {
            podman,
            suite,
            image,
            directory: directory.into(),
            edge_uid,
            listen,
        })
    }
    pub(super) fn command(&self, args: &[OsString], stop: &AtomicBool) -> Result<Vec<u8>> {
        helper::output(&self.podman, args, &[], stop, Duration::from_secs(30))
    }
    fn validate(&self) -> Result<()> {
        super::private::directory(&self.directory)?;
        runtime::executable(&self.podman)?;
        runtime::executable(&self.suite)?;
        runtime::executable(&Path::new("/usr/bin/slirp4netns").canonicalize()?)?;
        ensure!(
            self.listen.port() > 1024,
            "public port must be unprivileged"
        );
        ensure!(
            self.edge_uid != unsafe { libc::geteuid() } && self.edge_uid != 0,
            "public listener identity differs"
        );
        ensure!(
            self.image
                .strip_prefix("sha256:")
                .is_some_and(protocol::identifier),
            "invalid image identity"
        );
        for path in [&self.directory, &self.suite] {
            argument(path)?;
        }
        Ok(())
    }
    pub fn name(&self) -> String {
        format!(
            "hypernet-admission-{}",
            &protocol::digest(self.directory.as_os_str().as_encoded_bytes())[..24]
        )
    }
    pub fn base(&self, network: bool) -> Result<Vec<OsString>> {
        self.validate()?;
        let mut args = vec![
            "run".into(),
            "--rm".into(),
            "--pull=never".into(),
            "--read-only".into(),
            "--user=1:1".into(),
            "--cap-drop=ALL".into(),
            "--security-opt=no-new-privileges".into(),
            "--pids-limit=32".into(),
            "--memory=134217728".into(),
            "--cpus=1".into(),
            "--ulimit=nofile=128:128".into(),
            "--log-driver=none".into(),
            "--workdir=/Edge".into(),
            "--entrypoint=/HyperNetSuite".into(),
            format!(
                "--network={}",
                if network {
                    "slirp4netns:allow_host_loopback=false,port_handler=slirp4netns"
                } else {
                    "none"
                }
            )
            .into(),
        ];
        for (host, target, options) in [
            (self.suite.clone(), "/HyperNetSuite", "ro"),
            (self.directory.join("Edge"), "/Edge", "rw"),
            (self.directory.join("Bridge"), "/Bridge", "ro"),
        ] {
            args.push("--volume".into());
            args.push(format!("{}:{target}:{options},nosuid,nodev", argument(&host)?).into());
        }
        Ok(args)
    }
    fn json(&self, arguments: &[&str], stop: &AtomicBool) -> Result<Value> {
        let mut args = self.base(false)?;
        args.push(self.image.clone().into());
        args.extend(arguments.iter().map(OsString::from));
        Ok(serde_json::from_slice(&self.command(&args, stop)?)?)
    }
    pub(super) fn stage(
        &self,
        name: &str,
        value: &impl Serialize,
        stop: &AtomicBool,
    ) -> Result<()> {
        ensure!(
            matches!(name, "Tls.json" | "Edge.json" | "Managed.json"),
            "invalid edge configuration file"
        );
        // All writes into edge-owned state occur as its isolated identity. Never
        // follow an edge-controlled path from a privileged host-side copy command.
        let mut args = self.base(false)?;
        args.extend([
            "--interactive".into(),
            self.image.clone().into(),
            "join".into(),
            "edge-configuration".into(),
            "--directory".into(),
            "/Edge".into(),
            "--kind".into(),
            match name {
                "Tls.json" => "tls",
                "Managed.json" => "certificate",
                _ => "listener",
            }
            .into(),
        ]);
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(value)?);
        let output = helper::output(&self.podman, &args, &bytes, stop, Duration::from_secs(30))?;
        let value: Value = serde_json::from_slice(&output)?;
        ensure!(
            value.get("status").and_then(Value::as_str) == Some("EdgeConfigurationWritten"),
            "edge configuration was not written"
        );
        Ok(())
    }
    pub fn prepare_state(&self, stop: &AtomicBool) -> Result<()> {
        self.validate()?;
        let root = self.directory.join("Edge");
        if !root.exists() {
            saved::create_directory(&root)?;
        }
        let m = std::fs::symlink_metadata(&root)?;
        ensure!(
            m.is_dir()
                && !m.file_type().is_symlink()
                && m.mode() & 0o077 == 0
                && (m.uid() == unsafe { libc::geteuid() } || m.uid() == self.edge_uid),
            "edge state ownership differs"
        );
        if m.uid() == unsafe { libc::geteuid() } {
            // Transfer only the new empty directory; later writes run inside the container.
            ensure!(
                std::fs::read_dir(&root)?.next().is_none(),
                "unexpected initial edge state"
            );
            self.command(
                &[
                    "unshare".into(),
                    "/usr/bin/chown".into(),
                    "--".into(),
                    "1:1".into(),
                    root.as_os_str().into(),
                ],
                stop,
            )?;
        }
        Ok(())
    }
    pub fn prepare(&self, host: &str, stop: &AtomicBool) -> Result<String> {
        self.prepare_state(stop)?;
        let tls = certificates::Configuration::Private {
            directory: "/Edge/Tls".into(),
            host: host.into(),
        };
        self.stage("Tls.json", &tls, stop)?;
        let inspected = self.json(
            &["join", "certificate-inspect", "--config", "/Edge/Tls.json"],
            stop,
        );
        let result = match inspected {
            Ok(v) => v,
            Err(_) => self.json(
                &[
                    "join",
                    "certificate-init",
                    "--directory",
                    "/Edge/Tls",
                    "--host",
                    host,
                ],
                stop,
            )?,
        };
        let pin = result
            .get("certificateAuthorityPin")
            .and_then(Value::as_str)
            .filter(|s| protocol::identifier(s))
            .ok_or_else(|| anyhow::anyhow!("public TLS authority pin unavailable"))?;
        Ok(pin.into())
    }
    pub fn configure(
        &self,
        location: &Location,
        listen: std::net::SocketAddr,
        stop: &AtomicBool,
    ) -> Result<()> {
        let config = edge::Configuration {
            version: 1,
            origin: location.origin.to_string(),
            native_link: location.url(true)?,
            listen: std::net::SocketAddr::new(
                std::net::Ipv4Addr::UNSPECIFIED.into(),
                listen.port(),
            ),
            tls: if location.certificate_authority_pin.is_some() {
                certificates::Configuration::Private {
                    directory: "/Edge/Tls".into(),
                    host: location.origin.host_str().unwrap().into(),
                }
            } else {
                certificates::Configuration::ManagedBundle {
                    bundle: "/Edge/Managed.json".into(),
                }
            },
            registrar: "/Bridge/Admission.sock".into(),
            registrar_uid: 1001,
        };
        config.validate()?;
        self.stage("Edge.json", &config, stop)
    }
    pub fn launch_arguments(&self) -> Result<Vec<OsString>> {
        let mut args = self.base(true)?;
        args.extend([
            "--publish".into(),
            format!("{}:{}/tcp", self.listen, self.listen.port()).into(),
            "--name".into(),
            self.name().into(),
            "--label".into(),
            format!(
                "org.hypernet.admission={}",
                protocol::digest(self.directory.as_os_str().as_encoded_bytes())
            )
            .into(),
            self.image.clone().into(),
            "join".into(),
            "listen".into(),
            "--config".into(),
            "/Edge/Edge.json".into(),
        ]);
        Ok(args)
    }
    pub fn stop(&self, stop: &AtomicBool) -> Result<()> {
        self.stop_named(&self.name(), stop)
    }
    pub(super) fn stop_named(&self, name: &str, stop: &AtomicBool) -> Result<()> {
        let rows = self.command(
            &[
                "ps".into(),
                "--all".into(),
                "--filter".into(),
                format!("name=^{name}$").into(),
                "--format=json".into(),
            ],
            stop,
        )?;
        let rows: Vec<Value> = serde_json::from_slice(&rows)?;
        ensure!(rows.len() <= 1, "ambiguous public listener container");
        let Some(row) = rows.first() else {
            return Ok(());
        };
        let id = row
            .get("Id")
            .or_else(|| row.get("ID"))
            .and_then(Value::as_str)
            .filter(|s| protocol::identifier(s))
            .ok_or_else(|| anyhow::anyhow!("container identity unavailable"))?;
        let inspect = self.command(
            &["inspect".into(), "--type=container".into(), id.into()],
            stop,
        )?;
        let records: Vec<Value> = serde_json::from_slice(&inspect)?;
        let item = records
            .first()
            .filter(|_| records.len() == 1)
            .ok_or_else(|| anyhow::anyhow!("container inspection differs"))?;
        ensure!(
            item.pointer("/Config/Labels/org.hypernet.admission")
                .and_then(Value::as_str)
                == Some(protocol::digest(self.directory.as_os_str().as_encoded_bytes()).as_str())
                && item
                    .get("Image")
                    .and_then(Value::as_str)
                    .is_some_and(|s| s.trim_start_matches("sha256:")
                        == self.image.trim_start_matches("sha256:")),
            "refusing to stop an unrelated container"
        );
        self.command(&["stop".into(), "--time=5".into(), id.into()], stop)?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rootless_mapping_requires_a_separate_subordinate_user() {
        assert_eq!(
            mapped_identity(b"0 1000 1\n1 231072 65536\n", 1000, 1).unwrap(),
            231072
        );
        for map in [
            b"0 1000 1\n".as_slice(),
            b"0 0 65536\n",
            b"0 1000 2\n1 2000 1\n",
        ] {
            assert!(mapped_identity(map, 1000, 1).is_err());
        }
    }
}
