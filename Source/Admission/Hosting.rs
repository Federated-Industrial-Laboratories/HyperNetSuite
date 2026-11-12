// SPDX-License-Identifier: MIT
// Shared hosting joins reviewed native provisioning to a private registrar and isolated public listener.
use super::{
    control, helper,
    host_isolation::Container,
    host_service,
    location::{Application, Location},
    password, protocol, registrar, registrar_isolation, runtime, saved, store,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
#[path = "HostingSoftware.rs"]
mod software;
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub version: u8,
    pub installation: PathBuf,
    pub native: Value,
    pub origin: String,
    pub listen: SocketAddr,
    pub mode: store::Mode,
    pub podman: PathBuf,
    #[serde(default)]
    pub tls: super::host_tls::Configuration,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase", deny_unknown_fields)]
pub enum Request {
    Preview {
        configuration: Configuration,
    },
    Create {
        configuration: Configuration,
        #[serde(rename = "reviewDigest")]
        review_digest: String,
        password: Option<String>,
    },
    Status,
    Resume,
    Start,
    Stop,
    Withdraw,
    EnableUnattended,
    Admin {
        action: control::Admin,
    },
    Invite {
        end: store::End,
        #[serde(rename = "maximumUses")]
        maximum_uses: u32,
    },
    Diagnose,
    PreviewSoftware,
    UpdateSoftware {
        #[serde(rename = "reviewDigest")]
        review_digest: String,
    },
}
impl Drop for Request {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Self::Create { password, .. } = self {
            password.zeroize();
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Setup {
    version: u8,
    configuration: Configuration,
    native_review: String,
    password: Option<password::Verifier>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ready {
    version: u8,
    container: Container,
    registrar: registrar_isolation::RegistrarContainer,
    name: String,
    location: String,
}
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("native host field {key} absent"))
}
fn path(value: &Value, key: &str) -> Result<PathBuf> {
    let path = PathBuf::from(field(value, key)?);
    ensure!(path.is_absolute(), "native host path must be absolute");
    Ok(path)
}
fn native(
    directory: &Path,
    config: &Configuration,
    action: Value,
    stop: &AtomicBool,
) -> Result<Value> {
    let executable = std::env::current_exe()?.canonicalize()?;
    let input = zeroize::Zeroizing::new(serde_json::to_vec(
        &json!({"format":"HyperNetNativeHost/1","action":action}),
    )?);
    let output = helper::output(
        &executable,
        &[
            "admission-host".into(),
            "request".into(),
            "--directory".into(),
            directory.join("NativeHost").into_os_string(),
            "--installation".into(),
            config.installation.as_os_str().into(),
            "--json-stdin".into(),
        ],
        &input,
        stop,
        Duration::from_secs(1800),
    )?;
    let value: Value = serde_json::from_slice(&output)?;
    ensure!(
        value.get("format").and_then(Value::as_str) == Some("HyperNetNativeHost/1"),
        "native host helper version differs"
    );
    Ok(value)
}
impl Configuration {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && self.native.is_object(),
            "invalid hosting configuration"
        );
        super::private::directory(&self.installation)?;
        runtime::executable(&self.podman)?;
        let location = Location::parse(&self.origin)?;
        ensure!(
            location.origin.as_str() == self.origin
                && location.identity_pin.is_none()
                && location.secret.is_none(),
            "host requires an exact HTTPS origin"
        );
        ensure!(
            self.listen.port() > 1024
                && location.origin.port_or_known_default() == Some(self.listen.port()),
            "public admission requires a matching unprivileged port"
        );
        let relay = self
            .native
            .get("relayPort")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow::anyhow!("native relay port absent"))?;
        let authority = self
            .native
            .get("authorityFirstPort")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow::anyhow!("native authority port absent"))?;
        ensure!(
            u64::from(self.listen.port()) != relay
                && !(authority..authority + 4).contains(&u64::from(self.listen.port())),
            "admission port overlaps native services"
        );
        self.tls.validate(
            &self.origin,
            &[
                self.listen.port(),
                relay as u16,
                authority as u16,
                (authority + 1) as u16,
                (authority + 2) as u16,
                (authority + 3) as u16,
            ],
        )?;
        ensure!(
            self.native.get("sameOrganisation").and_then(Value::as_bool) == Some(true),
            "review the single-organisation hosting topology"
        );
        let capacity = self
            .native
            .get("maximumParticipants")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let maximum = if self.native.get("hrc").is_some_and(|v| !v.is_null()) {
            32
        } else {
            64
        };
        ensure!(
            (2..=maximum).contains(&capacity),
            "participant capacity must include the owner and fit the selected service"
        );
        Ok(())
    }
}
pub fn preview(
    directory: &Path,
    configuration: &Configuration,
    stop: &AtomicBool,
) -> Result<Value> {
    configuration.validate()?;
    let result = native(
        directory,
        configuration,
        json!({"operation":"preview","configuration":configuration.native}),
        stop,
    )?;
    ensure!(
        field(&result, "status")? == "Preview",
        "native hosting review is unavailable"
    );
    let review = protocol::digest_value(
        &json!({"configuration":configuration,"nativeReview":field(&result,"reviewDigest")?}),
    )?;
    Ok(
        json!({"status":"Preview","reviewDigest":review,"native":result,"mode":configuration.mode,"origin":configuration.origin,"tls":configuration.tls.review(),"publicListener":{"identity":"separate rootless user","memoryBytes":134217728,"network":"isolated with source-preserving port forwarding","allowedState":"TLS files and authenticated admission socket"},"startsAfterLogout":host_service::linger_enabled()}),
    )
}
fn desired(directory: &Path) -> Result<bool> {
    Ok(saved::read::<Value>(&directory.join("HostingChoice.json"))?
        .get("running")
        .and_then(Value::as_bool)
        == Some(true))
}
fn choice(directory: &Path, running: bool) -> Result<()> {
    saved::replace(
        &directory.join("HostingChoice.json"),
        &json!({"running":running}),
    )
}
fn ready(directory: &Path) -> Result<Ready> {
    let r: Ready = saved::read(&directory.join("HostingReady.json"))?;
    ensure!(
        r.version == 1 && r.container.directory == directory,
        "saved hosting paths differ"
    );
    Ok(r)
}
fn executable_digest(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    runtime::executable(path)?;
    let mut file = std::fs::File::open(path)?;
    ensure!(
        file.metadata()?.len() <= 536870912,
        "installed executable exceeds bound"
    );
    let mut hash = Sha256::new();
    let mut bytes = [0u8; 65536];
    loop {
        let n = file.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        hash.update(&bytes[..n]);
    }
    Ok(hex::encode(hash.finalize()))
}
fn initialise_public(
    directory: &Path,
    setup: &Setup,
    native: &Value,
    stop: &AtomicBool,
) -> Result<Ready> {
    let configuration = &setup.configuration;
    let container = Container::new(
        directory,
        configuration.podman.clone(),
        path(native, "suiteExecutable")?,
        field(native, "coreImage")?.into(),
        configuration.listen,
        stop,
    )?;
    ensure!(
        executable_digest(&container.suite)?
            == executable_digest(&std::env::current_exe()?.canonicalize()?)?,
        "hosting must use the reviewed installed Suite executable"
    );
    let mut location = Location::parse(&configuration.origin)?;
    let hrc = native.get("hrc").filter(|v| !v.is_null());
    location.application = if hrc.is_some() {
        Application::Hrc
    } else {
        Application::Native
    };
    let isolated = registrar_isolation::RegistrarContainer {
        native: serde_json::from_value(
            native
                .get("registrarIsolation")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("native registrar isolation absent"))?,
        )?,
        hrc: hrc
            .map(|h| {
                serde_json::from_value(
                    h.get("registrarIsolation")
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("HRC registrar isolation absent"))?,
                )
                .map_err(anyhow::Error::from)
            })
            .transpose()?,
    };
    let hrc_binding = hrc.map(|_| helper::Hrc {
        executable: "/Hrc".into(),
        configuration: "/HrcAdmission/Binding.json".into(),
    });
    let registrar = registrar::Configuration {
        version: 1,
        directory: "/Registrar".into(),
        origin: configuration.origin.clone(),
        name: field(&configuration.native, "name")?.into(),
        native: helper::Native {
            configuration: isolated.native.configuration.clone(),
        },
        descriptor_key_file: isolated.native.descriptor_key_file.clone(),
        socket: "/Bridge/Admission.sock".into(),
        edge_uid: 1,
        owner_uid: Some(0),
        welcome: native
            .pointer("/pages/welcomePage")
            .and_then(Value::as_str)
            .map(Into::into),
        hrc: hrc_binding,
        hrc_descriptor: hrc
            .map(|h| {
                h.get("descriptor")
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("HRC descriptor absent"))
            })
            .transpose()?,
        reader: true,
    };
    let total = native
        .get("maximumParticipants")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("native capacity absent"))?;
    ensure!(
        native.get("ownerReservedSlots").and_then(Value::as_u64) == Some(1)
            && (2..=64).contains(&total),
        "native owner reservation differs"
    );
    let access = native
        .get("accessEnd")
        .ok_or_else(|| anyhow::anyhow!("native access lifetime absent"))?;
    let access = if access == &json!({"untilWithdrawn":1}) {
        store::End::UntilRemoved
    } else {
        store::End::Expires {
            expires_ms: access
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("invalid native access lifetime"))?,
        }
    };
    let pin = isolated.prepare(
        &container,
        registrar_isolation::Initial {
            configuration: registrar,
            maximum_members: (total - 1) as usize,
            access,
            mode: configuration.mode,
            password: setup.password.clone(),
        },
        stop,
    )?;
    location.identity_pin = Some(
        hex::decode(pin)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("registrar identity differs"))?,
    );
    location.certificate_authority_pin =
        configuration
            .tls
            .prepare(&container, &configuration.origin, stop)?;
    container.configure(&location, configuration.listen, stop)?;
    let result = Ready {
        version: 1,
        container,
        registrar: isolated,
        name: field(&configuration.native, "name")?.into(),
        location: location.url(location.certificate_authority_pin.is_some())?,
    };
    saved::replace(&directory.join("HostingReady.json"), &result)?;
    Ok(result)
}
fn public_status(r: &Ready) -> Result<Value> {
    r.registrar.owner(&r.container, control::Admin::Status)
}
fn verified_listener(r: &Ready) -> Result<()> {
    let location = Location::parse(&r.location)?;
    let descriptor: protocol::Descriptor =
        serde_json::from_slice(&super::transport::descriptor(&location)?)?;
    ensure!(
        descriptor.format == protocol::FORMAT,
        "public descriptor format differs"
    );
    let key = &descriptor.metadata.key;
    ensure!(
        location.identity_pin.is_some_and(
            |p| hex::encode(p) == protocol::digest(&hex::decode(key).unwrap_or_default())
        ),
        "public server identity differs"
    );
    let meta: protocol::Metadata =
        descriptor
            .metadata
            .verify("descriptor", key, protocol::SIGNED_BYTES)?;
    ensure!(
        meta.origin == location.origin.as_str(),
        "public server address differs"
    );
    Ok(())
}
fn running(directory: &Path, r: &Ready, stop: &AtomicBool) -> Result<()> {
    choice(directory, true)?;
    host_service::start(directory, &r.container.suite, stop)?;
    let until = Instant::now() + Duration::from_secs(120);
    while Instant::now() < until && !stop.load(Ordering::Acquire) {
        if public_status(r).is_ok() && verified_listener(r).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    anyhow::bail!("server joining is not reachable yet; setup and identities are retained")
}
fn complete(directory: &Path, setup: &Setup, resume: bool, stop: &AtomicBool) -> Result<Value> {
    ensure!(setup.version == 1, "unsupported hosting setup version");
    setup.configuration.validate()?;
    let configuration = &setup.configuration;
    let mut result = native(
        directory,
        configuration,
        json!({"operation":"create","configuration":configuration.native,"reviewDigest":setup.native_review}),
        stop,
    )?;
    if resume && field(&result, "status")? == "Stopped" {
        result = native(directory, configuration, json!({"operation":"start"}), stop)?;
    }
    ensure!(
        field(&result, "status")? == "Running",
        "native provisioning is incomplete; resume the retained setup"
    );
    let r = if directory.join("HostingReady.json").exists() {
        ready(directory)?
    } else {
        initialise_public(directory, setup, &result, stop)?
    };
    running(directory, &r, stop)?;
    status(directory, setup, &r, stop)
}
pub fn request(directory: &Path, request: Request, stop: &AtomicBool) -> Result<Value> {
    saved::create_directory(directory)?;
    let _lock = host_service::lock(directory, "HostControl.lock")?;
    if matches!(
        &request,
        Request::Create { .. } | Request::Start | Request::Resume
    ) {
        ensure!(
            !software::pending(directory)?,
            "complete the reviewed software update before starting"
        );
    }
    let cancellation_stops = matches!(
        &request,
        Request::Create { .. }
            | Request::Resume
            | Request::Start
            | Request::Stop
            | Request::Withdraw
    );
    let result = (|| match &request {
        Request::PreviewSoftware => software::preview(directory, stop),
        Request::UpdateSoftware { review_digest } => {
            software::update(directory, review_digest, stop)
        }
        Request::Preview { configuration } => preview(directory, configuration, stop),
        Request::Create {
            configuration,
            review_digest,
            password,
        } => {
            let checked = preview(directory, configuration, stop)?;
            ensure!(
                field(&checked, "reviewDigest")? == review_digest,
                "hosting review changed; review again"
            );
            let file = directory.join("HostingSetup.json");
            if file.exists() {
                let retained: Setup = saved::read(&file)?;
                ensure!(
                    protocol::digest_value(&retained.configuration)?
                        == protocol::digest_value(configuration)?,
                    "resume the original reviewed host configuration"
                );
            } else {
                let verifier = if configuration.mode == store::Mode::Password {
                    Some(password::Verifier::create(
                        password
                            .as_deref()
                            .ok_or_else(|| anyhow::anyhow!("set a server password"))?
                            .as_bytes(),
                    )?)
                } else {
                    None
                };
                saved::replace(
                    &file,
                    &Setup {
                        version: 1,
                        configuration: configuration.clone(),
                        native_review: field(checked.get("native").unwrap(), "reviewDigest")?
                            .into(),
                        password: verifier,
                    },
                )?;
            }
            let setup: Setup = saved::read(&file)?;
            complete(directory, &setup, false, stop)
        }
        Request::Resume => {
            let setup: Setup = saved::read(&directory.join("HostingSetup.json"))?;
            complete(directory, &setup, true, stop)
        }
        Request::EnableUnattended => {
            helper::output(
                &Path::new("/usr/bin/loginctl").canonicalize()?,
                &["enable-linger".into()],
                &[],
                stop,
                Duration::from_secs(60),
            )?;
            ensure!(
                host_service::linger_enabled(),
                "unattended user hosting is not enabled"
            );
            Ok(json!({"status":"UnattendedHostingEnabled"}))
        }
        _ => {
            let setup: Setup = saved::read(&directory.join("HostingSetup.json"))?;
            if matches!(request, Request::Stop | Request::Withdraw) {
                choice(directory, false)?;
                let public = if directory.join("HostingReady.json").exists() {
                    host_service::stop(directory, stop)
                } else {
                    Ok(())
                };
                let native = native(
                    directory,
                    &setup.configuration,
                    json!({"operation":if matches!(request,Request::Withdraw){"withdraw"}else{"stop"}}),
                    stop,
                )?;
                public?;
                return Ok(
                    json!({"status":native.get("status"),"desiredRunning":false,"native":native,"admission":null,"listenerVerifiedFromHost":false}),
                );
            }
            if !directory.join("HostingReady.json").exists() {
                return match request {
                    Request::Start => complete(directory, &setup, true, stop),
                    Request::Status => {
                        let n = native(
                            directory,
                            &setup.configuration,
                            json!({"operation":"status"}),
                            stop,
                        )?;
                        Ok(
                            json!({"status":readiness(false,false,n.get("status").and_then(Value::as_str)),"desiredRunning":n.get("desiredRunning"),"native":n,"admission":null,"listenerVerifiedFromHost":false,"setupIncomplete":true}),
                        )
                    }
                    _ => {
                        anyhow::bail!("complete the retained server setup before managing joining")
                    }
                };
            }
            let r = ready(directory)?;
            match &request {
                Request::Status => status(directory, &setup, &r, stop),
                Request::Start => {
                    let n = native(
                        directory,
                        &setup.configuration,
                        json!({"operation":"start"}),
                        stop,
                    )?;
                    ensure!(
                        field(&n, "status")? == "Running",
                        "native hosting has not reached readiness"
                    );
                    running(directory, &r, stop)?;
                    status(directory, &setup, &r, stop)
                }
                Request::Admin { action } => r.registrar.owner(
                    &r.container,
                    serde_json::from_value(serde_json::to_value(action)?)?,
                ),
                Request::Invite { end, maximum_uses } => {
                    let invitation = r.registrar.owner(
                        &r.container,
                        control::Admin::Invite {
                            end: end.clone(),
                            maximum_uses: *maximum_uses,
                        },
                    )?;
                    ensure!(
                        field(&invitation, "status")? == "InvitationCreated",
                        "invitation could not be created"
                    );
                    let mut location = Location::parse(&r.location)?;
                    location.invitation = Some(
                        hex::decode(field(&invitation, "id")?)?
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("invalid invitation ID"))?,
                    );
                    location.secret = Some(field(&invitation, "secret")?.into());
                    Ok(
                        json!({"status":"InvitationCreated","id":invitation.get("id"),"link":location.url(location.certificate_authority_pin.is_some())?,"instructions":instructions(&r,&location)?}),
                    )
                }
                Request::Diagnose => {
                    let n = native(
                        directory,
                        &setup.configuration,
                        json!({"operation":"status"}),
                        stop,
                    )?;
                    let p = public_status(&r).ok();
                    Ok(
                        json!({"status":"HostingDiagnosis","nativeStatus":n.get("status"),"nativePhase":n.get("phase"),"desiredRunning":desired(directory)?,"publicControlAvailable":p.is_some(),"joiningEnabled":p.as_ref().and_then(|v|v.get("enabled")),"listenerVerifiedFromHost":verified_listener(&r).is_ok(),"startsAfterLogout":host_service::linger_enabled()}),
                    )
                }
                _ => unreachable!(),
            }
        }
    })();
    // A cancelled helper is reaped before cleanup starts. Use a fresh bounded
    // owner request so cancellation cannot leave independently managed units running.
    if result.is_err()
        && cancellation_stops
        && stop.load(Ordering::Acquire)
        && directory.join("HostingSetup.json").exists()
    {
        let cleanup = AtomicBool::new(false);
        choice(directory, false)?;
        let public = if directory.join("HostingReady.json").exists() {
            host_service::stop(directory, &cleanup)
        } else {
            Ok(())
        };
        if directory.join("NativeHost/Hosting.json").exists() {
            let setup: Setup = saved::read(&directory.join("HostingSetup.json"))?;
            let result = native(
                directory,
                &setup.configuration,
                json!({"operation":if matches!(&request, Request::Withdraw){"withdraw"}else{"stop"}}),
                &cleanup,
            )?;
            ensure!(
                matches!(result["status"].as_str(), Some("Stopped" | "Withdrawn")),
                "hosting cancelled; offline choice saved but cleanup is incomplete; retry Stop"
            );
        }
        public?;
    }
    result
}
fn instructions(r: &Ready, location: &Location) -> Result<String> {
    Ok(format!(
        "Join {}\n\n{}\n\nInstall the signed HyperNet Suite{} package. Open the link, or choose Join a server and paste it. Review the server and permissions, choose a display name and join. If this server requires a password, obtain it separately from the host. The current desktop packages require Linux. Keep private invitations to yourself.\n",
        r.name,
        location.url(location.certificate_authority_pin.is_some())?,
        if r.registrar.hrc.is_some() {
            " and HyperNet RelayChat"
        } else {
            ""
        }
    ))
}
fn readiness(online: bool, accessible: bool, native: Option<&str>) -> &'static str {
    match native {
        Some("Withdrawn") => "Withdrawn",
        Some("WithdrawalPending") => "WithdrawalPending",
        Some("StopPending") => "StopPending",
        Some("Stopped") if !online => "Stopped",
        Some("Running") if online && accessible => "Running",
        _ => "NeedsAttention",
    }
}

fn status(directory: &Path, setup: &Setup, r: &Ready, stop: &AtomicBool) -> Result<Value> {
    let n = native(
        directory,
        &setup.configuration,
        json!({"operation":"status"}),
        stop,
    )?;
    let public = public_status(r).ok();
    let online = desired(directory)?;
    let accessible = online && public.is_some() && verified_listener(r).is_ok();
    Ok(
        json!({"status":readiness(online,accessible,n.get("status").and_then(Value::as_str)),"desiredRunning":online,"native":n,"admission":public,"link":r.location,"instructions":instructions(r,&Location::parse(&r.location)?)?,"listenerVerifiedFromHost":accessible,"tls":setup.configuration.tls.review(),"certificateRefresh":saved::read::<Value>(&directory.join("TlsHealth.json")).ok(),"externalReachability":"Check the shared link from another connection; local readiness does not prove router/firewall forwarding.","startsAfterLogout":host_service::linger_enabled()}),
    )
}
#[cfg(feature = "gui")]
pub(super) fn running_choice(directory: &Path) -> Result<bool> {
    desired(directory)
}
#[cfg(feature = "gui")]
pub(super) fn owner_reader(directory: &Path, refresh: bool, stop: &AtomicBool) -> Result<Value> {
    ensure!(
        desired(directory)?,
        "hosting is stopped; start it before opening Pages"
    );
    let setup: Setup = saved::read(&directory.join("HostingSetup.json"))?;
    let result = native(
        directory,
        &setup.configuration,
        json!({"operation":if refresh{"refreshReader"}else{"status"}}),
        stop,
    )?;
    ensure!(
        field(&result, "status")? == "Running",
        "native hosting is not ready"
    );
    let owner = result
        .get("owner")
        .ok_or_else(|| anyhow::anyhow!("host owner absent"))?;
    let candidate = path(owner, "candidateDirectory")?;
    ensure!(
        path(owner, "readerKeyFile")?.starts_with(&candidate)
            && path(owner, "readerProfile")?.starts_with(&candidate),
        "owner reader escapes its candidate directory"
    );
    Ok(result)
}
pub fn serve(directory: &Path, stop: Arc<AtomicBool>) -> Result<Value> {
    let _lock = host_service::lock(directory, "HostSession.lock")?;
    ensure!(
        !software::pending(directory)?,
        "complete the reviewed software update before starting"
    );
    if !desired(directory)? {
        return Ok(json!({"status":"Stopped"}));
    }
    let r = ready(directory)?;
    let setup: Setup = saved::read(&directory.join("HostingSetup.json"))?;
    r.container.stop(&stop)?;
    r.registrar.stop(&r.container, &stop)?;
    let _certificates = super::host_tls::Maintenance::start(
        setup.configuration.tls.clone(),
        r.container.clone(),
        setup.configuration.origin.clone(),
    );
    let mut registrar = runtime::Process::spawn(
        &r.container.podman,
        &r.registrar.launch_arguments(&r.container)?,
    )?;
    let result = (|| -> Result<()> {
        let mut listener =
            runtime::Process::spawn(&r.container.podman, &r.container.launch_arguments()?)?;
        let outcome = (|| -> Result<()> {
            while !stop.load(Ordering::Acquire) && desired(directory)? {
                ensure!(
                    registrar.running()? && listener.running()?,
                    "public joining worker stopped"
                );
                std::thread::sleep(Duration::from_millis(250));
            }
            Ok(())
        })();
        let cleanup = r.container.stop(&AtomicBool::new(false));
        drop(listener);
        outcome?;
        cleanup
    })();
    let cleanup = r.registrar.stop(&r.container, &AtomicBool::new(false));
    drop(registrar);
    result?;
    cleanup?;
    Ok(json!({"status":"Stopped"}))
}

#[cfg(test)]
mod readiness_tests {
    use super::readiness;
    #[test]
    fn offline_choice_does_not_hide_pending_cleanup_or_terminal_withdrawal() {
        for (native, expected) in [
            (Some("Running"), "NeedsAttention"),
            (Some("StopPending"), "StopPending"),
            (Some("WithdrawalPending"), "WithdrawalPending"),
            (Some("Withdrawn"), "Withdrawn"),
            (Some("Stopped"), "Stopped"),
            (None, "NeedsAttention"),
        ] {
            assert_eq!(readiness(false, false, native), expected);
        }
        assert_eq!(readiness(true, false, Some("Running")), "NeedsAttention");
        assert_eq!(readiness(true, true, Some("Running")), "Running");
    }
}
