// SPDX-License-Identifier: MIT
// One private Page window owns each saved reader profile and accepts bounded local navigation.
use super::{local, runtime, saved};
use anyhow::{Result, ensure};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub location: Option<String>,
}
fn validate(location: &str) -> Result<()> {
    ensure!(
        location.len() <= 512
            && location.starts_with("hypernet://")
            && location.bytes().all(|b| (33..127).contains(&b)),
        "a native Page address is required"
    );
    let document = crate::markup::parse(&format!(
        "{}\n# Address\n=> {location} Open\n",
        crate::markup::PROFILE
    ))
    .map_err(anyhow::Error::msg)?;
    ensure!(document.links.len() == 1, "invalid Page address");
    Ok(())
}
fn call(directory: &Path, action: &str, location: Option<&str>) -> Result<Value> {
    let root = local::sockets(directory).join("Pages");
    super::private::directory(&root)?;
    let mut channel = super::ipc::Channel::connect(
        &root.join("Control.sock"),
        unsafe { libc::geteuid() },
        Duration::from_secs(2),
    )?;
    Ok(serde_json::from_slice(&channel.exchange(
        &serde_json::to_vec(&json!({"version":1,"action":action,"location":location}))?,
        4096,
    )?)?)
}
pub fn open(directory: &Path, config: &Path, input: Input, stop: &AtomicBool) -> Result<Value> {
    if let Some(location) = &input.location {
        validate(location)?;
    }
    let _ = local::configuration(directory, config)?;
    let state: saved::State = saved::read(&directory.join("Server.json"))?;
    let (_, profile) = local::profiles(directory, &state)?;
    ensure!(profile.is_some(), "this server has no Page reader");
    ensure!(
        state.desired_online,
        "this saved server is offline; reconnect explicitly"
    );
    if let Ok(response) = call(directory, "open", input.location.as_deref()) {
        ensure!(
            response.get("status").and_then(Value::as_str) == Some("Accepted"),
            "Page window is busy; retry the link"
        );
        return Ok(json!({"status":"Opened"}));
    }
    runtime::ensure_running(directory, config, stop)?;
    launch(directory, Some(config), "page-session", input, stop)
}
pub fn open_owner(directory: &Path, input: Input, stop: &AtomicBool) -> Result<Value> {
    if let Some(location) = &input.location {
        validate(location)?;
    }
    let _ = super::hosting::owner_reader(directory, false, stop)?;
    if let Ok(response) = call(directory, "open", input.location.as_deref()) {
        ensure!(
            response.get("status").and_then(Value::as_str) == Some("Accepted"),
            "Page window is busy; retry the link"
        );
        return Ok(json!({"status":"Opened"}));
    }
    launch(directory, None, "host-page-session", input, stop)
}
fn launch(
    directory: &Path,
    config: Option<&Path>,
    command: &str,
    input: Input,
    stop: &AtomicBool,
) -> Result<Value> {
    let executable = std::env::current_exe()?.canonicalize()?;
    runtime::executable(&executable)?;
    let mut child = Command::new(executable);
    child.args(["join", command, "--directory"]).arg(directory);
    if let Some(config) = config {
        child.arg("--config").arg(config);
    }
    let mut child = child
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("Page input unavailable"))?
        .write_all(&serde_json::to_vec(&input)?)?;
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(response) = call(directory, "status", None)
            && response.get("status").and_then(Value::as_str) == Some("Ready")
        {
            return Ok(json!({"status":"Opened"}));
        }
        if child.try_wait()?.is_some() {
            // Another launcher may have won the private reader lock.
            let response = call(directory, "open", input.location.as_deref())?;
            ensure!(
                response.get("status").and_then(Value::as_str) == Some("Accepted"),
                "Page window could not open"
            );
            return Ok(json!({"status":"Opened"}));
        }
        if stop.load(Ordering::Acquire) || Instant::now() >= until {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("Page window did not become ready");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
struct Server {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
pub fn session(directory: &Path, config: &Path, input: Input) -> Result<Value> {
    let _ = local::configuration(directory, config)?;
    let state: saved::State = saved::read(&directory.join("Server.json"))?;
    ensure!(
        state.desired_online && local::ready(directory, &state),
        "saved connection is offline or not ready"
    );
    let (_, profile) = local::profiles(directory, &state)?;
    let profile = profile.ok_or_else(|| anyhow::anyhow!("Page profile unavailable"))?;
    let location = input
        .location
        .or(state.metadata.welcome)
        .ok_or_else(|| anyhow::anyhow!("server has no welcome Page; supply a Page address"))?;
    browse(directory, profile, location, None)
}
pub fn owner_session(directory: &Path, input: Input) -> Result<Value> {
    let state = super::hosting::owner_reader(directory, false, &AtomicBool::new(false))?;
    let owner = state
        .get("owner")
        .ok_or_else(|| anyhow::anyhow!("host owner reader unavailable"))?
        .clone();
    let profile = owner
        .get("readerProfile")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("owner Page profile absent"))?
        .into();
    let location = input
        .location
        .or_else(|| {
            state
                .pointer("/pages/welcomePage")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .ok_or_else(|| anyhow::anyhow!("welcome Page absent"))?;
    browse(directory, profile, location, Some(owner))
}
fn browse(
    directory: &Path,
    profile: std::path::PathBuf,
    location: String,
    owner: Option<Value>,
) -> Result<Value> {
    saved::create_directory(&local::sockets(directory))?;
    validate(&location)?;
    let root = local::sockets(directory).join("Pages");
    saved::create_directory(&root)?;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root.join("Browser.lock"))?;
    let m = lock.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.mode() & 0o077 == 0
            && m.uid() == unsafe { libc::geteuid() },
        "reader lock is not private"
    );
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "this reader window is already open"
    );
    let listener = crate::local_stream_ipc::Listener::bind(&root)?;
    listener.socket.set_nonblocking(true)?;
    let (sender, inbox) = crate::graphical::navigation_channel();
    let registration = crate::graphical::install_navigation(inbox)?;
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let thread = std::thread::spawn(move || {
        while !stopped.load(Ordering::Acquire) {
            match listener.socket.accept() {
                Ok((socket, _)) => {
                    let result = (|| -> Result<()> {
                        let mut channel = super::ipc::Channel::accepted(
                            socket,
                            unsafe { libc::geteuid() },
                            Duration::from_secs(2),
                        )?;
                        let mut size = [0u8; 4];
                        channel.read_exact(&mut size)?;
                        let size = u32::from_be_bytes(size) as usize;
                        ensure!(size > 0 && size <= 4096, "Page command exceeds bound");
                        let mut bytes = vec![0; size];
                        channel.read_exact(&mut bytes)?;
                        #[derive(Deserialize)]
                        #[serde(deny_unknown_fields)]
                        struct Request {
                            version: u8,
                            action: String,
                            location: Option<String>,
                        }
                        let request: Request = serde_json::from_slice(&bytes)?;
                        ensure!(request.version == 1, "unsupported Page command");
                        let status = match request.action.as_str() {
                            "status" => {
                                if sender.is_attached() {
                                    "Ready"
                                } else {
                                    "Starting"
                                }
                            }
                            "open" => {
                                if let Some(location) = &request.location {
                                    validate(location)?;
                                }
                                if sender.try_open(request.location).is_ok() {
                                    "Accepted"
                                } else {
                                    "Busy"
                                }
                            }
                            _ => anyhow::bail!("unsupported Page command"),
                        };
                        let bytes = serde_json::to_vec(&json!({"status":status}))?;
                        channel.write_all(&(bytes.len() as u32).to_be_bytes())?;
                        channel.write_all(&bytes)?;
                        Ok(())
                    })();
                    let _ = result;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                Err(_) => break,
            }
        }
    });
    let server = Server {
        stop,
        thread: Some(thread),
    };
    let key = if let Some(owner) = &owner {
        std::path::PathBuf::from(
            owner
                .get("readerKeyFile")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("owner reader key path absent"))?,
        )
    } else {
        directory.join("Native/Roles/0/Joined/Device.json")
    };
    let reader = register_reader(directory, owner, server.stop.clone())?;
    refresh_reader(&key)?;
    let arguments = vec![
        "HyperNetSuite".into(),
        "network".into(),
        "connect".into(),
        "--profile".into(),
        profile.into_os_string(),
        "--".into(),
        "browse".into(),
        "--gui".into(),
        location.into(),
    ];
    let result = crate::dispatch(crate::Options::try_parse_from(arguments)?.command);
    drop(server);
    drop(reader);
    drop(registration);
    drop(lock);
    result?;
    Ok(json!({"status":"PageWindowClosed"}))
}

struct ReaderContext {
    owner: Option<Value>,
    directory: std::path::PathBuf,
    stop: Arc<AtomicBool>,
}
static READER: std::sync::Mutex<Option<Arc<ReaderContext>>> = std::sync::Mutex::new(None);
struct ReaderRegistration;
impl Drop for ReaderRegistration {
    fn drop(&mut self) {
        if let Ok(mut reader) = READER.lock() {
            *reader = None;
        }
    }
}
fn register_reader(
    directory: &Path,
    owner: Option<Value>,
    stop: Arc<AtomicBool>,
) -> Result<ReaderRegistration> {
    let mut reader = READER
        .lock()
        .map_err(|_| anyhow::anyhow!("reader context unavailable"))?;
    ensure!(reader.is_none(), "saved reader already selected");
    *reader = Some(Arc::new(ReaderContext {
        owner,
        directory: directory.into(),
        stop,
    }));
    Ok(ReaderRegistration)
}
pub fn reader_needs_refresh(key: &Path) -> Result<Option<bool>> {
    let reader = READER
        .lock()
        .map_err(|_| anyhow::anyhow!("reader context unavailable"))?
        .clone();
    let Some(reader) = reader else {
        return Ok(None);
    };
    let (role, clock) = if let Some(owner) = &reader.owner {
        ensure!(
            super::hosting::running_choice(&reader.directory)?,
            "owner hosting is stopped"
        );
        ensure!(
            owner
                .get("readerKeyFile")
                .and_then(Value::as_str)
                .is_some_and(|p| Path::new(p) == key),
            "owner reader selected another identity"
        );
        let role = owner
            .get("reader")
            .ok_or_else(|| anyhow::anyhow!("owner reader descriptor absent"))?
            .clone();
        let clock = role
            .get("clockWitness")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("owner reader clock absent"))?
            .into();
        (role, clock)
    } else {
        ensure!(
            key == reader.directory.join("Native/Roles/0/Joined/Device.json"),
            "reader operation selected another identity"
        );
        let state: saved::State = saved::read(&reader.directory.join("Server.json"))?;
        ensure!(
            state.desired_online && !state.removed,
            "saved reader is offline or removed"
        );
        let role = state
            .installed
            .as_ref()
            .and_then(|v| v.get("profiles"))
            .and_then(Value::as_array)
            .and_then(|v| {
                v.iter()
                    .find(|p| p.get("role").and_then(Value::as_u64) == Some(0))
            })
            .ok_or_else(|| anyhow::anyhow!("installed reader absent"))?
            .clone();
        (role, reader.directory.join("Native/Clock/ClockHealth.json"))
    };
    let now = crate::authority_clock::health(&clock)?.observe()?.wall_ms;
    Ok(Some(role_needs_refresh(&role, now)?))
}
fn role_needs_refresh(role: &Value, now: u64) -> Result<bool> {
    let profile = role
        .get("profile")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("reader profile absent"))?;
    for name in ["authorityRoute", "destinationRoute"] {
        let file = role
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("reader route absent"))?;
        let endpoint = crate::private_route_client::Endpoint::load(Path::new(file))?;
        ensure!(
            endpoint.profile == Path::new(profile),
            "reader route selected another profile"
        );
        let route = endpoint.route;
        let record = crate::authority_domains::Record::parse(
            &route.voucher,
            route.network,
            route.incarnation,
        )?;
        let voucher = crate::authority_domains::routes::Voucher::parse(&record.payload)?;
        if voucher.expires <= now.saturating_add(61000) {
            return Ok(true);
        }
    }
    Ok(false)
}
pub fn refresh_reader(key: &Path) -> Result<()> {
    if reader_needs_refresh(key)? != Some(true) {
        return Ok(());
    }
    let reader = READER
        .lock()
        .map_err(|_| anyhow::anyhow!("reader context unavailable"))?
        .clone()
        .ok_or_else(|| anyhow::anyhow!("reader registration absent"))?;
    if let Some(owner) = &reader.owner {
        let result = super::hosting::owner_reader(&reader.directory, true, &reader.stop)?;
        let current = result
            .get("owner")
            .ok_or_else(|| anyhow::anyhow!("owner reader response absent"))?;
        for field in ["readerKeyFile", "readerProfile", "readerDirectory"] {
            ensure!(
                current.get(field) == owner.get(field),
                "owner reader identity path changed"
            );
        }
        for field in [
            "member",
            "profile",
            "authorityRoute",
            "destinationRoute",
            "clockWitness",
        ] {
            ensure!(
                current.get("reader").and_then(|v| v.get(field))
                    == owner.get("reader").and_then(|v| v.get(field)),
                "owner reader binding changed"
            );
        }
        return Ok(());
    }
    let result = super::client::run(
        &reader.directory,
        &super::client::Command::RenewReader,
        &reader.stop,
    )?;
    ensure!(
        result.get("status").and_then(Value::as_str) == Some("Joined"),
        "reader renewal pending or access removed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authority_deployment_tests as deployment,
        authority_domains::{Record, State, routes::Voucher},
        authority_proof::VersionRef,
        private_route_client::Endpoint,
        route_profile::{Assurance, Identity, Limits, Profile},
        trust_bootstrap as trust,
    };

    struct Directory(std::path::PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn saved_reader_refresh_loads_exact_endpoint_wrappers_and_profile_binding() {
        let root = std::env::temp_dir().join(format!(
            "HyperNetReaderEndpoints{}",
            crate::random_hex::<16>()
        ));
        saved::create_directory(&root).unwrap();
        let directory = Directory(root);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let (bootstrap, _) = crate::authority_recovery::tests::fixture(20, now);
        let profile = directory.0.join("Profile.json");
        let request = crate::networks::admission::prepare(&profile, &bootstrap, &[], 1, 0).unwrap();
        let original_profile = std::fs::read(&profile).unwrap();
        let checked = trust::inspect(&bootstrap, true).unwrap();
        let network = trust::hex32(&checked.summary.network).unwrap();
        let incarnation = trust::hex32(&checked.summary.incarnation).unwrap();
        let reference = |kind, id| VersionRef {
            kind,
            id: [id; 32],
            generation: 1,
            digest: [id; 32],
        };
        let identity = |service, seed| Identity {
            service: [service; 32],
            server_name: "route.invalid".into(),
            transport_key: deployment::key(seed).verifying_key().to_bytes(),
            leaf_der: deployment::leaf(seed),
            certificate_authority_pem: "Pinned route issuer".into(),
        };
        let endpoint = |protocol, expires| {
            let destination = if protocol == 1 { 14 } else { 16 };
            let voucher = Voucher {
                relay: reference(165, 12),
                destination: reference(165, destination),
                sponsor: trust::hex32(&request.member).unwrap(),
                grant: reference(102, 30),
                possession: trust::hex32(&request.relay).unwrap(),
                action: 0,
                scope: (3, [destination; 32]),
                connections: 16,
                bytes: 65_536,
                expires,
                creation: [31; 32],
                baseline: Some((0, 0)),
            };
            Endpoint {
                format: "HyperNetRelayEndpoint/1".into(),
                profile: profile.clone(),
                route: Profile {
                    version: 1,
                    network,
                    incarnation,
                    relay_address: "127.0.0.1:24443".parse().unwrap(),
                    relay: identity(12, 9),
                    destination: identity(destination, if protocol == 1 { 10 } else { 110 }),
                    domain: if protocol == 1 {
                        checked.summary.route.admission_domain.clone()
                    } else {
                        hex::encode([17; 32])
                    },
                    relay_domain: checked.summary.route.relay_domain.clone(),
                    protocol,
                    assurance: Assurance::Independent,
                    minimum_assurance: Assurance::Independent,
                    limits: Limits {
                        bytes: 16_384,
                        duration_ms: 1000,
                        idle_ms: 1000,
                    },
                    voucher: Record::next(
                        &State::empty(network, incarnation),
                        166,
                        [32; 32],
                        voucher.value(),
                    )
                    .unwrap()
                    .bytes,
                },
            }
        };
        let authority = directory.0.join("AuthorityRoute.json");
        let destination = directory.0.join("DestinationRoute.json");
        let role = json!({"role":0,"profile":profile,
            "authorityRoute":authority,"destinationRoute":destination});
        let live = [endpoint(1, now + 61_001), endpoint(2, now + 61_001)];
        for (path, route) in [(&authority, &live[0]), (&destination, &live[1])] {
            saved::replace(path, route).unwrap();
        }
        assert!(!role_needs_refresh(&role, now).unwrap());
        for (path, protocol, original) in [(&authority, 1, &live[0]), (&destination, 2, &live[1])] {
            saved::replace(path, &endpoint(protocol, now + 61_000)).unwrap();
            assert!(role_needs_refresh(&role, now).unwrap());
            saved::replace(path, original).unwrap();
        }
        let mut malformed = serde_json::to_value(&live[0]).unwrap();
        malformed["format"] = json!("UnknownEndpoint/1");
        saved::replace(&authority, &malformed).unwrap();
        assert!(role_needs_refresh(&role, now).is_err());
        saved::replace(&authority, &live[0].route).unwrap();
        assert!(role_needs_refresh(&role, now).is_err(), "no raw fallback");

        let other_profile = directory.0.join("OtherProfile.json");
        crate::transfer_files::write_new(&other_profile, &original_profile).unwrap();
        let mut changed = live[0].clone();
        changed.profile = other_profile;
        saved::replace(&authority, &changed).unwrap();
        Endpoint::load(&authority).unwrap();
        assert_eq!(
            role_needs_refresh(&role, now).unwrap_err().to_string(),
            "reader route selected another profile"
        );
        let mut changed = live[0].clone();
        changed.route.network[0] ^= 1;
        saved::replace(&authority, &changed).unwrap();
        assert!(role_needs_refresh(&role, now).is_err());
        let mut changed = live[0].clone();
        let record = Record::parse(&changed.route.voucher, network, incarnation).unwrap();
        let mut voucher = Voucher::parse(&record.payload).unwrap();
        voucher.possession = deployment::key(99).verifying_key().to_bytes();
        changed.route.voucher = Record::next(
            &State::empty(network, incarnation),
            166,
            record.reference.id,
            voucher.value(),
        )
        .unwrap()
        .bytes;
        saved::replace(&authority, &changed).unwrap();
        assert!(role_needs_refresh(&role, now).is_err());
        assert_eq!(std::fs::read(&profile).unwrap(), original_profile);
    }
}
