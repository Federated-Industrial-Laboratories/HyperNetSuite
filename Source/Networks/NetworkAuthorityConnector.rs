// SPDX-License-Identifier: MIT
// A private mapped connector forwards exact authority packets without holding the caller's signing state.
use super::*;
use crate::{
    authority_challenge::boot_time_ms,
    authority_domains::{Record, routes::Voucher},
    local_stream_ipc as ipc,
    mapped_ingress::Ingress,
    private_route_client::{self as transport, Endpoint, Selection},
    route_connector::{self, Session},
    trust_wire as wire,
};
use clap::Args;
use std::{
    io::{Read, Write},
    os::{fd::AsRawFd, unix::net::UnixStream},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};
#[path = "AuthorityConnectorPacket.rs"]
mod packet;
const DURATION_MS: u64 = 30000;
#[derive(Args)]
pub struct Arguments {
    #[arg(long)]
    profile: PathBuf,
    /// Private native directory; only its mapped Ingress child is exposed to Core.
    #[arg(long)]
    ipc_directory: PathBuf,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Binding {
    format: String,
    network: String,
    incarnation: String,
    bootstrap_digest: String,
    target_digest: String,
}
impl Binding {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = serde_json::from_slice(bytes)?;
        ensure!(
            value.format == "HyperNetAuthorityConnector/1",
            "unsupported authority connector binding"
        );
        for value in [
            &value.network,
            &value.incarnation,
            &value.bootstrap_digest,
            &value.target_digest,
        ] {
            let digest = trust::hex32(value)?;
            ensure!(
                digest != [0; 32] && hex::encode(digest) == *value,
                "authority connector binding has an invalid digest"
            );
        }
        Ok(value)
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self)?;
        Self::parse(&bytes)?;
        Ok(bytes)
    }
    fn new(route: &crate::route_profile::Profile, bootstrap: &trust::Verified) -> Result<Self> {
        let mut public = route.clone();
        public.voucher.clear();
        let value = Self {
            format: "HyperNetAuthorityConnector/1".into(),
            network: hex::encode(route.network),
            incarnation: hex::encode(route.incarnation),
            bootstrap_digest: hex::encode(bootstrap.file_digest()),
            target_digest: hex::encode(wire::digest(&serde_json::to_vec(&public)?)),
        };
        value.encode()?;
        Ok(value)
    }
}
#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    running: bool,
    active: bool,
    completed: u64,
    connections: u64,
    reused_exchanges: u64,
    refused: u64,
    voucher_expires_ms: u64,
    last_error: Option<String>,
}
struct Job {
    stream: UnixStream,
    deadline: u64,
}
fn ready(stream: &UnixStream, events: i16, deadline: u64) -> Result<()> {
    loop {
        transport::check_cancelled()?;
        let now = boot_time_ms()?;
        ensure!(
            now < deadline,
            "authority connector's original exchange deadline expired"
        );
        let mut poll = libc::pollfd {
            fd: stream.as_raw_fd(),
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut poll, 1, (deadline - now).min(100) as i32) };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        } else if result > 0 {
            return Ok(());
        }
    }
}
fn read(stream: &mut UnixStream, mut bytes: &mut [u8], deadline: u64) -> Result<()> {
    while !bytes.is_empty() {
        ready(stream, libc::POLLIN, deadline)?;
        match stream.read(bytes) {
            Ok(0) => anyhow::bail!("authority caller closed its request"),
            Ok(n) => bytes = &mut bytes[n..],
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn write(stream: &mut UnixStream, mut bytes: &[u8], deadline: u64) -> Result<()> {
    while !bytes.is_empty() {
        ready(stream, libc::POLLOUT, deadline)?;
        match stream.write(bytes) {
            Ok(0) => anyhow::bail!("authority caller closed its reply"),
            Ok(n) => bytes = &bytes[n..],
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn endpoint(path: &Path, binding: &Binding, bootstrap: &trust::Verified) -> Result<Endpoint> {
    let endpoint = Endpoint::load(path)?;
    let scope = bootstrap.descriptor().scope();
    ensure!(
        endpoint.route.protocol == 1
            && endpoint.route.network == scope.network
            && endpoint.route.incarnation == scope.incarnation
            && Binding::new(&endpoint.route, bootstrap)? == *binding,
        "retained authority route changed its pinned network or public target"
    );
    Ok(endpoint)
}
fn actor(
    receiver: mpsc::Receiver<Job>,
    selected: PathBuf,
    clock: PathBuf,
    binding: Binding,
    bootstrap: trust::Verified,
    status: Arc<Mutex<Status>>,
) {
    let current: Mutex<Option<UnixStream>> = Mutex::new(None);
    let cancelled = || {
        transport::cancelled()
            || current.lock().map_or(true, |caller| {
                caller
                    .as_ref()
                    .is_some_and(|stream| ipc::disconnected(stream).unwrap_or(true))
            })
    };
    let mut session = None;
    let mut retained = None;
    while let Ok(mut job) = receiver.recv() {
        if transport::cancelled() {
            break;
        }
        if let Ok(mut state) = status.lock() {
            state.active = true;
        }
        let result = (|| -> Result<()> {
            job.stream.set_nonblocking(true)?;
            *current
                .lock()
                .map_err(|_| anyhow::anyhow!("authority caller lock failed"))? =
                Some(job.stream.try_clone()?);
            let initial = job.deadline.min(boot_time_ms()?.saturating_add(5000));
            let mut size = [0; 4];
            read(&mut job.stream, &mut size, initial)?;
            let length = u32::from_be_bytes(size) as usize;
            ensure!(
                (1..=wire::MAXIMUM).contains(&length),
                "authority connector request exceeds its bound"
            );
            let mut request = vec![0; length];
            read(&mut job.stream, &mut request, initial)?;
            let route = endpoint(&selected, &binding, &bootstrap)?;
            packet::validate(route.route.network, route.route.incarnation, &request)?;
            let now = crate::authority_clock::health(&clock)?.observe()?.wall_ms;
            let record = Record::parse(
                &route.route.voucher,
                route.route.network,
                route.route.incarnation,
            )?;
            let voucher = Voucher::parse(&record.payload)?;
            if let Ok(mut state) = status.lock() {
                state.voucher_expires_ms = voucher.expires;
            }
            ensure!(
                now < voucher.expires,
                "authority route voucher expired; retain an explicitly renewed same-target route through an independently valid authority route"
            );
            let remaining = job.deadline.saturating_sub(boot_time_ms()?);
            let reusable = retained.as_ref() == Some(&route.route)
                && session.as_ref().is_some_and(|s: &Session<'_>| {
                    s.reusable_exchange(
                        remaining,
                        route_connector::exchange_reservation(request.len(), 4 * wire::MAXIMUM)
                            .unwrap_or(u64::MAX),
                    )
                });
            if !reusable {
                session = None;
                let possession = crate::networks::route_key(&route.profile, &route.route)?;
                let lifetime = boot_time_ms()?
                    .checked_add(route.route.limits.duration_ms)
                    .context("authority session lifetime overflow")?;
                session = Some(Session::connect_with_deadlines(
                    &route.route,
                    &possession,
                    lifetime,
                    job.deadline,
                    &cancelled,
                )?);
                retained = Some(route.route.clone());
                if let Ok(mut state) = status.lock() {
                    state.connections = state.connections.saturating_add(1);
                }
            } else if let Ok(mut state) = status.lock() {
                state.reused_exchanges = state.reused_exchanges.saturating_add(1);
            }
            let reply = session
                .as_mut()
                .context("authority route session absent")?
                .exchange(&request, job.deadline, 4 * wire::MAXIMUM)?;
            write(
                &mut job.stream,
                &(reply.len() as u32).to_be_bytes(),
                job.deadline,
            )?;
            write(&mut job.stream, &reply, job.deadline)?;
            Ok(())
        })();
        if let Ok(mut caller) = current.lock() {
            *caller = None;
        }
        if let Ok(mut state) = status.lock() {
            state.active = false;
            match result {
                Ok(()) => {
                    state.completed = state.completed.saturating_add(1);
                    state.last_error = None;
                }
                Err(error) => {
                    session = None;
                    retained = None;
                    state.refused = state.refused.saturating_add(1);
                    state.last_error = Some(format!("{error:#}").chars().take(512).collect());
                }
            }
        }
    }
}
pub fn status(directory: &Path) -> Result<()> {
    ipc::private(directory, false)?;
    let value: serde_json::Value = serde_json::from_slice(&files::read_single(
        &directory.join("Status.json"),
        16384,
        true,
    )?)?;
    crate::print_value(&value)
}
pub fn run(arguments: Arguments) -> Result<()> {
    let root = ipc::private(&arguments.ipc_directory, true)?;
    let _lock = files::profile_lock(&root, std::ffi::OsStr::new("Connector.lock"))?;
    let (profile, bootstrap) = load(&arguments.profile)?;
    let joined = profile
        .joined
        .as_ref()
        .filter(|v| v.admitted)
        .context("authority connector requires a joined network profile")?;
    let _requester = crate::authority_floor::Store::open(
        &joined.directory.join("Requester"),
        bootstrap.descriptor().clone(),
    )?;
    let _selection = Selection::new(&arguments.profile)?;
    let selected = joined.directory.join("AuthorityRoute.json");
    let first = Endpoint::load(&selected)?;
    ensure!(
        first.route.protocol == 1,
        "authority connector requires the retained authority protocol"
    );
    let binding = Binding::new(&first.route, &bootstrap)?;
    endpoint(&selected, &binding, &bootstrap)?;
    let record = Record::parse(
        &first.route.voucher,
        first.route.network,
        first.route.incarnation,
    )?;
    let expires = Voucher::parse(&record.payload)?.expires;
    let now = crate::authority_clock::health(&joined.clock_witness)?
        .observe()?
        .wall_ms;
    ensure!(
        now < expires,
        "authority route voucher expired; retain an explicitly renewed route before starting"
    );
    let mut ingress = Ingress::start_binding(
        &arguments.ipc_directory.join("Ingress"),
        &binding.encode()?,
        "authority",
    )?;
    let state = Arc::new(Mutex::new(Status {
        running: true,
        voucher_expires_ms: expires,
        ..Status::default()
    }));
    let (sender, receiver) = mpsc::sync_channel(16);
    let clock = joined.clock_witness.clone();
    let actor_state = state.clone();
    let actor_binding = binding.clone();
    let worker = thread::spawn(move || {
        actor(
            receiver,
            selected,
            clock,
            actor_binding,
            bootstrap,
            actor_state,
        )
    });
    let save = || -> Result<()> {
        let state = state
            .lock()
            .map_err(|_| anyhow::anyhow!("authority connector status lock failed"))?;
        files::atomic_at(
            &root,
            std::ffi::OsStr::new("Status.json"),
            &serde_json::to_vec(
                &json!({"format":"HyperNetAuthorityConnectorStatus/1","binding":binding,
                "status":*state,"maximumQueuedConnections":16,"maximumDurationMs":DURATION_MS,
                "sampleBootMs":boot_time_ms()?}),
            )?,
            true,
        )
    };
    let outcome = (|| -> Result<()> {
        save()?;
        crate::print_value(
            &json!({"status":"AuthorityConnectorReady","binding":binding,
            "directory":arguments.ipc_directory.join("Ingress"),"voucherExpiresMs":expires,"directFallback":false}),
        )?;
        let mut last = Instant::now();
        while !transport::cancelled() {
            ensure!(!worker.is_finished(), "authority connector actor stopped");
            if let Some(stream) = ingress.accept()? {
                let job = Job {
                    stream,
                    deadline: boot_time_ms()?.saturating_add(DURATION_MS),
                };
                if sender.try_send(job).is_err()
                    && let Ok(mut state) = state.lock()
                {
                    state.refused = state.refused.saturating_add(1);
                }
            }
            if last.elapsed() >= Duration::from_secs(1) {
                save()?;
                last = Instant::now();
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    })();
    transport::request_cancel();
    drop(sender);
    drop(ingress);
    let joined = worker
        .join()
        .map_err(|_| anyhow::anyhow!("authority connector actor failed"));
    if let Ok(mut state) = state.lock() {
        state.running = false;
        state.active = false;
    }
    let saved = save();
    outcome?;
    joined?;
    saved
}

#[cfg(test)]
#[path = "../../Tests/Unit/Networks/NetworkAuthorityConnectorUnitTests.rs"]
mod tests;
