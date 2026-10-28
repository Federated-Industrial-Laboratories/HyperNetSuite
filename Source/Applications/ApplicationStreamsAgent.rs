// SPDX-License-Identifier: MIT
// One protected companion owns bounded local streams and a serial authority requester.
use super::*;
use client::{Client, Plan, Target};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io::ErrorKind,
    os::unix::net::UnixStream,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender},
    },
    thread,
    time::{Duration, Instant},
};
#[derive(Args)]
pub struct Arguments {
    #[command(flatten)]
    online: Online,
    #[arg(long)]
    ipc_directory: PathBuf,
    /// Private JSON array of named targets; at most16 services.
    #[arg(long)]
    targets: Option<PathBuf>,
    /// Exact accepted service artifact; omit for an outgoing-only companion.
    #[arg(long)]
    binding: Option<PathBuf>,
    /// Local is only for a companion already running under the Core-compatible mapped UID.
    #[arg(long, default_value = "mapped", value_parser = ["mapped", "local"])]
    ingress_mode: String,
}
struct Active {
    info: ipc::ActiveInfo,
    cancel: Arc<AtomicBool>,
}
struct State {
    active: BTreeMap<String, Active>,
    errors: VecDeque<Value>,
    controls: usize,
}
struct Guard {
    state: Arc<Mutex<State>>,
    id: String,
}
impl Drop for Guard {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock()
            && let Some(active) = state.active.remove(&self.id)
        {
            active.cancel.store(true, Ordering::Relaxed);
        }
    }
}
fn reserve(
    state: &Arc<Mutex<State>>,
    direction: &str,
    service: String,
) -> Result<(Guard, Arc<AtomicBool>)> {
    let mut locked = state
        .lock()
        .map_err(|_| anyhow::anyhow!("agent connection state failed"))?;
    ensure!(
        locked.active.len() < 16,
        "application connection capacity exhausted"
    );
    let id = hex::encode(crate::route_protocol::random()?);
    let cancel = Arc::new(AtomicBool::new(false));
    locked.active.insert(
        id.clone(),
        Active {
            info: ipc::ActiveInfo {
                id: id.clone(),
                direction: direction.into(),
                service,
                peer: Value::Null,
            },
            cancel: cancel.clone(),
        },
    );
    Ok((
        Guard {
            state: state.clone(),
            id,
        },
        cancel,
    ))
}
fn error(state: &Arc<Mutex<State>>, id: Option<&str>, message: &str) {
    if let Ok(mut s) = state.lock() {
        if s.errors.len() == 8 {
            s.errors.pop_front();
        }
        let mut end = message.len().min(256);
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        s.errors.push_back(json!({
            "id":id,
            "bootMs":crate::authority_challenge::boot_time_ms().ok(),
            "message":&message[..end]
        }));
    }
}
fn annotate(guard: &Guard, peer: Value) -> Result<()> {
    let mut state = guard
        .state
        .lock()
        .map_err(|_| anyhow::anyhow!("agent connection state failed"))?;
    state
        .active
        .get_mut(&guard.id)
        .context("connection reservation disappeared")?
        .info
        .peer = peer;
    Ok(())
}
enum Job {
    Plan(
        Target,
        crate::authority_inspection::read_client::RetryBudget,
        SyncSender<Result<Plan>>,
    ),
    Done(Box<streams::Proof>),
}
fn actor(
    mut client: Client,
    targets: Vec<Target>,
    receiver: Receiver<Job>,
    ready: SyncSender<Result<()>>,
) {
    let initial = client.resume_agent(&targets);
    let success = initial.is_ok();
    let _ = ready.send(initial);
    if !success {
        return;
    }
    let mut slots = BTreeSet::new();
    while let Ok(job) = receiver.recv() {
        match job {
            Job::Plan(target, budget, reply) => {
                let result = if crate::private_route_client::cancelled() {
                    Err(anyhow::anyhow!("application agent is stopping"))
                } else {
                    client.plan(&target, &slots, budget, &targets)
                };
                if let Ok(plan) = &result {
                    slots.insert((plan.proof.service.id, plan.proof.slot));
                }
                if let Err(mpsc::SendError(Ok(plan))) = reply.send(result) {
                    slots.remove(&(plan.proof.service.id, plan.proof.slot));
                }
            }
            Job::Done(proof) => {
                if !crate::private_route_client::cancelled() {
                    let _ = client
                        .resume_agent(&targets)
                        .and_then(|()| client.close(&proof));
                }
                slots.remove(&(proof.service.id, proof.slot));
            }
        }
    }
}
struct Incoming {
    stream: UnixStream,
    context: Value,
    bytes: u64,
    duration: Duration,
    idle: Duration,
    guard: Guard,
    cancel: Arc<AtomicBool>,
    queued: Instant,
    ready: Receiver<Result<()>>,
}
#[derive(Clone)]
struct Runtime {
    state: Arc<Mutex<State>>,
    jobs: SyncSender<Job>,
    incoming: Arc<Mutex<Receiver<Incoming>>>,
    targets: Arc<Vec<Target>>,
    binding: Option<streams::local::Binding>,
    clock: Arc<crate::authority_clock::Source>,
    started: Instant,
    profile: Value,
}
fn request(mut stream: UnixStream, runtime: Runtime, handed_off: &AtomicBool) -> Result<()> {
    ipc::peer(&stream)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let parsed: ipc::Request = serde_json::from_slice(&ipc::read_frame(&mut stream)?)?;
    ensure!(
        parsed.version == 1,
        "unsupported application agent IPC version"
    );
    let timeout = Duration::from_millis(parsed.timeout_ms.unwrap_or(30000));
    ensure!(
        (100..=60000).contains(&(timeout.as_millis() as u64)),
        "local IPC timeout must be100..60000 milliseconds"
    );
    match parsed.action.as_str() {
        "status" => {
            let state = runtime
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("agent connection state failed"))?;
            ipc::write_json(
                &mut stream,
                &json!({"version":1,"ok":true,"status":"Ready","network":runtime.profile["network"],"incarnation":runtime.profile["incarnation"],"principal":runtime.profile["principal"],"binding":runtime.profile["binding"],"uptimeMs":runtime.started.elapsed().as_millis(),"incoming":runtime.binding.is_some(),"targets":runtime.targets.iter().map(|t|json!({"service":t.service,"protocol":t.protocol})).collect::<Vec<_>>(),"connections":state.active.values().map(|a|json!({"id":a.info.id,"direction":a.info.direction,"service":a.info.service,"peer":{"principal":a.info.peer["principal"],"owner":a.info.peer["owner"],"endpoint":a.info.peer["endpoint"]}})).collect::<Vec<_>>(),"recentErrors":state.errors}),
            )
        }
        "cancel" => {
            let id = parsed
                .id
                .context("cancel requires exact local connection ID")?;
            let state = runtime
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("agent connection state failed"))?;
            let active = state
                .active
                .get(&id)
                .context("local connection is absent or already complete")?;
            active.cancel.store(true, Ordering::Relaxed);
            ipc::write_json(
                &mut stream,
                &json!({"version":1,"ok":true,"id":id,"status":"Cancelling"}),
            )
        }
        "connect" => {
            let service = parsed.service.context("connect requires named service")?;
            let target = runtime
                .targets
                .iter()
                .find(|t| t.service == service)
                .context("service is not an approved local target")?
                .clone();
            ensure!(
                parsed
                    .protocol
                    .as_ref()
                    .is_none_or(|p| *p == target.protocol),
                "requested protocol differs from approved target"
            );
            let (guard, cancel) = reserve(&runtime.state, "outgoing", service.clone())?;
            let (reply, receive) = mpsc::sync_channel(1);
            let preparation_deadline = crate::authority_challenge::boot_time_ms()?
                .checked_add(timeout.as_millis() as u64)
                .context("application preparation deadline overflow")?;
            let preparation_caller = stream.try_clone()?;
            let preparation_cancel = cancel.clone();
            let budget = crate::authority_inspection::read_client::RetryBudget::new(
                preparation_deadline,
                move || {
                    preparation_cancel.load(Ordering::Relaxed)
                        || ipc::disconnected(&preparation_caller).unwrap_or(true)
                },
            );
            runtime
                .jobs
                .try_send(Job::Plan(target, budget, reply))
                .map_err(|_| anyhow::anyhow!("authority request queue is full"))?;
            let mut plan = receive
                .recv_timeout(timeout)
                .context("authority connection preparation timed out")??;
            let outcome = (|| -> Result<()> {
                let caller = stream.try_clone()?;
                let cancelled = || {
                    cancel.load(Ordering::Relaxed)
                        || crate::private_route_client::cancelled()
                        || !handed_off.load(Ordering::Relaxed)
                            && ipc::disconnected(&caller).unwrap_or(true)
                };
                let possession =
                    crate::networks::route_key(&plan.endpoint.profile, &plan.endpoint.route)?;
                let deadline = crate::authority_challenge::boot_time_ms()?
                    .checked_add(plan.proof.limits.duration_ms)
                    .context("stream deadline overflow")?;
                let mut session = crate::route_connector::Session::connect(
                    &plan.endpoint.route,
                    &possession,
                    deadline,
                    &cancelled,
                )?;
                let admitted = session.authenticate_application(
                    plan.endpoint.route.network,
                    plan.endpoint.route.incarnation,
                    &mut plan.proof,
                    plan.binding,
                    &plan.key,
                )?;
                let peer = json!({"network":hex::encode(plan.endpoint.route.network),"incarnation":hex::encode(plan.endpoint.route.incarnation),"service":service,"protocol":plan.proof.protocol,"owner":hex::encode(plan.owner),"endpoint":hex::encode(plan.endpoint_key),"route":hex::encode(plan.endpoint.route.destination.service),"session":hex::encode(admitted.id),"generation":admitted.generation,"expiresMs":plan.proof.expires,"maximumBytes":plan.proof.limits.bytes,"durationMs":plan.proof.limits.duration_ms,"idleMs":plan.proof.limits.idle_ms});
                annotate(&guard, peer.clone())?;
                handed_off.store(true, Ordering::Relaxed);
                ipc::write_json(
                    &mut stream,
                    &json!({"version":1,"ok":true,"id":guard.id,"peer":peer}),
                )?;
                session.forward_application(stream.try_clone()?, plan.proof.limits.bytes)
            })();
            if let Err(e) = &outcome {
                error(&runtime.state, Some(&guard.id), &format!("{e:#}"));
            }
            let _ = runtime.jobs.send(Job::Done(Box::new(plan.proof)));
            outcome
        }
        "accept" => {
            ensure!(
                runtime.binding.is_some(),
                "companion has no accepted incoming service binding"
            );
            let deadline = Instant::now() + timeout;
            loop {
                ensure!(
                    !crate::private_route_client::cancelled(),
                    "application agent is stopping"
                );
                ensure!(
                    !ipc::disconnected(&stream)?,
                    "local accept was cancelled by its caller"
                );
                if Instant::now() >= deadline {
                    ipc::failure(
                        &mut stream,
                        "Timeout",
                        "no incoming stream arrived before the local deadline",
                    );
                    return Ok(());
                }
                let incoming = runtime
                    .incoming
                    .lock()
                    .map_err(|_| anyhow::anyhow!("incoming queue failed"))?
                    .recv_timeout(Duration::from_millis(100));
                match incoming {
                    Ok(incoming) => {
                        if incoming.cancel.load(Ordering::Relaxed)
                            || incoming.queued.elapsed() >= incoming.duration
                        {
                            continue;
                        }
                        incoming
                            .ready
                            .recv_timeout(Duration::from_secs(5))
                            .context("local endpoint acceptance acknowledgement failed")??;
                        let duration = incoming.duration.saturating_sub(incoming.queued.elapsed());
                        handed_off.store(true, Ordering::Relaxed);
                        ipc::write_json(
                            &mut stream,
                            &json!({"version":1,"ok":true,"id":incoming.guard.id,"peer":incoming.context}),
                        )?;
                        let result = ipc::pump(
                            stream,
                            incoming.stream,
                            incoming.bytes,
                            duration,
                            incoming.idle,
                            incoming.cancel,
                        );
                        if let Err(e) = &result {
                            error(&runtime.state, Some(&incoming.guard.id), &format!("{e:#}"));
                        }
                        return result;
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => {
                        anyhow::bail!("incoming service stopped")
                    }
                }
            }
        }
        _ => anyhow::bail!("unsupported application agent action"),
    }
}
fn inbound(
    mut stream: UnixStream,
    runtime: Runtime,
    queue: SyncSender<Incoming>,
    guard: Guard,
    cancel: Arc<AtomicBool>,
) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let binding = runtime
        .binding
        .as_ref()
        .context("incoming service binding is absent")?;
    let nonce = crate::route_protocol::random()?;
    ipc::write_frame(&mut stream, &streams::local::local_challenge(nonce)?)?;
    let context = streams::local::verify_context(&ipc::read_frame(&mut stream)?, binding, nonce)?;
    let now = runtime.clock.health()?.observe()?.wall_ms;
    ensure!(
        context.expires_ms > now.saturating_add(1250),
        "incoming stream is expired or too close to expiry"
    );
    let mut value = serde_json::to_value(&context)?;
    value["owner"] = json!(hex::encode(binding.owner));
    value["endpoint"] = json!(hex::encode(binding.endpoint));
    annotate(&guard, value.clone())?;
    let duration = Duration::from_millis(context.duration_ms.min(context.expires_ms - now));
    let idle = Duration::from_millis(context.idle_ms);
    let (acknowledge, ready) = mpsc::sync_channel(1);
    queue
        .try_send(Incoming {
            stream: stream.try_clone()?,
            context: value,
            bytes: context.maximum_bytes,
            duration,
            idle,
            guard,
            cancel,
            queued: Instant::now(),
            ready,
        })
        .map_err(|_| anyhow::anyhow!("incoming connection queue is full"))?;
    let result = ipc::write_frame(&mut stream, &streams::local::local_challenge(nonce)?);
    let success = result.is_ok();
    let _ = acknowledge.send(result);
    ensure!(success, "local endpoint acceptance acknowledgement failed");
    Ok(())
}
fn targets(path: Option<&Path>, root: &Path) -> Result<Vec<Target>> {
    let Some(path) = path else {
        return Ok(vec![]);
    };
    let mut targets: Vec<Target> = serde_json::from_slice(&files::read_single(path, 65536, true)?)?;
    ensure!(targets.len() <= 16, "at most16 named targets are supported");
    let mut ids = BTreeSet::new();
    let routes = root.join("Routes");
    let directory = ipc::private(&routes, true)?;
    for target in &mut targets {
        let service = id(&target.service)?;
        ensure!(
            ids.insert(service)
                && !target.protocol.is_empty()
                && target.protocol.len() <= 96
                && target.renewal_ms <= 3600000,
            "target is duplicate or has invalid limits"
        );
        let source = crate::private_route_client::Endpoint::load(&target.route)?;
        let destination = routes.join(format!("{}.json", hex::encode(service)));
        let selected = if destination.try_exists()? {
            let current = crate::private_route_client::Endpoint::load(&destination)?;
            let mut a = current.route.clone();
            let mut b = source.route.clone();
            a.voucher.clear();
            b.voucher.clear();
            ensure!(
                current.profile == source.profile && a == b,
                "retained target route differs; explicitly reconfigure the stopped companion"
            );
            let old = domain::Record::parse(&current.route.voucher, a.network, a.incarnation)?;
            let new = domain::Record::parse(&source.route.voucher, b.network, b.incarnation)?;
            ensure!(
                old.reference.id == new.reference.id,
                "target voucher identity changed"
            );
            if old.reference.generation >= new.reference.generation {
                if old.reference.generation == new.reference.generation {
                    ensure!(
                        old.reference == new.reference,
                        "target voucher generation equivocated"
                    );
                }
                current
            } else {
                source
            }
        } else {
            source
        };
        files::atomic_at(
            &directory,
            destination.file_name().unwrap(),
            &serde_json::to_vec(&selected)?,
            true,
        )?;
        target.route = destination;
    }
    Ok(targets)
}
pub fn run(a: Arguments) -> Result<()> {
    let root = ipc::private(&a.ipc_directory, true)?;
    let _lock = files::profile_lock(&root, std::ffi::OsStr::new("Agent.lock"))?;
    let c = Client::new(&a.online)?;
    let clock = Arc::new(control::clock(
        &a.online.location,
        c.store.descriptor().voters(),
    )?);
    let binding = if let Some(path) = &a.binding {
        Some(
            offer::Artifact::parse(&c.bootstrap, &files::read_single(path, 16384, true)?, true)?
                .binding,
        )
    } else {
        None
    };
    let profile = json!({"network":hex::encode(c.store.descriptor().scope().network),
        "incarnation":hex::encode(c.store.descriptor().scope().incarnation),"principal":hex::encode(c.key.verifying_key().to_bytes()),
        "binding":binding.as_ref().map(|b|json!({"service":hex::encode(b.service),"owner":hex::encode(b.owner),"endpoint":hex::encode(b.endpoint),"protocol":b.protocol}))});
    let targets = targets(a.targets.as_deref(), &a.ipc_directory)?;
    let listener = ipc::Listener::bind(&a.ipc_directory)?;
    let mut mapped_ingress = None;
    let ingress = if let Some(binding) = &binding {
        if a.ingress_mode == "mapped" {
            mapped_ingress = Some(ingress::Ingress::start(
                &a.ipc_directory.join("Ingress"),
                binding,
            )?);
            None
        } else {
            let directory = a.ipc_directory.join("Ingress");
            let handle = ipc::private(&directory, true)?;
            files::atomic_at(
                &handle,
                std::ffi::OsStr::new("Binding.json"),
                &binding.encode()?,
                true,
            )?;
            Some(ipc::Listener::bind(&directory)?)
        }
    } else {
        None
    };
    let (jobs, receiver) = mpsc::sync_channel(16);
    let (ready, started) = mpsc::sync_channel(1);
    let actor_targets = targets.clone();
    let actor = thread::spawn(move || actor(c, actor_targets, receiver, ready));
    started.recv().context("authority actor did not start")??;
    let (incoming, queue) = mpsc::sync_channel(16);
    let state = Arc::new(Mutex::new(State {
        active: BTreeMap::new(),
        errors: VecDeque::new(),
        controls: 0,
    }));
    let runtime = Runtime {
        state: state.clone(),
        jobs,
        incoming: Arc::new(Mutex::new(queue)),
        targets: Arc::new(targets),
        binding,
        clock,
        started: Instant::now(),
        profile,
    };
    crate::private_route_client::install_cancellation()?;
    crate::print_value(
        &json!({"status":"Ready","directory":a.ipc_directory,"incoming":ingress.is_some() || mapped_ingress.is_some(),"targets":runtime.targets.len()}),
    )?;
    let mut workers = Vec::new();
    while !crate::private_route_client::cancelled() {
        match listener.socket.accept() {
            Ok((mut stream, _)) => {
                let allowed = {
                    let mut s = state
                        .lock()
                        .map_err(|_| anyhow::anyhow!("agent connection state failed"))?;
                    if s.controls >= 32 {
                        false
                    } else {
                        s.controls += 1;
                        true
                    }
                };
                if !allowed {
                    ipc::failure(&mut stream, "Capacity", "local control capacity exhausted");
                    continue;
                }
                let r = runtime.clone();
                workers.push(thread::spawn(move || {
                    let response = stream.try_clone();
                    let handed_off = AtomicBool::new(false);
                    let result = request(stream, r.clone(), &handed_off);
                    if let Err(e) = result
                        && !handed_off.load(Ordering::Relaxed)
                    {
                        error(&r.state, None, &format!("local control preparation: {e:#}"));
                        if let Ok(mut response) = response {
                            ipc::failure(&mut response, "Refused", &format!("{e:#}"));
                        }
                    }
                    if let Ok(mut s) = r.state.lock() {
                        s.controls = s.controls.saturating_sub(1);
                    }
                }));
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
        let incoming_stream = if let Some(helper) = &mut mapped_ingress {
            helper.accept()?
        } else if let Some(listener) = &ingress {
            match listener.socket.accept() {
                Ok((stream, _)) => {
                    if ipc::peer(&stream).is_ok() {
                        Some(stream)
                    } else {
                        None
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => None,
                Err(e) => return Err(e.into()),
            }
        } else {
            None
        };
        if let Some(stream) = incoming_stream {
            if workers.len() >= 64 {
                drop(stream);
                continue;
            }
            if let Ok((guard, cancel)) = reserve(
                &state,
                "incoming",
                hex::encode(runtime.binding.as_ref().unwrap().service),
            ) {
                let r = runtime.clone();
                let sender = incoming.clone();
                workers.push(thread::spawn(move || {
                    if let Err(e) = inbound(stream, r.clone(), sender, guard, cancel) {
                        error(&r.state, None, &format!("{e:#}"));
                    }
                }));
            }
        }
        if let Ok(queue) = runtime.incoming.try_lock() {
            let mut retained = Vec::new();
            while let Ok(item) = queue.try_recv() {
                if !item.cancel.load(Ordering::Relaxed)
                    && item.queued.elapsed()
                        < item.duration.min(item.idle).min(Duration::from_secs(30))
                {
                    retained.push(item);
                }
            }
            for item in retained {
                let _ = incoming.try_send(item);
            }
        }
        let mut index = 0;
        while index < workers.len() {
            if workers[index].is_finished() {
                let worker = workers.swap_remove(index);
                let _ = worker.join();
            } else {
                index += 1;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    if let Ok(s) = state.lock() {
        for active in s.active.values() {
            active.cancel.store(true, Ordering::Relaxed);
        }
    }
    for worker in workers {
        let _ = worker.join();
    }
    if let Ok(queue) = runtime.incoming.lock() {
        while let Ok(item) = queue.try_recv() {
            drop(item);
        }
    }
    drop(runtime);
    drop(incoming);
    let _ = actor.join();
    Ok(())
}
