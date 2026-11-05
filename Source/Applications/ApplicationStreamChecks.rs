// SPDX-License-Identifier: MIT
// One endpoint-authenticated control channel checks the companion's original incoming sessions.
use crate::{
    authority_challenge::boot_time_ms,
    authority_clock::Source,
    authority_domains::streams::{control as contract, local::Binding},
    authority_proof::VersionRef,
    local_stream_ipc as ipc,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    io::{ErrorKind, Read, Write},
    os::fd::AsRawFd,
    os::unix::net::UnixStream,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender},
    },
    time::Duration,
};

struct Work {
    request: contract::Request,
    cancel: Arc<AtomicBool>,
    connection_cancel: Arc<AtomicBool>,
    reply: SyncSender<contract::Receipt>,
    _pending: Arc<Pending>,
}
#[derive(Clone)]
struct Session {
    ready: contract::Ready,
    jobs: SyncSender<Work>,
    alive: Arc<AtomicBool>,
}
struct State {
    generation: u64,
    attached: bool,
    session: Option<Session>,
    pending: BTreeSet<String>,
}
pub(super) struct Checks {
    binding: Binding,
    clock: Arc<Source>,
    instance: [u8; 32],
    state: Arc<Mutex<State>>,
}
struct Attached<'a> {
    checks: &'a Checks,
    generation: u64,
}
impl Drop for Attached<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.checks.state.lock()
            && state.generation == self.generation
        {
            if let Some(session) = state.session.take() {
                session.alive.store(false, Ordering::Release);
            }
            state.attached = false;
        }
    }
}
struct Pending {
    state: Arc<Mutex<State>>,
    id: String,
}
impl Drop for Pending {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.pending.remove(&self.id);
        }
    }
}
struct CancelOnDrop(Arc<AtomicBool>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
impl Checks {
    pub fn new(binding: Binding, clock: Arc<Source>) -> Result<Self> {
        Ok(Self {
            binding,
            clock,
            instance: crate::route_protocol::random()?,
            state: Arc::new(Mutex::new(State {
                generation: 0,
                attached: false,
                session: None,
                pending: BTreeSet::new(),
            })),
        })
    }
    pub fn status(&self) -> Value {
        let ready = self
            .state
            .lock()
            .ok()
            .and_then(|s| s.session.clone())
            .filter(|s| s.alive.load(Ordering::Acquire));
        json!({"supported":true,"capability":contract::CAPABILITY,"endpointReady":ready.is_some(),"companionInstance":hex::encode(self.instance),"endpointInstance":ready.as_ref().map(|s|hex::encode(s.ready.endpoint_instance)),"controlGeneration":ready.as_ref().map(|s|s.ready.challenge.control_generation)})
    }
    pub fn ready(&self) -> bool {
        self.status()["endpointReady"] == true
    }
    pub fn stop(&self) {
        if let Ok(s) = self.state.lock()
            && let Some(session) = &s.session
        {
            session.alive.store(false, Ordering::Release);
        }
    }
    pub fn serve(&self, mut stream: UnixStream) -> Result<()> {
        let generation = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("check channel state failed"))?;
            ensure!(
                !state.attached,
                "an application check endpoint is already attached"
            );
            state.generation = state
                .generation
                .checked_add(1)
                .context("control generation exhausted")?;
            state.attached = true;
            state.generation
        };
        let _attached = Attached {
            checks: self,
            generation,
        };
        let challenge = contract::Challenge {
            binding_digest: self.binding.digest()?,
            companion_instance: self.instance,
            nonce: crate::route_protocol::random()?,
            kernel_boot: self.clock.verified_boot()?,
            control_generation: generation,
        };
        let deadline = boot_time_ms()?
            .checked_add(5000)
            .context("check deadline overflow")?;
        let stopping = || crate::private_route_client::cancelled();
        write_bounded(
            &mut stream,
            &contract::encode(&challenge)?,
            deadline,
            &stopping,
        )?;
        let ready: contract::Ready = contract::verify(
            &read_bounded(&mut stream, deadline, &stopping)?,
            &self.binding,
        )?;
        ensure!(
            ready.challenge == challenge && self.clock.verified_boot()? == challenge.kernel_boot,
            "check endpoint belongs to another host boot or challenge"
        );
        let (jobs, receiver) = mpsc::sync_channel(contract::MAXIMUM_PENDING);
        let session = Session {
            ready,
            jobs,
            alive: Arc::new(AtomicBool::new(true)),
        };
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("check channel state failed"))?
            .session = Some(session.clone());
        let result = self.exchange(&mut stream, &session, receiver);
        session.alive.store(false, Ordering::Release);
        result
    }
    fn exchange(
        &self,
        stream: &mut UnixStream,
        session: &Session,
        receiver: Receiver<Work>,
    ) -> Result<()> {
        stream.set_nonblocking(true)?;
        let mut pending: Vec<Flight> = Vec::with_capacity(contract::MAXIMUM_PENDING);
        let mut input = FrameInput::default();
        while session.alive.load(Ordering::Acquire) && !crate::private_route_client::cancelled() {
            let now = boot_time_ms()?;
            if let Some(stale) = pending.iter().find(|flight| {
                flight.cancelled() || now >= flight.work.request.caller_deadline_boot_ms
            }) {
                // Keep the existing fail-closed generation boundary. A partial
                // request frame cannot be followed by another record safely.
                if now < stale.work.request.caller_deadline_boot_ms
                    && pending.iter().all(Flight::sent)
                {
                    let cancel = contract::Cancel {
                        request: stale.work.request.clone(),
                    };
                    let _ = stream.write(&frame(&contract::encode(&cancel)?)?);
                }
                anyhow::bail!(
                    "application check cancelled or expired; control generation discarded"
                );
            }
            while pending.len() < contract::MAXIMUM_PENDING {
                let work = match receiver.try_recv() {
                    Ok(work) => work,
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(error) => return Err(error.into()),
                };
                if work.cancel.load(Ordering::Acquire)
                    || work.connection_cancel.load(Ordering::Acquire)
                    || boot_time_ms()? >= work.request.caller_deadline_boot_ms
                {
                    continue;
                }
                ensure!(
                    self.clock.verified_boot()? == session.ready.challenge.kernel_boot,
                    "check clock boot changed"
                );
                let bytes = frame(&contract::encode(&work.request)?)?;
                pending.push(Flight {
                    work,
                    bytes,
                    written: 0,
                });
            }
            for flight in &mut pending {
                if flight.sent() {
                    continue;
                }
                if flight.cancelled()
                    || boot_time_ms()? >= flight.work.request.caller_deadline_boot_ms
                {
                    break;
                }
                match stream.write(&flight.bytes[flight.written..]) {
                    Ok(0) => anyhow::bail!("application check channel closed"),
                    Ok(count) => flight.written += count,
                    Err(error) if retry_io(&error) => break,
                    Err(error) => return Err(error.into()),
                }
                if !flight.sent() {
                    break;
                }
            }
            if let Some(bytes) = input.read(stream)? {
                let receipt: contract::Receipt = contract::verify(&bytes, &self.binding)?;
                let index = pending
                    .iter()
                    .position(|flight| flight.sent() && receipt.request == flight.work.request)
                    .context("check receipt correlation differs")?;
                ensure!(
                    self.clock.verified_boot()? == session.ready.challenge.kernel_boot,
                    "check receipt clock boot changed"
                );
                let flight = pending.remove(index);
                if session.alive.load(Ordering::Acquire)
                    && !flight.cancelled()
                    && boot_time_ms()? < flight.work.request.caller_deadline_boot_ms
                {
                    let reply = flight.into_reply();
                    let _ = reply.try_send(receipt);
                }
            }
            wait_io(
                stream,
                pending.iter().any(|flight| !flight.sent()),
                pending
                    .iter()
                    .map(|flight| flight.work.request.caller_deadline_boot_ms)
                    .min(),
            )?;
        }
        Ok(())
    }
    pub fn check(
        &self,
        input: &Input<'_>,
        session_ref: VersionRef,
        connection_cancel: Arc<AtomicBool>,
        caller: &UnixStream,
    ) -> Result<Value> {
        let cancel = Arc::new(AtomicBool::new(false));
        let session = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("check channel state failed"))?;
            if state.pending.contains(input.id) || state.pending.len() >= contract::MAXIMUM_PENDING
            {
                return Ok(input.result("unavailable"));
            }
            let Some(session) = state
                .session
                .clone()
                .filter(|s| s.alive.load(Ordering::Acquire))
            else {
                return Ok(input.result("unavailable"));
            };
            state.pending.insert(input.id.into());
            session
        };
        let pending = Arc::new(Pending {
            state: self.state.clone(),
            id: input.id.into(),
        });
        let _cancel = CancelOnDrop(cancel.clone());
        if self.clock.verified_boot().ok().as_deref() != Some(&session.ready.challenge.kernel_boot)
        {
            return Ok(input.result("unavailable"));
        }
        let request = contract::Request {
            binding_digest: self.binding.digest()?,
            companion_instance: self.instance,
            endpoint_instance: session.ready.endpoint_instance,
            control_generation: session.ready.challenge.control_generation,
            local_connection_id: input.id.into(),
            session: session_ref,
            nonce: input.nonce,
            action_digest: input.action_digest,
            caller_started_boot_ms: input.started,
            caller_deadline_boot_ms: input.deadline,
        };
        request.matches_ready(&session.ready)?;
        let (reply, receiver) = mpsc::sync_channel(1);
        if session
            .jobs
            .try_send(Work {
                request: request.clone(),
                cancel,
                connection_cancel: connection_cancel.clone(),
                reply,
                _pending: pending.clone(),
            })
            .is_err()
        {
            return Ok(input.result("unavailable"));
        }
        let ended = || -> Result<Option<&'static str>> {
            if connection_cancel.load(Ordering::Acquire) || ipc::disconnected(caller)? {
                return Ok(Some("notActive"));
            }
            if boot_time_ms()? >= input.deadline {
                return Ok(Some("expired"));
            }
            if !session.alive.load(Ordering::Acquire) {
                return Ok(Some("unavailable"));
            }
            Ok(None)
        };
        loop {
            if let Some(disposition) = ended()? {
                return Ok(input.result(disposition));
            }
            let received = receiver.recv_timeout(Duration::from_millis(20));
            // A cancelled exchange can drop its reply sender while this caller
            // waits. Classify the original context before any receive outcome.
            if let Some(disposition) = ended()? {
                return Ok(input.result(disposition));
            }
            match received {
                Ok(receipt) => {
                    if receipt.authority.is_some() && boot_time_ms()? >= receipt.not_after_boot_ms {
                        return Ok(input.result("expired"));
                    }
                    let mut result = input.result(match receipt.disposition {
                        contract::Disposition::Permitted => "permitted",
                        contract::Disposition::Denied => "denied",
                        contract::Disposition::Unavailable => "unavailable",
                        contract::Disposition::Expired => "expired",
                        contract::Disposition::NotActive => "notActive",
                    });
                    result["result"]["session"] = json!(hex::encode(request.session.id));
                    result["result"]["generation"] = json!(request.session.generation);
                    result["result"]["companionInstance"] = json!(hex::encode(self.instance));
                    result["result"]["endpointInstance"] =
                        json!(hex::encode(session.ready.endpoint_instance));
                    result["result"]["controlGeneration"] = json!(request.control_generation);
                    result["result"]["kernelBoot"] = json!(session.ready.challenge.kernel_boot);
                    result["result"]["notAfterBootMs"] = json!(receipt.not_after_boot_ms);
                    result["result"]["privacy"] = if receipt.authority.is_some() {
                        incoming_privacy(&receipt.privacy)
                    } else {
                        unknown_incoming()
                    };
                    result["result"]["authority"] =
                        receipt.authority.map_or(Value::Null, authority);
                    return Ok(result);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    return Ok(input.result("unavailable"));
                }
            }
        }
    }
}
struct Flight {
    work: Work,
    bytes: Vec<u8>,
    written: usize,
}
impl Flight {
    fn into_reply(self) -> SyncSender<contract::Receipt> {
        let reply = self.work.reply.clone();
        // Release completed control work before the caller can publish its IPC
        // response and admit another check. The caller still owns its reservation.
        drop(self);
        reply
    }
    fn sent(&self) -> bool {
        self.written == self.bytes.len()
    }
    fn cancelled(&self) -> bool {
        self.work.cancel.load(Ordering::Acquire)
            || self.work.connection_cancel.load(Ordering::Acquire)
            || crate::private_route_client::cancelled()
    }
}
fn frame(bytes: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= contract::MAXIMUM_FRAME,
        "application check frame exceeds its bound"
    );
    let mut frame = Vec::with_capacity(bytes.len() + 4);
    frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    frame.extend_from_slice(bytes);
    Ok(frame)
}
fn retry_io(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
    )
}

#[derive(Default)]
struct FrameInput {
    header: [u8; 4],
    header_used: usize,
    body: Vec<u8>,
    body_used: usize,
}
impl FrameInput {
    // At most two nonblocking reads per turn; fragmented frames cannot hold dispatch.
    fn read(&mut self, stream: &mut UnixStream) -> Result<Option<Vec<u8>>> {
        if self.header_used < self.header.len() {
            match stream.read(&mut self.header[self.header_used..]) {
                Ok(0) => anyhow::bail!("application check channel closed"),
                Ok(count) => self.header_used += count,
                Err(error) if retry_io(&error) => return Ok(None),
                Err(error) => return Err(error.into()),
            }
            if self.header_used != self.header.len() {
                return Ok(None);
            }
            let length = u32::from_be_bytes(self.header) as usize;
            ensure!(
                length > 0 && length <= contract::MAXIMUM_FRAME,
                "application check frame exceeds its bound"
            );
            self.body = vec![0; length];
        }
        match stream.read(&mut self.body[self.body_used..]) {
            Ok(0) => anyhow::bail!("application check channel closed"),
            Ok(count) => self.body_used += count,
            Err(error) if retry_io(&error) => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        if self.body_used != self.body.len() {
            return Ok(None);
        }
        self.header_used = 0;
        self.body_used = 0;
        Ok(Some(std::mem::take(&mut self.body)))
    }
}
fn wait_io(stream: &UnixStream, writable: bool, deadline: Option<u64>) -> Result<()> {
    let mut descriptor = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN | if writable { libc::POLLOUT } else { 0 },
        revents: 0,
    };
    let timeout = match deadline {
        Some(deadline) => deadline.saturating_sub(boot_time_ms()?).min(5) as i32,
        None => 5,
    };
    // The descriptor remains borrowed and the one pollfd is valid for this call.
    if unsafe { libc::poll(&mut descriptor, 1, timeout) } < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
    Ok(())
}
pub(super) struct Input<'a> {
    pub id: &'a str,
    pub nonce: [u8; 32],
    pub action_digest: [u8; 32],
    pub started: u64,
    pub deadline: u64,
}
impl Input<'_> {
    pub fn result(&self, disposition: &str) -> Value {
        json!({"version":2,"ok":true,"id":self.id,"nonce":hex::encode(self.nonce),"actionDigest":hex::encode(self.action_digest),"result":{"disposition":disposition,"callerStartedBootMs":self.started,"callerDeadlineBootMs":self.deadline,"notAfterBootMs":0,"authority":null}})
    }
}
fn authority(a: contract::Authority) -> Value {
    json!({"network":hex::encode(a.network),"incarnation":hex::encode(a.incarnation),"configuration":hex::encode(a.configuration),"epoch":a.epoch,"height":a.height,"state":hex::encode(a.state),"statementDigest":hex::encode(a.statement_digest),"evaluatedAtMs":a.evaluated_at_ms,"expiresAtMs":a.expires_at_ms,"code":a.code})
}
pub(super) fn unknown_incoming() -> Value {
    json!({"direction":"incoming","transport":"HyperNet","transportAuthenticated":true,"endToEndMessageEncryption":"applicationDefined","relayPath":"unknown","provenance":"unavailable","physicalIndependenceVerified":false,"profileCurrentnessAsserted":false})
}
fn incoming_privacy(p: &contract::Privacy) -> Value {
    let mut value = unknown_incoming();
    value["endpointMode"] = json!(p.endpoint_mode);
    value["transportProtection"] = json!(p.transport_protection);
    value["provenance"] = json!("endpointAttestedArrival");
    if let Some(a) = &p.attachment {
        value["relayPath"] = json!("approvedAttachment");
        value["relayService"] = json!(hex::encode(a.relay_service));
        value["attachmentProfileDigest"] = json!(hex::encode(a.profile_digest));
    }
    value
}
fn remaining(deadline: u64, cancelled: &dyn Fn() -> bool) -> Result<Duration> {
    ensure!(!cancelled(), "application check cancelled");
    let ms = deadline
        .checked_sub(boot_time_ms()?)
        .filter(|n| *n > 0)
        .context("application check deadline expired")?;
    Ok(Duration::from_millis(ms.min(50)))
}
fn read_exact_bounded(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline, cancelled)?))?;
        match stream.read(bytes) {
            Ok(0) => anyhow::bail!("application check channel closed"),
            Ok(n) => bytes = &mut bytes[n..],
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn read_bounded(
    stream: &mut UnixStream,
    deadline: u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>> {
    let mut size = [0; 4];
    read_exact_bounded(stream, &mut size, deadline, cancelled)?;
    let size = u32::from_be_bytes(size) as usize;
    ensure!(
        size > 0 && size <= contract::MAXIMUM_FRAME,
        "application check frame exceeds its bound"
    );
    let mut bytes = vec![0; size];
    read_exact_bounded(stream, &mut bytes, deadline, cancelled)?;
    Ok(bytes)
}
fn write_bounded(
    stream: &mut UnixStream,
    bytes: &[u8],
    deadline: u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= contract::MAXIMUM_FRAME,
        "application check frame exceeds its bound"
    );
    let size = (bytes.len() as u32).to_be_bytes();
    for mut part in [size.as_slice(), bytes] {
        while !part.is_empty() {
            stream.set_write_timeout(Some(remaining(deadline, cancelled)?))?;
            match stream.write(part) {
                Ok(0) => anyhow::bail!("application check channel closed"),
                Ok(n) => part = &part[n..],
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
    Ok(())
}
#[cfg(test)]
#[path = "../../Tests/Unit/Applications/ApplicationStreamChecksTests.rs"]
mod tests;
