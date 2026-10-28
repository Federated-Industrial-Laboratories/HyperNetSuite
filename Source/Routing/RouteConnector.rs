// SPDX-License-Identifier: MIT
// A reader creates one fresh nested TLS stream; every socket wait shares its original deadline.
use crate::{
    authority_challenge::boot_time_ms, authority_domains as domains,
    authority_membership::reference, route_profile::Profile, route_protocol as protocol, route_tls,
    trust_wire,
};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use rustls::{ClientConnection, StreamOwned, pki_types::ServerName};
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    os::fd::{AsRawFd, FromRawFd},
};
#[derive(Debug)]
pub(crate) struct OperationDeadlineExpired {
    pub(crate) deadline: u64,
}
impl std::fmt::Display for OperationDeadlineExpired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("private route operation deadline expired")
    }
}
impl std::error::Error for OperationDeadlineExpired {}

#[path = "ApplicationStreamConnector.rs"]
mod application_streams;
struct Socket<'a> {
    opportunistic: bool,
    socket: TcpStream,
    deadline: u64,
    operation_deadline: Option<u64>,
    idle_deadline: u64,
    idle_ms: u64,
    remaining_bytes: u64,
    cancelled: &'a (dyn Fn() -> bool + Sync),
}
impl Socket<'_> {
    #[cfg(test)]
    fn reusable(&self) -> bool {
        self.reusable_for(crate::authority_challenge::MAXIMUM_DURATION_MS)
    }
    fn reusable_for(&self, duration: u64) -> bool {
        boot_time_ms().is_ok_and(|now| self.reusable_for_at(now, duration))
    }
    #[cfg(test)]
    fn reusable_at(&self, now: u64) -> bool {
        self.reusable_for_at(now, crate::authority_challenge::MAXIMUM_DURATION_MS)
    }
    fn reusable_for_at(&self, now: u64, duration: u64) -> bool {
        !(self.cancelled)()
            && self.operation_deadline.is_none()
            && self.remaining_bytes > 0
            && now < self.idle_deadline
            && self
                .deadline
                .checked_sub(now)
                .is_some_and(|remaining| remaining >= duration)
    }
    fn reusable_exchange_at(&self, now: u64, duration: u64, wire_bytes: u64) -> bool {
        self.reusable_for_at(now, duration) && self.remaining_bytes >= wire_bytes
    }
    fn admitted(&mut self, limits: crate::route_profile::Limits, received_at: u64) {
        // Readiness reports remaining admission time; the caller's original deadline stays fixed.
        self.deadline = self
            .deadline
            .min(received_at.saturating_add(limits.duration_ms));
        self.idle_deadline = self
            .idle_deadline
            .min(received_at.saturating_add(limits.idle_ms));
        self.idle_ms = limits.idle_ms;
        self.remaining_bytes = self.remaining_bytes.min(limits.bytes);
    }
    fn check(&self) -> io::Result<u64> {
        if (self.cancelled)() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "private route cancelled",
            ));
        }
        let now = boot_time_ms().map_err(io::Error::other)?;
        let deadline = self
            .deadline
            .min(self.operation_deadline.unwrap_or(u64::MAX))
            .min(self.idle_deadline);
        deadline.checked_sub(now).filter(|n| *n > 0).ok_or_else(|| {
            // An exhausted session budget remains terminal, including a tie with operation expiry.
            if now >= self.deadline {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "private route total deadline expired",
                )
            } else if now >= self.idle_deadline {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "private route idle deadline expired",
                )
            } else {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    OperationDeadlineExpired { deadline },
                )
            }
        })
    }
    fn ready(&self, events: libc::c_short) -> io::Result<()> {
        loop {
            let wait = self.check()?.min(100);
            let mut fd = libc::pollfd {
                fd: self.socket.as_raw_fd(),
                events,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut fd, 1, wait as i32) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            } else if result > 0 {
                if fd.revents & (libc::POLLNVAL | libc::POLLERR) != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "private route socket failed",
                    ));
                }
                if fd.revents & (events | libc::POLLHUP) != 0 {
                    return Ok(());
                }
            }
        }
    }
    fn used(&mut self, n: usize) -> io::Result<()> {
        self.remaining_bytes = self
            .remaining_bytes
            .checked_sub(n as u64)
            .ok_or_else(|| io::Error::other("private route byte admission exhausted"))?;
        if n > 0 {
            self.idle_deadline = boot_time_ms()
                .map_err(io::Error::other)?
                .saturating_add(self.idle_ms);
        }
        self.check()?;
        Ok(())
    }
}
impl Read for Socket<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            self.check()?;
            let maximum = bytes
                .len()
                .min(usize::try_from(self.remaining_bytes).unwrap_or(usize::MAX));
            if maximum == 0 {
                return Err(io::Error::other("private route byte admission exhausted"));
            }
            match self.socket.read(&mut bytes[..maximum]) {
                Ok(n) => {
                    self.used(n)?;
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if self.opportunistic {
                        return Err(e);
                    }
                    self.ready(libc::POLLIN)?;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}
impl Write for Socket<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            self.check()?;
            let maximum = bytes
                .len()
                .min(usize::try_from(self.remaining_bytes).unwrap_or(usize::MAX));
            if maximum == 0 {
                return Err(io::Error::other("private route byte admission exhausted"));
            }
            match self.socket.write(&bytes[..maximum]) {
                Ok(n) => {
                    self.used(n)?;
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if self.opportunistic {
                        return Err(e);
                    }
                    self.ready(libc::POLLOUT)?;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        Ok(())
    }
}
fn send(stream: &mut impl Write, bytes: &[u8]) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= protocol::FRAME,
        "private route frame exceeds bound"
    );
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()?;
    Ok(())
}
fn receive(stream: &mut impl Read, maximum: usize) -> Result<Vec<u8>> {
    let mut size = [0; 4];
    stream.read_exact(&mut size)?;
    let size = u32::from_be_bytes(size) as usize;
    ensure!(
        size > 0 && size <= maximum,
        "private route response exceeds bound"
    );
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn connect(
    address: SocketAddr,
    deadline: u64,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<TcpStream> {
    ensure!(!cancelled(), "private route cancelled");
    let family = if address.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd = unsafe {
        libc::socket(
            family,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    ensure!(fd >= 0, "cannot create private route socket");
    let socket = unsafe { TcpStream::from_raw_fd(fd) };
    let result = match address {
        SocketAddr::V4(address) => {
            let mut native: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            native.sin_family = libc::AF_INET as libc::sa_family_t;
            native.sin_port = address.port().to_be();
            native.sin_addr.s_addr = u32::from_ne_bytes(address.ip().octets());
            unsafe {
                libc::connect(
                    fd,
                    &native as *const _ as *const libc::sockaddr,
                    std::mem::size_of_val(&native) as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(address) => {
            ensure!(
                address.scope_id() == 0,
                "scoped interface addresses are not a private relay route"
            );
            let mut native: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            native.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            native.sin6_port = address.port().to_be();
            native.sin6_addr.s6_addr = address.ip().octets();
            unsafe {
                libc::connect(
                    fd,
                    &native as *const _ as *const libc::sockaddr,
                    std::mem::size_of_val(&native) as libc::socklen_t,
                )
            }
        }
    };
    let pending = Socket {
        opportunistic: false,
        socket,
        deadline,
        operation_deadline: None,
        idle_deadline: deadline,
        idle_ms: u64::MAX,
        remaining_bytes: u64::MAX,
        cancelled,
    };
    if result != 0 {
        ensure!(
            io::Error::last_os_error().raw_os_error() == Some(libc::EINPROGRESS),
            "private relay connection refused"
        );
        pending.ready(libc::POLLOUT)?;
        if let Some(error) = pending.socket.take_error()? {
            return Err(error.into());
        }
    }
    pending.check()?;
    pending.socket.set_nodelay(true)?;
    Ok(pending.socket)
}

type Stream<'a> = StreamOwned<ClientConnection, StreamOwned<ClientConnection, Socket<'a>>>;

/// Conservatively reserve both finite frames through the configured nested TLS record framing.
pub(crate) fn exchange_reservation(request: usize, maximum_response: usize) -> Result<u64> {
    ensure!(
        (1..=trust_wire::MAXIMUM).contains(&request)
            && (1..=4 * trust_wire::MAXIMUM).contains(&maximum_response),
        "invalid private route reservation extent"
    );
    fn framed(bytes: usize) -> u64 {
        // TLS1.3 permits 256 bytes of ciphertext expansion plus its five-byte header.
        // Each layer uses the default 16KiB fragment size. The four-byte frame prefix
        // is a separate write; outer records can also split at each inner write boundary.
        const FRAGMENT: u64 = 16384;
        const EXPANSION: u64 = 256 + 5;
        let bytes = bytes as u64;
        let inner_records = 1 + bytes.div_ceil(FRAGMENT);
        let inner = bytes + 4 + inner_records * EXPANSION;
        let outer_records = inner.div_ceil(FRAGMENT) + inner_records;
        inner + outer_records * EXPANSION
    }
    // The handshake is complete before reuse. Leave a further full record at each
    // TLS layer in each direction for pending post-handshake control traffic.
    // Unexpected peer fragmentation or control traffic still consumes the fixed
    // socket budget; exhaustion fails the submitted exchange without retry.
    Ok(framed(request) + framed(maximum_response) + 4 * (16384 + 256 + 5))
}

/// One admitted connection owns a fixed resource budget; failed exchanges cannot reconnect.
pub struct Session<'a> {
    stream: Option<Stream<'a>>,
}
impl<'a> Session<'a> {
    pub fn connect(
        profile: &Profile,
        possession: &SigningKey,
        deadline: u64,
        cancelled: &'a (dyn Fn() -> bool + Sync),
    ) -> Result<Self> {
        Self::connect_with_deadlines(profile, possession, deadline, deadline, cancelled)
    }
    /// Admission retains one fixed lifetime; its initial handshake has a separate caller deadline.
    pub(crate) fn connect_with_deadlines(
        profile: &Profile,
        possession: &SigningKey,
        session_deadline: u64,
        handshake_deadline: u64,
        cancelled: &'a (dyn Fn() -> bool + Sync),
    ) -> Result<Self> {
        profile.validate()?;
        let record =
            domains::Record::parse(&profile.voucher, profile.network, profile.incarnation)?;
        ensure!(
            record.reference.kind == 166,
            "private route profile requires a typed voucher record"
        );
        let voucher = domains::routes::Voucher::parse(&record.payload)?;
        ensure!(
            voucher.relay.id == profile.relay.service
                && voucher.destination.id == profile.destination.service
                && voucher.possession == possession.verifying_key().to_bytes(),
            "private route voucher differs from selected endpoints or possession key"
        );
        // Profiles retain the complete public voucher; relay admission selects its exact current record.
        let voucher = trust_wire::encode(&reference(&record.reference))?;
        let start = boot_time_ms()?;
        let deadline = session_deadline.min(
            start
                .checked_add(profile.limits.duration_ms)
                .context("private route deadline overflow")?,
        );
        let socket = Socket {
            opportunistic: false,
            socket: connect(
                profile.relay_address,
                deadline.min(handshake_deadline),
                cancelled,
            )?,
            deadline,
            operation_deadline: Some(handshake_deadline),
            idle_deadline: start.saturating_add(profile.limits.idle_ms),
            idle_ms: profile.limits.idle_ms,
            remaining_bytes: profile.limits.bytes,
            cancelled,
        };
        let connection = ClientConnection::new(
            route_tls::client(&profile.relay)?,
            ServerName::try_from(profile.relay.server_name.clone())?,
        )?;
        let mut outer = StreamOwned::new(connection, socket);
        outer
            .conn
            .complete_io(&mut outer.sock)
            .context("authenticate private relay")?;
        ensure!(
            outer.conn.alpn_protocol() == Some(route_tls::ALPN),
            "relay protocol differs"
        );
        let exporter = outer
            .conn
            .export_keying_material([0; 32], protocol::EXPORTER, None)?;
        let open = protocol::Open {
            network: profile.network,
            incarnation: profile.incarnation,
            relay: profile.relay.service,
            service: profile.destination.service,
            voucher,
            nonce: protocol::random()?,
            attachment: false,
        };
        send(&mut outer, &open.encode()?).context("send private route request")?;
        let challenge = protocol::parse_challenge(
            &receive(&mut outer, protocol::FRAME).context("wait for private relay challenge")?,
        )?;
        let signed = open.sign(challenge, exporter, possession)?;
        let binding = trust_wire::digest(&open.binding(challenge, exporter)?);
        send(&mut outer, &signed).context("send private route channel proof")?;
        let limits = protocol::parse_ready(
            &receive(&mut outer, protocol::FRAME).context("wait for private relay admission")?,
            binding,
            profile.limits,
        )?;
        outer.sock.admitted(limits, boot_time_ms()?);
        let connection = ClientConnection::new(
            route_tls::client(&profile.destination)?,
            ServerName::try_from(profile.destination.server_name.clone())?,
        )?;
        let mut inner = StreamOwned::new(connection, outer);
        inner
            .conn
            .complete_io(&mut inner.sock)
            .context("authenticate final private service")?;
        ensure!(
            inner.conn.alpn_protocol() == Some(route_tls::ALPN),
            "final service protocol differs"
        );
        protocol::parse_endpoint_ready(
            &receive(&mut inner, protocol::FRAME)
                .context("wait for final private service readiness")?,
            profile.network,
            profile.incarnation,
            profile.destination.service,
            profile.protocol,
        )?;
        inner.sock.sock.check()?;
        inner.sock.sock.operation_deadline = None;
        Ok(Self {
            stream: Some(inner),
        })
    }
    pub fn exchange(
        &mut self,
        request: &[u8],
        deadline: u64,
        maximum_response: usize,
    ) -> Result<Vec<u8>> {
        let result = (|| {
            ensure!(
                !request.is_empty()
                    && request.len() <= trust_wire::MAXIMUM
                    && (1..=4 * trust_wire::MAXIMUM).contains(&maximum_response),
                "invalid private route application frame"
            );
            let inner = self
                .stream
                .as_mut()
                .context("private route session is closed")?;
            inner.sock.sock.operation_deadline = Some(deadline);
            inner.sock.sock.check()?;
            // Endpoint readiness and both authenticated TLS layers precede every application credential.
            send(inner, request).context("send private application request")?;
            let response =
                receive(inner, maximum_response).context("receive private application response")?;
            inner.sock.sock.check()?;
            inner.sock.sock.operation_deadline = None;
            Ok(response)
        })();
        if result.is_err() {
            self.stream.take();
        }
        result
    }
    /// Preparation may reuse the remaining admission, never renew its budgets.
    pub(crate) fn reusable(&self) -> bool {
        self.reusable_for(crate::authority_challenge::MAXIMUM_DURATION_MS)
    }
    pub(crate) fn reusable_for(&self, duration: u64) -> bool {
        self.stream
            .as_ref()
            .is_some_and(|stream| stream.sock.sock.reusable_for(duration))
    }
    pub(crate) fn reusable_exchange(&self, duration: u64, wire_bytes: u64) -> bool {
        self.stream.as_ref().is_some_and(|stream| {
            boot_time_ms().is_ok_and(|now| {
                stream
                    .sock
                    .sock
                    .reusable_exchange_at(now, duration, wire_bytes)
            })
        })
    }
}
#[allow(dead_code)] // Shared one-shot entry point used by Core transport qualification.
pub fn exchange(
    profile: &Profile,
    possession: &SigningKey,
    request: &[u8],
    deadline: u64,
    maximum_response: usize,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<Vec<u8>> {
    Session::connect(profile, possession, deadline, cancelled)?.exchange(
        request,
        deadline,
        maximum_response,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::TcpListener,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    #[test]
    fn private_route_operation_deadline_never_resets_session_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        let now = boot_time_ms().unwrap();
        let mut stream = Socket {
            opportunistic: false,
            socket,
            deadline: now + 60000,
            operation_deadline: Some(now),
            idle_deadline: now + 30000,
            idle_ms: 30000,
            remaining_bytes: 12345,
            cancelled: &|| false,
        };
        let error = stream.check().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            error.to_string(),
            "private route operation deadline expired"
        );
        assert_eq!(
            error
                .get_ref()
                .unwrap()
                .downcast_ref::<OperationDeadlineExpired>()
                .unwrap()
                .deadline,
            now
        );
        stream.operation_deadline = Some(now + 5000);
        assert!(stream.check().unwrap() <= 5000);
        assert!(!stream.reusable());
        stream.operation_deadline = None;
        assert!(stream.check().unwrap() > 5000);
        assert!(stream.reusable());
        assert_eq!(stream.deadline, now + 60000);
        assert_eq!(stream.idle_deadline, now + 30000);
        assert_eq!(stream.remaining_bytes, 12345);
        stream.deadline = now;
        assert!(!stream.reusable());
        assert_eq!(
            stream.check().unwrap_err().to_string(),
            "private route total deadline expired"
        );
        stream.deadline = now + 60000;
        stream.idle_deadline = now;
        assert!(!stream.reusable());
        assert_eq!(
            stream.check().unwrap_err().to_string(),
            "private route idle deadline expired"
        );
        stream.operation_deadline = Some(now);
        for total in [false, true] {
            stream.deadline = if total { now } else { now + 60000 };
            stream.idle_deadline = if total { now + 30000 } else { now };
            let error = stream.check().unwrap_err();
            assert!(
                error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<OperationDeadlineExpired>()
                    .is_none()
            );
            assert_eq!(
                error.to_string(),
                if total {
                    "private route total deadline expired"
                } else {
                    "private route idle deadline expired"
                }
            );
        }
        stream.cancelled = &|| true;
        assert!(!stream.reusable());
        assert_eq!(
            stream.check().unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        stream.cancelled = &|| false;
        stream.deadline = now + 60000;
        stream.idle_deadline = now + 30000;
        stream.operation_deadline = None;
        stream.remaining_bytes = 0;
        assert!(!stream.reusable());
    }
    #[test]
    fn content_reuse_reserves_effect_and_completion_within_original_admission() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        let now = boot_time_ms().unwrap();
        let duration = crate::authority_challenge::MAXIMUM_DURATION_MS * 2;
        let mut stream = Socket {
            opportunistic: false,
            socket,
            deadline: now + duration,
            operation_deadline: None,
            idle_deadline: now + duration * 2,
            idle_ms: duration * 2,
            remaining_bytes: 12345,
            cancelled: &|| false,
        };
        assert!(stream.reusable_for_at(now, duration));
        let reservation = exchange_reservation(4096, 4 * trust_wire::MAXIMUM).unwrap();
        assert!(reservation > (4096 + 4 * trust_wire::MAXIMUM + 8) as u64);
        assert!(exchange_reservation(usize::MAX, 1).is_err());
        assert!(exchange_reservation(1, usize::MAX).is_err());
        stream.remaining_bytes = reservation;
        assert!(stream.reusable_exchange_at(now, duration, reservation));
        assert!(!stream.reusable_exchange_at(now + 1, duration, reservation));
        stream.remaining_bytes -= 1;
        assert!(!stream.reusable_exchange_at(now, duration, reservation));
        assert_eq!(stream.remaining_bytes, reservation - 1);
        stream.remaining_bytes = 12345;
        assert!(!stream.reusable_for_at(now + 1, duration));
        assert!(stream.reusable_at(now + 1));
        stream.remaining_bytes = 0;
        assert!(!stream.reusable_for_at(now, duration));
        stream.remaining_bytes = 12345;
        stream.idle_deadline = now;
        assert!(!stream.reusable_for_at(now, duration));
        stream.idle_deadline = now + duration * 2;
        stream.cancelled = &|| true;
        assert!(!stream.reusable_for_at(now, duration));
        stream.cancelled = &|| false;
        stream.deadline = now + 1000;
        assert!(stream.check().is_ok());
        assert!(!stream.reusable_for_at(now, duration));
        assert_eq!(stream.remaining_bytes, 12345);
        assert_eq!(stream.idle_deadline, now + duration * 2);
        assert_eq!(stream.deadline, now + 1000);
    }
    #[test]
    fn private_route_readiness_cannot_extend_original_socket_limits() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        let mut stream = Socket {
            opportunistic: false,
            socket,
            deadline: 5000,
            operation_deadline: None,
            idle_deadline: 4800,
            idle_ms: 1000,
            remaining_bytes: 12000,
            cancelled: &|| false,
        };
        let limits = crate::route_profile::Limits {
            bytes: 16384,
            duration_ms: 1000,
            idle_ms: 800,
        };
        stream.admitted(limits, 4500);
        assert_eq!(stream.deadline, 5000);
        assert_eq!(stream.idle_deadline, 4800);
        assert_eq!(stream.remaining_bytes, 12000);
        assert_eq!(stream.idle_ms, 800);
        // A stricter remaining allowance starts at readiness, not at the original connection start.
        stream.deadline = 9000;
        stream.idle_deadline = 9000;
        stream.remaining_bytes = 65536;
        stream.admitted(limits, 4500);
        assert_eq!(stream.deadline, 5500);
        assert_eq!(stream.idle_deadline, 5300);
        assert_eq!(stream.remaining_bytes, 16384);
    }
    #[test]
    fn authority_reuse_requires_the_full_existing_challenge_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        let now = boot_time_ms().unwrap();
        let duration = crate::authority_challenge::MAXIMUM_DURATION_MS;
        let mut stream = Socket {
            opportunistic: false,
            socket,
            deadline: now + duration,
            operation_deadline: None,
            idle_deadline: now + duration * 2,
            idle_ms: duration * 2,
            remaining_bytes: 12345,
            cancelled: &|| false,
        };
        assert!(stream.reusable_at(now));
        assert!(!stream.reusable_at(now + 1));
        stream.deadline = now + 1;
        assert!(!stream.reusable_at(now));
        assert_eq!(stream.deadline, now + 1);
        assert_eq!(stream.idle_deadline, now + duration * 2);
        assert_eq!(stream.remaining_bytes, 12345);
        // A fresh short admission remains usable; only reuse requires full challenge headroom.
        stream.deadline = boot_time_ms().unwrap() + 1000;
        assert!(stream.check().is_ok());
        assert!(!stream.reusable());
    }
    #[test]
    fn private_route_cancellation_does_not_retry_as_interrupted_io() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        socket.set_nonblocking(true).unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let signal = cancelled.clone();
        let task = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            signal.store(true, Ordering::Release);
        });
        let check = || cancelled.load(Ordering::Acquire);
        let start = boot_time_ms().unwrap();
        let mut stream = Socket {
            opportunistic: false,
            socket,
            deadline: start + 5000,
            operation_deadline: None,
            idle_deadline: start + 5000,
            idle_ms: 5000,
            remaining_bytes: 1024,
            cancelled: &check,
        };
        let error = stream.read_exact(&mut [0; 1]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert!(boot_time_ms().unwrap() - start < 1000);
        task.join().unwrap();
    }
    #[test]
    fn private_route_drip_traffic_cannot_extend_original_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        socket.set_nonblocking(true).unwrap();
        let task = std::thread::spawn(move || {
            for _ in 0..20 {
                if peer.write_all(&[1]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let start = boot_time_ms().unwrap();
        let mut stream = Socket {
            opportunistic: false,
            socket,
            deadline: start + 75,
            operation_deadline: None,
            idle_deadline: start + 1000,
            idle_ms: 1000,
            remaining_bytes: 1024,
            cancelled: &|| false,
        };
        let error = stream.read_exact(&mut [0; 20]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(boot_time_ms().unwrap() - start < 1000);
        drop(stream);
        task.join().unwrap();
    }
}
