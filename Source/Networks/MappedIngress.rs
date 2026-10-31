// SPDX-License-Identifier: MIT
// A rootless mapped ingress owns only the endpoint socket and forwards verified local descriptors.
use crate::{authority_domains::streams, local_stream_ipc as ipc, transfer_files as files};
use anyhow::{Context, Result, ensure};
use clap::Args;
use std::path::{Path, PathBuf};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::UnixStream,
            process::CommandExt,
        },
    },
    process::{Child, Command as Process, Stdio},
    time::{Duration, Instant},
};
#[derive(Args)]
pub struct Arguments {
    #[arg(long)]
    directory: PathBuf,
    #[arg(long)]
    descriptor: RawFd,
    #[arg(long, default_value = "application", value_parser = ["application", "authority"])]
    binding_kind: String,
}
pub struct Ingress {
    child: Child,
    channel: UnixStream,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DescriptorKind {
    Payload = 1,
    Checks = 2,
}
impl Ingress {
    pub fn start(directory: &Path, binding: &streams::local::Binding) -> Result<Self> {
        Self::start_binding(directory, &binding.encode()?, "application")
    }
    pub(crate) fn start_binding(directory: &Path, bytes: &[u8], kind: &str) -> Result<Self> {
        let (mut parent, child) = UnixStream::pair()?;
        parent.set_read_timeout(Some(Duration::from_secs(15)))?;
        parent.set_write_timeout(Some(Duration::from_secs(5)))?;
        let descriptor = child.as_raw_fd();
        let mut command = Process::new("/usr/bin/podman");
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C");
        for name in [
            "HOME",
            "XDG_RUNTIME_DIR",
            "DBUS_SESSION_BUS_ADDRESS",
            "CONTAINERS_CONF",
            "CONTAINERS_STORAGE_CONF",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command
            .args(["unshare", "--"])
            .arg(std::env::current_exe()?.canonicalize()?)
            .args(["network", "ingress-helper", "--directory"])
            .arg(directory)
            .args(["--binding-kind", kind])
            .arg("--descriptor")
            .arg(descriptor.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(descriptor, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let process = command
            .spawn()
            .context("start the rootless application ingress helper")?;
        drop(child);
        let result = Self {
            child: process,
            channel: parent.try_clone()?,
        };
        ipc::write_frame(&mut parent, bytes)?;
        ensure!(
            ipc::read_frame(&mut parent)? == b"Ready",
            "mapped ingress failed readiness"
        );
        result.channel.set_nonblocking(true)?;
        Ok(result)
    }
    pub fn accept(&mut self) -> Result<Option<UnixStream>> {
        self.accept_tagged()?
            .map(|(kind, stream)| {
                ensure!(
                    kind == DescriptorKind::Payload,
                    "unexpected mapped ingress descriptor kind"
                );
                Ok(stream)
            })
            .transpose()
    }
    pub fn accept_tagged(&mut self) -> Result<Option<(DescriptorKind, UnixStream)>> {
        if let Some(status) = self.child.try_wait()? {
            anyhow::bail!("mapped ingress helper stopped: {status}");
        }
        let stream = receive(&self.channel)?;
        if stream.is_some() {
            self.channel.write_all(&[1])?;
        }
        Ok(stream)
    }
}
impl Drop for Ingress {
    fn drop(&mut self) {
        let _ = self.channel.shutdown(std::net::Shutdown::Both);
        let end = Instant::now() + Duration::from_secs(3);
        while Instant::now() < end {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn send(channel: &UnixStream, stream: &UnixStream, kind: DescriptorKind) -> Result<()> {
    let mut byte = [kind as u8];
    let mut io = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 8];
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_iov = &mut io;
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    unsafe {
        let item = libc::CMSG_FIRSTHDR(&header);
        (*item).cmsg_level = libc::SOL_SOCKET;
        (*item).cmsg_type = libc::SCM_RIGHTS;
        (*item).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(item).cast::<RawFd>(), stream.as_raw_fd());
        ensure!(
            libc::sendmsg(channel.as_raw_fd(), &header, libc::MSG_NOSIGNAL) == 1,
            "cannot hand off the mapped ingress descriptor"
        );
    }
    Ok(())
}
fn receive(channel: &UnixStream) -> Result<Option<(DescriptorKind, UnixStream)>> {
    let mut byte = [0u8];
    let mut io = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 8];
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_iov = &mut io;
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen = std::mem::size_of_val(&control);
    let count = unsafe {
        libc::recvmsg(
            channel.as_raw_fd(),
            &mut header,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if count < 0 {
        let error = std::io::Error::last_os_error();
        if matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
        ) {
            return Ok(None);
        }
        return Err(error.into());
    }
    let mut descriptors = Vec::new();
    unsafe {
        let mut item = libc::CMSG_FIRSTHDR(&header);
        while !item.is_null() {
            if (*item).cmsg_level == libc::SOL_SOCKET && (*item).cmsg_type == libc::SCM_RIGHTS {
                let count =
                    ((*item).cmsg_len - libc::CMSG_LEN(0) as usize) / std::mem::size_of::<RawFd>();
                for index in 0..count {
                    descriptors.push(File::from_raw_fd(std::ptr::read_unaligned(
                        libc::CMSG_DATA(item).cast::<RawFd>().add(index),
                    )));
                }
            }
            item = libc::CMSG_NXTHDR(&header, item);
        }
    }
    ensure!(
        count == 1
            && matches!(byte[0], 1 | 2)
            && header.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0
            && descriptors.len() == 1,
        "mapped ingress descriptor response is absent or invalid"
    );
    let kind = if byte[0] == 1 {
        DescriptorKind::Payload
    } else {
        DescriptorKind::Checks
    };
    Ok(Some((kind, unsafe {
        UnixStream::from_raw_fd(descriptors.pop().unwrap().into_raw_fd())
    })))
}
fn restrict() -> Result<()> {
    const LOAD: u16 = 0x20;
    const JUMP: u16 = 0x15;
    const RET: u16 = 0x06;
    let statement = |code, k| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let equal = |k| libc::sock_filter {
        code: JUMP,
        jt: 0,
        jf: 1,
        k,
    };
    #[cfg(target_arch = "x86_64")]
    let architecture = 0xc000003e;
    #[cfg(target_arch = "aarch64")]
    let architecture = 0xc00000b7;
    let mut filter = vec![
        statement(LOAD, 4),
        equal(architecture),
        statement(RET, libc::SECCOMP_RET_ALLOW),
    ];
    // The architecture check must continue to syscall checks only for this native ABI.
    filter[1].jt = 1;
    filter[1].jf = 0;
    filter[2].k = libc::SECCOMP_RET_KILL_PROCESS;
    filter.push(statement(LOAD, 0));
    for syscall in [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_close,
        libc::SYS_recvmsg,
        libc::SYS_sendmsg,
        libc::SYS_recvfrom,
        libc::SYS_sendto,
        libc::SYS_accept4,
        libc::SYS_getsockopt,
        libc::SYS_shutdown,
        libc::SYS_fcntl,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_ppoll,
        libc::SYS_futex,
        libc::SYS_brk,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mprotect,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_unlinkat,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_geteuid,
        libc::SYS_getegid,
        libc::SYS_getuid,
        libc::SYS_getgid,
        libc::SYS_getpid,
        libc::SYS_gettid,
    ] {
        filter.push(equal(syscall as u32));
        filter.push(statement(RET, libc::SECCOMP_RET_ALLOW));
    }
    #[cfg(target_arch = "x86_64")]
    for syscall in [libc::SYS_unlink, libc::SYS_poll] {
        filter.push(equal(syscall as u32));
        filter.push(statement(RET, libc::SECCOMP_RET_ALLOW));
    }
    filter.push(statement(RET, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32));
    let program = libc::sock_fprog {
        len: filter.len().try_into()?,
        filter: filter.as_mut_ptr(),
    };
    unsafe {
        ensure!(
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0,
            "cannot restrict ingress privilege"
        );
        ensure!(
            libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) == 0,
            "cannot restrict ingress syscalls"
        );
    }
    Ok(())
}
pub fn run(a: Arguments) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && a.descriptor >= 3,
        "ingress helper requires its inherited rootless namespace channel"
    );
    let mapping = fs::read_to_string("/proc/self/uid_map")?;
    let rows = mapping
        .lines()
        .map(|line| {
            line.split_whitespace()
                .map(str::parse::<u64>)
                .collect::<std::result::Result<Vec<_>, _>>()
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        rows.len() == 2
            && rows[0].len() == 3
            && rows[0][0] == 0
            && rows[0][1] > 0
            && rows[0][2] == 1
            && rows[1].len() == 3
            && rows[1][0] == 1
            && rows[1][2] > 1001,
        "ingress helper requires the exact rootless subordinate UID mapping"
    );
    let mut channel = unsafe { UnixStream::from_raw_fd(a.descriptor) };
    ipc::peer(&channel)?;
    channel.set_read_timeout(Some(Duration::from_secs(5)))?;
    channel.set_write_timeout(Some(Duration::from_secs(5)))?;
    let bytes = ipc::read_frame(&mut channel)?;
    let canonical = match a.binding_kind.as_str() {
        "application" => serde_json::from_slice::<streams::local::Binding>(&bytes)?.encode()?,
        "authority" => crate::networks::authority_connector::Binding::parse(&bytes)?.encode()?,
        _ => anyhow::bail!("unsupported mapped ingress binding kind"),
    };
    ensure!(canonical == bytes, "ingress binding is not canonical");
    let parent = a.directory.parent().context("ingress parent is absent")?;
    ipc::private(parent, false)?;
    ensure!(
        a.directory.file_name() == Some(std::ffi::OsStr::new("Ingress")),
        "mapped ingress has another name"
    );
    match fs::create_dir(&a.directory) {
        Ok(()) => fs::set_permissions(&a.directory, fs::Permissions::from_mode(0o700))?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let info = fs::symlink_metadata(&a.directory)?;
    ensure!(
        info.is_dir()
            && [0, 1001].contains(&info.uid())
            && info.mode() & 0o7777 == 0o700
            && a.directory.canonicalize()? == a.directory,
        "mapped ingress directory has unsafe ownership or identity"
    );
    let root = File::open(&a.directory)?;
    let opened = root.metadata()?;
    ensure!(
        opened.dev() == info.dev() && opened.ino() == info.ino(),
        "mapped ingress directory changed during open"
    );
    // Open while namespace UID0 can traverse the host-owned private ancestors.
    unsafe {
        ensure!(
            libc::fchown(root.as_raw_fd(), 1001, 1001) == 0 && libc::fchdir(root.as_raw_fd()) == 0,
            "cannot select mapped ingress root"
        );
        ensure!(
            libc::chroot(c".".as_ptr()) == 0 && libc::chdir(c"/".as_ptr()) == 0,
            "cannot confine mapped ingress filesystem"
        );
        ensure!(
            libc::setgroups(0, std::ptr::null()) == 0
                && libc::setresgid(1001, 1001, 1001) == 0
                && libc::setresuid(1001, 1001, 1001) == 0,
            "cannot drop ingress helper to its exact mapped account"
        );
    }
    drop(root);
    let root = ipc::private(Path::new("/"), false)?;
    files::atomic_at(&root, std::ffi::OsStr::new("Binding.json"), &bytes, true)?;
    drop(root);
    let listener = ipc::Listener::bind(Path::new("/"))?;
    let checks = if a.binding_kind == "application" {
        Some(ipc::Listener::bind_named(Path::new("/"), "Checks.sock")?)
    } else {
        None
    };
    restrict()?;
    ipc::write_frame(&mut channel, b"Ready")?;
    loop {
        if ipc::disconnected(&channel)? {
            break;
        }
        let mut accepted = false;
        for (kind, listener) in std::iter::once((DescriptorKind::Payload, &listener)).chain(
            checks
                .as_ref()
                .map(|listener| (DescriptorKind::Checks, listener)),
        ) {
            match listener.socket.accept() {
                Ok((stream, _)) => {
                    if ipc::peer(&stream).is_err() {
                        continue;
                    }
                    accepted = true;
                    send(&channel, &stream, kind)?;
                    let mut ack = [0u8];
                    channel.read_exact(&mut ack)?;
                    ensure!(ack == [1], "parent refused ingress descriptor handoff");
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
        }
        if !accepted {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    Ok(())
}
#[cfg(test)]
#[path = "../../Tests/Unit/Networks/MappedIngressTests.rs"]
mod tests;
