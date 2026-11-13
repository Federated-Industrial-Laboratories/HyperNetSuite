// SPDX-License-Identifier: MIT
// A retained spawning thread binds child lifetime to its owner across GUI worker handoffs.
use anyhow::{Context, Result};
use std::{
    ffi::OsString,
    os::unix::process::CommandExt,
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc::{SyncSender, sync_channel},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub(in crate::admission) struct Process {
    child: Child,
    reaped: bool,
    parent: Option<(SyncSender<()>, JoinHandle<()>)>,
}
impl Process {
    pub(in crate::admission) fn spawn(program: &Path, args: &[OsString]) -> Result<Self> {
        super::executable(program)?;
        let parent = unsafe { libc::getpid() };
        let mut command = Command::new(program);
        command
            .args(args)
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        command.env("PATH", "/usr/bin:/bin").env("LANG", "C.UTF-8");
        for name in ["HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        // Linux binds this signal to the spawning thread, not the whole parent process.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent {
                    return Err(std::io::Error::other("runtime owner exited"));
                }
                Ok(())
            });
        }
        let (started, result) = sync_channel(1);
        let (release, lifetime) = sync_channel(0);
        let owner = thread::Builder::new()
            .name("saved-runtime-child".into())
            .spawn(move || {
                match started.send(command.spawn()) {
                    Ok(()) => {
                        // Keep the actual parent thread alive until Process has stopped its child.
                        let _ = lifetime.recv();
                    }
                    Err(error) => {
                        if let Ok(mut child) = error.0 {
                            terminate(&mut child);
                        }
                    }
                }
            })?;
        let child = result
            .recv()
            .context("runtime child startup interrupted")
            .and_then(|result| result.map_err(Into::into));
        match child {
            Ok(child) => Ok(Self {
                child,
                reaped: false,
                parent: Some((release, owner)),
            }),
            Err(error) => {
                drop(release);
                let _ = owner.join();
                Err(error)
            }
        }
    }
    pub(in crate::admission) fn running(&mut self) -> Result<bool> {
        if self.reaped {
            return Ok(false);
        }
        if self.child.try_wait()?.is_some() {
            self.reaped = true;
            Ok(false)
        } else {
            Ok(true)
        }
    }
}
fn terminate(child: &mut Child) {
    unsafe {
        libc::kill(-(child.id() as libc::pid_t), libc::SIGTERM);
    }
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    unsafe {
        libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
    }
    let _ = child.wait();
}
impl Drop for Process {
    fn drop(&mut self) {
        if !self.reaped {
            terminate(&mut self.child);
        }
        if let Some((release, owner)) = self.parent.take() {
            drop(release);
            let _ = owner.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
    };

    fn sleeper() -> Process {
        let executable = Path::new("/usr/bin/sleep").canonicalize().unwrap();
        Process::spawn(&executable, &["30".into()]).unwrap()
    }
    fn pidfd(pid: u32) -> OwnedFd {
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        assert!(fd >= 0, "{}", std::io::Error::last_os_error());
        unsafe { OwnedFd::from_raw_fd(fd) }
    }
    fn exited(fd: &OwnedFd, timeout: i32) -> bool {
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert!(unsafe { libc::poll(&mut poll, 1, timeout) } >= 0);
        poll.revents & libc::POLLIN != 0
    }

    #[test]
    fn runtime_process_survives_worker_handoff_and_drop_reaps_it() {
        let mut process = thread::spawn(sleeper).join().unwrap();
        let pid = process.child.id();
        let child = pidfd(pid);
        // This includes a second handoff after the original short-lived worker has exited.
        process = thread::spawn(move || {
            assert!(!exited(&child, 200));
            assert!(process.running().unwrap());
            process
        })
        .join()
        .unwrap();
        assert!(process.running().unwrap());
        drop(process);
        assert_eq!(
            unsafe { libc::waitpid(pid as i32, std::ptr::null_mut(), libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn runtime_process_abrupt_owner_exit_terminates_child() {
        const ROLE: &str = "HYPERNET_RUNTIME_PROCESS_OWNER_TEST";
        if std::env::var_os(ROLE).as_deref() == Some(std::ffi::OsStr::new("owner")) {
            let process = thread::spawn(sleeper).join().unwrap();
            println!("RuntimeChild={}", process.child.id());
            std::io::stdout().flush().unwrap();
            thread::sleep(Duration::from_secs(20));
            drop(process);
            panic!("test owner was not terminated");
        }
        struct Owner {
            process: Child,
            child: Option<OwnedFd>,
        }
        impl Drop for Owner {
            fn drop(&mut self) {
                if let Some(child) = &self.child {
                    unsafe {
                        libc::syscall(
                            libc::SYS_pidfd_send_signal,
                            child.as_raw_fd(),
                            libc::SIGKILL,
                            std::ptr::null::<libc::siginfo_t>(),
                            0,
                        );
                    }
                }
                let _ = self.process.kill();
                let _ = self.process.wait();
            }
        }
        let mut owner = Owner {
            process: Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "admission::runtime::process::tests::runtime_process_abrupt_owner_exit_terminates_child", "--nocapture", "--test-threads=1"])
                .env(ROLE, "owner")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
            child: None,
        };
        let mut output = owner.process.stdout.take().unwrap();
        let flags = unsafe { libc::fcntl(output.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(output.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
        let until = Instant::now() + Duration::from_secs(5);
        let mut bytes = Vec::new();
        let pid = loop {
            let mut buffer = [0; 512];
            match output.read(&mut buffer) {
                Ok(n) => bytes.extend_from_slice(&buffer[..n]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("{error}"),
            }
            assert!(bytes.len() <= 4096);
            if let Some(pid) = std::str::from_utf8(&bytes)
                .unwrap()
                .split("RuntimeChild=")
                .nth(1)
                .and_then(|s| s.split_once('\n'))
                .map(|(pid, _)| pid.parse::<u32>().unwrap())
            {
                break pid;
            }
            assert!(
                owner.process.try_wait().unwrap().is_none(),
                "test owner exited before child startup"
            );
            assert!(Instant::now() < until, "test child startup timed out");
            thread::sleep(Duration::from_millis(10));
        };
        owner.child = Some(pidfd(pid));
        let child = owner.child.as_ref().unwrap();
        assert!(!exited(child, 100));
        owner.process.kill().unwrap();
        owner.process.wait().unwrap();
        assert!(
            exited(child, 3000),
            "runtime child survived abrupt owner death"
        );
    }
}
