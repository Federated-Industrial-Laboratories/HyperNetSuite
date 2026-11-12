// SPDX-License-Identifier: MIT
// Desktop handoffs validate retained profiles and never replace saved identities.
use super::{protocol, runtime, saved};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    fs::OpenOptions,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    time::Duration,
};

pub fn sockets(directory: &Path) -> PathBuf {
    PathBuf::from(format!(
        "/run/user/{}/hypernet-{}",
        unsafe { libc::geteuid() },
        &protocol::digest(directory.as_os_str().as_encoded_bytes())[..20]
    ))
}
pub fn profiles(
    directory: &Path,
    state: &saved::State,
) -> Result<(Option<PathBuf>, Option<PathBuf>)> {
    super::private::directory(directory)?;
    ensure!(state.version == 1, "unsupported saved server version");
    let Some(installed) = &state.installed else {
        return Ok((None, None));
    };
    let profiles = installed
        .get("profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("native profiles absent"))?;
    let mut page = None;
    let mut chat = None;
    for role in &state.roles {
        let profile = profiles
            .iter()
            .find(|p| p.get("role").and_then(Value::as_u64) == Some(role.role))
            .ok_or_else(|| anyhow::anyhow!("native role profile absent"))?;
        let expected = directory.join(format!("Native/Roles/{}/Profile.json", role.role));
        ensure!(
            profile.get("profile").and_then(Value::as_str) == expected.to_str()
                && profile.get("member").and_then(Value::as_str) == Some(&role.member),
            "saved native role differs"
        );
        super::private::directory(expected.parent().unwrap())?;
        let _: Value = saved::read(&expected)?;
        if role.role == 0 {
            page = Some(expected);
        }
        if role.role == 1 {
            let hrc = directory.join("Hrc/Profile");
            super::private::directory(&hrc)?;
            let profile: Value = saved::read(&hrc.join("Profile.json"))?;
            let descriptor = state
                .metadata
                .permissions
                .hrc
                .as_ref()
                .and_then(|h| h.get("descriptor"));
            let identity = state
                .intent
                .as_ref()
                .and_then(|i| i.hrc.as_ref())
                .and_then(|h| h.request.get("identity"))
                .ok_or_else(|| anyhow::anyhow!("saved chat identity absent"))?;
            ensure!(
                profile.get("server") == descriptor
                    && profile
                        .pointer("/registration/transportPrincipal")
                        .and_then(Value::as_str)
                        == Some(&role.member),
                "saved chat server or principal differs"
            );
            for key in ["account", "endpoint", "endpointKey", "recoveryKey"] {
                ensure!(
                    profile.get("registration").and_then(|r| r.get(key)) == identity.get(key),
                    "saved chat identity differs"
                );
            }
            ensure!(
                profile.get("companion").and_then(Value::as_str)
                    == sockets(directory).join("Companion").to_str(),
                "chat companion differs from saved runtime"
            );
            chat = Some(hrc);
        }
    }
    Ok((chat, page))
}
pub fn configuration(directory: &Path, path: &Path) -> Result<runtime::Configuration> {
    ensure!(
        path == directory.join("Runtime.json"),
        "runtime configuration leaves saved server"
    );
    let value = saved::read(path)?;
    Ok(value)
}
pub fn joined(directory: &Path, path: &Path) -> Result<Value> {
    let _ = configuration(directory, path)?;
    let session = saved::Session::open(directory)?;
    let state = session.state()?;
    ensure!(state.installed.is_some(), "server is not joined");
    let (chat, page) = profiles(directory, &state)?;
    if let Some(profile) = &chat {
        saved::replace(
            &profile.join("SimpleServer.json"),
            &json!({"version":1,"directory":directory,"suite":std::env::current_exe()?.canonicalize()?,"runtimeConfiguration":path,"pageProfile":page,"name":state.metadata.name,"initialNickname":state.display_name}),
        )?;
    }
    Ok(
        json!({"status":"Joined","serverDirectory":directory,"hrcProfile":chat,"pageProfile":page,"runtimeConfiguration":path}),
    )
}
pub fn desire(directory: &Path, online: bool) -> Result<Value> {
    let session = saved::Session::open(directory)?;
    let mut state = session.state()?;
    ensure!(
        !online || !state.removed,
        "host removed this membership; automatic reconnect cannot restore it"
    );
    state.desired_online = online;
    session.save(&state)?;
    Ok(json!({"status":"SavedServerUpdated","desiredOnline":online}))
}
pub fn owned(directory: &Path) -> Result<bool> {
    let path = directory.join("Runtime.lock");
    if !path.try_exists()? {
        return Ok(false);
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.mode() & 0o077 == 0
            && m.uid() == unsafe { libc::geteuid() },
        "runtime lock is not private"
    );
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(false);
    }
    let error = std::io::Error::last_os_error();
    ensure!(
        error.kind() == std::io::ErrorKind::WouldBlock,
        "cannot inspect saved runtime ownership"
    );
    Ok(true)
}
pub fn ready(directory: &Path, state: &saved::State) -> bool {
    if state.removed
        || !state.desired_online
        || state.installed.is_none()
        || !owned(directory).unwrap_or(false)
    {
        return false;
    }
    if !saved::read::<Value>(&directory.join("RuntimeReady.json"))
        .is_ok_and(|v| v.get("ready") == Some(&Value::Bool(true)))
    {
        return false;
    }
    if crate::authority_clock::health(&directory.join("Native/Clock/ClockHealth.json"))
        .and_then(|c| c.observe())
        .is_err()
    {
        return false;
    }
    let Some(chat) = state.roles.iter().find(|r| r.role == 1) else {
        return true;
    };
    let check = || -> Result<bool> {
        let directory = sockets(directory).join("Companion");
        super::private::directory(&directory)?;
        let mut channel = super::ipc::Channel::connect(
            &directory.join("Control.sock"),
            unsafe { libc::geteuid() },
            Duration::from_secs(1),
        )?;
        let response: Value = serde_json::from_slice(
            &channel.exchange(br#"{"version":1,"action":"status"}"#, 16384)?,
        )?;
        Ok(response.get("ok") == Some(&Value::Bool(true))
            && response.get("status").and_then(Value::as_str) == Some("Ready")
            && response.get("network").and_then(Value::as_str) == Some(&state.metadata.network)
            && response.get("incarnation").and_then(Value::as_str)
                == Some(&state.metadata.incarnation)
            && response.get("principal").and_then(Value::as_str) == Some(&chat.member)
            && response
                .get("targets")
                .and_then(Value::as_array)
                .is_some_and(|targets| {
                    targets.iter().any(|t| {
                        t.get("service")
                            == state
                                .metadata
                                .permissions
                                .hrc
                                .as_ref()
                                .and_then(|h| h.pointer("/descriptor/home/service"))
                            && t.get("protocol").and_then(Value::as_str) == Some("hrc/1")
                    })
                }))
    };
    check().unwrap_or(false)
}
pub fn status(directory: &Path, path: &Path) -> Result<Value> {
    super::private::directory(directory)?;
    let _ = configuration(directory, path)?;
    let state: saved::State = saved::read(&directory.join("Server.json"))?;
    let (chat, page) = profiles(directory, &state)?;
    Ok(
        json!({"status":"SavedServer","desiredOnline":state.desired_online,"runtimeReady":ready(directory, &state),"runtimeOwned":owned(directory)?,"hrcProfile":chat,"pageProfile":page}),
    )
}
