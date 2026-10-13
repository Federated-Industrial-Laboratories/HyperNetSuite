// SPDX-License-Identifier: MIT
// Explicit route selection keeps cancellation and credential release inside one connector.
use anyhow::{Result, ensure};
use std::sync::atomic::{AtomicBool, Ordering};

static CANCELLED: AtomicBool = AtomicBool::new(false);
extern "C" fn cancel(_: libc::c_int) {
    request_cancel();
}
pub fn request_cancel() {
    CANCELLED.store(true, Ordering::Relaxed);
}
pub fn cancelled() -> bool {
    CANCELLED.load(Ordering::Relaxed)
}
pub fn check_cancelled() -> Result<()> {
    ensure!(
        !cancelled(),
        "connection cancelled; an unresolved mutation remains retained until its exact outcome or explicit fence"
    );
    Ok(())
}
pub fn install_cancellation() -> Result<()> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = cancel as *const () as usize;
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
    }
    for signal in [libc::SIGINT, libc::SIGTERM] {
        ensure!(
            unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } == 0,
            "cannot install connection cancellation handler"
        );
    }
    Ok(())
}

use crate::{route_profile, transfer_files as files};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
};
static SELECTED: Mutex<Option<PathBuf>> = Mutex::new(None);
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Endpoint {
    pub format: String,
    pub profile: PathBuf,
    pub route: route_profile::Profile,
}
impl Endpoint {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = files::read_single(path, 600000, true)?;
        let endpoint: Self = serde_json::from_slice(&bytes)?;
        ensure!(
            endpoint.format == "HyperNetRelayEndpoint/1",
            "unsupported selected endpoint"
        );
        endpoint.route.validate()?;
        ensure!(
            endpoint.profile.is_absolute() && endpoint.profile.canonicalize()? == endpoint.profile,
            "relay endpoint requires its exact canonical private client profile"
        );
        if let Some(selected) = SELECTED
            .lock()
            .map_err(|_| anyhow::anyhow!("route selection poisoned"))?
            .as_ref()
        {
            ensure!(
                *selected == endpoint.profile,
                "endpoint belongs to another selected client profile"
            );
        }
        crate::networks::route_key(&endpoint.profile, &endpoint.route)?;
        Ok(endpoint)
    }
    pub fn prepare(self) -> Result<Prepared> {
        let key = crate::networks::route_key(&self.profile, &self.route)?;
        let deadline = crate::authority_challenge::boot_time_ms()?
            .checked_add(self.route.limits.duration_ms)
            .context("private route setup deadline overflow")?;
        let protocol = match self.route.protocol {
            1 => "Authority",
            2 => "Content",
            3 => "Media",
            4 => "Mail",
            5 => "Transfer",
            6 => "Bridge",
            _ => "Unknown",
        };
        let session =
            crate::route_connector::Session::connect(&self.route, &key, deadline, &cancelled)
                .with_context(|| format!("prepare private {protocol} route"))?;
        Ok(Prepared {
            endpoint: self,
            deadline,
            session: std::cell::RefCell::new(session),
        })
    }
}
pub struct Prepared {
    endpoint: Endpoint,
    deadline: u64,
    session: std::cell::RefCell<crate::route_connector::Session<'static>>,
}
impl Prepared {
    pub(crate) fn setup_deadline(&self) -> u64 {
        self.deadline
    }
    #[cfg(test)]
    pub(crate) fn from_channel(
        endpoint: Endpoint,
        session: crate::route_connector::Session<'static>,
        deadline: u64,
    ) -> Self {
        Self {
            endpoint,
            deadline,
            session: std::cell::RefCell::new(session),
        }
    }
    pub(crate) fn route(&self) -> &route_profile::Profile {
        &self.endpoint.route
    }
    pub fn exchange(&self, request: &[u8], deadline: u64, maximum: usize) -> Result<Vec<u8>> {
        let bytes = self
            .session
            .try_borrow_mut()
            .context("private route session already has an active exchange")?
            .exchange(request, deadline, maximum)?;
        let observation = serde_json::json!({
            "format":"HyperNetRouteObservation/1","network":hex::encode(self.endpoint.route.network),
            "incarnation":hex::encode(self.endpoint.route.incarnation),"relay":hex::encode(self.endpoint.route.relay.service),
            "relayAddress":self.endpoint.route.relay_address,"relayTransportKey":hex::encode(self.endpoint.route.relay.transport_key),
            "destination":hex::encode(self.endpoint.route.destination.service),
            "destinationTransportKey":hex::encode(self.endpoint.route.destination.transport_key),
            "assurance":self.endpoint.route.assurance,"tlsVersion":"TLS1.3","earlyData":false,"resumption":false,
            "sourceAddressForwarded":false,"observedAtBootMs":crate::authority_challenge::boot_time_ms()?,
            "physicalPathVerified":false,"membershipAnonymous":false,
        });
        let parent = self
            .endpoint
            .profile
            .parent()
            .context("profile parent absent")?;
        let directory = files::private_directory(parent)?;
        files::atomic_at(
            &directory,
            observation_path(&self.endpoint.profile)?
                .file_name()
                .context("observation filename absent")?,
            &serde_json::to_vec(&observation)?,
            true,
        )?;
        Ok(bytes)
    }
}
pub(crate) fn observation_path(profile: &Path) -> Result<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let profile = profile.canonicalize()?;
    let digest = crate::trust_wire::digest(profile.as_os_str().as_bytes());
    Ok(profile
        .parent()
        .context("profile parent absent")?
        .join(format!("RouteObservation{}.json", hex::encode(digest))))
}
pub fn require_local_allowed() -> Result<()> {
    ensure!(
        SELECTED
            .lock()
            .map_err(|_| anyhow::anyhow!("route selection poisoned"))?
            .is_none(),
        "selected network requires relay transport; local or direct fallback is prohibited"
    );
    Ok(())
}
pub struct Selection;
impl Selection {
    pub fn new(profile: &Path) -> Result<Self> {
        let mut selected = SELECTED
            .lock()
            .map_err(|_| anyhow::anyhow!("route selection poisoned"))?;
        ensure!(selected.is_none(), "a client network is already selected");
        *selected = Some(profile.canonicalize()?);
        Ok(Self)
    }
}
impl Drop for Selection {
    fn drop(&mut self) {
        if let Ok(mut selected) = SELECTED.lock() {
            *selected = None;
        }
    }
}
