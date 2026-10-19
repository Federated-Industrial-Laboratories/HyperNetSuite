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
    sync::{Arc, Mutex, Weak},
};
pub(crate) struct AuthorityPool {
    active: bool,
    route: Option<Prepared>,
}
impl AuthorityPool {
    pub(crate) fn shared() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            active: true,
            route: None,
        }))
    }
    pub(crate) fn take(pool: &Arc<Mutex<Self>>, endpoint: &Endpoint) -> Result<Option<Prepared>> {
        let mut pool = pool
            .lock()
            .map_err(|_| anyhow::anyhow!("authority transport pool poisoned"))?;
        let Some(mut route) = pool.route.take() else {
            return Ok(None);
        };
        let reusable = pool.active && route.matches(endpoint)? && route.session.borrow().reusable();
        if reusable {
            route.reused = true;
            Ok(Some(route))
        } else {
            Ok(None)
        }
    }
    fn close(&mut self) {
        self.active = false;
        self.route = None;
    }
}
/// One finite application connection belongs to its caller and never supplies cached permission.
#[derive(Default)]
pub(crate) struct ContentPool {
    route: Option<Prepared>,
}
impl ContentPool {
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.route.is_none()
    }
    pub(crate) fn clear(&mut self) {
        self.route = None;
    }
    pub(crate) fn prepare(
        &mut self,
        path: &Path,
        duration: u64,
        protocol: u64,
        wire_bytes: u64,
        check: impl FnOnce(&Endpoint) -> Result<()>,
    ) -> Result<Prepared> {
        // Take first: even a failed profile or subject check invalidates the retained connection.
        let retained = self.route.take();
        check_cancelled()?;
        let endpoint = Endpoint::load(path)?;
        ensure!(
            matches!(protocol, 2 | 3 | 5) && endpoint.route.protocol == protocol,
            "application exchange requires its exact selected protocol"
        );
        check(&endpoint)?;
        if let Some(route) = retained
            && route.matches(&endpoint)?
            && route
                .session
                .borrow()
                .reusable_exchange(duration, wire_bytes)
        {
            return Ok(route);
        }
        endpoint.prepare()
    }
    pub(crate) fn retain(&mut self, route: Prepared, duration: u64) {
        if !cancelled() && route.session.borrow().reusable_for(duration) {
            self.route = Some(route);
        }
    }
}
struct Selected {
    profile: PathBuf,
    authority: Arc<Mutex<AuthorityPool>>,
}
static SELECTED: Mutex<Option<Selected>> = Mutex::new(None);
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Endpoint {
    pub format: String,
    pub profile: PathBuf,
    pub route: route_profile::Profile,
}
impl Endpoint {
    pub(crate) fn same_identity(&self, other: &Self) -> Result<bool> {
        Ok(serde_json::to_vec(self)? == serde_json::to_vec(other)?)
    }
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
                selected.profile == endpoint.profile,
                "endpoint belongs to another selected client profile"
            );
        }
        crate::networks::route_key(&endpoint.profile, &endpoint.route)?;
        Ok(endpoint)
    }
    pub fn prepare(self) -> Result<Prepared> {
        check_cancelled()?;
        let key = crate::networks::route_key(&self.profile, &self.route)?;
        let authority = {
            let selected = SELECTED
                .lock()
                .map_err(|_| anyhow::anyhow!("route selection poisoned"))?;
            if let Some(selected) = selected.as_ref() {
                ensure!(
                    selected.profile == self.profile,
                    "selected client profile changed"
                );
            }
            selected
                .as_ref()
                .filter(|_| self.route.protocol == 1)
                .map(|selected| Arc::downgrade(&selected.authority))
                .unwrap_or_default()
        };
        if let Some(pool) = authority.upgrade()
            && let Some(route) = AuthorityPool::take(&pool, &self)?
        {
            return Ok(route);
        }
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
            observed: std::cell::Cell::new(false),
            authority,
            reused: false,
            completed_floor: None,
        })
    }
}
pub struct Prepared {
    endpoint: Endpoint,
    deadline: u64,
    session: std::cell::RefCell<crate::route_connector::Session<'static>>,
    observed: std::cell::Cell<bool>,
    authority: Weak<Mutex<AuthorityPool>>,
    reused: bool,
    completed_floor: Option<(
        crate::authority_proof::Prefix,
        Option<crate::authority_history::TreeHead>,
    )>,
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
            observed: std::cell::Cell::new(false),
            authority: Weak::new(),
            reused: false,
            completed_floor: None,
        }
    }
    pub(crate) fn route(&self) -> &route_profile::Profile {
        &self.endpoint.route
    }
    pub(crate) fn reused(&self) -> bool {
        self.reused
    }
    pub(crate) fn fits_authority_challenge(&self) -> bool {
        self.session.borrow().reusable()
    }
    pub(crate) fn take_completed_floor(
        &mut self,
    ) -> Option<(
        crate::authority_proof::Prefix,
        Option<crate::authority_history::TreeHead>,
    )> {
        self.completed_floor.take()
    }
    fn matches(&self, endpoint: &Endpoint) -> Result<bool> {
        self.endpoint.same_identity(endpoint)
    }
    #[cfg(test)]
    pub(crate) fn in_pool(mut self, pool: &Arc<Mutex<AuthorityPool>>) -> Self {
        self.authority = Arc::downgrade(pool);
        self
    }
    /// Only a fully validated successful operation may retain its connection.
    pub(crate) fn retain(
        mut self,
        completed_floor: Option<(
            crate::authority_proof::Prefix,
            Option<crate::authority_history::TreeHead>,
        )>,
    ) {
        if cancelled() || !self.session.borrow().reusable() {
            return;
        }
        self.completed_floor = completed_floor;
        if let Some(pool) = self.authority.upgrade()
            && let Ok(mut pool) = pool.lock()
            && pool.active
            && pool.route.is_none()
        {
            pool.route = Some(self);
        }
    }
    pub fn exchange(&self, request: &[u8], deadline: u64, maximum: usize) -> Result<Vec<u8>> {
        let bytes = self
            .session
            .try_borrow_mut()
            .context("private route session already has an active exchange")?
            .exchange(request, deadline, maximum)?;
        if self.observed.get() {
            return Ok(bytes);
        }
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
        self.observed.set(true);
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
pub struct Selection {
    authority: Arc<Mutex<AuthorityPool>>,
}
impl Selection {
    pub fn new(profile: &Path) -> Result<Self> {
        let mut selected = SELECTED
            .lock()
            .map_err(|_| anyhow::anyhow!("route selection poisoned"))?;
        ensure!(selected.is_none(), "a client network is already selected");
        let authority = AuthorityPool::shared();
        *selected = Some(Selected {
            profile: profile.canonicalize()?,
            authority: authority.clone(),
        });
        Ok(Self { authority })
    }
}
impl Drop for Selection {
    fn drop(&mut self) {
        if let Ok(mut selected) = SELECTED.lock() {
            *selected = None;
        }
        if let Ok(mut pool) = self.authority.lock() {
            pool.close();
        }
    }
}
