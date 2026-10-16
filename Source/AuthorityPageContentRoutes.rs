// SPDX-License-Identifier: MIT
// Private local routes bind explicit host identities to owner-selected local transports.
use super::*;
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
const ROUTES: &str = "ContentRoutes.json";
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Route {
    host: String,
    service_socket: Option<PathBuf>,
    service_directory: Option<PathBuf>,
    core: PathBuf,
}
#[derive(Args)]
pub struct Options {
    /// Existing private requester directory in which to retain this explicit route.
    #[arg(long)]
    directory: PathBuf,
    #[arg(long)]
    host: String,
    #[arg(
        long,
        conflicts_with = "service_directory",
        required_unless_present = "service_directory"
    )]
    service_socket: Option<PathBuf>,
    #[arg(long, conflicts_with = "service_socket")]
    service_directory: Option<PathBuf>,
    #[arg(long, default_value = "HyperNet")]
    core: PathBuf,
}
fn load(directory: &std::fs::File) -> Result<Vec<Route>> {
    match files::read_at(directory, OsStr::new(ROUTES), 65536, true) {
        Ok(bytes) => {
            let routes: Vec<Route> = serde_json::from_slice(&bytes)?;
            ensure!(routes.len() <= 64, "too many local content routes");
            ensure!(
                routes.windows(2).all(|w| w[0].host < w[1].host),
                "content routes repeat or are unsorted"
            );
            for route in &routes {
                route.transport()?;
            }
            Ok(routes)
        }
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(vec![])
        }
        Err(error) => Err(error),
    }
}
pub(crate) fn search_route(
    c: &Client,
    placement: &content::Placement,
    search: bool,
) -> Result<(VersionRef, PathBuf)> {
    let directory = files::private_directory(&c.directory)?;
    let routes = load(&directory)?;
    let cache = c.cache()?;
    for host in &placement.hosts {
        let record = cache.state.record(147, host.id)?;
        ensure!(record.reference == *host, "search content host changed");
        let configured = page::Host::parse(
            &record.payload,
            cache.state.network,
            cache.state.incarnation,
        )?;
        if configured.withdrawn
            || !configured
                .profile
                .content
                .as_ref()
                .is_some_and(|p| !search || p.search)
        {
            continue;
        }
        if let Some(path) = routes
            .iter()
            .find(|r| r.host == hex::encode(host.id))
            .and_then(|r| r.service_socket.clone())
        {
            return Ok((host.clone(), path));
        }
    }
    anyhow::bail!("no exact consenting search host has an explicit service route")
}
impl Route {
    fn transport(&self) -> Result<Transport> {
        let host = id(&self.host)?;
        match (&self.service_socket, &self.service_directory) {
            (Some(socket), None) => {
                ensure!(
                    socket.is_absolute(),
                    "content socket route must be absolute"
                );
                Ok(Transport::socket(host, socket.clone()))
            }
            (None, Some(directory)) => {
                crate::private_route_client::require_local_allowed()?;
                ensure!(
                    directory.is_absolute(),
                    "installed content directory must be absolute"
                );
                Ok(Transport::installed(
                    host,
                    directory.clone(),
                    self.core.clone(),
                ))
            }
            _ => anyhow::bail!("content route requires exactly one local transport"),
        }
    }
}
pub fn retain(options: Options) -> Result<()> {
    let directory = files::private_directory(&options.directory)?;
    let _lock = files::lock(&directory)?;
    let route = Route {
        host: options.host,
        service_socket: options.service_socket,
        service_directory: options.service_directory,
        core: options.core,
    };
    route.transport()?;
    if let Some(socket) = &route.service_socket {
        crate::authority_local_transport::LocalControl::validate(socket)?;
    }
    if let Some(path) = &route.service_directory {
        files::private_directory(path)?;
    }
    let mut routes = load(&directory)?;
    routes.retain(|r| r.host != route.host);
    routes.push(route);
    routes.sort_by(|a, b| a.host.cmp(&b.host));
    ensure!(routes.len() <= 64, "too many local content routes");
    files::atomic_at(
        &directory,
        OsStr::new(ROUTES),
        &serde_json::to_vec(&routes)?,
        true,
    )?;
    crate::print_value(
        &json!({"status":"ContentRouteRetained","routes":routes.len(),"directory":options.directory}),
    )
}
pub(crate) fn fetch_source(
    c: &mut Client,
    grant: &VersionRef,
    placement: &VersionRef,
    effect: Effect,
) -> Result<Vec<u8>> {
    fetch_source_from(c, grant, placement, effect, None)
}
pub(crate) fn fetch_source_from(
    c: &mut Client,
    grant: &VersionRef,
    placement: &VersionRef,
    effect: Effect,
    selected_host: Option<&VersionRef>,
) -> Result<Vec<u8>> {
    ensure!(
        matches!(effect, Effect::Read | Effect::Inspect),
        "source fetch requires read or inspection"
    );
    resume_metadata(c, placement)?;
    if c.store.resume_ordinary()?.is_none() {
        c.action(
            Action::Content(content::Command::Get {
                placement: placement.clone(),
            }),
            Some(grant.clone()),
            Resolved::default(),
        )?;
    }
    let cache = c.cache()?;
    let record = cache.state.record(159, placement.id)?;
    ensure!(
        record.reference == *placement,
        "source fetch selected another placement"
    );
    let value = content::Placement::parse(&record.payload)?;
    let directory = files::private_directory(&c.directory)?;
    let routes = load(&directory)?;
    let pending_host = client::pending(&c.store)?
        .map(|request| match request.command() {
            Action::Content(content::Command::Authorise {
                placement: p,
                host,
                effect: e,
                ..
            }) if p == placement && *e == effect => Ok(host.clone()),
            _ => anyhow::bail!("another request is pending before content fetch"),
        })
        .transpose()?;
    let host=value.hosts.iter().find(|host|selected_host.is_none_or(|p|p==*host) && pending_host.as_ref().is_none_or(|p|p==*host) && routes.iter().any(|r|r.host==hex::encode(host.id))).context("no explicitly selected content route for this exact placement host; bind a host with pages content route")?;
    let route = routes
        .iter()
        .find(|r| r.host == hex::encode(host.id))
        .unwrap()
        .transport()?;
    let path = c.directory.join(format!(
        "Content{}Host{}Effect{}",
        hex::encode(placement.digest),
        hex::encode(host.id),
        effect.code()
    ));
    job_with_metadata(
        c,
        grant.clone(),
        placement.clone(),
        &route,
        &path,
        effect,
        None,
    )
}

pub(crate) fn upload_source(
    c: &mut Client,
    grant: &VersionRef,
    placement: &VersionRef,
    bytes: &[u8],
) -> Result<()> {
    write_source(c, grant, placement, bytes, Effect::Upload)
}
pub(crate) fn repair_source(
    c: &mut Client,
    grant: &VersionRef,
    placement: &VersionRef,
    bytes: &[u8],
) -> Result<()> {
    write_source(c, grant, placement, bytes, Effect::Repair)
}
pub(crate) fn selected_transport(c: &Client, hosts: &[VersionRef]) -> Result<Transport> {
    let directory = files::private_directory(&c.directory)?;
    let routes = load(&directory)?;
    for host in hosts {
        if let Some(route) = routes.iter().find(|r| r.host == hex::encode(host.id)) {
            return route.transport();
        }
    }
    anyhow::bail!("no explicit transport retained for the selected content or media hosts")
}
fn write_source(
    c: &mut Client,
    grant: &VersionRef,
    placement: &VersionRef,
    bytes: &[u8],
    effect: Effect,
) -> Result<()> {
    resume_metadata(c, placement)?;
    let cache = c.cache()?;
    let record = cache.state.record(159, placement.id)?;
    ensure!(record.reference == *placement, "upload placement changed");
    let selected = content::Placement::parse(&record.payload)?;
    ensure!(
        bytes.len() as u64 == selected.bytes && digest(bytes) == selected.digest,
        "upload bytes differ from exact placement"
    );
    let directory = files::private_directory(&c.directory)?;
    let routes = load(&directory)?;
    let pending_host = client::pending(&c.store)?
        .map(|request| match request.command() {
            Action::Content(content::Command::Authorise {
                placement: p,
                host,
                effect: e,
                ..
            }) if p == placement && *e == effect => Ok(host.clone()),
            _ => anyhow::bail!("another content effect is pending"),
        })
        .transpose()?;
    let mut hosts = selected
        .hosts
        .iter()
        .filter(|host| routes.iter().any(|r| r.host == hex::encode(host.id)))
        .cloned()
        .collect::<Vec<_>>();
    ensure!(
        hosts.len() as u64 >= selected.copies
            && pending_host.as_ref().is_none_or(|h| hosts.contains(h)),
        "explicit content routes cannot meet the required copies"
    );
    hosts.sort_by_key(|host| pending_host.as_ref() != Some(host));
    for host in hosts {
        let transport = routes
            .iter()
            .find(|r| r.host == hex::encode(host.id))
            .context("content route disappeared")?
            .transport()?;
        let path = c.directory.join(format!(
            "Content{}Host{}Effect{}",
            hex::encode(placement.digest),
            hex::encode(host.id),
            effect.code()
        ));
        job(
            c,
            grant.clone(),
            placement.clone(),
            &transport,
            &path,
            effect,
            Some(bytes),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::{
        fd::AsRawFd,
        unix::{fs::PermissionsExt, net::UnixListener},
    };

    struct Directory(PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn first_content_route_is_retained_and_corrupt_or_symlink_routes_refuse() {
        let path =
            std::env::temp_dir().join(format!("HyperNetRoutes{}", crate::random_hex::<16>()));
        let _cleanup = Directory(path.clone());
        let directory = files::create_directory(&path).unwrap();
        assert!(load(&directory).unwrap().is_empty());
        let socket = path.join("Control.sock");
        let bound =
            PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join("Control.sock");
        let _listener = UnixListener::bind(bound).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        retain(Options {
            directory: path.clone(),
            host: hex::encode([11; 32]),
            service_socket: Some(socket.clone()),
            service_directory: None,
            core: PathBuf::from("HyperNet"),
        })
        .unwrap();
        let routes = load(&directory).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].host, hex::encode([11; 32]));
        assert_eq!(routes[0].service_socket.as_ref(), Some(&socket));
        std::fs::write(path.join(ROUTES), b"corrupt").unwrap();
        assert!(load(&directory).is_err());
        std::fs::remove_file(path.join(ROUTES)).unwrap();
        std::os::unix::fs::symlink(path.join("Missing.json"), path.join(ROUTES)).unwrap();
        assert!(load(&directory).is_err());
    }
}
