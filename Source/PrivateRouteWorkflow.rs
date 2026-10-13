// SPDX-License-Identifier: MIT
// Client commands inherit one retained network and cannot replace it with local or direct transports.
use super::*;
use crate::private_route_client::{Endpoint, Selection};
use clap::{Args, CommandFactory, Parser};
use sha2::Digest as _;
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
};
#[derive(Args)]
pub struct Connect {
    #[arg(long)]
    profile: PathBuf,
    /// Exact retained destination ID for a store exchange when the command does not name its service.
    #[arg(long)]
    route: Option<String>,
    /// Separate retained bridge route for foreign media proof discovery.
    #[arg(long)]
    bridge_route: Option<String>,
    #[arg(last = true, required = true, num_args = 1..)]
    command: Vec<OsString>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SavedRoute {
    pub service: String,
    pub subject: String,
    pub protocol: u64,
}
fn routes(directory: &Path) -> Result<Vec<SavedRoute>> {
    let path = directory.join("Routes.json");
    let bytes = files::read_single(&path, 65536, true)?;
    let routes: Vec<SavedRoute> = serde_json::from_slice(&bytes)?;
    ensure!(
        routes.len() <= 128 && routes.windows(2).all(|w| w[0].service < w[1].service),
        "invalid retained route inventory"
    );
    for route in &routes {
        trust::hex32(&route.service)?;
        trust::hex32(&route.subject)?;
        ensure!((1..=6).contains(&route.protocol), "invalid route protocol");
        let endpoint = Endpoint::load(&route_path(directory, &route.service))?;
        ensure!(
            hex::encode(endpoint.route.destination.service) == route.service
                && endpoint.route.protocol == route.protocol,
            "route inventory differs from retained endpoint"
        );
    }
    Ok(routes)
}
fn route_path(directory: &Path, service: &str) -> PathBuf {
    directory.join("Routes").join(format!("{service}.json"))
}
fn value(arguments: &[OsString], name: &str) -> Result<Option<String>> {
    let flag = format!("--{name}");
    for (i, arg) in arguments.iter().enumerate() {
        if arg == OsStr::new(&flag) {
            return Ok(Some(
                arguments
                    .get(i + 1)
                    .context("flag value absent")?
                    .to_str()
                    .context("non-UTF8 flag value")?
                    .into(),
            ));
        }
        if let Some(value) = arg
            .to_str()
            .and_then(|v| v.strip_prefix(&(flag.clone() + "=")))
        {
            return Ok(Some(value.into()));
        }
    }
    Ok(None)
}
fn has(arguments: &[OsString], name: &str) -> bool {
    let flag = format!("--{name}");
    arguments.iter().any(|v| {
        v == OsStr::new(&flag)
            || v.to_str()
                .is_some_and(|v| v.starts_with(&(flag.clone() + "=")))
    })
}
fn leaf<'a>(command: &'a clap::Command, words: &[OsString]) -> Result<&'a clap::Command> {
    if command.get_subcommands().next().is_none() {
        return Ok(command);
    }
    let name = words
        .first()
        .and_then(|v| v.to_str())
        .context("command name required before options")?;
    let next = command
        .find_subcommand(name)
        .context("unknown network client command")?;
    leaf(next, &words[1..])
}
fn append(
    arguments: &mut Vec<OsString>,
    available: &BTreeMap<String, String>,
    name: &str,
    value: impl Into<OsString>,
) {
    if available.contains_key(name) && !has(arguments, name) {
        arguments.push(format!("--{name}").into());
        arguments.push(value.into());
    }
}
fn online_defaults(
    argv: &mut Vec<OsString>,
    available: &BTreeMap<String, String>,
    checked: &trust::Verified,
    joined: &onboarding::Joined,
) -> Result<()> {
    append(
        argv,
        available,
        "bootstrap",
        joined.directory.join("Bootstrap.cbor"),
    );
    append(
        argv,
        available,
        "bootstrap-digest",
        hex::encode(checked.file_digest()),
    );
    let requester = if !available.contains_key("key") {
        value(argv, "mailbox")?
            .map(|name| {
                joined.directory.join(format!(
                    "MailRequester{}",
                    hex::encode(trust_wire::digest(name.as_bytes()))
                ))
            })
            .unwrap_or_else(|| joined.directory.join("Requester"))
    } else {
        joined.directory.join("Requester")
    };
    append(argv, available, "directory", requester);
    append(
        argv,
        available,
        "clock-witness",
        joined.clock_witness.clone(),
    );
    append(argv, available, "key", joined.directory.join("Device.json"));
    append(
        argv,
        available,
        "socket",
        joined.directory.join("AuthorityRoute.json"),
    );
    append(argv, available, "grant", joined.reader_grant.clone());
    Ok(())
}
pub fn connect(arguments: Connect) -> Result<()> {
    let (profile, checked) = load(&arguments.profile)?;
    let joined = profile
        .joined
        .as_ref()
        .filter(|v| v.admitted)
        .context("network has no retained successful membership; run network join")?;
    ensure!(
        matches!(
            arguments.command.first().and_then(|v| v.to_str()),
            Some(
                "routes"
                    | "browse"
                    | "pages"
                    | "media"
                    | "mail"
                    | "forms"
                    | "transfers"
                    | "services"
                    | "federation"
                    | "applications"
                    | "authority-inspection"
            )
        ),
        "network connect requires a normal client command"
    );
    let schema = crate::Options::command();
    let selected = leaf(&schema, &arguments.command)?;
    let available = selected
        .get_arguments()
        .filter_map(|a| {
            a.get_long()
                .map(|name| (name.to_string(), a.get_id().to_string()))
        })
        .collect::<BTreeMap<_, _>>();
    let mut argv = arguments.command;
    for forbidden in [
        "bootstrap",
        "bootstrap-digest",
        "socket",
        "clock-witness",
        "clock-monitor-key",
        "host-kernel-boot",
        "service-socket",
        "service-directory",
        "media-route",
        "media-service",
        "media-core",
        "form-socket",
        "form-service-directory",
        "form-core",
        "bridge-socket",
        "bridge-directory",
        "bridge-core",
        "core",
    ] {
        ensure!(
            !has(&argv, forbidden),
            "network connect controls --{forbidden}; a transport or trust override is not allowed"
        );
    }
    let _selection = Selection::new(&arguments.profile)?;
    let known = routes(&joined.directory)?;
    online_defaults(&mut argv, &available, &checked, joined)?;
    if available.contains_key("service-socket") {
        let service = value(&argv, "service")?.or(value(&argv, "host")?);
        let expected = match argv.first().and_then(|v| v.to_str()) {
            Some("media") => 3,
            Some("mail" | "forms") => 4,
            Some("transfers") => 5,
            Some("federation") if argv.get(1).is_some_and(|s| s == "media") => 3,
            Some("federation") => 6,
            _ => 2,
        };
        let route = known.iter().filter(|r| r.protocol == expected).find(|r| arguments.route.as_ref().map_or_else(|| service.as_ref().is_some_and(|s| *s == r.subject), |id| *id == r.service))
            .context("store command requires a retained service route; select it with network connect --route")?;
        append(
            &mut argv,
            &available,
            "service-socket",
            route_path(&joined.directory, &route.service),
        );
    }
    if available.contains_key("bridge-socket") {
        let selected = arguments.bridge_route.as_ref().context(
            "foreign media requires --bridge-route with its retained destination identifier",
        )?;
        let route = known
            .iter()
            .find(|r| r.service == *selected && r.protocol == 6)
            .context("selected bridge route is absent")?;
        append(
            &mut argv,
            &available,
            "bridge-socket",
            route_path(&joined.directory, &route.service),
        );
    }
    if available.contains_key("media-route") {
        append(
            &mut argv,
            &available,
            "media-directory",
            joined.directory.join("Media"),
        );
        for route in known.iter().filter(|r| r.protocol == 3) {
            argv.push("--media-route".into());
            argv.push(
                format!(
                    "{}={}",
                    route.subject,
                    route_path(&joined.directory, &route.service).display()
                )
                .into(),
            );
        }
    }
    if let Some(service) = value(&argv, "form-service")? {
        let route = known
            .iter()
            .find(|r| r.protocol == 4 && r.subject == service)
            .context("form service has no retained relay route")?;
        append(
            &mut argv,
            &available,
            "form-socket",
            route_path(&joined.directory, &route.service),
        );
    }
    argv.insert(0, "HyperNetSuite".into());
    let parsed = crate::Options::try_parse_from(argv)?;
    crate::dispatch(parsed.command)
}
pub fn status(path: &Path) -> Result<()> {
    let (profile, checked) = load(path)?;
    let mut value = json!({"state":if profile.joined.as_ref().is_some_and(|v|v.admitted) {"Joined"} else {"Prepared"},
        "network":checked.summary.network,"incarnation":checked.summary.incarnation,
        "minimumRoute":profile.minimum_route,"directFallback":false,"hostingRoles":[],
        "currentAuthority":false,"networkUsed":false,"operatorIndependenceVerified":false});
    if let Some(joined) = &profile.joined {
        value["directory"] = json!(joined.directory);
        value["member"] = json!(joined.member);
        value["routes"] = json!(routes(&joined.directory)?);
        value["clockHealthy"] =
            json!(crate::authority_clock::health(&joined.clock_witness).is_ok());
        let store = crate::authority_floor::Store::open(
            &joined.directory.join("Requester"),
            checked.descriptor().clone(),
        )?;
        value["retainedCertifiedHeight"] = json!(store.prefix().height());
        value["pendingMutation"] = json!(store.resume_ordinary()?.is_some());
    }
    let observation = crate::private_route_client::observation_path(path)?;
    match files::read_single(&observation, 16384, true) {
        Ok(bytes) => {
            let observation: serde_json::Value = serde_json::from_slice(&bytes)?;
            ensure!(
                observation["network"] == checked.summary.network
                    && observation["incarnation"] == checked.summary.incarnation,
                "retained connection observation belongs to another network"
            );
            value["lastConnectionObservation"] = observation;
        }
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
        Err(error) => return Err(error),
    }
    crate::print_value(&value)
}

#[derive(Args)]
pub struct Retain {
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    route_profile: PathBuf,
    /// SHA256 of the complete route profile received through an authenticated channel.
    #[arg(long)]
    fingerprint: String,
    /// Domain service or host identifier carried by content, media, mail or transfer metadata.
    #[arg(long)]
    subject: String,
}
pub fn retain(arguments: Retain) -> Result<()> {
    let _guard = profile_lock(&arguments.profile)?;
    let (profile, _) = load(&arguments.profile)?;
    let joined = profile
        .joined
        .as_ref()
        .filter(|v| v.admitted)
        .context("join the network before retaining another route")?;
    let bytes = files::read_single(&arguments.route_profile, 600000, false)?;
    ensure!(
        sha2::Sha256::digest(&bytes).as_slice() == trust::hex32(&arguments.fingerprint)?,
        "route differs from independently accepted fingerprint"
    );
    let route: crate::route_profile::Profile = serde_json::from_slice(&bytes)?;
    route_key(&arguments.profile, &route)?;
    let subject = trust::hex32(&arguments.subject)?;
    ensure!(subject != [0; 32], "route subject is absent");
    retain_route(&arguments.profile, &joined.directory, route, subject)?;
    crate::print_value(
        &json!({"state":"RelayRouteRetained","directFallback":false,"networkUsed":false}),
    )
}
pub(super) fn retain_route(
    profile: &Path,
    directory: &Path,
    route: crate::route_profile::Profile,
    subject: [u8; 32],
) -> Result<()> {
    route_key(profile, &route)?;
    let root = files::private_directory(directory)?;
    let route_root = directory.join("Routes");
    let route_dir = if route_root.exists() {
        files::private_directory(&route_root)?
    } else {
        files::create_directory(&route_root)?
    };
    let service = hex::encode(route.destination.service);
    let protocol = route.protocol;
    let endpoint = Endpoint {
        format: "HyperNetRelayEndpoint/1".into(),
        profile: profile.canonicalize()?,
        route,
    };
    let mut inventory = match files::read_single(&directory.join("Routes.json"), 65536, true) {
        Ok(bytes) => serde_json::from_slice::<Vec<SavedRoute>>(&bytes)?,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            vec![]
        }
        Err(error) => return Err(error),
    };
    inventory.retain(|r| r.service != service);
    inventory.push(SavedRoute {
        service: service.clone(),
        subject: hex::encode(subject),
        protocol,
    });
    inventory.sort_by(|a, b| a.service.cmp(&b.service));
    ensure!(
        inventory.len() <= 128,
        "retained route inventory capacity exceeded"
    );
    let content = if protocol == 2 {
        let content = inventory.iter().filter(|r|r.protocol == 2).map(|r|json!({
            "host":r.subject,"serviceSocket":route_path(directory,&r.service),"serviceDirectory":null,"core":"HyperNet"
        })).collect::<Vec<_>>();
        let mut content = content;
        content.sort_by(|a, b| a["host"].as_str().cmp(&b["host"].as_str()));
        ensure!(
            content.windows(2).all(|w| w[0]["host"] != w[1]["host"]),
            "one content host has several selected routes"
        );
        Some(content)
    } else {
        None
    };
    files::atomic_at(
        &route_dir,
        OsStr::new(&format!("{service}.json")),
        &serde_json::to_vec(&endpoint)?,
        true,
    )?;
    files::atomic_at(
        &root,
        OsStr::new("Routes.json"),
        &serde_json::to_vec(&inventory)?,
        true,
    )?;
    if protocol == 1 {
        files::atomic_at(
            &root,
            OsStr::new("AuthorityRoute.json"),
            &serde_json::to_vec(&endpoint)?,
            true,
        )?;
    }
    if let Some(content) = content {
        let requester = files::private_directory(&directory.join("Requester"))?;
        files::atomic_at(
            &requester,
            OsStr::new("ContentRoutes.json"),
            &serde_json::to_vec(&content)?,
            true,
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "PrivateRouteWorkflowTests.rs"]
mod tests;
