// SPDX-License-Identifier: Apache-2.0
// A native hosting review binds exact installed software, resource limits and public exposure.
use super::{configuration::Configuration, engine::*};
use crate::admission::{host_service, protocol, runtime};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::Path,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

fn cidr(value: &str) -> Result<(u32, u32)> {
    let (ip, prefix) = value.split_once('/').context("subnet prefix absent")?;
    let ip: Ipv4Addr = ip.parse()?;
    let prefix: u32 = prefix.parse()?;
    ensure!(prefix <= 32, "subnet prefix differs");
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let start = u32::from(ip);
    ensure!(start & mask == start, "subnet has host bits");
    Ok((start, start | !mask))
}
fn subnet_available(c: &Configuration, value: &Value) -> Result<bool> {
    ensure!(
        value["version"] == 1 && value["complete"] == true,
        "subnet inventory incomplete"
    );
    let entries = value["ipv4Subnets"]
        .as_array()
        .context("subnet inventory absent")?;
    ensure!(entries.len() <= 1024, "subnet inventory exceeds bound");
    for entry in entries {
        let (start, end) = cidr(entry.as_str().context("subnet entry differs")?)?;
        for n in 0..4 {
            let (own_first, own_last) =
                cidr(&format!("10.89.{}.0/24", u16::from(c.subnet_octet) + n))?;
            if start <= own_last && own_first <= end {
                return Ok(false);
            }
        }
    }
    Ok(true)
}
fn requirement(component: &str, ready: bool, action: &str) -> Value {
    json!({"component":component,"ready":ready,"action":action})
}
pub fn review(
    root: &Path,
    installation: &Installation,
    c: &Configuration,
    stop: &AtomicBool,
) -> Result<Value> {
    c.validate()?;
    ensure!(
        root.is_absolute()
            && root
                .components()
                .all(|c| !matches!(c, std::path::Component::ParentDir)),
        "native host path must be absolute"
    );
    let mut requirements = Vec::new();
    let end = Instant::now() + Duration::from_secs(180);
    for (name, path) in [
        ("Rootless Podman", Path::new("/usr/bin/podman")),
        ("OpenSSL", Path::new("/usr/bin/openssl")),
        ("User service manager", Path::new("/usr/bin/systemctl")),
        ("Clock observer", c.clock.chronyc.as_path()),
    ] {
        requirements.push(requirement(
            name,
            runtime::executable(path).is_ok(),
            "Install the distribution prerequisite, then review again.",
        ));
    }
    if let Some(path) = &c.clock.chronyd {
        requirements.push(requirement(
            "Private authenticated clock",
            runtime::executable(path).is_ok(),
            "Install chrony for the private authenticated clock observer.",
        ));
    }
    if let Some(path) = &c.clock.socket {
        requirements.push(requirement(
            "Clock control socket",
            path.exists(),
            "Select the existing local clock observer socket.",
        ));
    }
    for (name, executable) in [
        ("Core protocol", &installation.core),
        ("Suite protocol", &installation.suite),
    ] {
        let features = invoke(executable, &bytes(&["protocol-features"]), stop, end, name)?;
        let required = [
            "UntilWithdrawn/1",
            "PersistentActivation/2",
            "PrivateAuthorityRouting/1",
            "ManagedAuthoritySession/1",
            "PersistentPages/1",
        ];
        let available = features["features"]
            .as_array()
            .context("native protocol capabilities absent")?;
        requirements.push(requirement(
            name,
            required.iter().all(|f| available.iter().any(|v| v == f)),
            "Install the coordinated compatible Core and Suite packages.",
        ));
    }
    let resumes = root.join("Hosting.json").exists();
    let network = invoke(
        &installation.core,
        &bytes(&["runtime", "network-preview"]),
        stop,
        end,
        "private network inspection",
    );
    requirements.push(requirement(
        "Private authority networks",
        resumes
            || network
                .as_ref()
                .is_ok_and(|v| subnet_available(c, v).unwrap_or(false)),
        "Select four free private authority subnets. Existing networks are preserved.",
    ));
    requirements.push(requirement(
        "Assigned address",
        TcpListener::bind(SocketAddr::from((c.bind_address, 0))).is_ok(),
        "Select a reachable IPv4 address assigned to this computer.",
    ));
    if !resumes {
        let ports = std::iter::once((c.bind_address, c.relay_port))
            .chain((0..4).map(|n| (Ipv4Addr::LOCALHOST, c.authority_first_port + n)));
        let available = ports
            .map(|p| TcpListener::bind(SocketAddr::from(p)))
            .collect::<std::io::Result<Vec<_>>>()
            .is_ok();
        requirements.push(requirement(
            "Native ports",
            available,
            "Select unused relay and local authority ports.",
        ));
    }
    let lifetime = c.access_end.contains(now()?.saturating_add(60_000))
        && c.hosting_end.contains(now()?.saturating_add(60_000));
    requirements.push(requirement("Access and hosting consent",lifetime,"Choose a future finite deadline or explicit access until removal and hosting until withdrawal."));
    let hrc_digest = c
        .hrc
        .as_ref()
        .map(|h| binary_digest(&h.executable))
        .transpose()?;
    let review = protocol::digest_value(
        &json!({"format":"HyperNetNativeHostReview/1","directory":root,"installation":installation.selection,"configuration":c,"hrcDigest":hrc_digest,"generatedPages":1}),
    )?;
    Ok(
        json!({"format":"HyperNetNativeHost/1","status":"Preview","reviewDigest":review,"requirements":requirements,
        "exposure":{"publicTcp":[c.relay_port],"authority":"Four private committee bridges; host ports bind only to 127.0.0.1","http":"Separate reviewed admission listener","organisation":"One organisation controls this host and all four authority voters"},
        "resources":{"perRole":c.resources,"roles":c.role_count(),"maximumMemoryBytes":c.resources.memory_bytes_per_role*c.role_count(),
            "admittedStorageBytes":c.resources.state_bytes_per_role*c.role_count(),"storageEnforcement":"Bounded objects and journals with free-space admission"},
        "accessEnd":c.access_end,"hostingEnd":c.hosting_end,"maximumParticipants":c.maximum_participants,"ownerReservedSlots":1,
        "defaultPermissions":"Read Pages and, when enabled, chat in permitted rooms. No member room creation, moderation, publication or hosting.",
        "pages":["Welcome","Joining and access","External agents when chat is enabled"],"startsAfterLogout":host_service::linger_enabled()}),
    )
}
pub fn load_image(host: &Host<'_>) -> Result<()> {
    let inspected = super::operator::podman(
        host,
        &bytes(&["image", "inspect", "--format", "json", &host.state.image]),
    );
    if let Ok(bytes) = inspected {
        let rows: Value = serde_json::from_slice(&bytes)?;
        if rows.as_array().is_some_and(|r| r.len() == 1)
            && rows[0]["Id"].as_str().is_some_and(|id| {
                id.strip_prefix("sha256:").unwrap_or(id)
                    == host
                        .state
                        .image
                        .strip_prefix("sha256:")
                        .unwrap_or(&host.state.image)
            })
            && rows[0]["Os"] == "linux"
            && rows[0]["Architecture"] == "amd64"
        {
            return Ok(());
        }
    }
    let args: Vec<std::ffi::OsString> = bytes(&[
        "native-installation",
        "load-image",
        "--directory",
        &text(&host.c.installation)?,
        "--json",
    ])
    .iter()
    .map(Into::into)
    .collect();
    let output = crate::admission::helper::output(
        &host.c.suite,
        &args,
        &[],
        host.cancel,
        Duration::from_secs(180),
    )?;
    ensure!(
        serde_json::from_slice::<Value>(&output)?["imageId"] == host.state.image,
        "verified image import differs"
    );
    Ok(())
}
