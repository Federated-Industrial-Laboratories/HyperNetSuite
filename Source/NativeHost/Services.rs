// SPDX-License-Identifier: Apache-2.0
// Adapted from RelayChat's exact deployment and route authoring workflow.
use super::{engine::*, files as native, operator::*};
use anyhow::{Result, anyhow, ensure};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
#[path = "InitialPossession.rs"]
mod initial_possession;
pub(super) fn offer(host: &Host<'_>, name: &str) -> Result<PathBuf> {
    initial_possession::selected(host, name)
}
fn raw_id(s: &str) -> Result<Vec<u8>> {
    let v = hex::decode(s).map_err(|_| anyhow!("retained native deployment differs"))?;
    if v.len() != 32 {
        return Err(anyhow!("retained native deployment differs"));
    }
    Ok(v)
}
fn der(host: &Host<'_>, pem: &Path) -> Result<Vec<u8>> {
    raw(
        Path::new("/usr/bin/openssl"),
        &bytes(&["x509", "-in", &text(pem)?, "-outform", "DER"]),
        host.cancel,
        host.end,
        "certificate conversion",
    )
}
pub(super) fn roles(
    host: &Host<'_>,
) -> Vec<(&'static str, &'static str, &'static str, &'static str)> {
    let mut roles = vec![
        ("Relay", "RelayOperator", "relay", "relay"),
        (
            "AuthorityEndpoint",
            "AuthorityOperator",
            "authority",
            "authority",
        ),
        ("PageEndpoint", "PageEndpointOperator", "pages", "content"),
    ];
    if host.c.hrc.is_some() {
        roles.push((
            "ApplicationEndpoint",
            "ApplicationOperator",
            "application",
            "application",
        ));
    }
    roles
}

pub(super) fn active_directory(host: &Host<'_>, name: &str) -> Result<PathBuf> {
    match host
        .remembered(&format!("active-service/{name}"))
        .or_else(|| host.remembered(&format!("service-input/{name}")))
    {
        Some(value) => {
            let path = PathBuf::from(
                value
                    .as_str()
                    .ok_or(anyhow!("retained native deployment differs"))?,
            );
            if !path.starts_with(host.p("Successor/Certificates"))
                || path
                    .components()
                    .any(|p| matches!(p, std::path::Component::ParentDir))
            {
                return Err(anyhow!("retained native deployment differs"));
            }
            Ok(path)
        }
        None => Ok(host.p(&format!("Services/{name}"))),
    }
}
pub(super) fn author_route(
    host: &Host<'_>,
    role: (&str, &str, &str, &str),
    manifest: &Path,
    profile: &str,
    output: &Path,
) -> Result<()> {
    let issuer = active_directory(host, role.0)?.join("Inputs/CertificateAuthority.pem");
    author_route_with_issuer(host, role, manifest, profile, output, &issuer)
}
pub(super) fn author_route_with_issuer(
    host: &Host<'_>,
    role: (&str, &str, &str, &str),
    manifest: &Path,
    profile: &str,
    output: &Path,
    issuer: &Path,
) -> Result<()> {
    let (name, operator_name, id_name, protocol) = role;
    let mut a = bytes(&["routes", "profile"]);
    a.extend(host.trust()?);
    a.extend(bytes(&[
        "--manifest",
        &text(manifest)?,
        "--profile-digest",
        profile,
        "--key",
        &text(&host.p(&format!("Keys/{operator_name}.json")))?,
        "--service",
        &host.state.ids[id_name],
        "--endpoint",
        &host.state.ids[&format!("endpoint/{name}")],
        "--domain",
        &host.state.ids["domain"],
        "--mode",
        if name == "Relay" { "relay" } else { "attached" },
        "--protocol",
        protocol,
        "--server-name",
        &host.c.advertised_address.to_string(),
        "--certificate-authority",
        &text(issuer)?,
        "--assurance",
        "Organisational",
        "--maximum-bytes",
        &host.c.resources.connection_bytes.to_string(),
        "--maximum-duration-ms",
        &(host.c.resources.connection_seconds * 1000).to_string(),
        "--maximum-idle-ms",
        "30000",
        "--maximum-connections",
        &if name == "Relay" {
            host.c.resources.relay_connections
        } else {
            host.c.resources.endpoint_connections
        }
        .to_string(),
    ]));
    if name != "Relay" {
        a.extend(bytes(&["--relay", &host.state.ids["relay"]]));
    }
    a.extend(bytes(&["--output", &text(output)?]));
    host.suite(&a)?;
    Ok(())
}
pub(super) fn prepare(host: &mut Host<'_>) -> Result<()> {
    host.phase("Route deployment review")?;
    let bootstrap = host.bootstrap()?;
    for (name, operator_name, id_name, protocol) in roles(host) {
        if host.remembered(&format!("active-service/{name}")).is_some() {
            continue;
        }
        let folder = active_directory(host, name)?;
        host.dir(&text(folder.strip_prefix(&host.c.root)?)?)?;
        let inputs = folder.join("Inputs");
        native::directory(&inputs)?;
        let peer = public_read(&super::certificates::peer(host, name)?)?;
        let role = host
            .remembered(&format!("role/{name}"))
            .ok_or(anyhow!("retained native deployment differs"))?;
        native::exact_file(
            &inputs.join("Certificate.pem"),
            string(&peer, "certificatePem")?.as_bytes(),
        )
        .map_err(|_| anyhow!("retained native deployment differs"))?;
        native::exact_file(
            &inputs.join("CertificateAuthority.pem"),
            string(&peer, "authorityPem")?.as_bytes(),
        )
        .map_err(|_| anyhow!("retained native deployment differs"))?;
        for file in ["Service.key", "Transport.key"] {
            let data = zeroize::Zeroizing::new(
                native::read(&host.p(&format!("Keys/{name}/{file}")), 16384)
                    .map_err(|_| anyhow!("retained native deployment differs"))?,
            );
            native::exact_file(&inputs.join(file), &data)
                .map_err(|_| anyhow!("retained native deployment differs"))?;
        }
        native::exact_file(
            &inputs.join("Bootstrap.cbor"),
            &native::public_file(&host.p("Network/Bootstrap.cbor"), 1_048_576)
                .map_err(|_| anyhow!("retained native deployment differs"))?,
        )
        .map_err(|_| anyhow!("retained native deployment differs"))?;
        let endpoint = host.id(&format!("endpoint/{name}"))?;
        let volume = host.id(&format!("volume/{name}"))?;
        let host_id = host.id(&format!("host/{name}"))?;
        let deployment_id = host.id(&format!("deployment/{name}"))?;
        let mut endpoints = vec![
            json!({"endpointId":raw_id(&endpoint)?,"serviceKey":raw_id(&string(&role,"identity")?)?,"address":host.c.advertised_address,"port":host.c.relay_port,"transportKey":raw_id(&string(&role,"transport")?)?,"leafDer":der(host,&inputs.join("Certificate.pem"))?}),
        ];
        let mut outbound: Vec<Vec<u8>> = Vec::new();
        if name != "Relay" {
            let id = host.id(&format!("outbound/{name}"))?;
            outbound.push(raw_id(&id)?);
            let relay = host
                .remembered("role/Relay")
                .ok_or(anyhow!("retained native deployment differs"))?;
            endpoints.push(json!({"endpointId":raw_id(&id)?,"serviceKey":raw_id(&string(&relay,"identity")?)?,"address":host.c.advertised_address,"port":host.c.relay_port,"transportKey":raw_id(&string(&relay,"transport")?)?,"leafDer":der(host,&active_directory(host,"Relay")?.join("Inputs/Certificate.pem"))?}));
        }
        endpoints.sort_by_key(|v| {
            v["endpointId"]
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_u64).collect::<Vec<_>>())
                .unwrap_or_default()
        });
        let manifest = json!({"generation":1,"previousProfile":null,"previousConsent":null,"network":raw_id(&string(&bootstrap,"network")?)?,"incarnation":raw_id(&string(&bootstrap,"incarnation")?)?,"deployment":raw_id(&deployment_id)?,"host":raw_id(&host_id)?,"operator":raw_id(&string(&host.state.results[operator_name],"publicKey")?)?,"bootstrapDigest":raw_id(&host.bootstrap_file_digest()?)?,"softwareDigest":raw_id(&binary_digest(&host.c.core)?)?,"validity":[host.state.created_ms,host.c.hosting_end],"sessionMode":1,
            "roles":[{"role":5,"serviceKey":raw_id(&string(&role,"identity")?)?,"imageDigest":raw_id(host.state.image.strip_prefix("sha256:").ok_or(anyhow!("retained native deployment differs"))?)?,"memoryBytes":host.c.resources.memory_bytes_per_role,"pids":host.c.resources.pids_per_role,"cpuQuota":host.c.resources.cpu_quota_per_role,"cpuPeriod":100000,"stateAdmissionBytes":host.c.resources.state_bytes_per_role,"bindEndpointIds":[raw_id(&endpoint)?],"outboundEndpointIds":outbound,"volumeIds":[raw_id(&volume)?]}],
            "volumes":[{"volumeId":raw_id(&volume)?,"readOnly":false,"storageAdmissionBytes":host.c.resources.state_bytes_per_role}],"endpoints":endpoints,"clock":{"monitorKey":raw_id(&host.monitor()?)?,"kernelBoot":"CurrentHost","witnessFileName":"ClockHealth.cbor","maximumErrorMs":250,"maximumObservationAgeMs":1000},"placement":{"hosts":[raw_id(&host_id)?],"volumes":[raw_id(&volume)?],"backups":[],"copies":1},"limits":[host.c.resources.connection_bytes,1024,if name=="Relay"{host.c.resources.relay_connections}else{host.c.resources.endpoint_connections},32],"consentPolicy":{"allowOpaque":true,"reviewerRoots":[]},"authorityConfig":null});
        host.immutable_json(&folder.join("Manifest.json"), &manifest)?;
        let profile = deployment(host, name, operator_name)?;
        let offer = offer(host, name)?;
        let route = inputs.join("RouteProfile.cbor");
        if !route.exists() {
            author_route(
                host,
                (name, operator_name, id_name, protocol),
                &inputs.join("Manifest.cbor"),
                &profile,
                &route,
            )?;
        }
        host.artifact(&route)?;
        let config = relay_configuration(host, name)?;
        host.immutable_json(&folder.join("RelayConfiguration.json"), &config)?;
        if name != "ApplicationEndpoint" {
            host.immutable_json(&inputs.join("ServiceConfig.json"), &config)?;
        }
        let key = format!("deployment/{name}");
        if host.remembered(&key).is_none() {
            let mut a = bytes(&["authority-inspection", "deployments", "register"]);
            a.extend(online(host, "Administrator")?);
            a.extend(bytes(&[
                "--grant",
                &host.root_grant()?,
                "--offer",
                &text(&offer)?,
            ]));
            let v = operator(host, "Administrator", &a)?;
            host.remember(&key, v)?;
        }
        let key = format!("route/{name}");
        if host.remembered(&key).is_none() {
            let mut a = bytes(&["routes", "register"]);
            a.extend(online(host, "Administrator")?);
            a.extend(bytes(&[
                "--grant",
                &host.root_grant()?,
                "--profile",
                &text(&route)?,
            ]));
            let v = operator(host, "Administrator", &a)?;
            host.remember(&key, v)?;
        }
        if host.remembered(&format!("service-input/{name}")).is_some() {
            host.remember(&format!("active-service/{name}"), json!(folder))?;
            host.state.results.remove(&format!("service-input/{name}"));
            host.save()?;
        }
    }
    Ok(())
}

pub(super) fn relay_configuration(host: &Host<'_>, name: &str) -> Result<Value> {
    if name == "Relay" {
        return Ok(json!({"version":1,"relayIdentity":null,"relayAddress":null}));
    }
    let relay = host
        .remembered("role/Relay")
        .ok_or(anyhow!("retained relay identity absent"))?;
    let peer = public_read(&super::certificates::peer(host, "Relay")?)?;
    Ok(
        json!({"version":1,"relayIdentity":{"service":raw_id(&host.state.ids["relay"])?,
        "serverName":host.c.advertised_address.to_string(),"transportKey":raw_id(&string(&relay,"transport")?)?,
        "leafDer":crate::runtime_manifest::certificates::der(&string(&peer,"certificatePem")?)?,
        "certificateAuthorityPem":peer["authorityPem"]},
        "relayAddress":format!("{}:{}",host.c.advertised_address,host.c.relay_port)}),
    )
}

pub(super) fn deployment(host: &mut Host<'_>, name: &str, operator_name: &str) -> Result<String> {
    let folder = active_directory(host, name)?;
    let inputs = folder.join("Inputs");
    let prepared_key = if folder == host.p(&format!("Services/{name}")) {
        format!("manifest/{name}")
    } else {
        ensure!(
            folder.starts_with(host.p("Successor/Certificates")),
            "initial input path differs"
        );
        format!("manifest/{name}/{}", digest(text(&folder)?.as_bytes()))
    };
    let prepared = if let Some(v) = host.remembered(&prepared_key) {
        v
    } else {
        let original = inputs.join("Manifest.cbor");
        let target = if original.exists() {
            inputs.join(format!(".manifest-{}.cbor", random()?))
        } else {
            original.clone()
        };
        let mut a = bytes(&["authority-inspection", "deployments", "prepare"]);
        a.extend(host.trust()?);
        a.extend(bytes(&[
            "--manifest-json",
            &text(&folder.join("Manifest.json"))?,
            "--output",
            &text(&target)?,
        ]));
        let result = host.suite(&a)?;
        if target != original {
            let old = native::public_file(&original, 65536)
                .map_err(|_| anyhow!("retained native deployment differs"))?;
            let new = native::public_file(&target, 65536)
                .map_err(|_| anyhow!("retained native deployment differs"))?;
            if old != new {
                return Err(anyhow!("retained native deployment differs"));
            }
            std::fs::remove_file(&target)
                .map_err(|_| anyhow!("retained native deployment differs"))?;
        }
        host.remember(&prepared_key, result)?
    };
    let profile = string(&prepared, "profileDigest")?;
    let consent = folder.join("Consent.cbor");
    if !consent.exists() {
        let mut a = bytes(&["authority-inspection", "deployments", "consent"]);
        a.extend(host.trust()?);
        a.extend(bytes(&[
            "--manifest",
            &text(&inputs.join("Manifest.cbor"))?,
            "--profile-digest",
            &profile,
            "--key",
            &text(&host.p(&format!("Keys/{operator_name}.json")))?,
            "--output",
            &text(&consent)?,
        ]));
        host.suite(&a)?;
    }
    let possession_start = now()?
        .saturating_sub(crate::authority_governance::UNCERTAINTY_MS)
        .max(host.state.created_ms);
    let expiry = host.c.hosting_end.bound(possession_start + 86_400_000);
    let mut classes = vec![
        (
            "service",
            "--key",
            if name == "PageStore" {
                host.p("Keys/PageStore.json")
            } else {
                host.p(&format!("Keys/{name}/Identity.json"))
            },
        ),
        ("monitor", "--key", host.p("Native/Clock/ClockSigner.json")),
    ];
    if name != "PageStore" {
        classes.push((
            "transport",
            "--tls-key",
            host.p(&format!("Keys/{name}/Transport.key")),
        ));
    }
    for (class, flag, key) in &classes {
        let out = folder.join(format!("{class}.cbor"));
        if !out.exists() {
            let mut a = bytes(&["authority-inspection", "deployments", "possess"]);
            a.extend(host.trust()?);
            a.extend(bytes(&[
                "--manifest",
                &text(&inputs.join("Manifest.cbor"))?,
                "--class",
                class,
                flag,
                &text(key)?,
                "--not-before-ms",
                &possession_start.to_string(),
                "--expires-ms",
                &expiry.to_string(),
                "--output",
                &text(&out)?,
            ]));
            host.suite(&a)?;
        }
    }
    let offer = folder.join("Offer.cbor");
    if !offer.exists() {
        let mut a = bytes(&["authority-inspection", "deployments", "assemble"]);
        a.extend(host.trust()?);
        a.extend(bytes(&[
            "--manifest",
            &text(&inputs.join("Manifest.cbor"))?,
            "--consent",
            &text(&consent)?,
        ]));
        for (class, _, _) in &classes {
            a.extend(bytes(&[
                "--possession",
                &text(&folder.join(format!("{class}.cbor")))?,
            ]));
        }
        a.extend(bytes(&["--output", &text(&offer)?]));
        host.suite(&a)?;
    }
    let mut inspect = bytes(&["authority-inspection", "deployments", "inspect-offer"]);
    inspect.extend(host.trust()?);
    inspect.extend(bytes(&["--offer", &text(&offer)?]));
    let inspected = host.suite(&inspect)?;
    if inspected["profileDigest"] != profile {
        return Err(anyhow!("retained native deployment differs"));
    }
    for file in [
        "Manifest.cbor",
        "Bootstrap.cbor",
        "Service.key",
        "Transport.key",
    ] {
        if file != "Transport.key" || name != "PageStore" {
            host.artifact(&inputs.join(file))?;
        }
    }
    host.artifact(&offer)?;
    host.artifact(&consent)?;
    if host.remembered(&format!("deployment/{name}")).is_none() {
        initial_possession::refresh(host, name, &folder)?;
    }
    Ok(profile)
}
