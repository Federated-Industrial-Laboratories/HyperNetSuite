// SPDX-License-Identifier: Apache-2.0
// A private service receiver uses normal membership and its own renewable authority voucher.
use super::{bootstrap, engine::*, files, operator::*, units};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::path::Path;

pub(super) fn companion_status(root: &Path, state: &Journal) -> Result<Value> {
    let directory = super::chat::companion_path(root, &state.configuration_digest, "Receiver")?;
    let value =
        crate::local_stream_ipc::call(&directory, json!({"version":1,"action":"status"}))?.0;
    ensure!(
        value["ok"] == true
            && value["status"] == "Ready"
            && value["network"] == state.results["bootstrap"]["network"]
            && value["incarnation"] == state.results["bootstrap"]["incarnation"]
            && value["principal"] == state.results["Receiver"]["publicKey"]
            && value["incoming"] == true
            && value["binding"]["service"] == state.ids["application"]
            && value["binding"]["protocol"] == "hrc/1",
        "private receiver identity or service differs"
    );
    let route = value["authorityRoute"].clone();
    ensure!(
        matches!(
            route["state"].as_str(),
            Some("current" | "quotaExhausted" | "unavailable")
        ) && route["mode"] == "automatic",
        "private receiver route status is unavailable"
    );
    Ok(route)
}
fn clock_now(root: &Path) -> Result<u64> {
    Ok(
        crate::authority_clock::health(&root.join("Native/Clock/ClockHealth.json"))?
            .observe()?
            .wall_ms,
    )
}
fn expired_route(route: &Value, now: u64) -> Result<bool> {
    let expires = number(route, "expiresAtMs")?;
    ensure!(
        expires > 0 && (route["state"] == "current" || route["recoveryAfterMs"] == expires),
        "private receiver recovery boundary differs"
    );
    Ok(now >= expires)
}
pub(super) fn recovery_due(root: &Path, state: &Journal) -> Result<bool> {
    expired_route(&companion_status(root, state)?, clock_now(root)?)
}

fn retain(host: &Host<'_>, profile: &Path, route: &Path) -> Result<()> {
    host.suite(&bytes(&[
        "network",
        "retain-route",
        "--profile",
        &text(profile)?,
        "--route-profile",
        &text(route)?,
        "--fingerprint",
        &digest(&files::public_file(route, 1_048_576)?),
        "--subject",
        &host.state.ids["authority"],
    ]))?;
    Ok(())
}
fn route_args(
    host: &Host<'_>,
    id: &str,
    request: &Value,
    authorisation: (&str, u64),
    expires: u64,
    template: &Path,
    output: &Path,
) -> Result<Vec<String>> {
    Ok(bytes(&[
        "--grant",
        authorisation.0,
        "--id",
        id,
        "--relay",
        &host.state.ids["relay"],
        "--destination",
        &host.state.ids["authority"],
        "--possession",
        &string(request, "relayPublicKey")?,
        "--action",
        &authorisation.1.to_string(),
        "--scope",
        &string(&host.bootstrap()?, "network")?,
        "--connections",
        "64",
        "--bytes",
        &host
            .c
            .resources
            .connection_bytes
            .checked_mul(64)
            .context("receiver byte limit overflow")?
            .to_string(),
        "--expires-ms",
        &expires.to_string(),
        "--route-template",
        &text(template)?,
        "--output",
        &text(output)?,
    ]))
}
fn owner_route(host: &Host<'_>, args: Vec<String>) -> Result<()> {
    let mut a = bytes(&["routes", "issue"]);
    a.extend(online(host, "Administrator")?);
    a.extend(args);
    operator(host, "Administrator", &a)?;
    Ok(())
}
// An expired signed issuance can be fenced, but a different pending command must first
// resume through the normal exact command. Never treat a timeout as an absent request.
fn resolve_expired(
    exact_current_expiry: Option<u64>,
    mut recover: impl FnMut() -> Result<Value>,
    retry: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let result = match recover() {
        Ok(result) => result,
        Err(first) => {
            let retried = retry();
            recover().with_context(|| {
                format!(
                    "expired route recovery remains unresolved: {first:#}; exact retry: {retried:?}"
                )
            })?
        }
    };
    ensure!(
        result["state"] == "RouteIssueRecovery",
        "route recovery response differs"
    );
    ensure!(
        matches!(
            result["status"].as_str(),
            Some("NothingPending" | "Recovered")
        ) || (result["status"] == "Waiting"
            && exact_current_expiry.is_some_and(|expiry| result["expiresAtMs"] == expiry)),
        "route issuance remains unresolved; retain its exact arguments and retry at its original expiry: {result}"
    );
    Ok(())
}
fn owner_recovery(host: &Host<'_>, id: &str) -> Result<Value> {
    let mut a = bytes(&["routes", "recover-expired-issue", "--id", id]);
    a.extend(online(host, "Administrator")?);
    operator(host, "Administrator", &a)
}
fn unrecorded_expiry(result: &Value, fresh: u64) -> Result<u64> {
    ensure!(
        result["state"] == "RouteIssueRecovery",
        "route recovery response differs"
    );
    match result["status"].as_str() {
        Some("Waiting") => number(result, "expiresAtMs"),
        Some("NothingPending" | "Recovered") => Ok(fresh),
        _ => anyhow::bail!("initial receiver route remains unresolved; retry its exact recovery"),
    }
}
fn recover_owner(host: &Host<'_>, id: &str, retry: impl FnOnce() -> Result<()>) -> Result<()> {
    resolve_expired(None, || owner_recovery(host, id), retry)
}
fn own_route(host: &Host<'_>, profile: &Path, args: Vec<String>) -> Result<()> {
    let mut a = bytes(&[
        "network",
        "connect",
        "--profile",
        &text(profile)?,
        "--",
        "routes",
        "issue",
    ]);
    a.extend(args);
    host.suite(&a)?;
    Ok(())
}
fn new_cycle(previous: &Value, expires: u64, now: u64) -> Result<Value> {
    ensure!(
        expires > now.saturating_add(1250),
        "host's finite consent has expired; review normal host consent before resuming"
    );
    if previous["complete"] != true {
        ensure!(
            number(previous, "expires")? <= now,
            "receiver issuance still has a live allowance"
        );
    }
    let generation = number(previous, "generation")?
        .checked_add(1)
        .context("receiver recovery exhausted")?;
    let mut value = json!({"generation":generation,"expires":expires,"complete":false});
    if previous.get("expires").is_some() {
        value["previous"] =
            json!({"generation":previous["generation"],"expires":previous["expires"]});
    }
    Ok(value)
}
fn route_expiry(path: &Path) -> Result<u64> {
    let profile: crate::route_profile::Profile =
        serde_json::from_slice(&files::public_file(path, 600000)?)?;
    profile.validate()?;
    let record = crate::authority_domains::Record::parse(
        &profile.voucher,
        profile.network,
        profile.incarnation,
    )?;
    Ok(crate::authority_domains::routes::Voucher::parse(&record.payload)?.expires)
}
fn cleanup_cycles(host: &Host<'_>, folder: &Path, current: u64, join: bool) -> Result<()> {
    for entry in std::fs::read_dir(folder)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let number = if join {
            name.strip_prefix("JoinRoute")
        } else {
            name.strip_prefix("RecoveryTls")
                .or_else(|| name.strip_prefix("Recovery"))
                .or_else(|| name.strip_prefix("Owned"))
        }
        .and_then(|s| s.strip_suffix(".json"))
        .and_then(|s| s.split('-').next())
        .and_then(|s| s.parse::<u64>().ok());
        if number.is_some_and(|n| n.saturating_add(1) < current) {
            if name.starts_with("Owned") {
                files::remove(&entry.path())?;
            } else {
                retire_export(host, "Administrator", &entry.path())?;
            }
        }
    }
    Ok(())
}
fn selected_template(host: &Host<'_>) -> Result<Option<std::path::PathBuf>> {
    host.remembered("receiver-route-template")
        .map(|selected| {
            let path = std::path::PathBuf::from(string(&selected, "path")?);
            ensure!(
                path.starts_with(host.p("Successor/Certificates")) && path.canonicalize()? == path,
                "receiver certificate template escapes the reviewed successor directory"
            );
            crate::admission::private::directory(
                path.parent().context("receiver template parent absent")?,
            )?;
            ensure!(
                digest(&files::read(&path, 600000)?) == string(&selected, "sha256")?,
                "receiver certificate template differs from its retained digest"
            );
            Ok(path)
        })
        .transpose()
}
fn route_record(route: &crate::route_profile::Profile) -> Result<crate::authority_domains::Record> {
    route.validate()?;
    let record =
        crate::authority_domains::Record::parse(&route.voucher, route.network, route.incarnation)?;
    ensure!(
        record.reference.kind == 166,
        "receiver route lacks a voucher"
    );
    Ok(record)
}
fn same_allowance(
    original: &crate::authority_domains::Record,
    successor: &crate::authority_domains::Record,
) -> Result<()> {
    use crate::authority_domains::routes::Voucher;
    let old = Voucher::parse(&original.payload)?;
    let new = Voucher::parse(&successor.payload)?;
    ensure!(
        original.reference.id == successor.reference.id
            && successor.reference.generation > original.reference.generation
            && old.sponsor == new.sponsor
            && old.possession == new.possession
            && old.grant == new.grant
            && old.relay.id == new.relay.id
            && old.destination.id == new.destination.id
            && old.action == new.action
            && old.scope == new.scope
            && old.connections == new.connections
            && old.bytes == new.bytes
            && old.expires == new.expires
            && old.baseline.unwrap_or((0, 0)) == new.baseline.unwrap_or((0, 0)),
        "receiver certificate refresh changed its identity, expiry or allowance"
    );
    Ok(())
}
fn exact_voucher_args(
    record: &crate::authority_domains::Record,
    template: &Path,
    output: &Path,
) -> Result<Vec<String>> {
    let old = crate::authority_domains::routes::Voucher::parse(&record.payload)?;
    Ok(bytes(&[
        "--grant",
        &hex::encode(old.grant.id),
        "--id",
        &hex::encode(record.reference.id),
        "--relay",
        &hex::encode(old.relay.id),
        "--destination",
        &hex::encode(old.destination.id),
        "--possession",
        &hex::encode(old.possession),
        "--action",
        &old.action.to_string(),
        "--scope-kind",
        &old.scope.0.to_string(),
        "--scope",
        &hex::encode(old.scope.1),
        "--connections",
        &old.connections.to_string(),
        "--bytes",
        &old.bytes.to_string(),
        "--expires-ms",
        &old.expires.to_string(),
        "--route-template",
        &text(template)?,
        "--output",
        &text(output)?,
    ]))
}
fn cleanup_certificates(host: &Host<'_>, folder: &Path, generation: u64) -> Result<()> {
    for entry in std::fs::read_dir(folder)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let old = name
            .strip_prefix("CertificateOriginal")
            .or_else(|| name.strip_prefix("CertificateOwned"))
            .or_else(|| name.strip_prefix("CertificateRecovery"))
            .and_then(|v| v.strip_suffix(".json"))
            .and_then(|v| v.parse::<u64>().ok());
        if old.is_some_and(|old| old.saturating_add(1) < generation) {
            if name.starts_with("CertificateRecovery") {
                retire_export(host, "Administrator", &entry.path())?;
            } else {
                files::remove(&entry.path())?;
            }
        }
    }
    Ok(())
}
// Initial setup can stop after owner transport is retained but before the receiver
// signs its own voucher. Refresh that transport without rewriting the exact cycle.
fn recovery_transport(
    host: &mut Host<'_>,
    folder: &Path,
    template: &Path,
    cycle: &mut Value,
    original: &Path,
) -> Result<std::path::PathBuf> {
    let selected_bytes = files::read(template, 600000)?;
    let selected: crate::route_profile::Profile = serde_json::from_slice(&selected_bytes)?;
    let route: crate::route_profile::Profile =
        serde_json::from_slice(&files::read(original, 600000)?)?;
    if route.relay == selected.relay && route.destination == selected.destination {
        return Ok(original.into());
    }
    let old = route_record(&route)?;
    let generation = number(cycle, "generation")?;
    let template_digest = digest(&selected_bytes);
    let previous = cycle.get("transport").cloned();
    let mut transport = if let Some(value) = previous.as_ref()
        && value["template"] == template_digest
    {
        value.clone()
    } else {
        ensure!(
            previous.as_ref().is_none_or(|p| p["complete"] == true),
            "finish the exact pending owner transport refresh first"
        );
        let revision = previous
            .as_ref()
            .map(|p| number(p, "revision"))
            .transpose()?
            .unwrap_or(0)
            .checked_add(1)
            .context("receiver transport refresh exhausted")?;
        let value = json!({"revision":revision,"template":template_digest,"complete":false});
        cycle["transport"] = value.clone();
        host.remember("receiver-cycle", cycle.clone())?;
        value
    };
    let revision = number(&transport, "revision")?;
    let output = folder.join(format!("RecoveryTls{generation}-{revision}.json"));
    if !output.exists() {
        owner_route(host, exact_voucher_args(&old, template, &output)?)?;
    }
    let encoded = files::read(&output, 600000)?;
    let refreshed: crate::route_profile::Profile = serde_json::from_slice(&encoded)?;
    same_allowance(&old, &route_record(&refreshed)?)?;
    ensure!(
        refreshed.relay == selected.relay && refreshed.destination == selected.destination,
        "receiver owner transport differs from reviewed certificates"
    );
    if transport["complete"] == true {
        ensure!(
            transport["sha256"] == digest(&encoded),
            "receiver owner transport changed after retention"
        );
    } else {
        transport["complete"] = json!(true);
        transport["sha256"] = json!(digest(&encoded));
        cycle["transport"] = transport;
        host.remember("receiver-cycle", cycle.clone())?;
    }
    for entry in std::fs::read_dir(folder)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .and_then(|s| s.strip_prefix(&format!("RecoveryTls{generation}-")))
            .and_then(|s| s.strip_suffix(".json"))
            .and_then(|s| s.parse::<u64>().ok())
            .is_some_and(|old| old.saturating_add(1) < revision)
        {
            retire_export(host, "Administrator", &entry.path())?;
        }
    }
    Ok(output)
}
fn reusable_recovery(
    host: &Host<'_>,
    folder: &Path,
    selected: &crate::route_profile::Profile,
    now: u64,
) -> Result<Option<Vec<u8>>> {
    let Some(cycle) = host.remembered("receiver-cycle") else {
        return Ok(None);
    };
    let generation = number(&cycle, "generation")?;
    let path = if cycle["transport"]["complete"] == true {
        folder.join(format!(
            "RecoveryTls{generation}-{}.json",
            number(&cycle["transport"], "revision")?
        ))
    } else {
        folder.join(format!("Recovery{generation}.json"))
    };
    if !path.try_exists()? {
        return Ok(None);
    }
    let encoded = files::read(&path, 600000)?;
    if cycle["transport"]["complete"] == true {
        ensure!(
            cycle["transport"]["sha256"] == digest(&encoded),
            "retained receiver recovery transport changed"
        );
    }
    let route: crate::route_profile::Profile = serde_json::from_slice(&encoded)?;
    let record = route_record(&route)?;
    let voucher = crate::authority_domains::routes::Voucher::parse(&record.payload)?;
    if route.relay == selected.relay
        && route.destination == selected.destination
        && voucher.expires > now.saturating_add(1250)
    {
        Ok(Some(encoded))
    } else {
        Ok(None)
    }
}
/// A stopped receiver changes only its certified TLS references within the original allowance.
pub(super) fn refresh_certificates(host: &mut Host<'_>) -> Result<()> {
    let Some(template) = selected_template(host)? else {
        return Ok(());
    };
    if host.remembered("receiver-joined").is_none() {
        return Ok(());
    }
    ensure!(
        !units::active(host, "receiver")?,
        "stop the receiver before refreshing its certificates"
    );
    let folder = host.dir("ReceiverClient")?;
    let profile = folder.join("Profile.json");
    let selected: crate::route_profile::Profile =
        serde_json::from_slice(&files::read(&template, 600000)?)?;
    let template_digest = digest(&files::read(&template, 600000)?);
    let endpoint =
        crate::private_route_client::Endpoint::load(&folder.join("Joined/AuthorityRoute.json"))?;
    let current = clock_now(&host.c.root)?;
    let prior = host.remembered("receiver-certificate-refresh");
    let mut plan = if let Some(plan) = &prior
        && plan["complete"] != true
    {
        ensure!(
            plan["template"] == template_digest,
            "finish the exact pending receiver certificate refresh first"
        );
        plan.clone()
    } else {
        let record = route_record(&endpoint.route)?;
        let voucher = crate::authority_domains::routes::Voucher::parse(&record.payload)?;
        if voucher.expires <= current {
            return prepare(host);
        }
        if endpoint.route.relay == selected.relay
            && endpoint.route.destination == selected.destination
        {
            return Ok(());
        }
        if hex::encode(voucher.sponsor) != string(&host.state.results["Receiver"], "publicKey")? {
            // Normal setup retains a reviewed owner/candidate transport before it creates
            // receiver authority. Its exact cycle owns the transport successor and own Issue.
            return prepare(host);
        }
        ensure!(
            hex::encode(record.reference.id) == host.id("receiver-authority-route")?,
            "retained receiver authority voucher has another identifier"
        );
        let generation = prior
            .as_ref()
            .map(|p| number(p, "generation"))
            .transpose()?
            .unwrap_or(0)
            .checked_add(1)
            .context("receiver certificate refresh exhausted")?;
        let original = folder.join(format!("CertificateOriginal{generation}.json"));
        let encoded = serde_json::to_vec(&endpoint.route)?;
        files::exact_file(&original, &encoded)?;
        let plan = json!({"generation":generation,"template":template_digest,"expires":voucher.expires,
            "originalSha256":digest(&encoded),"complete":false});
        host.remember("receiver-certificate-refresh", plan.clone())?;
        plan
    };
    let generation = number(&plan, "generation")?;
    let original = files::read(
        &folder.join(format!("CertificateOriginal{generation}.json")),
        600000,
    )?;
    ensure!(
        digest(&original) == string(&plan, "originalSha256")?,
        "receiver certificate refresh original changed"
    );
    let original: crate::route_profile::Profile = serde_json::from_slice(&original)?;
    let record = route_record(&original)?;
    let old = crate::authority_domains::routes::Voucher::parse(&record.payload)?;
    ensure!(
        old.expires == number(&plan, "expires")?,
        "receiver certificate refresh deadline changed"
    );
    let recovery = folder.join(format!("CertificateRecovery{generation}.json"));
    let output = folder.join(format!("CertificateOwned{generation}.json"));
    let owner_id = host.id("receiver-recovery-route")?;
    let request = host.suite(&bytes(&[
        "network",
        "inspect-request",
        "--request",
        &text(&folder.join("Request.cbor"))?,
    ]))?;
    if old.expires <= current {
        // Both exact pending issuances used this expiry. Resolve owner locally; normal
        // prepare then obtains fresh transport and resolves the receiver's expired issue.
        recover_owner(host, &owner_id, || {
            owner_route(
                host,
                route_args(
                    host,
                    &owner_id,
                    &request,
                    (&host.root_grant()?, 0),
                    old.expires,
                    &template,
                    &recovery,
                )?,
            )
        })?;
        // Retire this expired plan before normal setup; its native pending requests
        // remain in their floors. A later live voucher may need its own exact plan.
        plan["complete"] = json!(true);
        plan["expired"] = json!(true);
        host.remember("receiver-certificate-refresh", plan)?;
        prepare(host)?;
        return cleanup_certificates(host, &folder, generation);
    } else {
        if !recovery.exists()
            && plan["recoveryStarted"] != true
            && let Some(encoded) = reusable_recovery(host, &folder, &selected, current)?
        {
            files::exact_file(&recovery, &encoded)?;
        }
        if !recovery.exists() {
            plan["recoveryStarted"] = json!(true);
            host.remember("receiver-certificate-refresh", plan.clone())?;
            owner_route(
                host,
                route_args(
                    host,
                    &owner_id,
                    &request,
                    (&host.root_grant()?, 0),
                    old.expires,
                    &template,
                    &recovery,
                )?,
            )?;
        }
        retain(host, &profile, &recovery)?;
        if !output.exists() {
            own_route(
                host,
                &profile,
                exact_voucher_args(&record, &template, &output)?,
            )?;
        }
        let refreshed: crate::route_profile::Profile =
            serde_json::from_slice(&files::read(&output, 600000)?)?;
        same_allowance(&record, &route_record(&refreshed)?)?;
        ensure!(
            refreshed.relay == selected.relay && refreshed.destination == selected.destination,
            "receiver certificate output differs from the reviewed template"
        );
        retain(host, &profile, &output)?;
    }
    plan["complete"] = json!(true);
    host.remember("receiver-certificate-refresh", plan)?;
    cleanup_certificates(host, &folder, generation)
}

pub fn prepare(host: &mut Host<'_>) -> Result<()> {
    if units::active(host, "receiver")? {
        let status = companion_status(&host.c.root, &host.state)?;
        if expired_route(&status, clock_now(&host.c.root)?)? {
            units::stop(host, "receiver")?;
        } else {
            if status["state"] != "current" {
                host.phase("Waiting for the receiver's connection allowance to renew")?;
                anyhow::bail!(
                    "receiver authority access is unavailable within its current allowance; retry after its retained recovery boundary"
                );
            }
            return Ok(());
        }
    }
    host.phase("Private service receiver")?;
    let folder = host.dir("ReceiverClient")?;
    let profile = folder.join("Profile.json");
    if !profile.exists() {
        host.suite(&bytes(&[
            "network",
            "prepare",
            "--bootstrap",
            &text(&host.p("Network/Bootstrap.cbor"))?,
            "--fingerprint",
            &host.bootstrap_file_digest()?,
            "--minimum-route",
            "Organisational",
            "--output",
            &text(&profile)?,
        ]))?;
    }
    let prepared = host.suite(&bytes(&[
        "network",
        "inspect",
        "--profile",
        &text(&profile)?,
    ]))?;
    let subject = string(&prepared, "devicePublicKey")?;
    #[derive(serde::Deserialize)]
    struct Profile {
        device: crate::Identity,
    }
    let identity: Profile =
        serde_json::from_slice(&zeroize::Zeroizing::new(files::read(&profile, 1_048_576)?))?;
    ensure!(
        identity.device.public_key == subject,
        "receiver identity differs"
    );
    let key = host.p("Keys/Receiver.json");
    files::exact_file(
        &key,
        &zeroize::Zeroizing::new(serde_json::to_vec(&identity.device)?),
    )?;
    bootstrap::identity(host, "Receiver", &key)?;
    let request = folder.join("Request.cbor");
    if !request.exists() {
        host.suite(&bytes(&[
            "network",
            "request",
            "--profile",
            &text(&profile)?,
            "--output",
            &text(&request)?,
        ]))?;
    }
    let request = host.suite(&bytes(&[
        "network",
        "inspect-request",
        "--request",
        &text(&request)?,
    ]))?;
    let reader = host.id("receiver-reader")?;
    if host.remembered("receiver-reader").is_none() {
        let mut a = bytes(&["authority-inspection", "delegate-grant"]);
        a.extend(online(host, "Administrator")?);
        a.extend(bytes(&[
            "--context-grant",
            &host.root_grant()?,
            "--parent",
            &host.root_grant()?,
            "--id",
            &reader,
            "--subject",
            &subject,
            "--actions",
            "0,6",
            "--not-before-ms",
            &host.state.created_ms.to_string(),
            "--limits",
            &host.c.resources.connection_bytes.to_string(),
            "1024",
            &host.c.resources.relay_connections.min(64).to_string(),
            "16",
        ]));
        a.extend(end_arguments(host.c.hosting_end));
        let v = operator(host, "Administrator", &a)?;
        host.remember("receiver-reader", v)?;
    }
    let template = folder.join("AuthorityTemplate.json");
    if !template.exists() {
        let mut a = bytes(&["routes", "template"]);
        a.extend(host.trust()?);
        a.extend(bytes(&[
            "--relay-profile",
            &text(&host.p("Services/Relay/Inputs/RouteProfile.cbor"))?,
            "--destination-profile",
            &text(&host.p("Services/AuthorityEndpoint/Inputs/RouteProfile.cbor"))?,
            "--minimum-route",
            "Organisational",
            "--output",
            &text(&template)?,
        ]));
        host.suite(&a)?;
    }
    let template = selected_template(host)?.unwrap_or(template);
    let joined = folder.join("Joined");
    if host.remembered("receiver-joined").is_none() {
        let offer = folder.join("Offer.cbor");
        if !offer.exists() {
            let member = host.id("receiver-member")?;
            let mut a = bytes(&["authority-inspection", "invite-member"]);
            let mut common = online(host, "Administrator")?;
            common.truncate(common.len() - 2);
            a.extend(common);
            a.extend(bytes(&[
                "--reader-grant",
                &reader,
                "--member",
                &member,
                "--not-before-ms",
                &host.state.created_ms.to_string(),
                "--output",
                &text(&offer)?,
            ]));
            a.extend(end_arguments(host.c.hosting_end));
            operator(host, "Administrator", &a)?;
        }
        if host.remembered("receiver-pending").is_none() {
            let mut a = bytes(&["routes", "invite"]);
            a.extend(online(host, "Administrator")?);
            a.extend(bytes(&[
                "--grant",
                &host.root_grant()?,
                "--offer",
                &text(&offer)?,
            ]));
            let v = operator(host, "Administrator", &a)?;
            host.remember("receiver-pending", v)?;
        }
        // Persist each exact finite deadline before signing. The immutable invitation always
        // retains its first route; later transport successors do not change member acceptance.
        let id = host.id("receiver-join-route")?;
        let current = clock_now(&host.c.root)?;
        let mut join_cycle = match host.remembered("receiver-join-cycle") {
            Some(value) => value,
            None => {
                let original = folder.join("JoinRoute.json");
                let expires = if original.exists() {
                    route_expiry(&original)?
                } else {
                    unrecorded_expiry(
                        &owner_recovery(host, &id)?,
                        host.c.hosting_end.bound(current.saturating_add(3_600_000)),
                    )?
                };
                let value = json!({"generation":0,"expires":expires,"complete":false});
                host.remember("receiver-join-cycle", value.clone())?;
                value
            }
        };
        let path_for = |generation| {
            if generation == 0 {
                folder.join("JoinRoute.json")
            } else {
                folder.join(format!("JoinRoute{generation}.json"))
            }
        };
        let mut join_route = path_for(number(&join_cycle, "generation")?);
        if number(&join_cycle, "expires")? <= current {
            recover_owner(host, &id, || {
                owner_route(
                    host,
                    route_args(
                        host,
                        &id,
                        &request,
                        (&host.root_grant()?, 10),
                        number(&join_cycle, "expires")?,
                        &template,
                        &join_route,
                    )?,
                )
            })?;
            join_cycle = new_cycle(
                &join_cycle,
                host.c.hosting_end.bound(current.saturating_add(3_600_000)),
                current,
            )?;
            host.remember("receiver-join-cycle", join_cycle.clone())?;
            join_route = path_for(number(&join_cycle, "generation")?);
        }
        if !join_route.exists() {
            owner_route(
                host,
                route_args(
                    host,
                    &id,
                    &request,
                    (&host.root_grant()?, 10),
                    number(&join_cycle, "expires")?,
                    &template,
                    &join_route,
                )?,
            )?;
        }
        let invitation = folder.join("Invitation.json");
        if !invitation.exists() {
            let mut a = bytes(&["network", "invitation"]);
            a.extend(host.trust()?);
            a.extend(bytes(&[
                "--offer",
                &text(&offer)?,
                "--admission-grant",
                &host.root_grant()?,
                "--authority-route",
                &text(&join_route)?,
                "--output",
                &text(&invitation)?,
            ]));
            host.suite(&a)?;
        }
        // The new route is certified and the original is embedded in the immutable invitation.
        // Retire older transport exports even if member redemption needs another exact retry.
        cleanup_cycles(host, &folder, number(&join_cycle, "generation")?, true)?;
        let mut a = bytes(&[
            "network",
            "join",
            "--profile",
            &text(&profile)?,
            "--invitation",
            &text(&invitation)?,
            "--invitation-digest",
            &digest(&files::public_file(&invitation, 1_048_576)?),
            "--directory",
            &text(&joined)?,
            "--clock-witness",
            &text(&host.p("Native/Clock/ClockHealth.json"))?,
        ]);
        // Passing the same original route needs no override. A replaced route must prove the
        // explicit expired-voucher and same-identity successor contract in normal network join.
        let invitation_value: Value =
            serde_json::from_slice(&files::public_file(&invitation, 1_048_576)?)?;
        let selected: Value = serde_json::from_slice(&files::public_file(&join_route, 600000)?)?;
        if invitation_value["authorityRoute"] != selected {
            a.extend(bytes(&[
                "--authority-route",
                &text(&join_route)?,
                "--authority-route-digest",
                &digest(&files::public_file(&join_route, 600000)?),
            ]));
        }
        let v = host.suite(&a)?;
        host.remember("receiver-joined", v)?;
        join_cycle["complete"] = json!(true);
        host.remember("receiver-join-cycle", join_cycle)?;
    }
    let receiver = json!({"profile":profile,"member":subject,"directory":joined.join("Requester"),
        "authorityRoute":joined.join("AuthorityRoute.json"),"readerGrant":reader});
    if let Ok(endpoint) =
        crate::private_route_client::Endpoint::load(&joined.join("AuthorityRoute.json"))
    {
        let record = crate::authority_domains::Record::parse(
            &endpoint.route.voucher,
            endpoint.route.network,
            endpoint.route.incarnation,
        )?;
        let voucher = crate::authority_domains::routes::Voucher::parse(&record.payload)?;
        if hex::encode(voucher.sponsor) == subject && voucher.expires > clock_now(&host.c.root)? {
            let selected: crate::route_profile::Profile =
                serde_json::from_slice(&files::read(&template, 600000)?)?;
            if endpoint.route.relay != selected.relay
                || endpoint.route.destination != selected.destination
            {
                refresh_certificates(host)?;
            }
            host.remember("receiver-native", receiver)?;
            return Ok(());
        }
    }
    // A stopped receiver may have been offline beyond its own finite voucher.
    // The host offers one bounded recovery route; the receiver then signs its own renewal.
    let current = clock_now(&host.c.root)?;
    let mut cycle = host
        .remembered("receiver-cycle")
        .unwrap_or(json!({"generation":0,"complete":true}));
    let owner_id = host.id("receiver-recovery-route")?;
    let own_id = host.id("receiver-authority-route")?;
    if cycle["complete"] == true || number(&cycle, "expires")? <= current {
        if cycle["complete"] != true {
            let old = folder.join(format!("Recovery{}.json", number(&cycle, "generation")?));
            recover_owner(host, &owner_id, || {
                owner_route(
                    host,
                    route_args(
                        host,
                        &owner_id,
                        &request,
                        (&host.root_grant()?, 0),
                        number(&cycle, "expires")?,
                        &template,
                        &old,
                    )?,
                )
            })?;
        }
        cycle = new_cycle(
            &cycle,
            host.c.hosting_end.bound(current.saturating_add(3_600_000)),
            current,
        )?;
        host.remember("receiver-cycle", cycle.clone())?;
    }
    let generation = number(&cycle, "generation")?;
    let expires = number(&cycle, "expires")?;
    let recovery = folder.join(format!("Recovery{generation}.json"));
    let own = folder.join(format!("Owned{generation}.json"));
    if !recovery.exists() {
        owner_route(
            host,
            route_args(
                host,
                &owner_id,
                &request,
                (&host.root_grant()?, 0),
                expires,
                &template,
                &recovery,
            )?,
        )?;
    }
    let recovery = recovery_transport(host, &folder, &template, &mut cycle, &recovery)?;
    retain(host, &profile, &recovery)?;
    if cycle["ownStarted"] != true {
        // A fresh owner transport permits resolving the receiver's old signed request without
        // replaying an expired voucher. Unknown effects remain in the normal requester floor.
        resolve_expired(
            Some(expires),
            || {
                host.suite(&bytes(&[
                    "network",
                    "connect",
                    "--profile",
                    &text(&profile)?,
                    "--",
                    "routes",
                    "recover-expired-issue",
                    "--id",
                    &own_id,
                ]))
            },
            || {
                let previous = &cycle["previous"];
                let old = folder.join(format!("Owned{}.json", number(previous, "generation")?));
                own_route(
                    host,
                    &profile,
                    route_args(
                        host,
                        &own_id,
                        &request,
                        (&reader, 0),
                        number(previous, "expires")?,
                        &template,
                        &old,
                    )?,
                )
            },
        )?;
        cycle["ownStarted"] = json!(true);
        host.remember("receiver-cycle", cycle.clone())?;
    }
    cleanup_cycles(host, &folder, generation, false)?;
    if !own.exists() {
        own_route(
            host,
            &profile,
            route_args(
                host,
                &own_id,
                &request,
                (&reader, 0),
                expires,
                &template,
                &own,
            )?,
        )?;
    }
    retain(host, &profile, &own)?;
    cycle["complete"] = json!(true);
    host.remember("receiver-cycle", cycle)?;
    host.remember(
        "receiver-native",
        json!({"profile":profile,"member":subject,"directory":joined.join("Requester"),
        "authorityRoute":joined.join("AuthorityRoute.json"),"readerGrant":reader}),
    )?;
    // An already exported own result may predate a certificate transaction. Preserve
    // that exact completion first, then refresh only its TLS within the same allowance.
    let selected: crate::route_profile::Profile =
        serde_json::from_slice(&files::read(&template, 600000)?)?;
    let own: crate::route_profile::Profile = serde_json::from_slice(&files::read(&own, 600000)?)?;
    if own.relay != selected.relay || own.destination != selected.destination {
        refresh_certificates(host)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../Tests/Unit/NativeHost/ReceiverTests.rs"]
mod tests;
