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
    if let Some(cycle) = host.remembered("receiver-cycle") {
        let current = number(&cycle, "generation")?;
        for entry in std::fs::read_dir(&folder)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let generation = name
                .strip_prefix("Recovery")
                .or_else(|| name.strip_prefix("Owned"))
                .and_then(|s| s.strip_suffix(".json"))
                .and_then(|s| s.parse::<u64>().ok());
            if generation.is_some_and(|n| n < current) {
                if name.starts_with("Recovery") {
                    retire_export(host, "Administrator", &entry.path())?;
                } else {
                    files::remove(&entry.path())?;
                }
            }
        }
    }
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
        let join_route = folder.join("JoinRoute.json");
        if !join_route.exists() {
            let id = host.id("receiver-join-route")?;
            owner_route(
                host,
                route_args(
                    host,
                    &id,
                    &request,
                    (&host.root_grant()?, 10),
                    host.c.hosting_end.bound(now()? + 3_600_000),
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
        let v = host.suite(&bytes(&[
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
        ]))?;
        host.remember("receiver-joined", v)?;
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
            host.remember("receiver-native", receiver)?;
            return Ok(());
        }
    }
    // A stopped receiver may have been offline beyond its own finite voucher.
    // The host offers one bounded recovery route; the receiver then signs its own renewal.
    let mut cycle = host
        .remembered("receiver-cycle")
        .unwrap_or(json!({"generation":0,"complete":true}));
    if cycle["complete"] == true {
        let generation = number(&cycle, "generation")?
            .checked_add(1)
            .context("receiver recovery exhausted")?;
        cycle = json!({"generation":generation,"expires":host.c.hosting_end.bound(now()?+3_600_000),"complete":false});
        host.remember("receiver-cycle", cycle.clone())?;
    }
    let generation = number(&cycle, "generation")?;
    let expires = number(&cycle, "expires")?;
    let recovery = folder.join(format!("Recovery{generation}.json"));
    let own = folder.join(format!("Owned{generation}.json"));
    if !recovery.exists() {
        let id = host.id("receiver-recovery-route")?;
        owner_route(
            host,
            route_args(
                host,
                &id,
                &request,
                (&host.root_grant()?, 0),
                expires,
                &template,
                &recovery,
            )?,
        )?;
    }
    retain(host, &profile, &recovery)?;
    if !own.exists() {
        let id = host.id("receiver-authority-route")?;
        let mut a = bytes(&[
            "network",
            "connect",
            "--profile",
            &text(&profile)?,
            "--",
            "routes",
            "issue",
        ]);
        a.extend(route_args(
            host,
            &id,
            &request,
            (&reader, 0),
            expires,
            &template,
            &own,
        )?);
        host.suite(&a)?;
    }
    retain(host, &profile, &own)?;
    cycle["complete"] = json!(true);
    host.remember("receiver-cycle", cycle)?;
    host.remember(
        "receiver-native",
        json!({"profile":profile,"member":subject,"directory":joined.join("Requester"),
        "authorityRoute":joined.join("AuthorityRoute.json"),"readerGrant":reader}),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exhausted_receiver_waits_for_original_expiry_before_recovery() {
        let mut route = json!({"state":"quotaExhausted","expiresAtMs":5000,"recoveryAfterMs":5000});
        assert!(!expired_route(&route, 4999).unwrap());
        assert!(expired_route(&route, 5000).unwrap());
        route["recoveryAfterMs"] = json!(1000);
        assert!(expired_route(&route, 5000).is_err());
        route["state"] = json!("current");
        route["recoveryAfterMs"] = Value::Null;
        assert!(expired_route(&route, 5000).unwrap());
    }
}
