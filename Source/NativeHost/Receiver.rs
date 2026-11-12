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
            name.strip_prefix("Recovery")
                .or_else(|| name.strip_prefix("Owned"))
        }
        .and_then(|s| s.strip_suffix(".json"))
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
    let template = if let Some(selected) = host.remembered("receiver-route-template") {
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
        path
    } else {
        template
    };
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
    #[test]
    fn interrupted_recovery_replays_discovery_but_never_advances_waiting_or_uncertain_work() {
        use std::cell::Cell;
        let calls = Cell::new(0);
        let replayed = Cell::new(false);
        resolve_expired(
            None,
            || {
                calls.set(calls.get() + 1);
                if !replayed.get() {
                    anyhow::bail!("pending RouteContext")
                }
                Ok(json!({"state":"RouteIssueRecovery","status":"Recovered"}))
            },
            || {
                replayed.set(true);
                anyhow::bail!("exact old issuance is expired")
            },
        )
        .unwrap();
        assert_eq!(calls.get(), 2);
        assert_eq!(
            unrecorded_expiry(
                &json!({"state":"RouteIssueRecovery","status":"Waiting","expiresAtMs":5000}),
                10000
            )
            .unwrap(),
            5000
        );
        resolve_expired(
            Some(5000),
            || Ok(json!({"state":"RouteIssueRecovery","status":"Waiting","expiresAtMs":5000})),
            || panic!("current exact command resumes outside recovery"),
        )
        .unwrap();
        for status in ["Waiting", "RecoveryPending"] {
            assert!(
                resolve_expired(
                    None,
                    || Ok(json!({"state":"RouteIssueRecovery","status":status})),
                    || panic!("live/uncertain request must not be replayed")
                )
                .is_err()
            );
        }
        assert!(resolve_expired(None, || anyhow::bail!("unavailable"), || Ok(())).is_err());
        let old = json!({"generation":7,"expires":5000,"complete":false,"previous":{"generation":6,"expires":1000}});
        assert!(new_cycle(&old, 10000, 4999).is_err());
        assert!(new_cycle(&old, 5000, 5000).is_err());
        let next = new_cycle(&old, 10000, 5000).unwrap();
        assert_eq!(next["previous"], json!({"generation":7,"expires":5000}));
        assert_eq!(old["complete"], false);
    }
}
