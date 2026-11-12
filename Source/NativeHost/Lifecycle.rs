// SPDX-License-Identifier: Apache-2.0
//! Retained setup and explicit owner stop/withdrawal compose the normal native controls.
use super::{activation, bootstrap, chat, engine::*, pages, policy, receiver, services, units};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

fn service_roles(host: &Host<'_>) -> Vec<&'static str> {
    let mut roles = vec!["PageStore", "Relay", "AuthorityEndpoint", "PageEndpoint"];
    if host.c.hrc.is_some() {
        roles.push("ApplicationEndpoint");
    }
    roles
}
fn required_units(hrc: bool) -> Vec<String> {
    let mut names = vec![
        "clock".into(),
        "a1".into(),
        "a2".into(),
        "a3".into(),
        "a4".into(),
    ];
    names.extend(bytes(&[
        "pagestore",
        "relay",
        "authorityendpoint",
        "pageendpoint",
    ]));
    if hrc {
        names.push("applicationendpoint".into());
        names.extend(bytes(&["receiver", "owner-chat", "hrc"]));
    }
    names
}
fn descriptor(host: &Host<'_>) -> Result<Value> {
    let value = policy::registrar(host, json!({"operation":"describe"}))?;
    let bootstrap = host.bootstrap()?;
    ensure!(
        value["status"] == "descriptor"
            && value["network"] == bootstrap["network"]
            && value["incarnation"] == bootstrap["incarnation"]
            && value["policy"].as_str() == host.state.ids.get("policy").map(String::as_str)
            && value["accessEnd"] == serde_json::to_value(host.c.access_end)?
            && value["maximumParticipants"] == host.c.maximum_participants,
        "native admission readiness differs from the reviewed server"
    );
    Ok(value)
}
fn summary(host: &Host<'_>, status: &str, observations: Value) -> Result<Value> {
    let bootstrap = host.remembered("bootstrap").unwrap_or(Value::Null);
    Ok(
        json!({"format":"HyperNetNativeHost/1", "status":status,"phase":host.state.phase,
        "desiredRunning":host.state.desired_running,"withdrawn":host.state.withdrawn,"completed":host.state.completed,
        "network":bootstrap.get("network"),"incarnation":bootstrap.get("incarnation"),"bootstrap":bootstrap,
        "registrarConfiguration":host.p("Registrar/Registrar.json"),"descriptorKeyFile":host.p("Registrar/Descriptor.key"),
        "policy":host.state.ids.get("policy"),"accessEnd":host.c.access_end,"maximumParticipants":host.c.maximum_participants,
        "ownerReservedSlots":1,"roles":if host.c.hrc.is_some(){vec![0,1]}else{vec![0]},
        "pages":host.remembered("pages"),"owner":host.remembered("owner-report"),"hrc":host.remembered("hrc"),
        "registrarIsolation":host.remembered("registrar-isolation"),"coreImage":host.state.image,
        "suiteExecutable":host.c.suite,"services":observations}),
    )
}
pub fn complete(host: &mut Host<'_>) -> Result<Value> {
    ensure!(
        host.state.desired_running && !host.state.withdrawn,
        "this host remains offline or withdrawn; use explicit owner start for an offline host"
    );
    bootstrap::prepare(host)?;
    bootstrap::activate(host)?;
    services::prepare(host)?;
    pages::prepare(host)?;
    activation::activate(host, "PageStore", "PageOperator", 1)?;
    for (name, operator) in [
        ("Relay", "RelayOperator"),
        ("AuthorityEndpoint", "AuthorityOperator"),
        ("PageEndpoint", "PageEndpointOperator"),
    ] {
        activation::activate(host, name, operator, 5)?;
    }
    if host.c.hrc.is_some() {
        host.phase("Chat service registration")?;
        chat::service_owner(host)?;
        chat::prepare_application(host)?;
        receiver::prepare(host)?;
        chat::start_receiver(host)?;
        chat::register_application(host)?;
        activation::activate(host, "ApplicationEndpoint", "ApplicationOperator", 5)?;
    }
    pages::publish(host)?;
    policy::prepare(host)?;
    host.phase("Owner participant enrolment")?;
    policy::owner_prepare(host)?;
    let existing = host.remembered("owner-installed").is_some();
    let mut installed = policy::owner_install(host)?;
    if host.c.hrc.is_some() {
        if existing && !units::active(host, "owner-chat")? {
            installed = policy::refresh(host, vec![1])?;
        }
        let mut role = installed["profiles"]
            .as_array()
            .context("owner native profiles absent")?
            .iter()
            .find(|p| p["role"] == 1)
            .cloned()
            .context("owner chat role absent")?;
        role["companion"] = json!(chat::owner_companion(host)?);
        let role = chat::owner_chat(host, role)?;
        host.phase("Owner chat and community room")?;
        chat::prepare_hrc(
            host,
            json!({"principal":role["member"],"companion":role["companion"]}),
        )?;
    }
    let owner = policy::owner_report(host)?;
    host.remember("owner-report", owner)?;
    descriptor(host)?;
    host.state.completed = true;
    host.save()?;
    host.phase("Running")?;
    // This final observation includes current certified admission, not just child creation.
    let observed = status(host)?;
    ensure!(
        observed["status"] == "Running",
        "native host setup completed but readiness changed"
    );
    Ok(observed)
}
fn observations(host: &Host<'_>) -> Result<(Value, bool, bool)> {
    let mut values = Vec::new();
    let mut active = true;
    let mut stopped = true;
    let names = required_units(host.c.hrc.is_some());
    let states = unit_states(&host.c.root, host.c.hrc.is_some(), host.cancel).ok();
    for (index, role) in names.iter().enumerate() {
        let state = states
            .as_ref()
            .map(|values| values[index].as_str())
            .unwrap_or("Unavailable");
        active &= state == "active";
        stopped &= matches!(state, "inactive" | "failed");
        values.push(json!({"role":role,"unit":units::name(&host.c.root,role)?,"state":state}));
    }
    for (role, service) in service_roles(host)
        .into_iter()
        .map(|r| (r.to_owned(), true))
        .chain((1..=4).map(|n| (format!("A{n}"), false)))
    {
        let path = host.p(&role);
        let profile = path.join(if service {
            "ServiceProfile.json"
        } else {
            "Profile.json"
        });
        if !profile.exists() {
            continue;
        }
        let mut args = bytes(&["runtime"]);
        if service {
            args.push("services".into());
        }
        args.extend(bytes(&["status", "--directory", &text(&path)?]));
        let state = host
            .core(&args)
            .unwrap_or_else(|_| json!({"status":"Unavailable"}));
        active &= state["running"] == true;
        stopped &= if service {
            state["running"] == false && state["cleanupComplete"] == true
        } else {
            authority_stopped(&state, host.state.withdrawn)
        };
        values.push(json!({"role":role,"native":state}));
    }
    if host.c.hrc.is_some() && active {
        let route = receiver::companion_status(&host.c.root, &host.state)
            .unwrap_or_else(|_| json!({"state":"unavailable"}));
        active &= route["state"] == "current";
        values.push(json!({"role":"receiver","authorityRoute":route}));
    }
    Ok((json!(values), active, stopped))
}
fn authority_stopped(state: &Value, withdraw: bool) -> bool {
    state["running"] == false
        && state["pendingOperation"] == false
        && if withdraw {
            state["status"] == "Withdrawn"
                && state["withdrawalGeneration"]
                    .as_u64()
                    .is_some_and(|v| v > 0)
                && state["resourceCount"] == 0
        } else {
            // Core Stop retains its resolved private bridge for an explicitly requested restart.
            state["status"] == "Stopped"
        }
}
fn readiness(
    desired: bool,
    withdrawn: bool,
    completed: bool,
    active: bool,
    stopped: bool,
    certified: bool,
) -> &'static str {
    if withdrawn {
        if stopped {
            "Withdrawn"
        } else {
            "WithdrawalPending"
        }
    } else if !desired {
        if stopped { "Stopped" } else { "StopPending" }
    } else if completed && active && certified {
        "Running"
    } else {
        "NeedsAttention"
    }
}
pub fn status(host: &mut Host<'_>) -> Result<Value> {
    let (observed, active, stopped) = observations(host)?;
    let certified = host.state.desired_running
        && !host.state.withdrawn
        && host.state.completed
        && active
        && descriptor(host).is_ok();
    summary(
        host,
        readiness(
            host.state.desired_running,
            host.state.withdrawn,
            host.state.completed,
            active,
            stopped,
            certified,
        ),
        observed,
    )
}
fn authority_cleanup(host: &mut Host<'_>, name: &str, withdraw: bool) -> Result<()> {
    let path = host.p(name);
    if !path.join("Profile.json").exists() {
        return Ok(());
    }
    let current = host.core(&bytes(&["runtime", "status", "--directory", &text(&path)?]))?;
    let withdrawn = current["withdrawalGeneration"].as_u64().unwrap_or(0) > 0;
    if authority_stopped(&current, withdraw) {
        return Ok(());
    }
    let operation = if withdraw { "withdraw" } else { "stop" };
    let key = if operation == "withdraw" {
        format!("withdraw-request/{name}")
    } else {
        format!("stop-request/{name}/{}", number(&current, "generation")?)
    };
    let request = if let Some(value) = host.remembered(&key) {
        value
    } else {
        ensure!(
            !withdraw || !withdrawn,
            "resume the original native withdrawal request; no replacement operation is authorised"
        );
        let preview = host.core(&bytes(&[
            "runtime",
            "preview",
            "--directory",
            &text(&path)?,
        ]))?;
        let id = host.id(&key)?;
        host.remember(
            &key,
            json!({"operation":operation,"id":&id[..32],"generation":number(&preview,"generation")?,
            "profileDigest":string(&preview,"profileDigest")?}),
        )?
    };
    let result = host.core(&bytes(&[
        "runtime",
        &string(&request, "operation")?,
        "--directory",
        &text(&path)?,
        "--operation-id",
        &string(&request, "id")?,
        "--expected-generation",
        &number(&request, "generation")?.to_string(),
        "--profile-digest",
        &string(&request, "profileDigest")?,
    ]))?;
    ensure!(
        result["ok"] == true,
        "native restrictive operation remains unresolved"
    );
    Ok(())
}
pub fn stop(host: &mut Host<'_>, withdraw: bool) -> Result<Value> {
    // Publish the restart veto before any cleanup. Errors cannot silently restore desire.
    host.state.desired_running = false;
    host.state.withdrawn |= withdraw;
    host.save()?;
    host.phase(if host.state.withdrawn {
        "Withdrawing"
    } else {
        "Stopping"
    })?;
    let mut failed = Vec::new();
    for purpose in [
        "supervisor",
        "hrc",
        "owner-chat",
        "applicationendpoint",
        "receiver",
        "pageendpoint",
        "authorityendpoint",
        "relay",
        "pagestore",
    ] {
        if units::stop(host, purpose).is_err() {
            failed.push(purpose.to_owned());
        }
    }
    for role in service_roles(host).into_iter().rev() {
        if !host.p(role).join("ServiceProfile.json").exists() {
            continue;
        }
        let result = host.core(&bytes(&[
            "runtime",
            "services",
            if host.state.withdrawn {
                "withdraw"
            } else {
                "stop"
            },
            "--directory",
            &text(&host.p(role))?,
        ]));
        if !result.is_ok_and(|v| v.get("cleanupComplete") != Some(&Value::Bool(false))) {
            failed.push(role.into());
        }
    }
    for n in (1..=4).rev() {
        if units::stop(host, &format!("a{n}")).is_err() {
            failed.push(format!("a{n}"));
        }
        let withdrawn = host.state.withdrawn;
        if authority_cleanup(host, &format!("A{n}"), withdrawn).is_err() {
            failed.push(format!("A{n}"));
        }
    }
    if units::stop(host, "clock").is_err() {
        failed.push("clock".into());
    }
    let (observed, _, stopped) = observations(host)?;
    let complete = stopped && failed.is_empty();
    let label = if host.state.withdrawn {
        if complete {
            "Withdrawn"
        } else {
            "WithdrawalPending"
        }
    } else if complete {
        "Stopped"
    } else {
        "StopPending"
    };
    host.phase(label)?;
    let mut result = summary(host, label, observed)?;
    result["cleanupFailedRoles"] = json!(failed);
    result["localWithdrawalOnly"] = json!(host.state.withdrawn);
    Ok(result)
}
/// A heartbeat reads local service and companion health without changing authority or budgets.
pub fn tick(directory: &Path, cancel: &AtomicBool) -> Result<bool> {
    let current: Journal = serde_json::from_value(read(&directory.join("Hosting.json"))?)?;
    ensure!(
        current.format == "HyperNetNativeHost/1"
            && current.configuration_digest
                == crate::admission::protocol::digest_value(&current.configuration)?,
        "retained host configuration changed"
    );
    if !current.desired_running || current.withdrawn {
        return Ok(false);
    }
    ensure!(
        unit_states(directory, current.configuration.hrc.is_some(), cancel)?
            .iter()
            .all(|s| s == "active"),
        "one or more native services need recovery"
    );
    if current.configuration.hrc.is_some() {
        ensure!(
            !receiver::recovery_due(directory, &current)?,
            "receiver needs recovery after its finite authority route expired"
        );
    }
    Ok(true)
}
fn unit_states(directory: &Path, hrc: bool, cancel: &AtomicBool) -> Result<Vec<String>> {
    let names = required_units(hrc);
    let mut args = bytes(&["--user", "show", "--property=ActiveState", "--value"]);
    for role in &names {
        args.push(units::name(directory, role)?);
    }
    let output = raw(
        Path::new("/usr/bin/systemctl"),
        &args,
        cancel,
        Instant::now() + Duration::from_secs(10),
        "native health observation",
    )?;
    let states: Vec<String> = std::str::from_utf8(&output)?
        .lines()
        .filter(|s| !s.is_empty())
        .map(Into::into)
        .collect();
    ensure!(
        states.len() == names.len(),
        "native unit observations are incomplete"
    );
    Ok(states)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordinary_stop_retains_bridge_but_pending_or_withdrawn_cleanup_cannot_claim_stopped() {
        let mut value = json!({"status":"Stopped","running":false,"pendingOperation":false,
            "withdrawalGeneration":0,"resourceCount":1});
        assert!(authority_stopped(&value, false));
        assert!(!authority_stopped(&value, true));
        value["pendingOperation"] = json!(true);
        assert!(!authority_stopped(&value, false));
        value["pendingOperation"] = json!(false);
        value["status"] = json!("Withdrawn");
        value["withdrawalGeneration"] = json!(1);
        assert!(!authority_stopped(&value, true));
        value["resourceCount"] = json!(0);
        assert!(authority_stopped(&value, true));
        value["running"] = json!(true);
        assert!(!authority_stopped(&value, true));
    }
}
