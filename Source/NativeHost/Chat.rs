// SPDX-License-Identifier: Apache-2.0
//! Compose normal native streams and HRC provisioning with separately scoped registrar state.
use super::{engine::*, files, operator, services};
use crate::admission::{helper, private, protocol, saved};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    fs::{DirBuilder, File},
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn delegate(
    host: &mut Host<'_>,
    label: &str,
    subject: &str,
    actions: &str,
    scoped: bool,
) -> Result<()> {
    let retained = format!("grant/{label}");
    if host.remembered(&retained).is_some() {
        return Ok(());
    }
    let id = host.id(label)?;
    let root = host.root_grant()?;
    let mut args = bytes(&["authority-inspection", "delegate-grant"]);
    args.extend(operator::online(host, "Administrator")?);
    args.extend(bytes(&[
        "--context-grant",
        &root,
        "--parent",
        &root,
        "--id",
        &id,
        "--subject",
        subject,
        "--actions",
        actions,
        "--not-before-ms",
        &host.state.created_ms.to_string(),
        "--limits",
        &host.c.resources.connection_bytes.to_string(),
        "1024",
        "8",
        "16",
    ]));
    args.extend(end_arguments(if scoped {
        host.c.hosting_end
    } else {
        host.c.governance_end()
    }));
    if scoped {
        args.extend(bytes(&[
            "--scopes",
            &format!("3:{}", host.state.ids["application"]),
        ]));
    }
    let value = operator::operator(host, "Administrator", &args)?;
    host.remember(&retained, value)?;
    Ok(())
}
pub fn service_owner(host: &mut Host<'_>) -> Result<()> {
    let subject = string(&host.state.results["ServiceOwner"], "publicKey")?;
    delegate(host, "owner-reader", &subject, "0,6", false)?;
    delegate(host, "owner-manage", &subject, "29", true)?;
    let reference = format!(
        "{}:1:{}",
        host.state.ids["owner-manage"],
        string(&host.state.results["grant/owner-manage"], "recordDigest")?
    );
    host.remember("owner-manage", json!(reference))?;
    let folder = host.dir("ServiceOwnerMember")?;
    let offer = folder.join("Offer.cbor");
    let accepted = folder.join("Accepted.cbor");
    let receipt = folder.join("Receipt.cbor");
    if !offer.exists() {
        let member = host.id("member/service-owner")?;
        let mut args = bytes(&["authority-inspection", "invite-member"]);
        let mut common = operator::online(host, "Administrator")?;
        common.truncate(common.len() - 2);
        args.extend(common);
        args.extend(bytes(&[
            "--reader-grant",
            &host.state.ids["owner-reader"],
            "--member",
            &member,
            "--not-before-ms",
            &host.state.created_ms.to_string(),
            "--output",
            &text(&offer)?,
        ]));
        args.extend(end_arguments(host.c.governance_end()));
        operator::operator(host, "Administrator", &args)?;
    }
    if !accepted.exists() {
        let mut args = bytes(&["authority-inspection", "accept-member"]);
        args.extend(host.trust()?);
        args.extend(bytes(&[
            "--key",
            &text(&host.p("Keys/ServiceOwner.json"))?,
            "--offer",
            &text(&offer)?,
            "--output",
            &text(&accepted)?,
        ]));
        host.suite(&args)?;
    }
    if !receipt.exists() {
        let mut args = bytes(&["authority-inspection", "admit-member"]);
        args.extend(operator::online(host, "Administrator")?);
        args.extend(bytes(&[
            "--context-grant",
            &host.root_grant()?,
            "--grant",
            &host.root_grant()?,
            "--accepted",
            &text(&accepted)?,
            "--receipt",
            &text(&receipt)?,
        ]));
        operator::operator(host, "Administrator", &args)?;
    }
    let mut args = bytes(&["authority-inspection", "confirm-member"]);
    args.extend(host.trust()?);
    args.extend(bytes(&[
        "--accepted",
        &text(&accepted)?,
        "--receipt",
        &text(&receipt)?,
    ]));
    host.suite(&args)?;
    for path in [&offer, &accepted, &receipt] {
        host.artifact(path)?;
    }
    operator::initialise(host, "ServiceOwner")
}
pub fn prepare_application(host: &mut Host<'_>) -> Result<()> {
    let folder = services::active_directory(host, "ApplicationEndpoint")?;
    let inputs = folder.join("Inputs");
    let reference =
        operator::record_reference(&host.state.results["route/ApplicationEndpoint"], 165)?;
    let owner = string(&host.state.results["ServiceOwner"], "publicKey")?;
    let offer = folder.join("ServiceOffer.cbor");
    let accepted = folder.join("ServiceAccepted.cbor");
    if !offer.exists() {
        let mut args = bytes(&["streams", "offer"]);
        args.extend(host.trust()?);
        args.extend(bytes(&[
            "--key",
            &text(&host.p("Keys/ServiceOwner.json"))?,
            "--service",
            &host.state.ids["application"],
            "--route",
            &reference,
            "--operator",
            &string(&host.state.results["ApplicationOperator"], "publicKey")?,
            "--endpoint",
            &string(&host.state.results["role/ApplicationEndpoint"], "identity")?,
            "--protocol",
            "hrc/1",
            "--not-before-ms",
            &host.state.created_ms.to_string(),
            "--maximum-bytes",
            &host.c.resources.connection_bytes.to_string(),
            "--duration-ms",
            &(host.c.resources.connection_seconds * 1000).to_string(),
            "--idle-ms",
            "30000",
            "--output",
            &text(&offer)?,
        ]));
        args.extend(end_arguments(host.c.hosting_end));
        host.suite(&args)?;
    }
    if !accepted.exists() {
        let mut args = bytes(&["streams", "accept"]);
        args.extend(host.trust()?);
        args.extend(bytes(&[
            "--offer",
            &text(&offer)?,
            "--owner-key",
            &owner,
            "--key",
            &text(&host.p("Keys/ApplicationOperator.json"))?,
            "--route-profile",
            &text(&inputs.join("RouteProfile.cbor"))?,
            "--output",
            &text(&accepted)?,
        ]));
        host.suite(&args)?;
    }
    let mut args = bytes(&["streams", "inspect-offer"]);
    args.extend(host.trust()?);
    args.extend(bytes(&["--offer", &text(&offer)?, "--owner-key", &owner]));
    host.suite(&args)?;
    let configuration = inputs.join("ServiceConfig.json");
    if !configuration.exists() {
        let mut args = bytes(&["streams", "endpoint-config"]);
        args.extend(host.trust()?);
        args.extend(bytes(&[
            "--accepted",
            &text(&accepted)?,
            "--configuration",
            &text(&folder.join("RelayConfiguration.json"))?,
            "--output",
            &text(&configuration)?,
        ]));
        host.suite(&args)?;
    }
    for path in [&offer, &accepted, &configuration] {
        host.artifact(path)?;
    }
    Ok(())
}
pub fn register_application(host: &mut Host<'_>) -> Result<()> {
    let accepted =
        services::active_directory(host, "ApplicationEndpoint")?.join("ServiceAccepted.cbor");
    if host.remembered("application-registration").is_none() {
        let reference = host
            .remembered("owner-manage")
            .context("service owner grant is absent")?;
        let mut args = bytes(&["streams", "register"]);
        args.extend(operator::online(host, "ServiceOwner")?);
        args.extend(bytes(&[
            "--grant",
            reference
                .as_str()
                .context("service owner reference differs")?,
            "--accepted",
            &text(&accepted)?,
        ]));
        let result = operator::operator(host, "ServiceOwner", &args)?;
        host.remember("application-registration", result)?;
    }
    Ok(())
}

fn runtime_root(host: &Host<'_>) -> Result<PathBuf> {
    let parent = PathBuf::from(format!("/run/user/{}", unsafe { libc::geteuid() }));
    private::directory(&parent)?;
    let root = companion_path(&host.c.root, &host.state.configuration_digest, "Receiver")?
        .parent()
        .context("companion parent absent")?
        .to_owned();
    if !root.exists() {
        use std::os::unix::fs::PermissionsExt;
        DirBuilder::new().mode(0o711).create(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o711))?;
        File::open(&parent)?.sync_all()?;
    }
    let meta = std::fs::symlink_metadata(&root)?;
    ensure!(
        meta.is_dir()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o7777 == 0o711
            && root.canonicalize()? == root,
        "native socket namespace differs"
    );
    Ok(root)
}
pub(super) fn companion_path(
    root: &Path,
    configuration_digest: &str,
    name: &str,
) -> Result<PathBuf> {
    ensure!(
        ["Receiver", "OwnerChat"].contains(&name),
        "unsupported native companion"
    );
    let identity = protocol::digest_value(&json!([root, configuration_digest]))?;
    Ok(PathBuf::from(format!(
        "/run/user/{}/HN{}",
        unsafe { libc::geteuid() },
        &identity[..20]
    ))
    .join(name))
}
fn companion(host: &Host<'_>, name: &str) -> Result<PathBuf> {
    ensure!(
        ["Receiver", "OwnerChat"].contains(&name),
        "unsupported native companion"
    );
    let directory = runtime_root(host)?.join(name);
    saved::create_directory(&directory)?;
    Ok(directory)
}
pub fn owner_chat(host: &mut Host<'_>, role: Value) -> Result<Value> {
    ensure!(
        role["role"] == 1,
        "chat owner requires the certified chat role"
    );
    let profile = PathBuf::from(string(&role, "profile")?);
    let route = PathBuf::from(string(&role, "destinationRoute")?);
    let selected = companion(host, "OwnerChat")?;
    ensure!(
        profile.starts_with(&host.c.root)
            && route.starts_with(&host.c.root)
            && string(&role, "companion")? == text(&selected)?
            && protocol::identifier(&string(&role, "member")?),
        "chat owner role leaves the retained native host"
    );
    // Profile and voucher validation belongs to the normal native connect command.
    // The immutable target can renew its finite connection proof under the native grant.
    let target = json!([{"service":host.state.ids["application"], "protocol":"hrc/1",
        "grant":string(&role,"connectGrant")?, "route":route, "renewalMs":60000}]);
    let targets = host.p("Client/OwnerChatTargets.json");
    host.immutable_json(&targets, &target)?;
    host.unit(
        "owner-chat",
        &host.c.suite,
        &bytes(&[
            "network",
            "connect",
            "--profile",
            &text(&profile)?,
            "--",
            "streams",
            "agent",
            "--ipc-directory",
            &text(&selected)?,
            "--targets",
            &text(&targets)?,
        ]),
    )?;
    host.wait(
        || {
            let value = host.suite(&bytes(&[
                "streams",
                "status",
                "--directory",
                &text(&selected)?,
            ]))?;
            validate_companion(&value, &host.bootstrap()?, &string(&role, "member")?, None)
        },
        30,
    )?;
    host.remember("owner-chat", role.clone())?;
    Ok(role)
}
/// The policy module uses this exact path before preparing the role's HRC binding.
pub fn owner_companion(host: &Host<'_>) -> Result<PathBuf> {
    companion(host, "OwnerChat")
}

fn hrc_request(host: &Host<'_>, action: Value) -> Result<Value> {
    let hrc = host.c.hrc.as_ref().context("HRC is not selected")?;
    ensure!(
        Some(binary_digest(&hrc.executable)?) == host.state.hrc_digest,
        "reviewed HRC executable changed"
    );
    check(host.cancel, host.end)?;
    let args: Vec<OsString> = bytes(&[
        "service",
        "host-request",
        "--directory",
        &text(&host.p("HRC"))?,
    ])
    .into_iter()
    .map(Into::into)
    .collect();
    let remaining = host
        .end
        .saturating_duration_since(Instant::now())
        .min(Duration::from_secs(60));
    let response = helper::invoke(
        &hrc.executable,
        &args,
        &json!({"format":"HyperNet.HrcHost/1", "action":action}),
        host.cancel,
        remaining,
    )?;
    ensure!(
        serde_json::to_vec(&response)?.len() <= 65536,
        "HRC host response exceeds bound"
    );
    Ok(response)
}
fn validate_hrc_response(
    root: &Path,
    home: &Value,
    agents: bool,
    maximum_agents: u32,
    response: &Value,
) -> Result<()> {
    ensure!(
        response["format"] == "HyperNet.HrcHost/1"
            && matches!(response["status"].as_str(), Some("Prepared" | "Ready"))
            && response["descriptor"]["version"] == 1
            && response["descriptor"]["home"] == *home
            && response["descriptor"]["protocol"] == "hrc/1"
            && protocol::identifier(&string(&response["descriptor"], "signingKey")?)
            && response["policy"]
                == json!({"agentsEnabled":agents,"maxAgentsPerOperator":maximum_agents}),
        "HRC host response does not match the reviewed native service"
    );
    for (field, relative) in [
        ("serviceDirectory", "Home"),
        ("ownerProfile", "Owner/Profile"),
        ("recoveryKeyFile", "Owner/Recovery.key"),
        ("admissionBinding", "Registrar.json"),
    ] {
        ensure!(
            response[field].as_str() == root.join(relative).to_str(),
            "HRC host artifact path differs"
        );
    }
    let rooms = response["rooms"]
        .as_array()
        .context("HRC community rooms absent")?;
    ensure!(
        rooms.len() == usize::from(response["status"] == "Ready"),
        "HRC community room count differs"
    );
    for room in rooms {
        ensure!(
            room["home"] == *home && protocol::identifier(&string(room, "local")?),
            "HRC community room belongs to another Home"
        );
    }
    Ok(())
}
pub fn prepare_hrc(host: &mut Host<'_>, owner: Value) -> Result<Value> {
    let hrc = host.c.hrc.clone().context("HRC is not selected")?;
    let owner_principal = string(&owner, "principal")?;
    let owner_companion = PathBuf::from(string(&owner, "companion")?);
    ensure!(
        protocol::identifier(&owner_principal)
            && owner_companion == companion(host, "OwnerChat")?
            && host.state.results["owner-chat"]["member"].as_str() == Some(&owner_principal),
        "HRC owner binding differs"
    );
    let receiver = companion(host, "Receiver")?;
    ensure!(
        host.state.results["receiver"]["directory"].as_str() == receiver.to_str(),
        "HRC receiver is not provisioned"
    );
    let bootstrap = host.bootstrap()?;
    let home = json!({"network":{"network":string(&bootstrap,"network")?,
        "incarnation":string(&bootstrap,"incarnation")?},"service":host.state.ids["application"]});
    let bridge = runtime_root(host)?.join("HrcAdmission");
    let (uid, _gid) = operator::mapped_ids(host)?;
    let action = json!({"operation":"prepare", "home":home,
        "receiverCompanion":receiver,
        "clock":{"observation":host.p("Native/Clock/Public/ClockHealth.cbor"),"monitorKey":host.monitor()?},
        "ownerPrincipal":owner_principal, "ownerCompanion":owner_companion,
        "nickname":hrc.nickname,"motd":hrc.motd,"agentsEnabled":hrc.agents_enabled,
        "maxAgentsPerOperator":hrc.max_agents_per_operator,"admissionBridge":bridge,"admissionUid":uid});
    let prepared = hrc_request(host, action)?;
    validate_hrc_response(
        &host.p("HRC"),
        &home,
        hrc.agents_enabled,
        hrc.max_agents_per_operator,
        &prepared,
    )?;
    host.unit(
        "hrc",
        &hrc.executable,
        &bytes(&["service", "run", "--directory", &text(&host.p("HRC/Home"))?]),
    )?;
    host.wait(
        || {
            let socket = std::fs::symlink_metadata(host.p("HRC/Home/Admission.sock"))?;
            ensure!(
                socket.file_type().is_socket()
                    && socket.uid() == unsafe { libc::geteuid() }
                    && socket.mode() & 0o7777 == 0o600,
                "HRC Home control is not ready"
            );
            Ok(())
        },
        30,
    )?;
    // Home finish replays the same retained signed owner operations after interruption.
    let ready = hrc_request(host, json!({"operation":"finish"}))?;
    validate_hrc_response(
        &host.p("HRC"),
        &home,
        hrc.agents_enabled,
        hrc.max_agents_per_operator,
        &ready,
    )?;
    ensure!(
        ready["status"] == "Ready" && ready["descriptor"] == prepared["descriptor"],
        "HRC owner provisioning is incomplete"
    );
    let state = host.p("HrcRegistrar");
    provision_registrar(host, &state, &ready["descriptor"])?;
    let result = json!({"descriptor":ready["descriptor"],"admissionBinding":ready["admissionBinding"],
        "ownerProfile":ready["ownerProfile"],"rooms":ready["rooms"],"policy":ready["policy"],
        "registrarIsolation":{"executable":hrc.executable,"stateDirectory":state,
            "bridgeDirectory":bridge,"hostUid":uid}});
    host.remember("hrc", result.clone())?;
    Ok(result)
}

pub fn start_receiver(host: &mut Host<'_>) -> Result<()> {
    let native = host
        .remembered("receiver-native")
        .context("receiver native membership is absent")?;
    let profile = PathBuf::from(string(&native, "profile")?);
    let principal = string(&native, "member")?;
    ensure!(
        profile.starts_with(&host.c.root)
            && principal == string(&host.state.results["Receiver"], "publicKey")?,
        "receiver native identity differs from its retained key"
    );
    let selected = companion(host, "Receiver")?;
    let accepted =
        services::active_directory(host, "ApplicationEndpoint")?.join("ServiceAccepted.cbor");
    host.unit(
        "receiver",
        &host.c.suite,
        &bytes(&[
            "network",
            "connect",
            "--profile",
            &text(&profile)?,
            "--",
            "streams",
            "agent",
            "--ipc-directory",
            &text(&selected)?,
            "--binding",
            &text(&accepted)?,
        ]),
    )?;
    host.wait(
        || {
            let value = host.suite(&bytes(&[
                "streams",
                "status",
                "--directory",
                &text(&selected)?,
            ]))?;
            validate_companion(
                &value,
                &host.bootstrap()?,
                &principal,
                Some(&host.state.ids["application"]),
            )
        },
        30,
    )?;
    host.remember(
        "receiver",
        json!({"directory":selected,"profile":profile,"principal":principal}),
    )?;
    Ok(())
}
fn validate_companion(
    value: &Value,
    bootstrap: &Value,
    principal: &str,
    service: Option<&str>,
) -> Result<()> {
    ensure!(
        value["ok"] == true
            && value["status"] == "Ready"
            && value["network"] == bootstrap["network"]
            && value["incarnation"] == bootstrap["incarnation"]
            && value["principal"].as_str() == Some(principal)
            && value["incoming"].as_bool() == Some(service.is_some()),
        "native companion is not ready for the retained identity"
    );
    if let Some(service) = service {
        ensure!(
            value["binding"]["service"].as_str() == Some(service)
                && value["binding"]["protocol"] == "hrc/1",
            "receiver service binding differs"
        );
    } else {
        ensure!(
            value["binding"].is_null(),
            "owner companion unexpectedly accepts incoming streams"
        );
    }
    Ok(())
}
fn provision_registrar(host: &mut Host<'_>, state: &Path, descriptor: &Value) -> Result<()> {
    let binding = json!({"directory":"/HrcBridge","peerUid":0,
        "home":descriptor["home"],"serviceKey":descriptor["signingKey"],
        "registrarKeyFile":"/HrcAdmission/Registrar.key"});
    let source = host.p("HRC/RegistrarIsolation.json");
    host.immutable_json(&source, &binding)?;
    // The generic mapped writer receives bounded private stdin and runs as the
    // destination's isolated UID. Resumed registrar state never receives owner-level writes.
    operator::directory(host, state)?;
    operator::copy(host, &source, &state.join("Binding.json"))?;
    let key = host.p("HRC/Registrar.key");
    let secret = zeroize::Zeroizing::new(files::read(&key, 32)?);
    ensure!(secret.len() == 32, "HRC scoped registrar key differs");
    operator::copy(host, &key, &state.join("Registrar.key"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn home() -> Value {
        json!({"network":{"network":"11".repeat(32),"incarnation":"22".repeat(32)},"service":"33".repeat(32)})
    }
    fn response(root: &Path) -> Value {
        json!({"format":"HyperNet.HrcHost/1","status":"Ready",
            "descriptor":{"version":1,"home":home(),"signingKey":"44".repeat(32),"protocol":"hrc/1"},
            "serviceDirectory":root.join("Home"),"ownerProfile":root.join("Owner/Profile"),
            "recoveryKeyFile":root.join("Owner/Recovery.key"),"admissionBinding":root.join("Registrar.json"),
            "rooms":[{"home":home(),"local":"55".repeat(32)}],
            "policy":{"agentsEnabled":false,"maxAgentsPerOperator":2}})
    }
    #[test]
    fn hrc_provisioning_refuses_other_home_paths_or_expanded_policy() {
        let root = Path::new("/private/host/HRC");
        let original = response(root);
        validate_hrc_response(root, &home(), false, 2, &original).unwrap();
        for pointer in [
            "/descriptor/home/service",
            "/rooms/0/home/service",
            "/serviceDirectory",
        ] {
            let mut changed = original.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("66".repeat(32));
            assert!(validate_hrc_response(root, &home(), false, 2, &changed).is_err());
        }
        let mut changed = original;
        changed["policy"]["agentsEnabled"] = json!(true);
        assert!(validate_hrc_response(root, &home(), false, 2, &changed).is_err());
    }
    #[test]
    fn native_companion_readiness_binds_principal_and_exact_incoming_service() {
        let bootstrap = home()["network"].clone();
        let principal = "77".repeat(32);
        let service = "33".repeat(32);
        let mut value = json!({"ok":true,"status":"Ready","network":bootstrap["network"],
            "incarnation":bootstrap["incarnation"],"principal":principal,"incoming":true,
            "binding":{"service":service,"protocol":"hrc/1"}});
        validate_companion(&value, &bootstrap, &principal, Some(&service)).unwrap();
        value["principal"] = json!("88".repeat(32));
        assert!(validate_companion(&value, &bootstrap, &principal, Some(&service)).is_err());
        value["principal"] = json!(principal);
        value["binding"]["service"] = json!("99".repeat(32));
        assert!(validate_companion(&value, &bootstrap, &principal, Some(&service)).is_err());
        assert!(validate_companion(&value, &bootstrap, &principal, None).is_err());
    }
}
