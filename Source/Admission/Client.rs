// SPDX-License-Identifier: MIT
// One saved join workflow verifies current native authority and resumes exact enrolled identities.
use super::{
    helper,
    location::Location,
    protocol::{self, Descriptor, Intent, Metadata, Request, Response, Signed},
    saved::{self, Session, State},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{path::PathBuf, sync::atomic::AtomicBool, time::Duration};
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HrcOptions {
    pub executable: PathBuf,
    pub companion: PathBuf,
    pub clock: Value,
    pub classification: Value,
    pub rooms: Vec<Value>,
    pub allow_initiate: bool,
    pub allow_agent_replies: bool,
    pub successor: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase", deny_unknown_fields)]
pub enum Command {
    Preview {
        location: String,
    },
    Prepare {
        location: String,
        #[serde(rename = "displayName")]
        display_name: String,
        #[serde(rename = "minimumRoute")]
        minimum_route: u64,
        hrc: Option<HrcOptions>,
    },
    Consent {
        consent: Value,
    },
    Connect {
        admission: Option<protocol::Admission>,
    },
    Continue,
    Renew,
    RenewReader,
    RenewChat,
    Offline,
    Status,
}
impl Drop for Command {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        match self {
            Self::Preview { location } | Self::Prepare { location, .. } => location.zeroize(),
            _ => {}
        }
    }
}
fn field<'a>(v: &'a Value, name: &str) -> Result<&'a str> {
    v.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("admission result field absent"))
}
fn native(session: &Session, body: Value, stop: &AtomicBool) -> Result<Value> {
    helper::candidate(&session.native(), body, stop)
}
fn hrc(session: &Session, options: &HrcOptions, action: Value, stop: &AtomicBool) -> Result<Value> {
    let response = helper::invoke(
        &options.executable,
        &[
            "profile".into(),
            "admission-request".into(),
            "--directory".into(),
            session.directory.join("Hrc").into_os_string(),
        ],
        &json!({"format":"HyperNet.HrcParticipant/1","action":action}),
        stop,
        Duration::from_secs(15),
    )?;
    ensure!(
        response.get("format").and_then(Value::as_str) == Some("HyperNet.HrcParticipant/1"),
        "HRC participant helper version differs"
    );
    Ok(response)
}
fn descriptor(
    session: &Session,
    location: &Location,
    stop: &AtomicBool,
) -> Result<(Descriptor, Metadata)> {
    let descriptor: Descriptor = serde_json::from_slice(&super::transport::descriptor(location)?)?;
    ensure!(
        descriptor.format == protocol::FORMAT,
        "unsupported admission protocol"
    );
    let expected = location.identity_pin.map(hex::encode);
    let inspected = native(
        session,
        json!({"operation":"inspect","bootstrap":field(&descriptor.native,"bootstrap")?,"proof":field(&descriptor.native,"proof")?,"expectedKey":expected}),
        stop,
    )?;
    ensure!(
        field(&inspected, "status")? == "descriptor",
        "native admission proof unavailable"
    );
    let key = field(&inspected, "signingKey")?;
    let metadata: Metadata = descriptor.metadata.verify("descriptor", key, 65536)?;
    ensure!(
        metadata.origin == location.origin.as_str()
            && metadata.signing_key == key
            && metadata.network == field(&inspected, "network")?
            && metadata.incarnation == field(&inspected, "incarnation")?
            && metadata.policy == field(&inspected, "policy")?
            && Some(metadata.generation)
                == inspected.get("policyGeneration").and_then(Value::as_u64)
            && metadata.bootstrap_digest
                == protocol::digest(&hex::decode(field(&descriptor.native, "bootstrap")?)?),
        "descriptor differs from certified native identity"
    );
    ensure!(
        location
            .identity_pin
            .is_none_or(|p| hex::encode(p) == field(&inspected, "currentKey").unwrap_or("")),
        "server identity differs from invitation"
    );
    ensure!(
        !metadata.name.is_empty()
            && metadata.name.len() <= 128
            && !metadata.name.chars().any(char::is_control)
            && !metadata.permissions.room_creation
            && !metadata.permissions.moderation
            && !metadata.permissions.publishing
            && !metadata.permissions.hosting,
        "unsupported simple-join permission preset"
    );
    protocol::native_permissions(&inspected, &metadata.permissions)?;
    Ok((descriptor, metadata))
}
fn pinned(location: &Location, metadata: &Metadata) -> Result<Location> {
    let mut location = location.clone();
    location.identity_pin = Some(
        hex::decode(protocol::digest(&hex::decode(&metadata.signing_key)?))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid descriptor key"))?,
    );
    location.invitation = None;
    location.secret = None;
    Ok(location)
}
fn prepare(
    session: &Session,
    location: &Location,
    name: &str,
    minimum_route: u64,
    options: Option<&HrcOptions>,
    stop: &AtomicBool,
) -> Result<Value> {
    if session.directory.join("Server.json").exists() {
        let state = session.state()?;
        ensure!(
            state.metadata.origin == location.origin.as_str() && state.display_name == name,
            "saved server differs; resume its original join"
        );
        ensure!(
            location.identity_pin.is_none_or(|p| hex::encode(p)
                == protocol::digest(&hex::decode(&state.metadata.signing_key).unwrap_or_default())),
            "saved server identity differs from invitation"
        );
        return summary(session, &state);
    }
    let (descriptor, metadata) = descriptor(session, location, stop)?;
    let mut roles = vec![];
    if metadata.permissions.reader {
        roles.push(0);
    }
    if options.is_some() {
        ensure!(metadata.permissions.chat, "this server does not offer chat");
        roles.push(1);
    }
    ensure!(
        !roles.is_empty(),
        "selected server has no requested service"
    );
    let prepared = native(
        session,
        json!({"operation":"prepare","bootstrap":field(&descriptor.native,"bootstrap")?,"proof":field(&descriptor.native,"proof")?,"expectedKey":protocol::digest(&hex::decode(&metadata.signing_key)?),"roles":roles,"minimumRoute":minimum_route}),
        stop,
    )?;
    ensure!(
        field(&prepared, "status")? == "prepared",
        "native keys are not prepared"
    );
    let roles: Vec<protocol::Role> = serde_json::from_value(
        prepared
            .get("roles")
            .ok_or_else(|| anyhow::anyhow!("native roles absent"))?
            .clone(),
    )?;
    let public_location = pinned(location, &metadata)?.url(false)?;
    let mut state = State {
        version: 1,
        location: public_location,
        metadata,
        desired_online: false,
        roles,
        display_name: name.into(),
        intent: None,
        native_claim: None,
        native_bound: false,
        installed: None,
        hrc: None,
        removed: false,
        retirement: None,
        removal_acknowledged: false,
    };
    let mut intent = Intent {
        attempt: session.identity.attempt.clone(),
        control_key: session.identity.control_key.clone(),
        descriptor_digest: protocol::digest_value(&state.metadata)?,
        display_name: name.into(),
        roles: state.roles.clone(),
        hrc: None,
        invitation: location.invitation.map(hex::encode),
    };
    if let Some(options) = options {
        ensure!(
            options.executable.is_absolute() && options.companion.is_absolute(),
            "HRC local helper configuration must be absolute"
        );
        let advertised = state
            .metadata
            .permissions
            .hrc
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("HRC descriptor absent"))?;
        let principal = &state
            .roles
            .iter()
            .find(|r| r.role == 1)
            .ok_or_else(|| anyhow::anyhow!("chat role absent"))?
            .member;
        let prepared = hrc(
            session,
            options,
            json!({"operation":"prepare","server":advertised.get("descriptor"),"claimId":intent.attempt,"nativePrincipal":principal,"classification":options.classification,"rooms":options.rooms,"allowInitiate":options.allow_initiate,"allowAgentReplies":options.allow_agent_replies,"successor":options.successor,"companion":options.companion,"clock":options.clock}),
            stop,
        )?;
        intent.hrc = Some(protocol::HrcIntent {
            request: prepared
                .get("request")
                .ok_or_else(|| anyhow::anyhow!("HRC request absent"))?
                .clone(),
        });
        saved::replace(&session.directory.join("HrcOptions.json"), options)?;
    }
    intent.validate()?;
    state.intent = Some(intent);
    session.save(&state)?;
    summary(session, &state)
}
fn summary(session: &Session, state: &State) -> Result<Value> {
    let operator = state
        .intent
        .as_ref()
        .and_then(|i| i.hrc.as_ref())
        .filter(|h| {
            h.request
                .pointer("/classification/kind")
                .and_then(Value::as_str)
                == Some("agent")
                && h.request.get("operatorConsent").is_none()
        });
    Ok(
        json!({"status":if state.removed{"Removed"}else if state.installed.is_some(){"Joined"}else if operator.is_some(){"OperatorConsentRequired"}else{"Prepared"},"directory":session.directory,"server":state.metadata,"desiredOnline":state.desired_online,"native":state.installed,"hrc":state.hrc,"operatorRequest":operator.map(|h|&h.request)}),
    )
}
fn challenge(
    session: &Session,
    state: &mut State,
    location: &Location,
    client: &reqwest::blocking::Client,
) -> Result<Signed> {
    let intent = state
        .intent
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("join intent absent"))?;
    let bytes = super::transport::response(
        client
            .post(location.endpoint("/v1/admission/challenge")?)
            .json(&protocol::ChallengeRequest {
                attempt: intent.attempt.clone(),
                control_key: intent.control_key.clone(),
                intent_digest: intent.digest()?,
                previous: if session.directory.join("Challenge.json").exists() {
                    Some(saved::read(&session.directory.join("Challenge.json"))?)
                } else {
                    None
                },
            })
            .send()
            .map_err(|_| anyhow::anyhow!("admission connection interrupted"))?,
    )?;
    let signed: Signed = serde_json::from_slice(&bytes)?;
    let c: protocol::Challenge = signed.verify("challenge", &state.metadata.signing_key, 4096)?;
    ensure!(
        c.origin == state.metadata.origin
            && c.attempt == intent.attempt
            && c.control_key == intent.control_key
            && c.intent_digest == intent.digest()?
            && protocol::identifier(&c.native_claim),
        "admission challenge differs from retained intent"
    );
    if let Some(old) = &state.native_claim {
        ensure!(
            old == &c.native_claim || !state.native_bound,
            "server discarded the retained claim; review a new admission explicitly"
        );
    }
    state.native_claim = Some(c.native_claim);
    session.save(state)?;
    saved::replace(&session.directory.join("Challenge.json"), &signed)?;
    Ok(signed)
}
fn post(session: &Session, state: &mut State, action: protocol::Action) -> Result<Response> {
    let location = Location::parse(&state.location)?;
    let client = super::transport::client(&location)?;
    let challenge = challenge(session, state, &location, &client)?;
    let request = Signed::new("request", &Request { challenge, action }, &session.key)?;
    ensure!(
        serde_json::to_vec(&request)?.len() <= protocol::REQUEST_BYTES,
        "signed admission request exceeds bound"
    );
    let bytes = super::transport::response(
        client
            .post(location.endpoint("/v1/admission/request")?)
            .json(&request)
            .send()
            .map_err(|_| {
                anyhow::anyhow!("admission interrupted; same keys and request retained")
            })?,
    )?;
    Ok(serde_json::from_slice(&bytes)?)
}
fn advance(
    session: &Session,
    state: &mut State,
    mut response: Response,
    stop: &AtomicBool,
    selected: Option<&[u64]>,
) -> Result<Value> {
    for _ in 0..6 {
        response = match response {
            Response::Removed { result } => {
                let verified = native(
                    session,
                    json!({"operation":"acceptResult","result":result,"roles":selected}),
                    stop,
                )?;
                ensure!(
                    field(&verified, "status")? == "retired",
                    "native retirement proof did not retire this exact claim"
                );
                state.removed = true;
                state.retirement = Some(result.clone());
                state.desired_online = false;
                session.save(state)?;
                return confirm_removal(session, state, post);
            }
            Response::RemovalAcknowledged => {
                return Ok(json!({"status":"Removed","code":"ParticipantRemoved"}));
            }
            Response::NativeChallenge { challenge } => {
                let intent = state.intent.as_ref().unwrap();
                let accepted = native(
                    session,
                    json!({"operation":"acceptChallenge","challenge":challenge,"applicationBinding":intent.application_binding()?,"requestDigest":intent.digest()?,"claim":state.native_claim}),
                    stop,
                )?;
                ensure!(
                    field(&accepted, "status")? == "acceptance",
                    "native challenge not accepted"
                );
                state.native_bound = true;
                session.save(state)?;
                post(
                    session,
                    state,
                    protocol::Action::AcceptNative {
                        acceptance: field(&accepted, "acceptance")?.into(),
                    },
                )?
            }
            Response::NativeReady {
                result,
                hrc: invitation,
            } => {
                let installed = native(
                    session,
                    json!({"operation":"acceptResult","result":result,"roles":selected}),
                    stop,
                )?;
                if field(&installed, "status")? == "pending" {
                    return Ok(json!({"status":"Pending","code":installed.get("code")}));
                }
                ensure!(
                    field(&installed, "status")? == "installed",
                    "native result not installed"
                );
                let invitation =
                    invitation.ok_or_else(|| anyhow::anyhow!("HRC invitation absent"))?;
                let options: HrcOptions = saved::read(&session.directory.join("HrcOptions.json"))?;
                let registration = hrc(
                    session,
                    &options,
                    json!({"operation":"registration","invitation":invitation.get("invitation")}),
                    stop,
                )?;
                post(
                    session,
                    state,
                    protocol::Action::AcceptHrc {
                        registration: registration
                            .get("registration")
                            .filter(|v| !v.is_null())
                            .ok_or_else(|| anyhow::anyhow!("HRC registration unavailable"))?
                            .clone(),
                    },
                )?
            }
            Response::Ready {
                native: result,
                hrc,
            } => {
                let installed = native(
                    session,
                    json!({"operation":"acceptResult","result":field(&result,"result")?,"roles":selected}),
                    stop,
                )?;
                if field(&installed, "status")? == "pending" {
                    return Ok(json!({"status":"Pending","code":installed.get("code")}));
                }
                ensure!(
                    field(&installed, "status")? == "installed",
                    "native result not installed"
                );
                state.installed = Some(installed);
                state.hrc = hrc;
                session.save(state)?;
                return summary(session, state);
            }
            Response::RenewalChallenge { challenge } => {
                let proof = native(
                    session,
                    json!({"operation":"renewalProof","challenge":challenge}),
                    stop,
                )?;
                ensure!(
                    field(&proof, "status")? == "acceptance",
                    "native renewal consent unavailable"
                );
                post(
                    session,
                    state,
                    protocol::Action::Renew {
                        proof: field(&proof, "acceptance")?.into(),
                    },
                )?
            }
            Response::Pending { code } => return Ok(json!({"status":"Pending","code":code})),
            Response::Refused { code } => return Ok(json!({"status":"Refused","code":code})),
        };
    }
    anyhow::bail!("admission phase limit reached; exact progress retained")
}
pub fn run(directory: &std::path::Path, command: &Command, stop: &AtomicBool) -> Result<Value> {
    let session = Session::open(directory)?;
    match command {
        Command::Preview { location } => {
            let (_, metadata) = descriptor(&session, &Location::parse(location)?, stop)?;
            Ok(json!({"status":"ReviewServer","server":metadata}))
        }
        Command::Prepare {
            location,
            display_name,
            minimum_route,
            hrc,
        } => prepare(
            &session,
            &Location::parse(location)?,
            display_name,
            *minimum_route,
            hrc.as_ref(),
            stop,
        ),
        Command::Consent { consent } => {
            let mut state = session.state()?;
            ensure!(
                state.installed.is_none(),
                "completed enrolment cannot change its consent"
            );
            let hrc = state
                .intent
                .as_mut()
                .and_then(|i| i.hrc.as_mut())
                .ok_or_else(|| anyhow::anyhow!("Agent request absent"))?;
            ensure!(
                hrc.request
                    .pointer("/classification/kind")
                    .and_then(Value::as_str)
                    == Some("agent")
                    && consent.get("claimId").and_then(Value::as_str)
                        == Some(&session.identity.attempt),
                "operator consent differs from Agent"
            );
            let artifact = consent
                .get("operatorConsent")
                .filter(|v| v.is_object())
                .ok_or_else(|| anyhow::anyhow!("operator consent absent"))?;
            hrc.request
                .as_object_mut()
                .unwrap()
                .insert("operatorConsent".into(), artifact.clone());
            session.save(&state)?;
            summary(&session, &state)
        }
        Command::Connect { admission } => {
            let mut state = session.state()?;
            if state.removed {
                return confirm_removal(&session, &mut state, post);
            }
            state.desired_online = true;
            session.save(&state)?;
            let response = {
                let intent = state
                    .intent
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("join request absent"))?;
                if let Some(h) = &intent.hrc {
                    ensure!(
                        h.request
                            .pointer("/classification/kind")
                            .and_then(Value::as_str)
                            != Some("agent")
                            || h.request.get("operatorConsent").is_some(),
                        "operator consent required"
                    );
                }
                let auth: protocol::Admission = if let Some(admission) = admission {
                    serde_json::from_value(serde_json::to_value(admission)?)?
                } else {
                    ensure!(
                        state.native_claim.is_some(),
                        "admission credential required"
                    );
                    protocol::Admission::Public
                };
                post(
                    &session,
                    &mut state,
                    protocol::Action::Start {
                        intent,
                        admission: auth,
                    },
                )?
            };
            advance(&session, &mut state, response, stop, None)
        }
        Command::Continue | Command::Renew | Command::RenewReader | Command::RenewChat => {
            let mut state = session.state()?;
            if state.removed {
                return confirm_removal(&session, &mut state, post);
            }
            ensure!(
                state.desired_online,
                "saved server is offline; reconnect explicitly"
            );
            let selected = match command {
                Command::RenewReader => Some([0u64]),
                Command::RenewChat => Some([1u64]),
                _ => None,
            };
            ensure!(
                selected.is_none()
                    || (state.installed.is_some()
                        && state.roles.iter().any(|r| Some([r.role]) == selected)),
                "reader refresh requires an installed reader"
            );
            let action = if matches!(
                command,
                Command::Renew | Command::RenewReader | Command::RenewChat
            ) {
                protocol::Action::RenewalChallenge
            } else {
                protocol::Action::Status
            };
            let response = post(&session, &mut state, action)?;
            advance(
                &session,
                &mut state,
                response,
                stop,
                selected.as_ref().map(|v| v.as_slice()),
            )
        }
        Command::Offline => {
            let mut state = session.state()?;
            state.desired_online = false;
            session.save(&state)?;
            summary(&session, &state)
        }
        Command::Status => summary(&session, &session.state()?),
    }
}

fn confirm_removal(
    session: &Session,
    state: &mut State,
    send: impl FnOnce(&Session, &mut State, protocol::Action) -> Result<Response>,
) -> Result<Value> {
    ensure!(
        state.removed && !state.desired_online,
        "membership is not removed"
    );
    let result = state
        .retirement
        .as_ref()
        .filter(|s| protocol::artifact(s, 128 * 1024))
        .ok_or_else(|| anyhow::anyhow!("verified retirement evidence is absent"))?;
    let digest = protocol::digest(result.as_bytes());
    // A lost acknowledgement must remain retryable without restoring access or
    // starting the clock and chat runtime. Only an explicit reconnect contacts it.
    if !state.removal_acknowledged
        && matches!(
            send(
                session,
                state,
                protocol::Action::AcknowledgeRemoval {
                    result_digest: digest,
                }
            ),
            Ok(Response::RemovalAcknowledged)
        )
    {
        state.removal_acknowledged = true;
        session.save(state)?;
    }
    Ok(
        json!({"status":"Removed","code":"ParticipantRemoved","removalAcknowledged":state.removal_acknowledged}),
    )
}

#[cfg(test)]
mod removal_tests {
    use super::*;

    #[test]
    fn interrupted_removal_acknowledgement_survives_restart_without_rejoining() {
        let directory =
            std::env::temp_dir().join(format!("join-removal-{}", crate::random_hex::<8>()));
        let session = Session::open(&directory).unwrap();
        let state: State = serde_json::from_value(json!({
            "version":1,"location":"https://localhost/","metadata":{
                "origin":"https://localhost/","name":"Example","network":"01".repeat(32),
                "incarnation":"02".repeat(32),"policy":"03".repeat(32),"generation":1,
                "bootstrapDigest":"04".repeat(32),"signingKey":"05".repeat(32),
                "permissions":{"modes":["inviteOnly"],"access":{"mode":"untilRemoved"},
                    "reader":true,"chat":false,"roomCreation":false,"moderation":false,
                    "publishing":false,"hosting":false,"agents":false,"maximumMembers":1,"hrc":null},"welcome":null},
            "desiredOnline":false,"roles":[],"displayName":"Reader","intent":null,
            "nativeClaim":"06".repeat(32),"nativeBound":true,"installed":{"retained":true},
            "hrc":null,"removed":true,"retirement":"aabb"
        })).unwrap();
        session.save(&state).unwrap();
        let mut state = session.state().unwrap();
        let result=confirm_removal(&session,&mut state,|_,_,action| {
            assert!(matches!(action,protocol::Action::AcknowledgeRemoval{result_digest} if result_digest==protocol::digest(b"aabb")));
            anyhow::bail!("connection lost before acknowledgement")
        }).unwrap();
        assert_eq!(result["status"], "Removed");
        drop(session);
        let session = Session::open(&directory).unwrap();
        let mut state = session.state().unwrap();
        assert!(!state.removal_acknowledged && state.removed && !state.desired_online);
        assert_eq!(state.retirement.as_deref(), Some("aabb"));
        confirm_removal(&session, &mut state, |_, _, _| {
            Ok(Response::Refused {
                code: "TemporaryFailure".into(),
            })
        })
        .unwrap();
        assert!(!state.removal_acknowledged);
        confirm_removal(&session, &mut state, |_, _, _| {
            Ok(Response::RemovalAcknowledged)
        })
        .unwrap();
        assert!(session.state().unwrap().removal_acknowledged);
        confirm_removal(&session, &mut state, |_, _, _| {
            panic!("confirmed receipt must not reconnect")
        })
        .unwrap();
        assert!(state.removed && !state.desired_online);
        assert_eq!(state.installed, Some(json!({"retained":true})));
        drop(session);
        assert_eq!(
            run(
                &directory,
                &Command::Connect { admission: None },
                &AtomicBool::new(false)
            )
            .unwrap()["status"],
            "Removed"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
