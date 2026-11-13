// SPDX-License-Identifier: Apache-2.0
// The owner reserves one ordinary participant slot through the same scoped native protocol.
use super::{engine::*, files, operator::*};
use crate::admission::{helper, host_isolation, protocol};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{ffi::OsString, path::Path, time::Duration};

const FORMAT: &str = "HyperNetNativeAdmission/1";
fn response(bytes: &[u8]) -> Result<Value> {
    let value: Value = serde_json::from_slice(bytes)?;
    ensure!(
        value["format"] == FORMAT && value["body"].is_object(),
        "native helper envelope differs"
    );
    Ok(value["body"].clone())
}
fn expected(value: Value, status: &str) -> Result<Value> {
    ensure!(
        value["status"] == status,
        "native admission is incomplete or refused"
    );
    Ok(value)
}
pub fn registrar(host: &Host<'_>, request: Value) -> Result<Value> {
    let mut a = bytes(&[
        "run",
        "--interactive",
        "--rm",
        "--pull=never",
        "--network=none",
        "--userns=nomap",
        "--user=1000:1000",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--read-only",
        "--pids-limit=64",
        "--memory=268435456",
        "--cpus=1",
        "--log-driver=none",
        "--workdir=/Native",
        "--entrypoint=/HyperNetSuite",
    ]);
    for (source, target, mode) in [
        (host.c.suite.clone(), "/HyperNetSuite", "ro"),
        (host.p("Registrar"), "/Native", "rw"),
        (host.p("A1/Launch/State/Control"), "/Authority", "ro"),
        (host.p("Native/Clock/Public"), "/Clock", "ro"),
    ] {
        a.extend(bytes(&[
            "--volume",
            &format!(
                "{}:{target}:{mode},nosuid,nodev",
                host_isolation::argument(&source)?
            ),
        ]));
    }
    a.extend(bytes(&[
        &host.state.image,
        "authority-inspection",
        "admission",
        "registrar",
        "--configuration",
        "/Native/Registrar.json",
        "--json-stdin",
    ]));
    let a: Vec<OsString> = a.iter().map(Into::into).collect();
    let input = zeroize::Zeroizing::new(serde_json::to_vec(
        &json!({"format":FORMAT,"body":request}),
    )?);
    response(&helper::output(
        Path::new("/usr/bin/podman"),
        &a,
        &input,
        host.cancel,
        Duration::from_secs(60),
    )?)
}
fn candidate(host: &Host<'_>, request: Value) -> Result<Value> {
    let a = bytes(&[
        "authority-inspection",
        "admission",
        "candidate",
        "--directory",
        &text(&host.p("OwnerCandidate"))?,
        "--clock-witness",
        &text(&host.p("Native/Clock/ClockHealth.json"))?,
        "--json-stdin",
    ]);
    let a: Vec<OsString> = a.iter().map(Into::into).collect();
    let input = zeroize::Zeroizing::new(serde_json::to_vec(
        &json!({"format":FORMAT,"body":request}),
    )?);
    response(&helper::output(
        &host.c.suite,
        &a,
        &input,
        host.cancel,
        Duration::from_secs(60),
    )?)
}
pub fn prepare(host: &mut Host<'_>) -> Result<()> {
    host.phase("Restricted participant policy")?;
    let resource = &host.c.resources;
    let limit = json!([
        resource.connection_bytes,
        1024,
        resource.relay_connections.min(16),
        16
    ]);
    let mut templates = vec![
        json!({"role":0,"destination":host.state.ids["pages"],"application":null,
        "page":string(&host.state.results["PageStore"],"publicKey")?,"limits":limit,"connections":64,
        "bytes":resource.connection_bytes.checked_mul(64).context("route byte budget overflow")?,"voucherMs":3600000}),
    ];
    if host.c.hrc.is_some() {
        templates.push(json!({"role":1,"destination":host.state.ids["application"],
        "application":host.state.ids["application"],"page":null,"limits":limit,"connections":64,
        "bytes":resource.connection_bytes.checked_mul(64).context("route byte budget overflow")?,"voucherMs":3600000}));
    }
    let spec = json!({"id":host.state.ids["policy"],"parent":host.root_grant()?,
        "registrar":string(&host.state.results["Registrar"],"publicKey")?,"descriptor":string(&host.state.results["Descriptor"],"publicKey")?,
        "maximumSlots":host.c.maximum_participants,"validity":[host.state.created_ms,host.c.access_end],
        "relay":host.state.ids["relay"],"authority":host.state.ids["authority"],"templates":templates,"legacy":[],"enabled":true});
    let spec_file = host.p("Network/AdmissionPolicy.json");
    host.immutable_json(&spec_file, &spec)?;
    if host.remembered("admission-policy").is_none() {
        let mut a = bytes(&["authority-inspection", "admission", "policy"]);
        a.extend(online(host, "Administrator")?);
        a.extend(bytes(&["--spec", &text(&spec_file)?]));
        let result = operator(host, "Administrator", &a)?;
        host.remember("admission-policy", result)?;
    }
    let root = host.p("Registrar");
    directory(host, &root)?;
    copy(
        host,
        &host.p("Network/Bootstrap.cbor"),
        &root.join("Bootstrap.cbor"),
    )?;
    copy(
        host,
        &host.p("Keys/Registrar.json"),
        &root.join("Identity.json"),
    )?;
    let descriptor: crate::Identity = serde_json::from_slice(&zeroize::Zeroizing::new(
        files::read(&host.p("Keys/Descriptor.json"), 8192)?,
    ))?;
    let secret = host.p("Keys/Descriptor.key");
    files::exact_file(&secret, descriptor.secret_key.as_bytes())?;
    host.artifact(&secret)?;
    copy(host, &secret, &root.join("Descriptor.key"))?;
    let config = json!({"format":"HyperNetAdmissionRegistrar/1","bootstrap":"/Native/Bootstrap.cbor","bootstrapDigest":host.bootstrap_file_digest()?,
        "directory":"/Native/Requester","clockWitness":"/Clock/ClockHealth.cbor","clockMonitorKey":host.monitor()?,"hostKernelBoot":"CurrentHost",
        "keyFile":"/Native/Identity.json","socket":"/Authority/Control.sock","policy":host.state.ids["policy"]});
    let source = host.p("Network/Registrar.json");
    host.immutable_json(&source, &config)?;
    copy(host, &source, &root.join("Registrar.json"))?;
    let (uid, gid) = mapped_ids(host)?;
    host.remember("registrar-isolation",json!({"namespaceUid":1001,"namespaceGid":1001,"hostUid":uid,"hostGid":gid,
        "configuration":"/Native/Registrar.json","descriptorKeyFile":"/Native/Descriptor.key","mounts":[
            {"source":root,"target":"/Native","readOnly":false},
            {"source":host.p("A1/Launch/State/Control"),"target":"/Authority","readOnly":true},
            {"source":host.p("Native/Clock/Public"),"target":"/Clock","readOnly":true}]}))?;
    Ok(())
}
pub fn owner_prepare(host: &mut Host<'_>) -> Result<Value> {
    if let Some(roles) = host.remembered("owner-roles") {
        return Ok(roles);
    }
    let descriptor = expected(
        registrar(host, json!({"operation":"describe"}))?,
        "descriptor",
    )?;
    let roles = if host.c.hrc.is_some() {
        vec![0, 1]
    } else {
        vec![0]
    };
    let prepared = expected(
        candidate(
            host,
            json!({"operation":"prepare","bootstrap":descriptor["bootstrap"],"proof":descriptor["proof"],
        "expectedKey":descriptor["currentKey"],"roles":roles,"minimumRoute":0}),
        )?,
        "prepared",
    )?;
    host.remember("owner-roles", prepared["roles"].clone())
}
pub fn owner_install(host: &mut Host<'_>) -> Result<Value> {
    if let Some(installed) = host.remembered("owner-installed") {
        return Ok(installed);
    }
    let roles = owner_prepare(host)?;
    let application = host.id("owner-application-binding")?;
    let request_digest =
        protocol::digest_value(&json!({"owner":roles,"applicationBinding":application}))?;
    let claim = match host.state.ids.get("owner-claim") {
        Some(v) => v.clone(),
        None => {
            let descriptor = expected(
                registrar(host, json!({"operation":"describe"}))?,
                "descriptor",
            )?;
            let ordinal = number(&descriptor, "claimFloor")?
                .checked_add(1)
                .context("claim ordinal exhausted")?;
            let mut value = crate::random_hex::<32>();
            value.replace_range(..16, &hex::encode(ordinal.to_be_bytes()));
            host.state.ids.insert("owner-claim".into(), value.clone());
            host.save()?;
            value
        }
    };
    let binding = if let Some(binding) = host.remembered("owner-binding") {
        binding
    } else {
        let challenge = registrar(
            host,
            json!({"operation":"challenge","claim":claim,"requestDigest":request_digest,"roles":roles,"applicationBinding":application}),
        )?;
        let enrolled = if challenge["status"] == "ready" || renewal_required(&challenge) {
            challenge
        } else {
            let challenge = expected(challenge, "challenge")?;
            let acceptance = expected(
                candidate(
                    host,
                    json!({"operation":"acceptChallenge","challenge":challenge["challenge"],
            "applicationBinding":application,"requestDigest":request_digest,"claim":claim}),
                )?,
                "acceptance",
            )?;
            registrar(
                host,
                json!({"operation":"enrol","challenge":challenge["challenge"],"acceptance":acceptance["acceptance"]}),
            )?
        };
        ensure!(
            enrolled["status"] == "ready" || renewal_required(&enrolled),
            "owner enrolment is incomplete or refused"
        );
        enrolled["binding"].clone()
    };
    validate_owner_binding(&binding, &host.state.ids["policy"], &claim, &request_digest)?;
    // Enrolment may be complete while its finite route vouchers have expired.
    // Save the exact admitted binding before renewal so interruption cannot start a new claim.
    host.remember("owner-binding", binding.clone())?;
    let installed = install_owner(
        &binding,
        |request| registrar(host, request),
        |request| candidate(host, request),
    )?;
    host.remember("owner-installed", installed)
}
fn renewal_required(value: &Value) -> bool {
    value["status"] == "pending" && value["code"] == "RenewalRequired"
}
fn validate_owner_binding(
    binding: &Value,
    policy: &str,
    claim: &str,
    request_digest: &str,
) -> Result<()> {
    let binding: crate::authority_inspection::admission::types::Claim =
        serde_json::from_value(binding.clone())?;
    ensure!(
        binding.policy == policy
            && binding.claim == claim
            && binding.request_digest == request_digest
            && binding.slot < crate::authority_admission::MAX_SLOTS
            && binding.generation > 0,
        "owner binding differs from the retained exact request"
    );
    Ok(())
}
fn bound(value: Value, binding: &Value) -> Result<Value> {
    ensure!(
        value["binding"] == *binding,
        "owner admission response changes the retained binding"
    );
    Ok(value)
}
fn renew_owner(
    binding: &Value,
    registrar: &mut impl FnMut(Value) -> Result<Value>,
    candidate: &mut impl FnMut(Value) -> Result<Value>,
) -> Result<Value> {
    let challenge = expected(
        bound(
            registrar(json!({"operation":"renewalChallenge","binding":binding}))?,
            binding,
        )?,
        "challenge",
    )?;
    let proof = candidate(json!({"operation":"renewalProof","challenge":challenge["challenge"]}))?;
    let proof = expected(proof, "acceptance")?;
    expected(
        bound(
            registrar(json!({"operation":"renew","binding":binding,"proof":proof["acceptance"]}))?,
            binding,
        )?,
        "ready",
    )
}
fn install_owner(
    binding: &Value,
    mut registrar: impl FnMut(Value) -> Result<Value>,
    mut candidate: impl FnMut(Value) -> Result<Value>,
) -> Result<Value> {
    let current = bound(
        registrar(json!({"operation":"status","binding":binding}))?,
        binding,
    )?;
    let ready = if renewal_required(&current) || current["status"] == "challenge" {
        // A retained binding also covers interruption after RenewalChallenge or Renew.
        renew_owner(binding, &mut registrar, &mut candidate)?
    } else {
        expected(current, "ready")?
    };
    expected(
        bound(
            candidate(json!({"operation":"acceptResult","result":ready["result"]}))?,
            binding,
        )?,
        "installed",
    )
}
pub fn refresh(host: &mut Host<'_>, roles: Vec<u64>) -> Result<Value> {
    let binding = host
        .remembered("owner-binding")
        .context("owner admission is absent")?;
    let ready = renew_owner(
        &binding,
        &mut |request| registrar(host, request),
        &mut |request| candidate(host, request),
    )?;
    let installed = expected(
        candidate(
            host,
            json!({"operation":"acceptResult","result":ready["result"],"roles":roles}),
        )?,
        "installed",
    )?;
    host.remember("owner-installed", installed)
}
fn owner_reader_key(root: &Path, reader: &Value) -> Result<std::path::PathBuf> {
    let role = root.join("OwnerCandidate/Roles/0");
    let joined = role.join("Joined");
    let profile = std::path::PathBuf::from(string(reader, "profile")?);
    ensure!(
        reader["role"] == 0
            && profile == role.join("Profile.json")
            && Path::new(&string(reader, "directory")?) == joined,
        "owner Page path differs"
    );
    crate::admission::private::directory(&role)?;
    crate::admission::private::directory(&joined)?;
    let bytes = zeroize::Zeroizing::new(files::read(&profile, 1_048_576)?);
    #[derive(serde::Deserialize)]
    struct Joined {
        directory: std::path::PathBuf,
        admitted: bool,
    }
    #[derive(serde::Deserialize)]
    struct Profile {
        device: crate::Identity,
        joined: Joined,
    }
    let profile: Profile = serde_json::from_slice(&bytes)?;
    ensure!(
        profile.device.public_key == reader["member"]
            && profile.joined.directory == joined
            && profile.joined.admitted,
        "owner Page identity differs"
    );
    let key = joined.join("Device.json");
    let bytes = zeroize::Zeroizing::new(files::read(&key, 1_048_576)?);
    let device: crate::Identity = serde_json::from_slice(&bytes)?;
    ensure!(
        device.public_key == profile.device.public_key
            && device.secret_key == profile.device.secret_key,
        "owner Page key differs from the joined profile"
    );
    Ok(key)
}
pub fn owner_report(host: &mut Host<'_>) -> Result<Value> {
    let installed = host
        .remembered("owner-installed")
        .context("owner profiles absent")?;
    let profiles = installed["profiles"]
        .as_array()
        .context("owner profiles differ")?;
    let reader = profiles
        .iter()
        .find(|p| p["role"] == 0)
        .context("owner Page profile absent")?;
    let key = owner_reader_key(&host.c.root, reader)?;
    let chat = profiles.iter().find(|p| p["role"] == 1);
    Ok(
        json!({"candidateDirectory":host.p("OwnerCandidate"),"binding":installed["binding"],
        "readerProfile":reader["profile"],"readerDirectory":reader["directory"],"reader":reader,"readerKeyFile":key,
        "chatProfile":chat.map(|p|p["profile"].clone()),"chatCompanion":host.state.results.get("owner-chat").and_then(|p|p.get("companion")),
        "hrcProfile":host.state.results.get("hrc").and_then(|h|h.get("ownerProfile"))}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque};

    type Step = (&'static str, Value, Option<Value>);

    #[cfg(feature = "gui")]
    #[test]
    fn owner_reader_report_uses_the_joined_browser_key_and_refuses_substitution() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        struct Directory(std::path::PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let directory = Directory(
            std::env::temp_dir().join(format!("NativeOwnerReader{}", crate::random_hex::<16>())),
        );
        files::directory(&directory.0).unwrap();
        for relative in [
            "OwnerCandidate",
            "OwnerCandidate/Roles",
            "OwnerCandidate/Roles/0",
        ] {
            files::directory(&directory.0.join(relative)).unwrap();
        }
        let role = directory.0.join("OwnerCandidate/Roles/0");
        let path = role.join("Profile.json");
        let joined = role.join("Joined");
        files::directory(&joined).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let (bootstrap, _) = crate::authority_recovery::tests::fixture(20, now);
        let request = crate::networks::admission::prepare(&path, &bootstrap, &[], 1, 0).unwrap();
        let mut profile: Value =
            serde_json::from_slice(&files::read(&path, 1_048_576).unwrap()).unwrap();
        profile["joined"] = json!({
            "directory":joined,"clockWitness":directory.0.join("Clock.json"),
            "invitationDigest":"11".repeat(32),"member":"22".repeat(32),
            "readerGrant":"33".repeat(32),"admitted":true,
        });
        crate::admission::saved::replace(&path, &profile).unwrap();
        let key = joined.join("Device.json");
        let original_key = serde_json::to_vec(&profile["device"]).unwrap();
        files::exact_file(&key, &original_key).unwrap();
        files::exact_file(&joined.join("Routes.json"), b"[]").unwrap();
        let reader = json!({"role":0,"profile":path,"directory":joined,"member":request.member});
        let reported = owner_reader_key(&directory.0, &reader).unwrap();
        // Use the network consumer's real profile loading and key selection without route traffic.
        {
            let browser = crate::networks::application::Connection::open(&path).unwrap();
            assert_eq!(reported, browser.key());
        }
        assert_eq!(reported, key);
        let legacy_key = directory.0.join("Keys/OwnerReader.json");
        assert!(!legacy_key.exists());
        files::directory(&directory.0.join("Keys")).unwrap();
        files::exact_file(&legacy_key, &original_key).unwrap();
        let original_profile = std::fs::read(&path).unwrap();
        for (field, value) in [
            ("role", json!(1)),
            (
                "profile",
                json!(directory.0.join("OwnerCandidate/Roles/1/Profile.json")),
            ),
            (
                "directory",
                json!(directory.0.join("OwnerCandidate/Roles/1/Joined")),
            ),
            ("member", json!("44".repeat(32))),
        ] {
            let mut changed = reader.clone();
            changed[field] = value;
            assert!(owner_reader_key(&directory.0, &changed).is_err(), "{field}");
        }
        for (field, value) in [
            ("directory", json!(directory.0.join("Elsewhere"))),
            ("admitted", json!(false)),
        ] {
            let mut changed = profile.clone();
            changed["joined"][field] = value;
            crate::admission::saved::replace(&path, &changed).unwrap();
            assert!(owner_reader_key(&directory.0, &reader).is_err(), "{field}");
        }
        crate::admission::saved::replace(&path, &profile).unwrap();
        let mut changed = profile["device"].clone();
        changed["secretKey"] = json!("55".repeat(32));
        crate::admission::saved::replace(&key, &changed).unwrap();
        assert!(owner_reader_key(&directory.0, &reader).is_err());
        crate::admission::saved::replace(&key, &profile["device"]).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(owner_reader_key(&directory.0, &reader).is_err());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&joined, std::fs::Permissions::from_mode(0o711)).unwrap();
        assert!(owner_reader_key(&directory.0, &reader).is_err());
        std::fs::set_permissions(&joined, std::fs::Permissions::from_mode(0o700)).unwrap();
        let retained = joined.join("RetainedDevice.json");
        std::fs::rename(&key, &retained).unwrap();
        assert!(owner_reader_key(&directory.0, &reader).is_err());
        symlink(&retained, &key).unwrap();
        assert!(owner_reader_key(&directory.0, &reader).is_err());
        std::fs::remove_file(&key).unwrap();
        std::fs::rename(&retained, &key).unwrap();
        assert_eq!(owner_reader_key(&directory.0, &reader).unwrap(), key);
        assert_eq!(std::fs::read(&key).unwrap(), original_key);
        assert_eq!(std::fs::read(&legacy_key).unwrap(), original_key);
        assert_eq!(std::fs::read(&path).unwrap(), original_profile);
    }

    fn binding() -> Value {
        json!({"policy":"11".repeat(32),"slot":0,"generation":1,
            "claim":"22".repeat(32),"requestDigest":"33".repeat(32)})
    }

    fn run(binding: &Value, steps: Vec<Step>) -> Result<Value> {
        let steps = RefCell::new(VecDeque::from(steps));
        let invoke = |target: &str, request: Value| {
            let (expected_target, expected_request, response) = steps
                .borrow_mut()
                .pop_front()
                .expect("unexpected owner admission call");
            assert_eq!(target, expected_target);
            assert_eq!(request, expected_request);
            response.context("simulated interrupted helper response")
        };
        let result = install_owner(
            binding,
            |request| invoke("registrar", request),
            |request| invoke("candidate", request),
        );
        assert!(steps.borrow().is_empty());
        result
    }

    fn renewal(binding: &Value, current: Value) -> Vec<Step> {
        vec![
            (
                "registrar",
                json!({"operation":"status","binding":binding}),
                Some(current),
            ),
            (
                "registrar",
                json!({"operation":"renewalChallenge","binding":binding}),
                Some(json!({"status":"challenge","binding":binding,"challenge":"fresh"})),
            ),
            (
                "candidate",
                json!({"operation":"renewalProof","challenge":"fresh"}),
                Some(json!({"status":"acceptance","acceptance":"proof"})),
            ),
            (
                "registrar",
                json!({"operation":"renew","binding":binding,"proof":"proof"}),
                Some(json!({"status":"ready","binding":binding,"result":"current"})),
            ),
            (
                "candidate",
                // Initial installation must omit partial-refresh roles, even after renewal.
                json!({"operation":"acceptResult","result":"current"}),
                Some(json!({"status":"installed","binding":binding,"profiles":[]})),
            ),
        ]
    }

    #[test]
    fn owner_initial_install_renews_expired_routes_with_the_accepted_claim() {
        let binding = binding();
        let steps = renewal(
            &binding,
            json!({"status":"pending","code":"RenewalRequired","binding":binding}),
        );
        let installed = run(&binding, steps).unwrap();
        assert_eq!(installed["binding"], binding);
        assert_eq!(installed["status"], "installed");
    }

    #[test]
    fn owner_initial_install_resumes_interrupted_renewal_and_completed_handoff() {
        let binding = binding();
        let mut interrupted = renewal(
            &binding,
            json!({"status":"pending","code":"RenewalRequired","binding":binding}),
        );
        interrupted.truncate(4);
        interrupted[3].2 = None;
        assert!(run(&binding, interrupted).is_err());
        let resumed = renewal(
            &binding,
            json!({"status":"challenge","binding":binding,"challenge":"retained"}),
        );
        assert_eq!(run(&binding, resumed).unwrap()["binding"], binding);

        // Lost publication after Renew must use current status, without another renewal.
        let ready = || {
            vec![
                (
                    "registrar",
                    json!({"operation":"status","binding":binding}),
                    Some(json!({"status":"ready","binding":binding,"result":"current"})),
                ),
                (
                    "candidate",
                    json!({"operation":"acceptResult","result":"current"}),
                    Some(json!({"status":"installed","binding":binding,"profiles":[]})),
                ),
            ]
        };
        let mut interrupted = ready();
        interrupted[1].2 = None;
        assert!(run(&binding, interrupted).is_err());
        assert_eq!(run(&binding, ready()).unwrap()["binding"], binding);
    }

    #[test]
    fn owner_initial_install_refuses_changed_binding_and_unrelated_pending_states() {
        let binding = binding();
        validate_owner_binding(
            &binding,
            &"11".repeat(32),
            &"22".repeat(32),
            &"33".repeat(32),
        )
        .unwrap();
        for (field, value) in [
            ("policy", json!("44".repeat(32))),
            ("claim", json!("44".repeat(32))),
            ("requestDigest", json!("44".repeat(32))),
            ("slot", json!(crate::authority_admission::MAX_SLOTS)),
            ("generation", json!(0)),
        ] {
            let mut changed = binding.clone();
            changed[field] = value;
            assert!(
                validate_owner_binding(
                    &changed,
                    &"11".repeat(32),
                    &"22".repeat(32),
                    &"33".repeat(32),
                )
                .is_err()
            );
        }
        let mut changed = binding.clone();
        changed["generation"] = json!(2);
        for current in [
            json!({"status":"ready","binding":changed,"result":"foreign"}),
            json!({"status":"retired","binding":binding}),
            json!({"status":"pending","code":"ClockUnavailable","binding":binding}),
        ] {
            assert!(
                run(
                    &binding,
                    vec![(
                        "registrar",
                        json!({"operation":"status","binding":binding}),
                        Some(current),
                    )],
                )
                .is_err()
            );
        }
        let mut changed_challenge = renewal(
            &binding,
            json!({"status":"pending","code":"RenewalRequired","binding":binding}),
        );
        changed_challenge.truncate(2);
        changed_challenge[1].2.as_mut().unwrap()["binding"] = changed;
        assert!(run(&binding, changed_challenge).is_err());
    }
}
