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
    let challenge = registrar(
        host,
        json!({"operation":"challenge","claim":claim,"requestDigest":request_digest,"roles":roles,"applicationBinding":application}),
    )?;
    let ready = if challenge["status"] == "ready" {
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
        expected(
            registrar(
                host,
                json!({"operation":"enrol","challenge":challenge["challenge"],"acceptance":acceptance["acceptance"]}),
            )?,
            "ready",
        )?
    };
    host.remember("owner-binding", ready["binding"].clone())?;
    let current = expected(
        registrar(
            host,
            json!({"operation":"status","binding":ready["binding"]}),
        )?,
        "ready",
    )?;
    let installed = expected(
        candidate(
            host,
            json!({"operation":"acceptResult","result":current["result"]}),
        )?,
        "installed",
    )?;
    host.remember("owner-installed", installed)
}
pub fn refresh(host: &mut Host<'_>, roles: Vec<u64>) -> Result<Value> {
    let binding = host
        .remembered("owner-binding")
        .context("owner admission is absent")?;
    let challenge = expected(
        registrar(
            host,
            json!({"operation":"renewalChallenge","binding":binding}),
        )?,
        "challenge",
    )?;
    let proof = candidate(
        host,
        json!({"operation":"renewalProof","challenge":challenge["challenge"]}),
    )?;
    let proof = expected(proof, "acceptance")?;
    let ready = expected(
        registrar(
            host,
            json!({"operation":"renew","binding":binding,"proof":proof["acceptance"]}),
        )?,
        "ready",
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
    let profile = std::path::PathBuf::from(string(reader, "profile")?);
    ensure!(
        profile.starts_with(host.p("OwnerCandidate/Roles/0")),
        "owner Page path differs"
    );
    let bytes = zeroize::Zeroizing::new(files::read(&profile, 1_048_576)?);
    #[derive(serde::Deserialize)]
    struct Profile {
        device: crate::Identity,
    }
    let profile: Profile = serde_json::from_slice(&bytes)?;
    ensure!(
        profile.device.public_key == reader["member"],
        "owner Page identity differs"
    );
    let key = host.p("Keys/OwnerReader.json");
    files::exact_file(
        &key,
        &zeroize::Zeroizing::new(serde_json::to_vec(&profile.device)?),
    )?;
    let chat = profiles.iter().find(|p| p["role"] == 1);
    Ok(
        json!({"candidateDirectory":host.p("OwnerCandidate"),"binding":installed["binding"],
        "readerProfile":reader["profile"],"readerDirectory":reader["directory"],"reader":reader,"readerKeyFile":key,
        "chatProfile":chat.map(|p|p["profile"].clone()),"chatCompanion":host.state.results.get("owner-chat").and_then(|p|p.get("companion")),
        "hrcProfile":host.state.results.get("hrc").and_then(|h|h.get("ownerProfile"))}),
    )
}
