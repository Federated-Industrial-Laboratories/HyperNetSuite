// SPDX-License-Identifier: Apache-2.0
//! Certify exact renewed deployment, route and application bindings before local activation.
use super::*;
use crate::{
    runtime_manifest::{Manifest, certificates as tls},
    trust_wire,
};

pub(super) fn replace_template(
    host: &Host<'_>,
    g: &Generation,
    template: &mut Value,
) -> Result<()> {
    let folder = inputs::path(&host.c.root, g.number);
    let issuer = String::from_utf8(files::public_file(&folder.join("Authority.pem"), 16384)?)?;
    let mut peers = BTreeMap::new();
    for name in inputs::role_names(host.c.hrc.is_some()) {
        let path = folder.join(format!("Peers/{name}.json"));
        if path.exists() {
            let p = public_read(&path)?;
            ensure!(
                peers.insert(inputs::peer_identity(&p)?, p).is_none(),
                "repeated renewed transport identity"
            );
        }
    }
    template["issuerPem"] = json!(issuer);
    for endpoint in template["certificates"]
        .as_array_mut()
        .context("certificate endpoints absent")?
    {
        let peer = peers
            .get(&(
                string(endpoint, "serviceKey")?,
                string(endpoint, "transportKey")?,
            ))
            .context("renewed endpoint request absent")?;
        endpoint["certificatePem"] = peer["certificatePem"].clone();
    }
    Ok(())
}
fn checkpoint(host: &mut Host<'_>, g: &Generation) -> Result<()> {
    let mut s = state(&host.state)?;
    s.pending = Some(g.clone());
    save(host, &s)
}
fn record(host: &mut Host<'_>, g: &mut Generation, key: String, value: Value) -> Result<()> {
    g.steps.insert(key, value);
    checkpoint(host, g)
}
fn register(host: &mut Host<'_>, g: &mut Generation, name: &str, folder: &Path) -> Result<()> {
    let deployment = format!("deployment/{name}");
    if !g.steps.contains_key(&deployment) {
        let mut args = bytes(&["authority-inspection", "deployments", "register"]);
        args.extend(operator::online(host, "Administrator")?);
        args.extend(bytes(&[
            "--grant",
            &host.root_grant()?,
            "--offer",
            &text(&folder.join("Offer.cbor"))?,
        ]));
        let result = operator::operator(host, "Administrator", &args)?;
        host.remember(&deployment, result.clone())?;
        record(host, g, deployment, result)?;
    }
    let route = format!("route/{name}");
    if !g.steps.contains_key(&route) {
        let mut args = bytes(&["routes", "register"]);
        args.extend(operator::online(host, "Administrator")?);
        args.extend(bytes(&[
            "--grant",
            &host.root_grant()?,
            "--profile",
            &text(&folder.join("Inputs/RouteProfile.cbor"))?,
            "--expected-record",
            &string(
                &public_read(&folder.join("RoutePreview.json"))?,
                "expectedRecord",
            )?,
        ]));
        let result = operator::operator(host, "Administrator", &args)?;
        host.remember(&route, result.clone())?;
        record(host, g, route, result)?;
    }
    Ok(())
}
fn consent(
    host: &mut Host<'_>,
    name: &str,
    operator_name: &str,
    folder: &Path,
    profile: &str,
    initial: bool,
) -> Result<()> {
    let manifest = folder.join("Inputs/Manifest.cbor");
    let consent = folder.join("Consent.cbor");
    if !consent.exists() {
        let mut args = bytes(&["authority-inspection", "deployments", "consent"]);
        args.extend(host.trust()?);
        args.extend(bytes(&[
            "--manifest",
            &text(&manifest)?,
            "--profile-digest",
            profile,
            "--key",
            &text(&host.p(&format!("Keys/{operator_name}.json")))?,
            "--output",
            &text(&consent)?,
        ]));
        host.suite(&args)?;
    }
    let mut possessions = Vec::new();
    if initial {
        let at = now()?
            .saturating_sub(crate::authority_governance::UNCERTAINTY_MS)
            .max(host.state.created_ms);
        let end = host.c.hosting_end.bound(at + DAY);
        for (class, flag, key) in [
            (
                "service",
                "--key",
                host.p(&format!("Keys/{name}/Identity.json")),
            ),
            (
                "transport",
                "--tls-key",
                host.p(&format!("Keys/{name}/Transport.key")),
            ),
            ("monitor", "--key", host.p("Native/Clock/ClockSigner.json")),
        ] {
            let output = folder.join(format!("{class}.cbor"));
            if !output.exists() {
                let mut args = bytes(&["authority-inspection", "deployments", "possess"]);
                args.extend(host.trust()?);
                args.extend(bytes(&[
                    "--manifest",
                    &text(&manifest)?,
                    "--class",
                    class,
                    flag,
                    &text(&key)?,
                    "--not-before-ms",
                    &at.to_string(),
                    "--expires-ms",
                    &end.to_string(),
                    "--output",
                    &text(&output)?,
                ]));
                host.suite(&args)?;
            }
            possessions.push(output);
        }
    }
    let offer = folder.join("Offer.cbor");
    if !offer.exists() {
        let mut args = bytes(&["authority-inspection", "deployments", "assemble"]);
        args.extend(host.trust()?);
        args.extend(bytes(&[
            "--manifest",
            &text(&manifest)?,
            "--consent",
            &text(&consent)?,
        ]));
        for p in possessions {
            args.extend(bytes(&["--possession", &text(&p)?]));
        }
        args.extend(bytes(&["--output", &text(&offer)?]));
        host.suite(&args)?;
    }
    for p in [&manifest, &consent, &offer] {
        host.artifact(p)?;
    }
    Ok(())
}
fn copy_inputs(
    host: &mut Host<'_>,
    g: &Generation,
    name: &str,
    base: &Path,
    folder: &Path,
) -> Result<()> {
    let input = folder.join("Inputs");
    files::directory(&input)?;
    for file in ["Bootstrap.cbor", "Service.key", "Transport.key"] {
        let data =
            zeroize::Zeroizing::new(files::read(&base.join("Inputs").join(file), 1_048_576)?);
        files::exact_file(&input.join(file), &data)?;
        host.artifact(&input.join(file))?;
    }
    let peer =
        public_read(&inputs::path(&host.c.root, g.number).join(format!("Peers/{name}.json")))?;
    files::exact_file(
        &input.join("Certificate.pem"),
        string(&peer, "certificatePem")?.as_bytes(),
    )?;
    files::exact_file(
        &input.join("CertificateAuthority.pem"),
        string(&peer, "authorityPem")?.as_bytes(),
    )?;
    for file in ["Certificate.pem", "CertificateAuthority.pem"] {
        host.artifact(&input.join(file))?;
    }
    let mut configuration = if base.join("RelayConfiguration.json").exists() {
        public_read(&base.join("RelayConfiguration.json"))?
    } else {
        ensure!(
            !host.p(name).join("ServiceProfile.json").exists(),
            "running service configuration absent"
        );
        services::relay_configuration(host, name)?
    };
    if !configuration["relayIdentity"].is_null() {
        let relay = public_read(&inputs::path(&host.c.root, g.number).join("Peers/Relay.json"))?;
        configuration["relayIdentity"]["leafDer"] =
            json!(tls::der(&string(&relay, "certificatePem")?)?);
        configuration["relayIdentity"]["certificateAuthorityPem"] = relay["authorityPem"].clone();
    }
    host.immutable_json(&folder.join("RelayConfiguration.json"), &configuration)?;
    if name != "ApplicationEndpoint" {
        host.immutable_json(&input.join("ServiceConfig.json"), &configuration)?;
    }
    Ok(())
}
fn predecessor(host: &mut Host<'_>, g: &mut Generation, name: &str) -> Result<Option<Manifest>> {
    let key = format!("predecessor/{name}");
    let value = if let Some(v) = g.steps.get(&key) {
        v.clone()
    } else {
        let mut args = bytes(&["authority-inspection", "deployments", "context"]);
        args.extend(operator::online(host, "Administrator")?);
        args.extend(bytes(&[
            "--grant",
            &host.root_grant()?,
            "--deployment",
            &host.state.ids[&format!("deployment/{name}")],
        ]));
        let value = operator::operator(host, "Administrator", &args)?;
        let selected = value
            .get("registeredProfile")
            .context("native context lacks selected deployment metadata")?
            .clone();
        record(host, g, key, selected.clone())?;
        selected
    };
    if value.is_null() {
        return Ok(None);
    }
    ensure!(
        value["withdrawn"] == false,
        "withdrawn deployment cannot renew certificates"
    );
    let manifest: Manifest = serde_json::from_value(value["manifest"].clone())?;
    manifest.validate()?;
    ensure!(
        hex::encode(trust_wire::digest(&manifest.desired()?)) == string(&value, "profileDigest")?,
        "certified predecessor profile differs"
    );
    Ok(Some(manifest))
}
fn initial_or_successor(
    old: &Manifest,
    admitted: bool,
    issuer: String,
    previous_issuer: String,
    leaves: &BTreeMap<[u8; 32], Vec<u8>>,
    at: u64,
) -> Result<Manifest> {
    let mut next = old.clone();
    if admitted {
        next.generation = old
            .generation
            .checked_add(1)
            .context("manifest generation exhausted")?;
        next.previous_profile = Some(trust_wire::digest(&old.desired()?));
        next.previous_consent = Some(trust_wire::digest(&old.unsigned_consent(0)?));
        let old_issuer = old
            .transport_certificates
            .as_ref()
            .map_or(previous_issuer.as_str(), |c| c.issuer_pem.as_str());
        tls::issuer_successor(&tls::der(old_issuer)?, &tls::der(&issuer)?)?;
        for e in &old.endpoints {
            tls::leaf_successor(
                &e.leaf_der,
                leaves
                    .get(&e.endpoint_id)
                    .context("renewed endpoint absent")?,
                &tls::der(old_issuer)?,
                &tls::der(&issuer)?,
            )?;
        }
        next.adopt_certificates(old, issuer.clone(), leaves, previous_issuer)?;
    } else {
        // No native admission or local runtime exists; the inert first definition has no generation history.
        next.generation = 1;
        next.previous_profile = None;
        next.previous_consent = None;
        next.transport_certificates = None;
        ensure!(
            next.authority_config.is_none() && leaves.len() == next.endpoints.len(),
            "initial service certificate set differs"
        );
        for e in &mut next.endpoints {
            e.leaf_der = leaves
                .get(&e.endpoint_id)
                .context("initial endpoint absent")?
                .clone();
        }
        next.validate()?;
    }
    for e in &next.endpoints {
        tls::current(&e.leaf_der, &tls::der(&issuer)?, e.address, at)?;
    }
    Ok(next)
}
pub(super) fn renew(
    host: &mut Host<'_>,
    g: &mut Generation,
    role: (&str, &str, &str, &str),
) -> Result<()> {
    let (name, operator_name, _, _) = role;
    if g.steps.contains_key(name) {
        return Ok(());
    }
    let base = g
        .bases
        .get(name)
        .context("previous certificate service path absent")?
        .clone();
    let original = base.join("Inputs/Manifest.cbor");
    if !original.exists() {
        // Earlier setup may have written only a certificate or first JSON definition.
        // Keep it inert; the normal initial workflow authors and admits the fresh definition.
        if base.exists() {
            let folder = inputs::path(&host.c.root, g.number).join(format!("Services/{name}"));
            files::directory(&folder)?;
            files::directory(&folder.join("Inputs"))?;
            host.remember(&format!("service-input/{name}"), json!(folder))?;
        }
        return Ok(());
    }
    let runtime = host.p(name).join("ServiceProfile.json").exists();
    if runtime {
        let consent_key = format!("local-consent/{name}");
        if host.remembered(&consent_key).is_none() {
            let preview = host.core(&bytes(&[
                "runtime",
                "services",
                "preview",
                "--directory",
                &text(&host.p(name))?,
            ]))?;
            let value = host.core(&bytes(&[
                "runtime",
                "services",
                "consent",
                "--directory",
                &text(&host.p(name))?,
                "--profile-digest",
                &string(&preview, "profileDigest")?,
            ]))?;
            host.remember(&consent_key, value)?;
        }
        synchronise(host, name)?;
    }
    let folder = inputs::path(&host.c.root, g.number).join(format!("Services/{name}"));
    files::directory(&folder)?;
    files::directory(&folder.join("Inputs"))?;
    copy_inputs(host, g, name, &base, &folder)?;
    let manifest = folder.join("Inputs/Manifest.cbor");
    let bundle = folder.join("Certificates.json");
    let draft = folder.join("Draft.json");
    if !manifest.exists() {
        let result = if runtime {
            if !bundle.exists() {
                let mut t = command(host, name, true, "transport-template", &[])?;
                replace_template(host, g, &mut t)?;
                host.immutable_json(&bundle, &t)?;
            }
            if !draft.exists() {
                command(
                    host,
                    name,
                    true,
                    "prepare",
                    &bytes(&[
                        "--transport-bundle",
                        &text(&bundle)?,
                        "--output",
                        &text(&draft)?,
                    ]),
                )?;
            }
            command(
                host,
                name,
                true,
                "manifest",
                &bytes(&["--proposal", &text(&draft)?, "--output", &text(&manifest)?]),
            )?
        } else {
            let inert = Manifest::parse(&files::public_file(&original, 98304)?)?;
            let certified = predecessor(host, g, name)?;
            let old = certified.as_ref().unwrap_or(&inert);
            old.permits_definition(&inert)?;
            ensure!(
                old.software_digest == inert.software_digest
                    && old
                        .roles
                        .iter()
                        .zip(&inert.roles)
                        .all(|(a, b)| a.image_digest == b.image_digest),
                "certificate maintenance cannot adopt different reviewed software"
            );
            inputs::bundle(host, g, old, &bundle)?;
            let selected = public_read(&bundle)?;
            let leaves = selected["certificates"]
                .as_array()
                .context("certificate bundle absent")?
                .iter()
                .map(|v| {
                    Ok((
                        crate::trust_bootstrap::hex32(&string(v, "endpoint")?)?,
                        tls::der(&string(v, "certificatePem")?)?,
                    ))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            let next = initial_or_successor(
                old,
                certified.is_some(),
                string(&selected, "issuerPem")?,
                String::from_utf8(files::public_file(
                    &base.join("Inputs/CertificateAuthority.pem"),
                    16384,
                )?)?,
                &leaves,
                now()?,
            )?;
            let source = folder.join("Manifest.json");
            host.immutable_json(&source, &serde_json::to_value(&next)?)?;
            let mut args = bytes(&["authority-inspection", "deployments", "prepare"]);
            args.extend(host.trust()?);
            args.extend(bytes(&[
                "--manifest-json",
                &text(&source)?,
                "--output",
                &text(&manifest)?,
            ]));
            host.suite(&args)?
        };
        record(host, g, format!("manifest/{name}"), result)?;
    }
    let parsed = Manifest::parse(&files::public_file(&manifest, 98304)?)?;
    let profile = hex::encode(trust_wire::digest(&parsed.desired()?));
    consent(
        host,
        name,
        operator_name,
        &folder,
        &profile,
        parsed.generation == 1,
    )?;
    let route = folder.join("Inputs/RouteProfile.cbor");
    if !route.exists() {
        services::author_route_with_issuer(
            host,
            role,
            &manifest,
            &profile,
            &route,
            &folder.join("Inputs/CertificateAuthority.pem"),
        )?;
    }
    host.artifact(&route)?;
    // A newly created service has no earlier local generation or native route to recover.
    if host.remembered(&format!("deployment/{name}")).is_none() {
        let mut args = bytes(&["authority-inspection", "deployments", "register"]);
        args.extend(operator::online(host, "Administrator")?);
        args.extend(bytes(&[
            "--grant",
            &host.root_grant()?,
            "--offer",
            &text(&folder.join("Offer.cbor"))?,
        ]));
        let v = operator::operator(host, "Administrator", &args)?;
        host.remember(&format!("deployment/{name}"), v.clone())?;
        record(host, g, format!("deployment/{name}"), v)?;
    }
    let route_preview = folder.join("RoutePreview.json");
    if !route_preview.exists() {
        let mut args = bytes(&["routes", "register", "--preview"]);
        args.extend(operator::online(host, "Administrator")?);
        args.extend(bytes(&[
            "--grant",
            &host.root_grant()?,
            "--profile",
            &text(&route)?,
        ]));
        let v = operator::operator(host, "Administrator", &args)?;
        host.immutable_json(&route_preview, &v)?;
    }
    let predicted = string(&public_read(&route_preview)?, "expectedRecord")?;
    if name == "ApplicationEndpoint" {
        super::super::chat::service_owner(host)?;
        let certified = host
            .remembered("application-consent")
            .map(|v| string(&v, "directory").map(PathBuf::from))
            .transpose()?
            .unwrap_or_else(|| host.p("Services/ApplicationEndpoint"));
        super::super::chat::prepare_application_at(
            host,
            &folder,
            certified
                .join("ServiceAccepted.cbor")
                .exists()
                .then_some(certified.as_path()),
            Some(&predicted),
        )?;
    }
    let proposal = folder.join("Proposal.json");
    let preview = folder.join("Preview.json");
    if runtime {
        if !proposal.exists() {
            command(
                host,
                name,
                true,
                "prepare",
                &bytes(&[
                    "--transport-bundle",
                    &text(&bundle)?,
                    "--route-profile",
                    &text(&route)?,
                    if name == "ApplicationEndpoint" {
                        "--application-config"
                    } else {
                        "--route-config"
                    },
                    &text(&folder.join("Inputs/ServiceConfig.json"))?,
                    "--output",
                    &text(&proposal)?,
                ]),
            )?;
        }
        if !preview.exists() {
            let v = command(
                host,
                name,
                true,
                "preview",
                &bytes(&["--proposal", &text(&proposal)?]),
            )?;
            host.immutable_json(&preview, &v)?;
        }
        host.artifact(&proposal)?;
    }
    register(host, g, name, &folder)?;
    if name == "ApplicationEndpoint" && !g.steps.contains_key("application") {
        let mut args = bytes(&["streams", "register"]);
        args.extend(operator::online(host, "ServiceOwner")?);
        args.extend(bytes(&[
            "--grant",
            host.state.results["owner-manage"]
                .as_str()
                .context("service owner grant absent")?,
            "--accepted",
            &text(&folder.join("ServiceAccepted.cbor"))?,
        ]));
        if host.remembered("application-registration").is_some() {
            args.push("--renew".into());
        }
        let v = operator::operator(host, "ServiceOwner", &args)?;
        host.remember("application-registration", v.clone())?;
        host.remember("application-consent", json!({"directory":folder}))?;
        record(host, g, "application".into(), v)?;
    }
    if runtime {
        apply(host, g, name, true, &proposal, &preview)?;
    } else {
        g.steps.insert(name.into(), json!({"status":"Prepared"}));
    }
    host.remember(&format!("active-service/{name}"), json!(folder))?;
    checkpoint(host, g)
}
pub(super) fn receiver_template(host: &mut Host<'_>, g: &Generation) -> Result<()> {
    if host.remembered("receiver-native").is_none() {
        return Ok(());
    }
    let folder = inputs::path(&host.c.root, g.number);
    let output = folder.join("ReceiverAuthorityTemplate.json");
    if !output.exists() {
        let mut args = bytes(&["routes", "template"]);
        args.extend(host.trust()?);
        args.extend(bytes(&[
            "--relay-profile",
            &text(&services::active_directory(host, "Relay")?.join("Inputs/RouteProfile.cbor"))?,
            "--destination-profile",
            &text(
                &services::active_directory(host, "AuthorityEndpoint")?
                    .join("Inputs/RouteProfile.cbor"),
            )?,
            "--minimum-route",
            "Organisational",
            "--output",
            &text(&output)?,
        ]));
        host.suite(&args)?;
    }
    host.artifact(&output)?;
    let hash = digest(&files::public_file(&output, 1_048_576)?);
    host.remember(
        "receiver-route-template",
        json!({"path":output,"sha256":hash}),
    )?;
    Ok(())
}

pub(super) fn synchronise(host: &mut Host<'_>, name: &str) -> Result<()> {
    let history = host.p(name).join("OperationalOffers");
    if !history.exists() || std::fs::read_dir(&history)?.next().is_none() {
        return Ok(());
    }
    let mut args = bytes(&["authority-inspection", "deployments", "synchronise"]);
    args.extend(operator::online(host, "Administrator")?);
    args.extend(bytes(&[
        "--grant",
        &host.root_grant()?,
        "--offers-directory",
        &text(&history)?,
    ]));
    let result = operator::operator(host, "Administrator", &args)?;
    ensure!(
        result["status"] == "DeploymentSynchronised",
        "historical deployment synchronisation incomplete"
    );
    host.remember(&format!("certificate-history/{name}"), result)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interrupted_initial_definition_does_not_invent_admitted_history() {
        let (before, after) = crate::authority_domains::routes::tests::certificate_profiles();
        let leaves = after
            .manifest
            .endpoints
            .iter()
            .map(|e| (e.endpoint_id, e.leaf_der.clone()))
            .collect();
        let fresh = initial_or_successor(
            &before.manifest,
            false,
            after.identity.certificate_authority_pem.clone(),
            before.identity.certificate_authority_pem.clone(),
            &leaves,
            2000,
        )
        .unwrap();
        assert_eq!(fresh.generation, 1);
        assert!(
            fresh.previous_profile.is_none()
                && fresh.previous_consent.is_none()
                && fresh.transport_certificates.is_none()
        );
        assert_eq!(fresh.validity, before.manifest.validity);
        assert_eq!(fresh.operator, before.manifest.operator);
        assert_eq!(
            fresh.endpoints[0].transport_key,
            before.manifest.endpoints[0].transport_key
        );
        let renewed = initial_or_successor(
            &before.manifest,
            true,
            after.identity.certificate_authority_pem.clone(),
            before.identity.certificate_authority_pem.clone(),
            &leaves,
            2000,
        )
        .unwrap();
        assert_eq!(renewed, after.manifest);
        assert!(
            initial_or_successor(
                &before.manifest,
                true,
                after.identity.certificate_authority_pem,
                before.identity.certificate_authority_pem,
                &leaves,
                3 * DAY
            )
            .is_err()
        );
    }
}
