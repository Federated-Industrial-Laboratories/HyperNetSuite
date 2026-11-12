// SPDX-License-Identifier: Apache-2.0
// Read-only onboarding Pages use ordinary consent, placement, upload and approval operations.
use super::{engine::*, files, operator::*, services};
use crate::trust_validity::End;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

fn id(value: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(value)?;
    ensure!(bytes.len() == 32, "native identity length differs");
    Ok(bytes)
}
pub fn prepare(host: &mut Host<'_>) -> Result<()> {
    host.phase("Read-only Page hosting")?;
    let folder = host.dir("Services/PageStore")?;
    let input = host.dir("Services/PageStore/Inputs")?;
    let raw = zeroize::Zeroizing::new(files::read(&host.p("Keys/PageStore.json"), 8192)?);
    let identity: crate::Identity = serde_json::from_slice(&raw)?;
    let key = zeroize::Zeroizing::new(hex::decode(&identity.secret_key)?);
    files::exact_file(&input.join("Service.key"), &key)?;
    files::exact_file(
        &input.join("Bootstrap.cbor"),
        &files::public_file(&host.p("Network/Bootstrap.cbor"), 1_048_576)?,
    )?;
    let deployment = host.id("deployment/PageStore")?;
    let machine = host.id("host/PageStore")?;
    let volume = host.id("volume/PageStore")?;
    let bootstrap = host.bootstrap()?;
    let administrator = string(&host.state.results["Administrator"], "publicKey")?;
    let manifest = json!({"generation":1,"previousProfile":null,"previousConsent":null,
        "network":id(&string(&bootstrap,"network")?)?,"incarnation":id(&string(&bootstrap,"incarnation")?)?,
        "deployment":id(&deployment)?,"host":id(&machine)?,"operator":id(&string(&host.state.results["PageOperator"],"publicKey")?)?,
        "bootstrapDigest":id(&host.bootstrap_file_digest()?)?,"softwareDigest":id(&binary_digest(&host.c.core)?)?,
        "validity":[host.state.created_ms,host.c.hosting_end],"sessionMode":1,
        "roles":[{"role":1,"serviceKey":id(&identity.public_key)?,"imageDigest":id(host.state.image.strip_prefix("sha256:").context("image identity absent")?)?,
            "memoryBytes":host.c.resources.memory_bytes_per_role,"pids":host.c.resources.pids_per_role,"cpuQuota":host.c.resources.cpu_quota_per_role,"cpuPeriod":100000,
            "stateAdmissionBytes":host.c.resources.state_bytes_per_role,"bindEndpointIds":[],"outboundEndpointIds":[],"volumeIds":[id(&volume)?]}],
        "volumes":[{"volumeId":id(&volume)?,"readOnly":false,"storageAdmissionBytes":host.c.resources.state_bytes_per_role}],"endpoints":[],
        "clock":{"monitorKey":id(&host.monitor()?)?,"kernelBoot":"CurrentHost","witnessFileName":"ClockHealth.cbor","maximumErrorMs":250,"maximumObservationAgeMs":1000},
        "placement":{"hosts":[id(&machine)?],"volumes":[id(&volume)?],"backups":[],"copies":1},
        "limits":[host.c.resources.connection_bytes,1024,host.c.resources.endpoint_connections,32],
        "consentPolicy":{"allowOpaque":false,"reviewerRoots":[id(&administrator)?]},"authorityConfig":null});
    host.immutable_json(&folder.join("Manifest.json"), &manifest)?;
    let profile_digest = services::deployment(host, "PageStore", "PageOperator")?;
    if host.remembered("deployment/PageStore").is_none() {
        let mut a = bytes(&["authority-inspection", "deployments", "register"]);
        a.extend(online(host, "Administrator")?);
        a.extend(bytes(&[
            "--grant",
            &host.root_grant()?,
            "--offer",
            &text(&folder.join("Offer.cbor"))?,
        ]));
        let result = operator(host, "Administrator", &a)?;
        host.remember("deployment/PageStore", result)?;
    }
    let policy = json!({"metadataBytes":1048576,"dataBytes":16777216,"stagingBytes":8388608,
        "quarantineBytes":8388608,"maximumObjects":64,"opaque":false,"failureDomain":machine,"reviewerKeys":[administrator],"search":false});
    host.immutable_json(&folder.join("ContentPolicy.json"), &policy)?;
    let profile = input.join("PageProfile.cbor");
    if !profile.exists() {
        let mut a = bytes(&["pages", "host", "profile"]);
        a.extend(host.trust()?);
        a.extend(bytes(&[
            "--directory",
            &text(&host.dir("PageAuthoring")?)?,
            "--clock-witness",
            &text(&host.p("Native/Clock/ClockHealth.json"))?,
        ]));
        a.extend(bytes(&[
            "--manifest",
            &text(&input.join("Manifest.cbor"))?,
            "--profile-digest",
            &profile_digest,
            "--key",
            &text(&host.p("Keys/PageOperator.json"))?,
            "--role",
            "pages",
            "--volume",
            &volume,
            "--namespace",
            "Welcome",
            "--state-bytes",
            "33554432",
            "--maximum-asset-bytes",
            "8388608",
            "--content-policy",
            &text(&folder.join("ContentPolicy.json"))?,
            "--output",
            &text(&profile)?,
        ]));
        match host.c.hosting_end {
            End::UntilWithdrawn => a.push("--retention-until-withdrawn".into()),
            End::At(end) => a.extend(bytes(&[
                "--retention-ms",
                &end.checked_sub(host.state.created_ms)
                    .context("Page retention expired")?
                    .to_string(),
            ])),
        }
        host.suite(&a)?;
    }
    if host.remembered("page-host").is_none() {
        let mut a = bytes(&["pages", "host", "register"]);
        a.extend(online(host, "Administrator")?);
        a.extend(bytes(&[
            "--grant",
            &host.root_grant()?,
            "--profile",
            &text(&profile)?,
        ]));
        let result = operator(host, "Administrator", &a)?;
        host.remember("page-host", result)?;
    }
    let config = json!({"bootstrapFile":"/Config/Bootstrap.cbor","manifestFile":"/Config/Manifest.cbor","profileFile":"/Config/PageProfile.cbor",
        "identityFile":"/Config/Service.key","controlSocket":"/Authority/Control.sock","clockWitnessFile":"/Clock/ClockHealth.cbor","stateFile":"/State/PageState.bin"});
    host.immutable_json(&input.join("ServiceConfig.json"), &config)?;
    host.artifact(&profile)?;
    Ok(())
}
fn page_record(value: &Value, kind: u64) -> Result<Value> {
    value["records"]
        .as_array()
        .context("Page records absent")?
        .iter()
        .find(|r| r["kind"].as_u64() == Some(kind))
        .cloned()
        .context("Page record absent")
}
fn command(host: &Host<'_>, words: &[&str], args: &[String], grant: bool) -> Result<Value> {
    let mut a = bytes(words);
    a.extend(online(host, "Administrator")?);
    if grant {
        a.extend(bytes(&["--grant", &host.root_grant()?]));
    }
    a.extend_from_slice(args);
    operator(host, "Administrator", &a)
}
fn uri(host: &mut Host<'_>, name: &str) -> Result<String> {
    let page = host.id(&format!("page/{name}"))?;
    Ok(format!(
        "hypernet://{}/{}/Welcome/{}",
        string(&host.bootstrap()?, "network")?,
        string(&host.state.results["Administrator"], "publicKey")?,
        &page[..32]
    ))
}
pub fn publish(host: &mut Host<'_>) -> Result<()> {
    host.phase("Welcome Page publication")?;
    let welcome = uri(host, "Welcome")?;
    let joining = uri(host, "Joining")?;
    let agents = uri(host, "Agents")?;
    let lifetime = match host.c.access_end {
        End::UntilWithdrawn => "Access lasts until the owner removes it.",
        End::At(_) => "Access has the time limit shown when you join.",
    };
    let mut documents = vec![
        (
            "Welcome",
            format!(
                "HyperNetPage/2\n# {}\n: Welcome to this HyperNet server.\n: These Pages are read-only for members. Hosting and publication stay with the owner.\n=> {joining} Joining and access\n",
                host.c.name
            ),
        ),
        (
            "Joining",
            format!(
                "HyperNetPage/2\n# Joining and access\n: Open the server link or scan its QR code in HyperNet or RelayChat. Review the server and permissions, then join.\n: A password or a private invitation may be required. Keep private invitations private.\n: Your identity keys stay on your device. Existing manual invitations remain available.\n: {lifetime} The client refreshes temporary connection proofs automatically. An owner can still remove access.\n: Disconnect keeps this server offline until you reconnect.\n=> {welcome} Welcome\n"
            ),
        ),
    ];
    if host.c.hrc.is_some() {
        documents[0]
            .1
            .push_str(&format!("=> {agents} External agents\n"));
        documents.push(("Agents",format!("HyperNetPage/2\n# External agents\n: An external agent uses its own Agent profile, with an operator's explicit permission. It does not require the built-in model runner.\n: The operator chooses permitted rooms and message access in RelayChat. API credentials stay in private local files.\n: Automated history reading, initiating conversations and replying to other agents require separate permission.\n: Use the packaged API and command-line documentation for the supported local transport. Ordinary accounts cannot create rooms or administer this server.\n=> {welcome} Welcome\n")));
    }
    let public = string(&host.state.results["PageStore"], "publicKey")?;
    let mut route = bytes(&[
        "pages",
        "content",
        "route",
        "--directory",
        &text(&host.p("AdministratorFloor"))?,
        "--host",
        &public,
        "--service-socket",
        &text(&host.p("PageStore/Launch/State/Control/Control.sock"))?,
    ]);
    operator(host, "Administrator", &route)?;
    route.clear();
    for (name, source) in documents {
        let complete = format!("page-approved/{name}");
        if host.remembered(&complete).is_some() {
            continue;
        }
        let folder = host.dir(&format!("Pages/{name}"))?;
        let input = folder.join("Source.hpn");
        files::exact_file(&input, source.as_bytes())?;
        host.artifact(&input)?;
        let page = host.state.ids[&format!("page/{name}")][..32].to_owned();
        let statement = folder.join("Author.cbor");
        if !statement.exists() {
            let mut a = bytes(&[
                "--source",
                &text(&input)?,
                "--namespace",
                "Welcome",
                "--page-id",
                &page,
                "--revision",
                "1",
                "--output",
                &text(&statement)?,
            ]);
            a.extend(end_arguments(host.c.hosting_end));
            command(host, &["pages", "author"], &a, true)?;
        }
        let label = format!("page-submitted/{name}");
        let submitted = if let Some(v) = host.remembered(&label) {
            v
        } else {
            let v = command(
                host,
                &["pages", "submit"],
                &bytes(&[
                    "--source",
                    &text(&input)?,
                    "--statement",
                    &text(&statement)?,
                ]),
                false,
            )?;
            host.remember(&label, v)?
        };
        let revision = page_record(&submitted, 141)?;
        let placement_label = format!("page-placed/{name}");
        let placed = if let Some(v) = host.remembered(&placement_label) {
            v
        } else {
            let host_record = command(
                host,
                &["pages", "host", "get"],
                &bytes(&["--role", "pages", "--host", &public]),
                true,
            )?;
            let mut a = bytes(&[
                "--revision",
                &string(&revision, "id")?,
                "--revision-generation",
                &number(&revision, "generation")?.to_string(),
                "--revision-digest",
                &string(&revision, "digest")?,
                "--host-version",
                &format!(
                    "{}:{}:{}",
                    public,
                    number(&host_record, "generation")?,
                    string(&host_record, "digest")?
                ),
                "--copies",
                "1",
                "--failure-domains",
                "1",
            ]);
            a.extend(end_arguments(host.c.hosting_end));
            let v = command(host, &["pages", "content", "place"], &a, true)?;
            host.remember(&placement_label, v)?
        };
        let placement = page_record(&placed, 159)?;
        let upload_label = format!("page-upload/{name}");
        if host.remembered(&upload_label).is_none() {
            let v = command(
                host,
                &["pages", "content", "upload"],
                &bytes(&[
                    "--placement",
                    &string(&placement, "id")?,
                    "--placement-generation",
                    &number(&placement, "generation")?.to_string(),
                    "--placement-digest",
                    &string(&placement, "digest")?,
                    "--host",
                    &public,
                    "--service-socket",
                    &text(&host.p("PageStore/Launch/State/Control/Control.sock"))?,
                    "--progress-directory",
                    &text(&folder.join("Upload"))?,
                    "--input",
                    &text(&input)?,
                ]),
                true,
            )?;
            ensure!(
                v["status"] == "ContentComplete",
                "Page source upload is incomplete"
            );
            host.remember(&upload_label, v)?;
        }
        let inspection = folder.join("Inspection.cbor");
        if !inspection.exists() {
            command(
                host,
                &["pages", "inspect"],
                &bytes(&[
                    "--page-id",
                    &page,
                    "--output",
                    &text(&inspection)?,
                    "--ascii",
                ]),
                true,
            )?;
        }
        let decision = folder.join("Decision.cbor");
        if !decision.exists() {
            command(
                host,
                &["pages", "review-sign"],
                &bytes(&[
                    "--input",
                    &text(&inspection)?,
                    "--decision",
                    "approve",
                    "--expires-ms",
                    &host.c.hosting_end.bound(now()? + 240_000).to_string(),
                    "--output",
                    &text(&decision)?,
                ]),
                true,
            )?;
        }
        let v = command(
            host,
            &["pages", "review"],
            &bytes(&["--input", &text(&decision)?]),
            false,
        )?;
        host.remember(&complete, v)?;
    }
    host.remember(
        "pages",
        json!({"service":public,"route":host.state.ids["pages"],"welcomePage":welcome}),
    )?;
    Ok(())
}
