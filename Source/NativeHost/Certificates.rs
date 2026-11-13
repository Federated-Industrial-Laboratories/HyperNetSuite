// SPDX-License-Identifier: Apache-2.0
//! Same-key transport maintenance retains exact stopped transitions and original consent.
use super::{bootstrap, engine::*, files, lifecycle, operator, policy, services};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
#[path = "CertificateInputs.rs"]
mod inputs;
#[path = "CertificateRetirement.rs"]
mod retirement;
#[path = "CertificateServices.rs"]
mod service;
const DAY: u64 = 86_400_000;
const LEAD: u64 = 30 * DAY;
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct State {
    generation: u64,
    current: Option<Generation>,
    previous: Option<Generation>,
    pending: Option<Generation>,
    #[serde(default)]
    retiring: Option<retirement::Retirement>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Generation {
    number: u64,
    issued: bool,
    steps: BTreeMap<String, Value>,
    bases: BTreeMap<String, PathBuf>,
}
fn state(journal: &Journal) -> Result<State> {
    let s: State = journal
        .results
        .get("certificates")
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()?
        .unwrap_or_default();
    for g in [&s.current, &s.previous, &s.pending].into_iter().flatten() {
        ensure!(
            g.number > 0 && g.number <= s.generation && g.steps.len() <= 64 && g.bases.len() <= 8,
            "retained certificate transaction differs"
        );
    }
    Ok(s)
}
fn save(host: &mut Host<'_>, s: &State) -> Result<()> {
    host.remember("certificates", serde_json::to_value(s)?)?;
    Ok(())
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Probe {
    pub due: bool,
    pub pending: bool,
    pub not_after_ms: Option<u64>,
    pub inspected: usize,
}
pub(super) fn probe(root: &Path, journal: &Journal, cancel: &AtomicBool) -> Result<Probe> {
    let s = state(journal)?;
    let mut result = Probe {
        due: false,
        pending: s.pending.is_some(),
        not_after_ms: None,
        inspected: 0,
    };
    let mut include = |deadline: u64| {
        result.not_after_ms = Some(
            result
                .not_after_ms
                .map_or(deadline, |old| old.min(deadline)),
        );
        result.inspected += 1;
    };
    // The published certificate set also covers interrupted setup before runtime state exists.
    let issuer = inputs::issuer_path(root, &s);
    if issuer.exists() {
        let pem = String::from_utf8(files::public_file(&issuer, 16384)?)?;
        let (_, end) = crate::runtime_manifest::certificates::interval(
            &crate::runtime_manifest::certificates::der(&pem)?,
        )?;
        include(end.checked_mul(1000).context("certificate time overflow")?);
    }
    for role in inputs::role_names(journal.configuration.hrc.is_some()) {
        let p = inputs::peer_path(root, &s, &role);
        if p.exists() {
            include(inputs::interval(&public_read(&p)?)?.1);
        }
    }
    // Existing runtime generations can predate an input-only renewal after interrupted setup.
    if !result.pending {
        let core = PathBuf::from(string(&journal.installation, "coreExecutable")?);
        let end = Instant::now() + Duration::from_secs(30);
        let roles = (1..=4).map(|n| (format!("A{n}"), false)).chain(
            [
                "Relay",
                "AuthorityEndpoint",
                "PageEndpoint",
                "ApplicationEndpoint",
            ]
            .into_iter()
            .map(|n| (n.into(), true)),
        );
        for (name, service) in roles {
            let runtime = root.join(name);
            if !runtime
                .join(if service {
                    "ServiceProfile.json"
                } else {
                    "Profile.json"
                })
                .exists()
            {
                continue;
            }
            if runtime.join("Transition.json").exists() {
                result.pending = true;
                continue;
            }
            let mut args = bytes(&["runtime"]);
            if service {
                args.push("services".into());
            }
            args.extend(bytes(&[
                "transition",
                "transport-status",
                "--directory",
                &text(&runtime)?,
            ]));
            let value = invoke(&core, &args, cancel, end, "certificate inspection")?;
            let deadline = number(&value, "notAfterMs")?;
            result.not_after_ms = Some(
                result
                    .not_after_ms
                    .map_or(deadline, |old| old.min(deadline)),
            );
            result.inspected += 1;
        }
    }
    let at = now()?;
    result.due = result
        .not_after_ms
        .is_some_and(|end| end <= at.saturating_add(LEAD));
    Ok(result)
}
pub(super) fn peer(host: &Host<'_>, role: &str) -> Result<PathBuf> {
    let s = state(&host.state)?;
    if let Some(pending) = &s.pending {
        let p = inputs::path(&host.c.root, pending.number).join(format!("Peers/{role}.json"));
        if p.exists() {
            return Ok(p);
        }
    }
    let current = inputs::peer_path(&host.c.root, &s, role);
    Ok(if current.exists() {
        current
    } else {
        host.p(&format!("Peers/{role}.json"))
    })
}
pub(super) fn issuer(host: &Host<'_>) -> Result<PathBuf> {
    let s = state(&host.state)?;
    if let Some(pending) = &s.pending {
        let p = inputs::path(&host.c.root, pending.number).join("Authority.pem");
        if p.exists() {
            return Ok(p);
        }
    }
    Ok(inputs::issuer_path(&host.c.root, &s))
}
fn begin(host: &mut Host<'_>, s: &mut State) -> Result<()> {
    if s.pending.is_none() {
        s.generation = s
            .generation
            .checked_add(1)
            .context("certificate generation exhausted")?;
        let mut bases = BTreeMap::new();
        for (name, _, _, _) in services::roles(host) {
            bases.insert(name.into(), services::active_directory(host, name)?);
        }
        s.pending = Some(Generation {
            number: s.generation,
            issued: false,
            steps: BTreeMap::new(),
            bases,
        });
        save(host, s)?;
    }
    let mut g = s
        .pending
        .clone()
        .context("certificate transaction absent")?;
    inputs::issue(host, s, &mut g)?;
    s.pending = Some(g);
    save(host, s)
}
/// Refresh inert issuance inputs before a first local runtime is created.
pub(super) fn prepare_inputs(host: &mut Host<'_>) -> Result<()> {
    if !host.p("Recovery/Issuer/Authority.pem").exists() {
        return Ok(());
    }
    let mut s = state(&host.state)?;
    recover_expired_inputs(host, &mut s)?;
    if s.pending.is_none() && !probe(&host.c.root, &host.state, host.cancel)?.due {
        return Ok(());
    }
    begin(host, &mut s)
}
pub(super) fn authority_inputs(host: &Host<'_>, n: u16) -> Result<PathBuf> {
    let s = state(&host.state)?;
    if !host.p(&format!("A{n}")).exists()
        && let Some(g) = s.pending.as_ref().or(s.current.as_ref())
    {
        return Ok(inputs::path(&host.c.root, g.number).join(format!("A{n}Inputs")));
    }
    Ok(host.p(&format!("A{n}Inputs")))
}
pub(super) fn maintain(host: &mut Host<'_>) -> Result<()> {
    let p = probe(&host.c.root, &host.state, host.cancel)?;
    if p.due || p.pending {
        renew_now(host)?;
    }
    Ok(())
}
pub(super) fn renew_now(host: &mut Host<'_>) -> Result<()> {
    ensure!(
        host.state.desired_running && !host.state.withdrawn,
        "certificate renewal requires running intent"
    );
    let mut s = state(&host.state)?;
    recover_expired_inputs(host, &mut s)?;
    begin(host, &mut s)?;
    lifecycle::maintenance_stop(host)?;
    let mut g = s
        .pending
        .clone()
        .context("certificate transaction absent")?;
    for n in 1..=4 {
        let name = format!("A{n}");
        if !host.p(&name).join("Profile.json").exists() {
            continue;
        }
        bootstrap::consent(host, n)?;
        authority(host, &mut g, &name)?;
        s.pending = Some(g.clone());
        save(host, &s)?;
    }
    bootstrap::activate(host)?;
    if let Some(previous) = &s.current {
        recover_registrations(host, previous)?;
    }
    recover_registrations(host, &g)?;
    for role in services::roles(host) {
        service::renew(host, &mut g, role)?;
        s.pending = Some(g.clone());
        save(host, &s)?;
    }
    service::receiver_template(host, &g)?;
    super::receiver::refresh_certificates(host)?;
    for (name, _, _, _) in services::roles(host) {
        service::synchronise(host, name)?;
    }
    if host.remembered("owner-installed").is_some() && host.c.hrc.is_some() {
        policy::refresh(host, vec![1])?;
    }
    // Publication follows all local and certified successors; originals remain immutable.
    s.previous = s.current.take();
    s.current = Some(g);
    s.pending = None;
    save(host, &s)?;
    for (name, _, _, _) in services::roles(host) {
        retirement::offers(host, name)?;
    }
    if let Some(current) = &s.current {
        retirement::authority_offers(host, current)?;
    }
    retirement::prune(host, &mut s)?;
    host.phase("Transport certificates renewed")?;
    Ok(())
}
fn command(
    host: &Host<'_>,
    name: &str,
    service: bool,
    operation: &str,
    extra: &[String],
) -> Result<Value> {
    let mut args = bytes(&["runtime"]);
    if service {
        args.push("services".into());
    }
    args.extend(bytes(&[
        "transition",
        operation,
        "--directory",
        &text(&host.p(name))?,
    ]));
    args.extend_from_slice(extra);
    host.core(&args)
}
fn authority(host: &mut Host<'_>, g: &mut Generation, name: &str) -> Result<()> {
    if g.steps.contains_key(name) {
        return Ok(());
    }
    let folder = inputs::path(&host.c.root, g.number).join(name);
    files::directory(&folder)?;
    let bundle = folder.join("Certificates.json");
    if !bundle.exists() {
        let mut template = command(host, name, false, "transport-template", &[])?;
        let previous = template.clone();
        service::replace_template(host, g, &mut template)?;
        if previous == template {
            g.steps.insert(name.into(), json!({"status":"Current"}));
            return Ok(());
        }
        host.immutable_json(&bundle, &template)?;
    }
    let proposal = folder.join("Proposal.json");
    if !proposal.exists() {
        command(
            host,
            name,
            false,
            "prepare",
            &bytes(&[
                "--transport-bundle",
                &text(&bundle)?,
                "--output",
                &text(&proposal)?,
            ]),
        )?;
    }
    let preview = folder.join("Preview.json");
    if !preview.exists() {
        let v = command(
            host,
            name,
            false,
            "preview",
            &bytes(&["--proposal", &text(&proposal)?]),
        )?;
        host.immutable_json(&preview, &v)?;
    }
    apply(host, g, name, false, &proposal, &preview)?;
    Ok(())
}
fn apply(
    host: &mut Host<'_>,
    g: &mut Generation,
    name: &str,
    service: bool,
    proposal: &Path,
    preview: &Path,
) -> Result<()> {
    let operation = host.id(&format!("certificate/{}/{name}", g.number))?;
    let mut args = bytes(&[
        "--proposal",
        &text(proposal)?,
        "--preview-digest",
        &string(&public_read(preview)?, "previewDigest")?,
        "--operation-id",
        &operation[..32],
    ]);
    let parsed: Value = public_read(proposal)?;
    let manifest: crate::runtime_manifest::Manifest =
        serde_json::from_value(parsed["successor"].clone())?;
    let at = now()?;
    if manifest.transport_expiry()?.is_some_and(|end| end <= at) {
        args.push("--historical".into());
    }
    let v = command(host, name, service, "apply", &args)?;
    ensure!(
        v["status"] == "SuccessorApplied",
        "expired certificate transition was retained; fresh certificate issuance is required before serving"
    );
    g.steps.insert(name.into(), v);
    Ok(())
}

fn pending_expiry(root: &Path, g: &Generation) -> Result<Option<u64>> {
    let folder = inputs::path(root, g.number);
    let mut deadline = None;
    for name in inputs::role_names(true) {
        let peer = folder.join(format!("Peers/{name}.json"));
        if peer.exists() {
            let end = inputs::interval(&public_read(&peer)?)?.1;
            deadline = Some(deadline.map_or(end, |old: u64| old.min(end)));
        }
    }
    Ok(deadline)
}
fn recover_expired_inputs(host: &mut Host<'_>, s: &mut State) -> Result<()> {
    let Some(mut g) = s.pending.clone() else {
        return Ok(());
    };
    let at = now()?;
    if pending_expiry(&host.c.root, &g)?.is_none_or(|end| end > at) {
        return Ok(());
    }
    lifecycle::maintenance_stop(host)?;
    let roles = (1..=4)
        .map(|n| (format!("A{n}"), false))
        .chain(
            services::roles(host)
                .into_iter()
                .map(|r| (r.0.into(), true)),
        )
        .collect::<Vec<_>>();
    for (name, service) in roles {
        let base = inputs::path(&host.c.root, g.number).join(if service {
            format!("Services/{name}")
        } else {
            name.clone()
        });
        let proposal = base.join("Proposal.json");
        if !proposal.exists() {
            continue;
        }
        let operation = host.id(&format!("certificate/{}/{name}", g.number))?;
        let result = command(
            host,
            &name,
            service,
            "apply",
            &bytes(&[
                "--proposal",
                &text(&proposal)?,
                "--preview-digest",
                &digest(&files::public_file(&proposal, 1_048_576)?),
                "--operation-id",
                &operation[..32],
                "--historical",
            ]),
        )?;
        ensure!(
            matches!(
                result["status"].as_str(),
                Some("HistoricalSuccessorRetained" | "SuccessorApplied")
            ),
            "historical certificate transition remains unresolved"
        );
        g.steps.insert(name.clone(), result);
        if service {
            host.remember(&format!("active-service/{name}"), json!(base))?;
        }
        s.pending = Some(g.clone());
        save(host, s)?;
    }
    // No new authority can be served from this expired set. The next set retains its exact predecessor.
    s.previous = s.current.take();
    s.current = Some(g);
    s.pending = None;
    save(host, s)
}
fn recover_registrations(host: &mut Host<'_>, g: &Generation) -> Result<()> {
    let at = now()?;
    let mut candidates = Vec::new();
    let mut application = None;
    for (name, _, _, _) in services::roles(host) {
        let current = inputs::path(&host.c.root, g.number).join(format!("Services/{name}"));
        let mut folders = Vec::new();
        if let Some(base) = g.bases.get(name) {
            folders.push(base.clone());
        }
        folders.push(current);
        for folder in folders {
            let path = folder.join("Inputs/Manifest.cbor");
            if !path.exists() {
                continue;
            }
            let manifest =
                crate::runtime_manifest::Manifest::parse(&files::public_file(&path, 98304)?)?;
            let mut end = manifest.validity.1.bound(u64::MAX);
            if let Some(expiry) = manifest.transport_expiry()? {
                end = end.min(expiry);
            }
            for e in &manifest.endpoints {
                end = end.min(
                    crate::runtime_manifest::certificates::interval(&e.leaf_der)?
                        .1
                        .checked_mul(1000)
                        .context("certificate time overflow")?,
                );
            }
            if end > at {
                continue;
            }
            let candidate = format!(
                "{}:{}",
                hex::encode(manifest.deployment),
                hex::encode(crate::trust_wire::digest(&manifest.desired()?))
            );
            if !candidates.contains(&candidate) {
                candidates.push(candidate);
            }
            if name == "ApplicationEndpoint" && folder.join("ServiceAccepted.cbor").exists() {
                application = Some(folder);
            }
        }
    }
    if candidates.is_empty() {
        return Ok(());
    }
    ensure!(
        candidates.len() <= 8,
        "expired registration candidate set exceeds bound"
    );
    for who in ["Administrator", "ServiceOwner"] {
        if !host.p(&format!("Op{who}")).exists() {
            continue;
        }
        let mut args = bytes(&["routes", "recover-expired-registration"]);
        args.extend(operator::online(host, who)?);
        args.push("--candidate".into());
        args.extend(candidates.clone());
        if who == "ServiceOwner" {
            let Some(folder) = &application else {
                continue;
            };
            args.extend(bytes(&[
                "--accepted",
                &text(&folder.join("ServiceAccepted.cbor"))?,
                "--route-profile",
                &text(&folder.join("Inputs/RouteProfile.cbor"))?,
            ]));
        }
        let v = operator::operator(host, who, &args)?;
        ensure!(
            matches!(v["status"].as_str(), Some("Recovered" | "NothingPending")),
            "expired certificate registration recovery is incomplete"
        );
    }
    Ok(())
}
