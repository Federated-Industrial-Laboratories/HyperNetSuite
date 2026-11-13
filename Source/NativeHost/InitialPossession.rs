// SPDX-License-Identifier: Apache-2.0
//! Resume first admission with fresh finite key proofs after exact expired-request recovery.
use super::*;
use crate::{authority_deployments::Offer, trust_wire};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs::File};
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Window {
    generation: u64,
    profile: String,
    start: u64,
    end: u64,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct State {
    generation: u64,
    current: Option<Window>,
    previous: Option<Window>,
    pending: Option<Window>,
    retiring: Option<Retirement>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Retirement {
    generation: u64,
    files: BTreeMap<String, String>,
}
fn load(host: &Host<'_>, name: &str) -> Result<State> {
    ensure!(
        [
            "Relay",
            "AuthorityEndpoint",
            "PageEndpoint",
            "ApplicationEndpoint",
            "PageStore"
        ]
        .contains(&name),
        "initial proof service differs"
    );
    let state: State = host
        .remembered(&format!("initial-proof/{name}"))
        .map(serde_json::from_value)
        .transpose()?
        .unwrap_or_default();
    for w in [&state.current, &state.previous, &state.pending]
        .into_iter()
        .flatten()
    {
        ensure!(
            crate::admission::protocol::identifier(&w.profile)
                && w.generation > 0
                && w.generation <= state.generation
                && w.start < w.end
                && w.end - w.start <= 86_400_000,
            "retained initial proof window differs"
        );
    }
    Ok(state)
}
fn save(host: &mut Host<'_>, name: &str, state: &State) -> Result<()> {
    host.remember(
        &format!("initial-proof/{name}"),
        serde_json::to_value(state)?,
    )?;
    Ok(())
}
fn folder(host: &Host<'_>, name: &str, g: u64) -> PathBuf {
    host.p(&format!("Successor/InitialOffers/{name}/Generation{g:020}"))
}
pub(super) fn selected(host: &Host<'_>, name: &str) -> Result<PathBuf> {
    let state = load(host, name)?;
    let definition = active_directory(host, name)?;
    if let Some(w) = state.current {
        let bytes = native::public_file(&definition.join("Inputs/Manifest.cbor"), 98_304)?;
        let manifest = crate::runtime_manifest::Manifest::parse(&bytes)?;
        if hex::encode(trust_wire::digest(&manifest.desired()?)) == w.profile {
            let path = folder(host, name, w.generation).join("Offer.cbor");
            ensure!(
                parse(&path)?.manifest_bytes == bytes,
                "selected initial proof belongs to another definition"
            );
            return Ok(path);
        }
    }
    Ok(definition.join("Offer.cbor"))
}
fn parse(path: &Path) -> Result<Offer> {
    let raw = native::public_file(path, 98_304)?;
    let value = trust_wire::decode(&raw)?;
    let f = value.array(6)?;
    ensure!(
        f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "AuthorityDeploymentOffer",
        "initial deployment offer differs"
    );
    Offer::parse(f[3].bytes()?, f[4].bytes()?, &f[5])
}
fn removable(state: &State, g: u64) -> bool {
    ![&state.current, &state.previous, &state.pending]
        .into_iter()
        .flatten()
        .any(|w| w.generation == g)
}
fn retire(host: &mut Host<'_>, name: &str, state: &mut State) -> Result<()> {
    if let Some(plan) = &state.retiring {
        ensure!(
            removable(state, plan.generation),
            "initial proof retirement became retained"
        );
        let root = folder(host, name, plan.generation);
        let mut mapped = Vec::new();
        for (file, hash) in &plan.files {
            ensure!(
                [
                    "service.cbor",
                    "transport.cbor",
                    "monitor.cbor",
                    "Offer.cbor"
                ]
                .contains(&file.as_str()),
                "retired initial proof name differs"
            );
            let path = root.join(file);
            if path.exists() {
                ensure!(
                    digest(&native::public_file(&path, 98_304)?) == *hash,
                    "retired initial proof changed"
                );
            }
            if let Some(old) = host.state.artifacts.get(&text(&path)?) {
                ensure!(old == hash, "initial proof artifact differs");
            }
            host.state.artifacts.remove(&text(&path)?);
            mapped.push((path, ExportKind::Input, hash.clone()));
        }
        host.save()?;
        mapped.retain(|(_, _, hash)| !host.state.artifacts.values().any(|v| v == hash));
        for batch in mapped.chunks(4) {
            retire_certificate_exports(host, "Administrator", batch)?;
        }
        for file in plan.files.keys() {
            let path = root.join(file);
            if path.exists() {
                std::fs::remove_file(path)?;
            }
        }
        if root.exists() {
            std::fs::remove_dir(&root)?;
        }
        File::open(root.parent().context("initial proof root absent")?)?.sync_all()?;
        state.retiring = None;
        save(host, name, state)?;
    }
    let parent = host.p(&format!("Successor/InitialOffers/{name}"));
    if !parent.exists() {
        return Ok(());
    }
    let entries = std::fs::read_dir(&parent)?
        .map(|e| Ok(e?.path()))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        entries.len() <= 64,
        "unresolved initial proof exports exceed bound"
    );
    for path in entries {
        let component = path
            .file_name()
            .and_then(|s| s.to_str())
            .context("initial proof generation absent")?;
        let g = component
            .strip_prefix("Generation")
            .context("unexpected initial proof export")?
            .parse::<u64>()?;
        ensure!(
            g > 0 && g <= state.generation && path == folder(host, name, g),
            "initial proof generation differs"
        );
        if !removable(state, g) {
            continue;
        }
        native::directory(&path)?;
        let mut hashes = BTreeMap::new();
        for entry in std::fs::read_dir(&path)? {
            let p = entry?.path();
            let file = p
                .file_name()
                .and_then(|s| s.to_str())
                .context("initial proof filename absent")?;
            ensure!(
                [
                    "service.cbor",
                    "transport.cbor",
                    "monitor.cbor",
                    "Offer.cbor"
                ]
                .contains(&file),
                "unexpected initial proof file"
            );
            hashes.insert(file.to_owned(), digest(&native::public_file(&p, 98_304)?));
        }
        state.retiring = Some(Retirement {
            generation: g,
            files: hashes,
        });
        save(host, name, state)?;
        return retire(host, name, state);
    }
    Ok(())
}
pub(super) fn refresh(host: &mut Host<'_>, name: &str, definition: &Path) -> Result<()> {
    let mut state = load(host, name)?;
    retire(host, name, &mut state)?;
    let original = selected(host, name)?;
    let offer = parse(&original)?;
    let at = now()?;
    let Some(deadline) = offer.possession_expiry()? else {
        return Ok(());
    };
    if deadline > at {
        return Ok(());
    }
    ensure!(
        offer.manifest.generation == 1
            && offer.manifest.validity.current(at, 0)
            && offer.manifest.current_transport(at).is_ok(),
        "initial manifest needs its own current consent or certificate successor"
    );
    let candidate = format!(
        "{}:{}",
        hex::encode(offer.manifest.deployment),
        hex::encode(trust_wire::digest(&offer.manifest.desired()?))
    );
    let mut args = bytes(&["routes", "recover-expired-registration"]);
    args.extend(online(host, "Administrator")?);
    args.extend(bytes(&["--candidate", &candidate]));
    let recovered = operator(host, "Administrator", &args)?;
    ensure!(
        matches!(
            recovered["status"].as_str(),
            Some("NothingPending" | "Recovered")
        ),
        "initial admission proof recovery remains unresolved"
    );
    let mut args = bytes(&["authority-inspection", "deployments", "context"]);
    args.extend(online(host, "Administrator")?);
    args.extend(bytes(&[
        "--grant",
        &host.root_grant()?,
        "--deployment",
        &hex::encode(offer.manifest.deployment),
    ]));
    let context = operator(host, "Administrator", &args)?;
    let registration = context
        .get("registeredProfile")
        .context("initial admission context lacks registration")?;
    if !registration.is_null() {
        let retained: crate::runtime_manifest::Manifest =
            serde_json::from_value(registration["manifest"].clone())?;
        ensure!(
            registration["withdrawn"] == false && retained == offer.manifest,
            "initial admission conflicts with current native definition"
        );
        return Ok(());
    }
    let profile = hex::encode(trust_wire::digest(&offer.manifest.desired()?));
    if state
        .pending
        .as_ref()
        .is_some_and(|w| w.end <= at || w.profile != profile)
    {
        state.pending = None;
        save(host, name, &state)?;
    }
    if state.pending.is_none() {
        state.generation = state
            .generation
            .checked_add(1)
            .context("initial proof generation exhausted")?;
        let start = at
            .saturating_sub(crate::authority_governance::UNCERTAINTY_MS)
            .max(offer.manifest.validity.0);
        state.pending = Some(Window {
            generation: state.generation,
            profile,
            start,
            end: offer.manifest.validity.1.bound(
                start
                    .checked_add(86_400_000)
                    .context("initial proof time overflow")?,
            ),
        });
        save(host, name, &state)?;
    }
    let window = state
        .pending
        .clone()
        .context("initial proof window absent")?;
    let target = host.dir(&format!(
        "Successor/InitialOffers/{name}/Generation{:020}",
        window.generation
    ))?;
    let mut classes = vec![
        (
            "service",
            "--key",
            if name == "PageStore" {
                host.p("Keys/PageStore.json")
            } else {
                host.p(&format!("Keys/{name}/Identity.json"))
            },
        ),
        ("monitor", "--key", host.p("Native/Clock/ClockSigner.json")),
    ];
    if name != "PageStore" {
        classes.push((
            "transport",
            "--tls-key",
            host.p(&format!("Keys/{name}/Transport.key")),
        ));
    }
    for (class, flag, key) in &classes {
        let output = target.join(format!("{class}.cbor"));
        if !output.exists() {
            let mut args = bytes(&["authority-inspection", "deployments", "possess"]);
            args.extend(host.trust()?);
            args.extend(bytes(&[
                "--manifest",
                &text(&definition.join("Inputs/Manifest.cbor"))?,
                "--class",
                class,
                flag,
                &text(key)?,
                "--not-before-ms",
                &window.start.to_string(),
                "--expires-ms",
                &window.end.to_string(),
                "--output",
                &text(&output)?,
            ]));
            host.suite(&args)?;
        }
        host.artifact(&output)?;
    }
    let output = target.join("Offer.cbor");
    if !output.exists() {
        let mut args = bytes(&["authority-inspection", "deployments", "assemble"]);
        args.extend(host.trust()?);
        args.extend(bytes(&[
            "--manifest",
            &text(&definition.join("Inputs/Manifest.cbor"))?,
            "--consent",
            &text(&definition.join("Consent.cbor"))?,
        ]));
        for (class, _, _) in &classes {
            args.extend(bytes(&[
                "--possession",
                &text(&target.join(format!("{class}.cbor")))?,
            ]));
        }
        args.extend(bytes(&["--output", &text(&output)?]));
        host.suite(&args)?;
    }
    let fresh = parse(&output)?;
    ensure!(
        fresh.manifest_bytes == offer.manifest_bytes
            && fresh.consent == offer.consent
            && fresh.current(now()?)?,
        "fresh possession changes the initial signed definition or expired"
    );
    host.artifact(&output)?;
    state.previous = state.current.take();
    state.current = state.pending.take();
    save(host, name, &state)?;
    retire(host, name, &mut state)
}
