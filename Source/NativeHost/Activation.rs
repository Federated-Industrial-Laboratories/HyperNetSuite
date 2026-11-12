// SPDX-License-Identifier: Apache-2.0
// Each deployment receives a separate activation-only application and retained requester state.
use super::{bootstrap, engine::*, files, operator::*, units};
use crate::{authority_runtime_activation as activation, trust_validity::End, trust_wire};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attempt {
    generation: u64,
    attempt: u64,
}
impl Attempt {
    fn parse(value: &str) -> Result<Self> {
        let (generation, attempt) = value.split_once('/').context("activation tuple absent")?;
        let out = Self {
            generation: generation.parse()?,
            attempt: attempt.parse()?,
        };
        ensure!(
            out.generation > 0 && out.suffix() == value,
            "activation tuple differs"
        );
        Ok(out)
    }
    fn suffix(self) -> String {
        format!("{}/{}", self.generation, self.attempt)
    }
    fn key(self, name: &str) -> String {
        format!("activation-complete/{name}/{}", self.suffix())
    }
    fn export(self, root: &Path, name: &str, kind: &str) -> PathBuf {
        root.join(format!(
            "Activation/{name}/{kind}{}-{}.cbor",
            self.generation, self.attempt
        ))
    }
}
fn launch(root: &Path, name: &str, results: &BTreeMap<String, Value>) -> Result<Option<Attempt>> {
    let Some(value) = results.get(&format!("service-launch/{name}")) else {
        return Ok(None);
    };
    ensure!(
        Path::new(&string(value, "runtime")?) == root.join(name),
        "activation runtime differs"
    );
    let request = PathBuf::from(string(value, "request")?);
    let basename = request
        .file_name()
        .and_then(|v| v.to_str())
        .context("activation request name absent")?;
    let tuple = basename
        .strip_prefix("Request")
        .and_then(|v| v.strip_suffix(".cbor"))
        .context("activation request name differs")?
        .replace('-', "/");
    let attempt = Attempt::parse(&tuple)?;
    ensure!(
        request == attempt.export(root, name, "Request"),
        "activation request path differs"
    );
    Ok(Some(attempt))
}
fn completed(results: &BTreeMap<String, Value>, name: &str) -> Result<Vec<Attempt>> {
    let prefix = format!("activation-complete/{name}/");
    let mut values = results
        .iter()
        .filter_map(|(key, value)| key.strip_prefix(&prefix).map(|s| (s, value)))
        .map(|(suffix, value)| {
            ensure!(
                value["status"] == "ActivationReported",
                "activation completion differs"
            );
            Attempt::parse(suffix)
        })
        .collect::<Result<Vec<_>>>()?;
    values.sort_unstable();
    Ok(values)
}
fn receipt_request(receipt: &[u8]) -> Result<Vec<u8>> {
    activation::Receipt::parse(receipt)?;
    Ok(trust_wire::decode_state(receipt)?.array(12)?[3]
        .bytes()?
        .to_vec())
}
fn checked_completion(
    root: &Path,
    name: &str,
    attempt: Attempt,
    value: &Value,
) -> Result<(String, String)> {
    let request = files::read(&attempt.export(root, name, "Request"), 1_048_576)?;
    let receipt = files::read(
        &attempt.export(root, name, "Receipt"),
        activation::RECEIPT_LIMIT,
    )?;
    ensure!(
        receipt_request(&receipt)? == request,
        "activation receipt belongs to another request"
    );
    ensure!(
        value["status"] == "ActivationReported"
            && value["intent"]
                == hex::encode(activation::Request::parse(&request)?.intent().digest),
        "activation completion intent differs"
    );
    let hashes = (digest(&request), digest(&receipt));
    for (key, expected) in [("requestSha256", &hashes.0), ("receiptSha256", &hashes.1)] {
        if let Some(value) = value.get(key) {
            ensure!(
                value.as_str() == Some(expected.as_str()),
                "activation export changed"
            );
        }
    }
    Ok(hashes)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Retirement {
    attempt: Attempt,
    request_sha256: String,
    receipt_sha256: String,
}
impl Retirement {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.attempt.generation > 0
                && crate::admission::protocol::identifier(&self.request_sha256)
                && crate::admission::protocol::identifier(&self.receipt_sha256),
            "activation retirement differs"
        );
        Ok(())
    }
    fn mapped(&self, root: &Path, name: &str) -> Result<[RetiredExport; 2]> {
        self.validate()?;
        Ok([
            RetiredExport {
                kind: ExportKind::Output,
                name: digest(text(&self.attempt.export(root, name, "Request"))?.as_bytes()),
                sha256: self.request_sha256.clone(),
            },
            RetiredExport {
                kind: ExportKind::Input,
                name: self.receipt_sha256.clone(),
                sha256: self.receipt_sha256.clone(),
            },
        ])
    }
}
fn remove_exact(path: &Path, expected: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            ensure!(
                digest(&files::read(path, 1_048_576)?) == expected,
                "activation export changed before retirement"
            );
            files::remove(path)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
fn retire_owner(root: &Path, name: &str, plan: &Retirement) -> Result<()> {
    plan.validate()?;
    remove_exact(
        &plan.attempt.export(root, name, "Request"),
        &plan.request_sha256,
    )?;
    remove_exact(
        &plan.attempt.export(root, name, "Receipt"),
        &plan.receipt_sha256,
    )
}
fn stage_retirement(
    root: &Path,
    name: &str,
    results: &mut BTreeMap<String, Value>,
    artifacts: &mut BTreeMap<String, String>,
    plan: &Retirement,
) -> Result<()> {
    plan.validate()?;
    let current = launch(root, name, results)?.context("activation launch absent")?;
    let prior = completed(results, name)?
        .into_iter()
        .filter(|a| *a < current)
        .max()
        .context("previous activation absent")?;
    ensure!(
        plan.attempt < prior,
        "current and previous activation must remain retained"
    );
    let request = current.export(root, name, "Request");
    ensure!(
        artifacts.get(&text(&request)?).is_some_and(
            |expected| files::read(&request, 1_048_576).is_ok_and(|b| digest(&b) == *expected)
        ),
        "successor activation request must be durably retained before retirement"
    );
    for kind in ["Request", "Receipt"] {
        artifacts.remove(&text(&plan.attempt.export(root, name, kind))?);
    }
    results.remove(&plan.attempt.key(name));
    results.insert(
        format!("activation-cleanup/{name}"),
        serde_json::to_value(plan)?,
    );
    Ok(())
}
fn cleanup(host: &mut Host<'_>, name: &str) -> Result<()> {
    let key = format!("activation-cleanup/{name}");
    loop {
        check(host.cancel, host.end)?;
        let Some(current) = launch(&host.c.root, name, &host.state.results)? else {
            return Ok(());
        };
        let plan = if let Some(value) = host.remembered(&key) {
            serde_json::from_value::<Retirement>(value)?
        } else {
            let complete = completed(&host.state.results, name)?;
            ensure!(
                complete.iter().all(|a| *a <= current),
                "activation completion is newer than retained launch"
            );
            let previous = complete.iter().rev().find(|a| **a < current).copied();
            let Some(old) = complete
                .iter()
                .find(|a| **a < current && Some(**a) != previous)
                .copied()
            else {
                return Ok(());
            };
            let (request_sha256, receipt_sha256) =
                checked_completion(&host.c.root, name, old, &host.state.results[&old.key(name)])?;
            let plan = Retirement {
                attempt: old,
                request_sha256,
                receipt_sha256,
            };
            // The durable plan replaces references before unlink, so reopening can resume after any deletion.
            stage_retirement(
                &host.c.root,
                name,
                &mut host.state.results,
                &mut host.state.artifacts,
                &plan,
            )?;
            host.save()?;
            plan
        };
        let previous = completed(&host.state.results, name)?
            .into_iter()
            .filter(|a| *a < current)
            .max()
            .context("previous activation absent during retirement")?;
        ensure!(
            plan.attempt < previous,
            "cannot retire the current or previous activation"
        );
        retire_exports(
            host,
            &format!("Manager{name}"),
            &plan.mapped(&host.c.root, name)?,
        )?;
        retire_owner(&host.c.root, name, &plan)?;
        host.state.results.remove(&key);
        host.save()?;
    }
}

fn reconcile(host: &mut Host<'_>, name: &str, attempt: Attempt, required: bool) -> Result<bool> {
    if let Some(value) = host.remembered(&attempt.key(name)) {
        checked_completion(&host.c.root, name, attempt, &value)?;
        return Ok(true);
    }
    let request = files::read(&attempt.export(&host.c.root, name, "Request"), 1_048_576)?;
    let receipt = attempt.export(&host.c.root, name, "Receipt");
    let pending = host.p(&format!("Activation/{name}/Completion.cbor"));
    if !receipt.try_exists()? {
        if !pending.try_exists()? {
            let exported = host.core(&bytes(&[
                "runtime",
                "services",
                "activation-receipt",
                "--directory",
                &text(&host.p(name))?,
                "--output",
                &text(&pending)?,
            ]));
            if !pending.try_exists()? {
                if required {
                    exported.context("running service has no exact retained activation report")?;
                    anyhow::bail!("activation receipt export produced no retained report");
                }
                return Ok(false);
            }
        }
        let report = files::read(&pending, activation::RECEIPT_LIMIT)?;
        if receipt_request(&report)? != request {
            // A newly saved launch may precede startup. Only an already reported old receipt can be discarded.
            let mut known = false;
            for old in completed(&host.state.results, name)? {
                let (_, hash) = checked_completion(
                    &host.c.root,
                    name,
                    old,
                    &host.state.results[&old.key(name)],
                )?;
                known |= hash == digest(&report);
            }
            ensure!(
                known,
                "unrecognised activation report retained; exact pending request must be reconciled"
            );
            files::remove(&pending)?;
            ensure!(
                !required,
                "running service has not reported its exact retained activation"
            );
            return Ok(false);
        }
        files::exact_file(&receipt, &report)?;
        files::remove(&pending)?;
    }
    let report = files::read(&receipt, activation::RECEIPT_LIMIT)?;
    ensure!(
        receipt_request(&report)? == request,
        "activation report differs from retained launch"
    );
    if pending.try_exists()? {
        ensure!(
            files::read(&pending, activation::RECEIPT_LIMIT)? == report,
            "pending activation export differs"
        );
        files::remove(&pending)?;
    }
    let mut a = bytes(&["authority-inspection", "deployments", "activation-complete"]);
    a.extend(online(host, &format!("Manager{name}"))?);
    a.extend(bytes(&["--receipt", &text(&receipt)?]));
    let mut value = operator(host, &format!("Manager{name}"), &a)?;
    checked_completion(&host.c.root, name, attempt, &value)?;
    value["requestSha256"] = json!(digest(&request));
    value["receiptSha256"] = json!(digest(&report));
    host.remember(&attempt.key(name), value)?;
    Ok(true)
}
fn recover_launch(
    active: bool,
    prior: Option<Attempt>,
    mut report: impl FnMut(Attempt, bool) -> Result<bool>,
) -> Result<Option<Attempt>> {
    if let Some(attempt) = prior {
        let completed = report(attempt, active)?;
        ensure!(
            !active || completed,
            "running service activation is unresolved"
        );
        Ok((!completed).then_some(attempt))
    } else {
        ensure!(
            !active,
            "running service has no retained activation request"
        );
        Ok(None)
    }
}

fn manager(host: &mut Host<'_>, name: &str) -> Result<(String, String)> {
    let who = format!("Manager{name}");
    let identity = host.p(&format!("Keys/{who}.json"));
    let subject = bootstrap::identity(host, &who, &identity)?;
    let grant = host.id(&format!("manager-grant/{name}"))?;
    let root = host.root_grant()?;
    let tier = string(
        &host.bootstrap()?["genesisGovernance"]["rootGrants"][0]["tier"],
        "id",
    )?;
    let scope = bytes(&["--parent", &root, "--tier", &tier]);
    let label = format!("manager-delegation/{name}");
    if host.remembered(&label).is_none() {
        let mut a = bytes(&["applications", "delegate"]);
        a.extend(online(host, "Administrator")?);
        a.extend(scope.clone());
        a.extend(bytes(&[
            "--id",
            &grant,
            "--subject",
            &subject,
            "--actions",
            "26",
            "--scopes",
            &format!("5:{}", host.state.ids[&format!("deployment/{name}")]),
            "--not-before-ms",
            &host.state.created_ms.to_string(),
            "--limits",
            "0,1,0,1",
        ]));
        a.extend(end_arguments(host.c.hosting_end));
        let value = operator(host, "Administrator", &a)?;
        host.remember(&label, value)?;
    }
    let folder = host.dir(&format!("Activation/{name}"))?;
    let offer = folder.join("Offer.cbor");
    let accepted = folder.join("Accepted.cbor");
    let receipt = folder.join("Receipt.cbor");
    if !offer.exists() {
        let mut a = bytes(&["applications", "context"]);
        a.extend(online(host, "Administrator")?);
        a.extend(scope.clone());
        a.extend(bytes(&["--child", &grant]));
        operator(host, "Administrator", &a)?;
        let mut a = bytes(&["applications", "offer"]);
        let mut common = online(host, "Administrator")?;
        common.truncate(common.len() - 2);
        a.extend(common);
        a.extend(scope.clone());
        a.extend(bytes(&[
            "--grant",
            &grant,
            "--not-before-ms",
            &host.state.created_ms.to_string(),
            "--output",
            &text(&offer)?,
        ]));
        a.extend(end_arguments(host.c.hosting_end));
        operator(host, "Administrator", &a)?;
    }
    if !accepted.exists() {
        let mut a = bytes(&["applications", "accept"]);
        a.extend(host.trust()?);
        a.extend(bytes(&[
            "--offer",
            &text(&offer)?,
            "--key",
            &text(&identity)?,
            "--owner-key",
            &string(&host.state.results["Administrator"], "publicKey")?,
            "--output",
            &text(&accepted)?,
        ]));
        host.suite(&a)?;
    }
    if !receipt.exists() {
        let mut a = bytes(&["applications", "register"]);
        a.extend(online(host, "Administrator")?);
        a.extend(scope);
        a.extend(bytes(&[
            "--accepted",
            &text(&accepted)?,
            "--receipt",
            &text(&receipt)?,
        ]));
        operator(host, "Administrator", &a)?;
    }
    let mut a = bytes(&["applications", "confirm"]);
    a.extend(host.trust()?);
    a.extend(bytes(&[
        "--accepted",
        &text(&accepted)?,
        "--receipt",
        &text(&receipt)?,
    ]));
    host.suite(&a)?;
    initialise(host, &who)?;
    Ok((who, grant))
}
fn request(host: &mut Host<'_>, name: &str, role: u64, generation: u64) -> Result<PathBuf> {
    let (who, grant) = manager(host, name)?;
    let persistent = host.c.hosting_end == End::UntilWithdrawn;
    let attempt_key = format!("activation-attempt/{name}/{generation}");
    let mut attempt = host
        .remembered(&attempt_key)
        .map(|v| v.as_u64().context("activation attempt differs"))
        .transpose()?
        .unwrap_or(0);
    if !persistent
        && host
            .remembered(&format!(
                "activation-complete/{name}/{generation}/{attempt}"
            ))
            .is_some()
    {
        attempt = attempt
            .checked_add(1)
            .context("activation attempts exhausted")?;
        host.remember(&attempt_key, json!(attempt))?;
    }
    let path = host.p(&format!(
        "Activation/{name}/Request{generation}-{attempt}.cbor"
    ));
    if !path.exists() {
        let mut a = bytes(&["authority-inspection", "deployments", "context"]);
        a.extend(online(host, &who)?);
        a.extend(bytes(&[
            "--deployment",
            &host.state.ids[&format!("deployment/{name}")],
            "--grant",
            &grant,
        ]));
        operator(host, &who, &a)?;
        let mut a = bytes(&["authority-inspection", "deployments", "activation-request"]);
        let mut common = online(host, &who)?;
        common.truncate(common.len() - 2);
        a.extend(common);
        a.extend(bytes(&[
            "--deployment",
            &host.state.ids[&format!("deployment/{name}")],
            "--grant",
            &grant,
            "--role",
            &role.to_string(),
            "--generation",
            &generation.to_string(),
            "--output",
            &text(&path)?,
        ]));
        if persistent {
            a.push("--persistent".into());
        }
        operator(host, &who, &a)?;
    }
    host.artifact(&path)?;
    Ok(path)
}
pub fn activate(host: &mut Host<'_>, name: &str, operator_name: &str, role: u64) -> Result<()> {
    let purpose = name.to_ascii_lowercase();
    let persistent = host.c.hosting_end == End::UntilWithdrawn;
    let active = units::active(host, &purpose)?;
    let prior = launch(&host.c.root, name, &host.state.results)?;
    let mut unresolved = None;
    if !persistent {
        cleanup(host, name)?;
        unresolved = recover_launch(active, prior, |attempt, required| {
            reconcile(host, name, attempt, required)
        })?;
    }
    if active {
        return Ok(());
    }
    let folder = host.p(&format!("Services/{name}"));
    let runtime = host.p(name);
    let input = folder.join("Inputs");
    if !runtime.exists() {
        let mut a = bytes(&[
            "runtime",
            "services",
            "setup",
            "--directory",
            &text(&runtime)?,
            "--configuration",
            &text(&input)?,
            "--operator-key",
            &text(&host.p(&format!("Keys/{operator_name}.json")))?,
            "--host-consent",
            &text(&folder.join("Consent.cbor"))?,
            "--authority-directory",
            &text(&host.p("A1"))?,
            "--clock-directory",
            &text(&host.p("Native/Clock/Public"))?,
        ]);
        if name == "PageEndpoint" {
            a.extend(bytes(&["--route-service", &text(&host.p("PageStore"))?]));
        }
        if name == "ApplicationEndpoint" {
            let receiver = PathBuf::from(string(&host.state.results["receiver"], "directory")?);
            a.extend(bytes(&[
                "--application-directory",
                &text(&receiver.join("Ingress"))?,
            ]));
        }
        host.core(&a)?;
    }
    let preview = host.core(&bytes(&[
        "runtime",
        "services",
        "preview",
        "--directory",
        &text(&runtime)?,
    ]))?;
    let consent_key = format!("local-consent/{name}");
    if host.remembered(&consent_key).is_none() {
        let v = host.core(&bytes(&[
            "runtime",
            "services",
            "consent",
            "--directory",
            &text(&runtime)?,
            "--profile-digest",
            &string(&preview, "profileDigest")?,
        ]))?;
        host.remember(&consent_key, v)?;
    }
    let generation = number(&preview, "localGeneration")?;
    if let Some(attempt) = unresolved {
        let current = host
            .remembered(&format!("activation-attempt/{name}/{generation}"))
            .map(|v| v.as_u64().context("activation attempt differs"))
            .transpose()?
            .unwrap_or(0);
        ensure!(
            attempt
                == Attempt {
                    generation,
                    attempt: current
                },
            "resolve the exact retained activation before changing generation or attempt"
        );
    }
    let request = request(host, name, role, generation)?;
    host.remember(
        &format!("service-launch/{name}"),
        json!({"request":request,"runtime":runtime}),
    )?;
    if !persistent {
        cleanup(host, name)?;
    }
    host.unit(
        &purpose,
        &host.c.suite,
        &bytes(&[
            "admission-host",
            "service",
            "--directory",
            &text(&host.c.root)?,
            "--name",
            name,
        ]),
    )?;
    host.wait(
        || {
            let current = host.core(&bytes(&[
                "runtime",
                "services",
                "status",
                "--directory",
                &text(&runtime)?,
            ]))?;
            ensure!(current["running"] == true, "native service is not running");
            Ok(())
        },
        60,
    )?;
    if !persistent {
        let attempt = launch(&host.c.root, name, &host.state.results)?
            .context("retained activation absent")?;
        reconcile(host, name, attempt, true)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interrupted_activation_requires_exact_reporting_before_active_return_or_new_attempt() {
        let attempt = Attempt {
            generation: 1,
            attempt: 7,
        };
        let mut reported = false;
        assert!(
            recover_launch(true, Some(attempt), |actual, required| {
                assert_eq!(actual, attempt);
                assert!(required);
                reported = true;
                anyhow::bail!("completion interrupted")
            })
            .is_err()
        );
        assert!(reported);
        assert!(recover_launch(true, Some(attempt), |_, _| Ok(false)).is_err());
        assert!(recover_launch(true, None, |_, _| panic!("no request")).is_err());
        assert_eq!(
            recover_launch(false, Some(attempt), |actual, required| {
                assert_eq!(actual, attempt);
                assert!(!required);
                Ok(false)
            })
            .unwrap(),
            Some(attempt)
        );
        assert_eq!(
            recover_launch(true, Some(attempt), |_, _| Ok(true)).unwrap(),
            None
        );
    }
    #[test]
    fn retirement_survives_partial_unlink_without_losing_retained_or_unresolved_requests() {
        let root =
            std::env::temp_dir().join(format!("hypernet-activation-{}", crate::random_hex::<16>()));
        files::directory(&root).unwrap();
        let outcome = (|| -> Result<()> {
            files::directory(&root.join("Activation"))?;
            files::directory(&root.join("Activation/Relay"))?;
            let mut results = BTreeMap::new();
            let mut artifacts = BTreeMap::new();
            for n in 0..3 {
                let a = Attempt {
                    generation: 1,
                    attempt: n,
                };
                let path = a.export(&root, "Relay", "Request");
                files::exact_file(&path, &[n as u8])?;
                artifacts.insert(text(&path)?, digest(&[n as u8]));
                if n < 2 {
                    results.insert(a.key("Relay"), json!({"status":"ActivationReported"}));
                }
            }
            let old = Attempt {
                generation: 1,
                attempt: 0,
            };
            let prior = Attempt {
                generation: 1,
                attempt: 1,
            };
            let current = Attempt {
                generation: 1,
                attempt: 2,
            };
            files::exact_file(&old.export(&root, "Relay", "Receipt"), b"old receipt")?;
            results.insert("service-launch/Relay".into(), json!({"request":current.export(&root,"Relay","Request"),"runtime":root.join("Relay")}));
            let plan = Retirement {
                attempt: old,
                request_sha256: digest(&[0]),
                receipt_sha256: digest(b"old receipt"),
            };
            stage_retirement(&root, "Relay", &mut results, &mut artifacts, &plan)?;
            let journal = root.join("Journal.json");
            write(&journal, &json!({"results":results,"artifacts":artifacts}))?;
            // Stop after the first unlink and recover only from the atomically retained receipt.
            remove_exact(&old.export(&root, "Relay", "Request"), &plan.request_sha256)?;
            let saved = read(&journal)?;
            let recovered: Retirement =
                serde_json::from_value(saved["results"]["activation-cleanup/Relay"].clone())?;
            retire_owner(&root, "Relay", &recovered)?;
            retire_owner(&root, "Relay", &recovered)?;
            assert!(saved["results"].get(old.key("Relay")).is_none());
            assert!(
                saved["artifacts"]
                    .get(text(&old.export(&root, "Relay", "Request"))?)
                    .is_none()
            );
            assert_eq!(
                files::read(&prior.export(&root, "Relay", "Request"), 1)?,
                [1]
            );
            assert_eq!(
                files::read(&current.export(&root, "Relay", "Request"), 1)?,
                [2]
            );
            assert!(saved["results"].get(current.key("Relay")).is_none());
            let previous_plan = Retirement {
                attempt: prior,
                request_sha256: digest(&[1]),
                receipt_sha256: digest(b"previous"),
            };
            assert!(
                stage_retirement(&root, "Relay", &mut results, &mut artifacts, &previous_plan)
                    .is_err()
            );
            Ok(())
        })();
        std::fs::remove_dir_all(&root).unwrap();
        outcome.unwrap();
    }
}
