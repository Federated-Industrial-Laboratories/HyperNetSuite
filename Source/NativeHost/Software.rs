// SPDX-License-Identifier: Apache-2.0
// A stopped controller successor changes only reviewed software and exact owned unit templates.
use super::{chat, engine::*, files, lifecycle, services, units};
use crate::admission::{private, protocol};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

const PLAN: &str = "SoftwareUpdate.json";
const LAST: &str = "controller-update";
const FORMAT: &str = "HyperNetNativeControllerUpdate/1";
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    format: String,
    review_digest: String,
    configuration_digest: String,
    old_installation: Value,
    new_installation: Value,
    units: Vec<units::Successor>,
}
fn selection(old: &Value, new: &Value) -> Result<()> {
    for value in [old, new] {
        ensure!(
            value["format"] == "HyperNetNativeInstallation/1" && value["status"] == "Ready",
            "controller selection is not an installed signed pair"
        );
    }
    ensure!(
        old["coreExecutable"] == new["coreExecutable"]
            && old["coreImage"] == new["coreImage"]
            && old["packages"]["core"] == new["packages"]["core"],
        "controller update requires the exact unchanged Core package and image"
    );
    let before = &old["packages"]["suite"];
    let after = &new["packages"]["suite"];
    ensure!(
        before["product"] == "HyperNetSuite"
            && after["product"] == before["product"]
            && after["rootPin"] == before["rootPin"]
            && after["stateContract"] == before["stateContract"],
        "controller publisher or state contract changed"
    );
    let previous = (
        number(before, "rootGeneration")?,
        number(before, "sequence")?,
    );
    let next = (number(after, "rootGeneration")?, number(after, "sequence")?);
    ensure!(
        next > previous && after["targetDigest"] != before["targetDigest"],
        "select a newer signed controller target; rollback and same-target replacement are refused"
    );
    ensure!(
        old["suiteExecutable"] != new["suiteExecutable"]
            && after["binarySha256"] != before["binarySha256"],
        "controller binary is already selected"
    );
    Ok(())
}
impl Plan {
    fn digest(&self, root: &Path) -> Result<String> {
        protocol::digest_value(&json!({"format":FORMAT,"directory":root,
            "configurationDigest":self.configuration_digest,"oldInstallation":self.old_installation,
            "newInstallation":self.new_installation,"units":self.units}))
    }
    fn validate(&self, root: &Path) -> Result<()> {
        ensure!(
            self.format == FORMAT
                && self.units.len() <= 16
                && protocol::identifier(&self.configuration_digest)
                && self.review_digest == self.digest(root)?,
            "retained controller update differs"
        );
        selection(&self.old_installation, &self.new_installation)
    }
    fn preview(&self) -> Value {
        json!({"format":"HyperNetNativeHost/1","status":"SoftwarePreview","reviewDigest":self.review_digest,
            "oldSuite":self.old_installation["suiteExecutable"],"newSuite":self.new_installation["suiteExecutable"],
            "oldInstallation":self.old_installation,"newInstallation":self.new_installation,
            "units":self.units.iter().map(|u| &u.purpose).collect::<Vec<_>>(),"startsAutomatically":false,
            "preserves":"Core image, native consent, identities, floors, pending results and participant state"})
    }
    fn receipt(&self) -> Result<Value> {
        Ok(
            json!({"format":"HyperNetNativeHost/1","status":"SoftwareUpdated","reviewDigest":self.review_digest,
            "newSuite":self.new_installation["suiteExecutable"],
            "selectionDigest":protocol::digest_value(&self.new_installation)?,"desiredRunning":false}),
        )
    }
}
fn retained_plan(root: &Path) -> Result<Option<Plan>> {
    match std::fs::symlink_metadata(root.join(PLAN)) {
        Ok(_) => {
            let plan: Plan = serde_json::from_slice(&files::read(&root.join(PLAN), 262144)?)?;
            plan.validate(root)?;
            Ok(Some(plan))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
pub fn pending(root: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(root) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    private::directory(root)?;
    Ok(retained_plan(root)?.is_some())
}
fn stopped(host: &mut Host<'_>) -> Result<()> {
    ensure!(
        !host.state.desired_running && !host.state.withdrawn,
        "stop this host before reviewing its controller update; withdrawal remains terminal"
    );
    ensure!(
        lifecycle::status(host)?["status"] == "Stopped",
        "native workloads or unresolved operations remain; finish normal Stop before controller update"
    );
    host.verify_artifacts()
}
fn unchanged_native(host: &Host<'_>, installed: &Installation) -> Result<()> {
    ensure!(
        host.c.installation == installed.directory
            && host.c.core == installed.core
            && host.state.image == installed.image
            && host.state.installation["packages"]["core"]
                == installed.selection["packages"]["core"],
        "controller update requires the exact retained Core installation and image"
    );
    ensure!(
        host.state.hrc_digest
            == host
                .c
                .hrc
                .as_ref()
                .map(|h| binary_digest(&h.executable))
                .transpose()?,
        "chat software changed; review that replacement separately"
    );
    Ok(())
}
fn unit_changes(host: &Host<'_>, controller: &Path, resume: bool) -> Result<Vec<units::Successor>> {
    let mut changes = Vec::new();
    let mut add = |purpose: &str, executable: &Path, args: Vec<String>| -> Result<()> {
        if units::exists(&host.c.root, purpose)? {
            changes.push(units::successor(
                host, purpose, executable, &args, controller, resume,
            )?);
        }
        Ok(())
    };
    for (purpose, command) in [("clock", "clock"), ("supervisor", "supervise")] {
        add(
            purpose,
            &host.c.suite,
            bytes(&[
                "admission-host",
                command,
                "--directory",
                &text(&host.c.root)?,
            ]),
        )?;
    }
    for n in 1..=4 {
        let purpose = format!("a{n}");
        if units::exists(&host.c.root, &purpose)? {
            let floor = host
                .remembered(&format!("signer-floor/A{n}"))
                .and_then(|v| v.as_u64())
                .context("retained signer floor absent")?;
            add(
                &purpose,
                &host.c.core,
                bytes(&[
                    "runtime",
                    "serve",
                    "--directory",
                    &text(&host.p(&format!("A{n}")))?,
                    "--managed-minimum-signer-generation",
                    &floor.to_string(),
                ]),
            )?;
        }
    }
    for role in [
        "PageStore",
        "Relay",
        "AuthorityEndpoint",
        "PageEndpoint",
        "ApplicationEndpoint",
    ] {
        if role != "ApplicationEndpoint" || host.c.hrc.is_some() {
            add(
                &role.to_ascii_lowercase(),
                &host.c.suite,
                bytes(&[
                    "admission-host",
                    "service",
                    "--directory",
                    &text(&host.c.root)?,
                    "--name",
                    role,
                ]),
            )?;
        }
    }
    if let Some(hrc) = &host.c.hrc {
        add(
            "hrc",
            &hrc.executable,
            bytes(&["service", "run", "--directory", &text(&host.p("HRC/Home"))?]),
        )?;
        if units::exists(&host.c.root, "receiver")? {
            let native = host
                .remembered("receiver-native")
                .context("receiver identity absent")?;
            add(
                "receiver",
                &host.c.suite,
                bytes(&[
                    "network",
                    "connect",
                    "--profile",
                    &string(&native, "profile")?,
                    "--",
                    "streams",
                    "agent",
                    "--ipc-directory",
                    &text(&chat::companion_path(
                        &host.c.root,
                        &host.state.configuration_digest,
                        "Receiver",
                    )?)?,
                    "--binding",
                    &text(
                        &services::active_directory(host, "ApplicationEndpoint")?
                            .join("ServiceAccepted.cbor"),
                    )?,
                ]),
            )?;
        }
        if units::exists(&host.c.root, "owner-chat")? {
            let installed = host
                .remembered("owner-installed")
                .context("owner identity absent")?;
            let profile = installed["profiles"]
                .as_array()
                .context("owner profiles absent")?
                .iter()
                .find(|p| p["role"] == 1)
                .context("owner chat profile absent")?;
            add(
                "owner-chat",
                &host.c.suite,
                bytes(&[
                    "network",
                    "connect",
                    "--profile",
                    &string(profile, "profile")?,
                    "--",
                    "streams",
                    "agent",
                    "--ipc-directory",
                    &text(&chat::companion_path(
                        &host.c.root,
                        &host.state.configuration_digest,
                        "OwnerChat",
                    )?)?,
                    "--targets",
                    &text(&host.p("Client/OwnerChatTargets.json"))?,
                ]),
            )?;
        }
    }
    Ok(changes)
}
fn plan(host: &Host<'_>, installed: &Installation) -> Result<Plan> {
    ensure!(
        host.c.installation == installed.directory,
        "controller update must use the retained installation root"
    );
    selection(&host.state.installation, &installed.selection)?;
    let mut plan = Plan {
        format: FORMAT.into(),
        review_digest: String::new(),
        configuration_digest: host.state.configuration_digest.clone(),
        old_installation: host.state.installation.clone(),
        new_installation: installed.selection.clone(),
        units: unit_changes(host, &installed.suite, false)?,
    };
    plan.review_digest = plan.digest(&host.c.root)?;
    Ok(plan)
}
fn verify_plan(host: &mut Host<'_>, installed: &Installation, plan: &Plan) -> Result<()> {
    plan.validate(&host.c.root)?;
    ensure!(
        host.c.installation == installed.directory
            && installed.selection == plan.new_installation
            && host.state.configuration_digest == plan.configuration_digest
            && (host.state.installation == plan.old_installation
                || host.state.installation == plan.new_installation),
        "resume the exact reviewed controller selection and host configuration"
    );
    host.c.suite = PathBuf::from(string(&plan.old_installation, "suiteExecutable")?);
    ensure!(
        unit_changes(host, &installed.suite, true)? == plan.units,
        "controller update unit set changed"
    );
    Ok(())
}
pub fn preview(root: &Path, installation: &Path, cancel: &AtomicBool) -> Result<Value> {
    let installed = Installation::inspect(installation, cancel)?;
    let mut host = Host::retained(root, cancel)?;
    unchanged_native(&host, &installed)?;
    stopped(&mut host)?;
    let plan = if let Some(plan) = retained_plan(root)? {
        verify_plan(&mut host, &installed, &plan)?;
        plan
    } else {
        plan(&host, &installed)?
    };
    Ok(plan.preview())
}
pub fn update(
    root: &Path,
    installation: &Path,
    review_digest: &str,
    cancel: &AtomicBool,
) -> Result<Value> {
    ensure!(
        protocol::identifier(review_digest),
        "controller review digest differs"
    );
    let installed = Installation::inspect(installation, cancel)?;
    let mut host = Host::retained(root, cancel)?;
    unchanged_native(&host, &installed)?;
    stopped(&mut host)?;
    if let Some(receipt) = host.remembered(LAST)
        && receipt["reviewDigest"] == review_digest
        && host.state.installation == installed.selection
        && receipt["selectionDigest"] == protocol::digest_value(&installed.selection)?
    {
        ensure!(
            receipt["status"] == "SoftwareUpdated" && receipt["newSuite"] == json!(installed.suite),
            "retained controller completion differs"
        );
        if let Some(plan) = retained_plan(root)? {
            ensure!(
                plan.review_digest == review_digest,
                "another controller update remains pending"
            );
            verify_plan(&mut host, &installed, &plan)?;
            for change in &plan.units {
                units::apply_successor(&host, change)?;
            }
            units::reload(&host)?;
            files::remove(&root.join(PLAN))?;
        }
        return Ok(receipt);
    }
    let plan = if let Some(plan) = retained_plan(root)? {
        verify_plan(&mut host, &installed, &plan)?;
        plan
    } else {
        let plan = plan(&host, &installed)?;
        ensure!(
            plan.review_digest == review_digest,
            "controller review changed; preview the exact successor again"
        );
        ensure!(
            crate::native_installation::admit_controller(installation)? == installed.selection,
            "controller package admission differs from the review"
        );
        // Admission and explicit owner review precede the durable transaction; retry never chooses new software.
        files::exact_file(&root.join(PLAN), &serde_json::to_vec(&plan)?)?;
        plan
    };
    ensure!(
        plan.review_digest == review_digest,
        "resume the exact pending controller review"
    );
    for change in &plan.units {
        units::apply_successor(&host, change)?;
    }
    units::reload(&host)?;
    ensure!(
        Installation::inspect(installation, cancel)?.selection == plan.new_installation,
        "installed controller selection changed during update; retained update remains offline"
    );
    let receipt = plan.receipt()?;
    host.state.installation = plan.new_installation;
    host.remember(LAST, receipt.clone())?;
    files::remove(&root.join(PLAN))?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn installation(n: u64) -> Value {
        json!({"format":"HyperNetNativeInstallation/1","status":"Ready","coreExecutable":"/installed/Core",
            "coreImage":"sha256:core","suiteExecutable":format!("/installed/Suite{n}"),"packages":{
                "core":{"binarySha256":"core","sequence":3},"suite":{"product":"HyperNetSuite",
                    "rootPin":"publisher","stateContract":"HyperNet080Client1","rootGeneration":1,
                    "sequence":n,"targetDigest":format!("target{n}"),"binarySha256":format!("binary{n}")}}})
    }
    #[test]
    fn controller_selection_refuses_core_change_downgrade_and_changed_publisher_or_contract() {
        let old = installation(2);
        let new = installation(3);
        selection(&old, &new).unwrap();
        assert!(selection(&new, &old).is_err());
        assert!(selection(&old, &old).is_err());
        for pointer in [
            "/coreExecutable",
            "/coreImage",
            "/packages/core/binarySha256",
            "/packages/suite/rootPin",
            "/packages/suite/stateContract",
        ] {
            let mut changed = new.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("changed");
            assert!(selection(&old, &changed).is_err(), "{pointer}");
        }
    }
    #[test]
    fn persisted_controller_plan_binds_directory_selection_and_exact_review_for_retry() {
        let root =
            std::env::temp_dir().join(format!("hypernet-controller-{}", crate::random_hex::<16>()));
        files::directory(&root).unwrap();
        let outcome = (|| -> Result<()> {
            let mut plan = Plan {
                format: FORMAT.into(),
                review_digest: String::new(),
                configuration_digest: "11".repeat(32),
                old_installation: installation(2),
                new_installation: installation(3),
                units: Vec::new(),
            };
            plan.review_digest = plan.digest(&root)?;
            files::exact_file(&root.join(PLAN), &serde_json::to_vec(&plan)?)?;
            assert!(pending(&root)?);
            let restored = retained_plan(&root)?.context("plan absent")?;
            assert_eq!(restored.receipt()?, plan.receipt()?);
            assert!(restored.validate(&root.join("other")).is_err());
            let mut changed = restored;
            changed.new_installation["suiteExecutable"] = json!("/other/Suite");
            assert!(changed.validate(&root).is_err());
            files::remove(&root.join(PLAN))?;
            assert!(!pending(&root)?);
            Ok(())
        })();
        std::fs::remove_dir_all(&root).unwrap();
        outcome.unwrap();
    }
}
