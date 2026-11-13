// SPDX-License-Identifier: MIT
// A stopped host adopts only the exact reviewed controller and preserves public admission state.
use super::*;
use std::fs::File;

const FORMAT: &str = "HyperNetHostingSoftware/1";
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    format: String,
    configuration_digest: String,
    native_review: Value,
    previous_ready: Option<Ready>,
    successor_ready: Option<Ready>,
    unit: host_service::Successor,
}
pub(super) fn pending(directory: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(directory.join("HostingSoftware.json")) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
fn offline(directory: &Path, ready: Option<&Ready>, stop: &AtomicBool) -> Result<File> {
    ensure!(
        !desired(directory)?,
        "stop hosting before updating its software"
    );
    let lock = host_service::lock(directory, "HostSession.lock")?;
    host_service::require_stopped(directory, stop)?;
    if let Some(r) = ready {
        for name in [
            r.container.name(),
            format!("{}-registrar", r.container.name()),
        ] {
            let output = r.container.command(
                &[
                    "ps".into(),
                    "--all".into(),
                    "--filter".into(),
                    format!("name=^{name}$").into(),
                    "--format=json".into(),
                ],
                stop,
            )?;
            let rows: Vec<Value> = serde_json::from_slice(&output)?;
            ensure!(
                rows.is_empty(),
                "stop and clean up public joining before updating its software"
            );
        }
    }
    Ok(lock)
}
fn summary(plan: &Plan) -> Result<Value> {
    Ok(
        json!({"status":"SoftwarePreview","reviewDigest":protocol::digest_value(plan)?,
        "native":plan.native_review,"remainsStopped":true,
        "preserves":"Identities, authority floors, permissions, invitations and history",
        "scope":"Installed Suite controller; Core, its image and HRC remain unchanged"}),
    )
}
fn validate(directory: &Path, plan: &Plan, setup: &Setup) -> Result<()> {
    ensure!(
        plan.format == FORMAT
            && plan.configuration_digest == protocol::digest_value(&setup.configuration)?,
        "retained hosting software review differs"
    );
    let old = path(&plan.native_review, "oldSuite")?;
    let new = path(&plan.native_review, "newSuite")?;
    plan.unit.validate(directory, &old, &new)?;
    match (&plan.previous_ready, &plan.successor_ready) {
        (Some(previous), Some(successor)) => {
            ensure!(
                previous.version == 1
                    && previous.container.directory == directory
                    && previous.container.suite == old
                    && successor.container.suite == new,
                "public controller selection differs"
            );
            let mut expected = previous.clone();
            expected.container.suite = new;
            ensure!(
                protocol::digest_value(&expected)? == protocol::digest_value(successor)?,
                "public controller update changes admission configuration"
            );
            let current = super::ready(directory)?;
            let current = protocol::digest_value(&current)?;
            ensure!(
                current == protocol::digest_value(previous)?
                    || current == protocol::digest_value(successor)?,
                "public admission state changed during software update"
            );
        }
        (None, None) => ensure!(
            !directory.join("HostingReady.json").try_exists()?,
            "public admission state appeared during software update"
        ),
        _ => anyhow::bail!("incomplete public controller review"),
    }
    Ok(())
}
fn prepare(directory: &Path, setup: &Setup, stop: &AtomicBool) -> Result<Plan> {
    let previous_ready = if directory.join("HostingReady.json").try_exists()? {
        Some(super::ready(directory)?)
    } else {
        None
    };
    let _session = offline(directory, previous_ready.as_ref(), stop)?;
    let native_review = native(
        directory,
        &setup.configuration,
        json!({"operation":"previewSoftware"}),
        stop,
    )?;
    ensure!(
        field(&native_review, "status")? == "SoftwarePreview",
        "native software review unavailable"
    );
    let old = path(&native_review, "oldSuite")?;
    let new = path(&native_review, "newSuite")?;
    let mut successor_ready = previous_ready.clone();
    if let Some(r) = &mut successor_ready {
        r.container.suite = new.clone();
    }
    let plan = Plan {
        format: FORMAT.into(),
        configuration_digest: protocol::digest_value(&setup.configuration)?,
        native_review,
        previous_ready,
        successor_ready,
        unit: host_service::review_successor(directory, &old, &new, stop)?,
    };
    validate(directory, &plan, setup)?;
    Ok(plan)
}
pub(super) fn preview(directory: &Path, stop: &AtomicBool) -> Result<Value> {
    let setup: Setup = saved::read(&directory.join("HostingSetup.json"))?;
    let plan = if pending(directory)? {
        let plan: Plan = saved::read(&directory.join("HostingSoftware.json"))?;
        validate(directory, &plan, &setup)?;
        let _session = offline(directory, plan.previous_ready.as_ref(), stop)?;
        plan
    } else {
        prepare(directory, &setup, stop)?
    };
    summary(&plan)
}
pub(super) fn update(directory: &Path, review: &str, stop: &AtomicBool) -> Result<Value> {
    ensure!(
        protocol::identifier(review),
        "invalid hosting software review"
    );
    let setup: Setup = saved::read(&directory.join("HostingSetup.json"))?;
    let target = directory.join("HostingSoftware.json");
    let receipt = directory.join("HostingSoftwareReceipt.json");
    let completed = if receipt.try_exists()? {
        Some(saved::read::<Plan>(&receipt)?)
    } else {
        None
    };
    let plan = if pending(directory)? {
        saved::read::<Plan>(&target)?
    } else if let Some(completed) = completed
        && protocol::digest_value(&completed)? == review
    {
        completed
    } else {
        let plan = prepare(directory, &setup, stop)?;
        ensure!(
            protocol::digest_value(&plan)? == review,
            "software review changed; review again"
        );
        saved::replace(&target, &plan)?;
        plan
    };
    ensure!(
        protocol::digest_value(&plan)? == review,
        "resume the exact retained software update"
    );
    validate(directory, &plan, &setup)?;
    let _session = offline(directory, plan.previous_ready.as_ref(), stop)?;
    let result = native(
        directory,
        &setup.configuration,
        json!({"operation":"updateSoftware","reviewDigest":field(&plan.native_review,"reviewDigest")?}),
        stop,
    )?;
    ensure!(
        field(&result, "status")? == "SoftwareUpdated"
            && result["newSuite"] == plan.native_review["newSuite"],
        "native software update is incomplete"
    );
    plan.unit.apply(directory, stop)?;
    if let Some(ready) = &plan.successor_ready {
        saved::replace(&directory.join("HostingReady.json"), ready)?;
    }
    saved::replace(&receipt, &plan)?;
    if pending(directory)? {
        std::fs::remove_file(&target)?;
    }
    File::open(directory)?.sync_all()?;
    Ok(
        json!({"status":"SoftwareUpdated","reviewDigest":review,"newSuite":result["newSuite"],"desiredRunning":false}),
    )
}
