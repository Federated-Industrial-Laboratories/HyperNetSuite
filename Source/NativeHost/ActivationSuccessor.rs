// SPDX-License-Identifier: Apache-2.0
// Exact stopped successors close one prior manager generation while preserving its unresolved history.
use super::*;
use crate::{authority_deployment_records::Registration, runtime_manifest::Manifest};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    manager: String,
    deployment: String,
    grant: String,
    role: u64,
    prior: Attempt,
    request_sha256: String,
    intent: String,
    stream_generation: u64,
    stream_generation_id: String,
    sequence: u64,
    generation: u64,
    profile_digest: String,
    consent_digest: String,
}
fn registration(bytes: &[u8], request: &activation::Request) -> Result<Registration> {
    let value = trust_wire::decode(bytes)?;
    let records = value.array(5)?[4].list(crate::authority_capacity::MAX_RECORDS)?;
    let bytes = records
        .iter()
        .find_map(|record| {
            let bytes = record.bytes().ok()?;
            (trust_wire::digest(bytes) == request.operation().admission.digest).then_some(bytes)
        })
        .context("prior activation registration absent")?;
    Registration::parse(
        bytes,
        request.intent().network,
        request.intent().incarnation,
    )
}
fn stopped(value: &Value, generation: u64) -> Result<Manifest> {
    ensure!(
        value["running"] == false
            && value["cleanupComplete"] == true
            && value["status"] == "Consented"
            && number(value, "localGeneration")? == generation,
        "activation succession requires the exact consented, fully stopped service"
    );
    let manifest: Manifest = serde_json::from_value(value["manifest"].clone())?;
    manifest.validate()?;
    ensure!(
        manifest.generation == generation,
        "installed activation generation differs"
    );
    Ok(manifest)
}
fn certified(value: &Value, manifest: &Manifest) -> Result<()> {
    let selected = &value["registeredProfile"];
    ensure!(
        selected["withdrawn"] == false
            && serde_json::from_value::<Manifest>(selected["manifest"].clone())? == *manifest
            && string(selected, "profileDigest")?
                == hex::encode(trust_wire::digest(&manifest.desired()?))
            && string(selected, "consentDigest")?
                == hex::encode(trust_wire::digest(&manifest.unsigned_consent(0)?)),
        "certified successor differs from the exact stopped local profile and consent"
    );
    Ok(())
}
impl Plan {
    #[allow(
        clippy::too_many_arguments,
        reason = "Bind each retained manager, request and exact successor input explicitly."
    )]
    fn new(
        manager: &str,
        deployment: &str,
        grant: &str,
        role: u64,
        prior: Attempt,
        bytes: &[u8],
        requester: &str,
        manifest: &Manifest,
    ) -> Result<Self> {
        let request = activation::Request::parse(bytes)?;
        let intent = request.intent();
        let operation = request.operation();
        let old = registration(bytes, &request)?;
        manifest.permits_definition(&old.manifest)?;
        ensure!(
            request.persistent()
                && prior.attempt == 0
                && operation.local_generation == prior.generation
                && old.manifest.generation == prior.generation
                && manifest.generation > prior.generation
                && intent.profile_generation == old.manifest.generation
                && hex::encode(intent.requester) == requester
                && hex::encode(intent.resource) == deployment
                && hex::encode(manifest.deployment) == deployment
                && hex::encode(operation.grant.id) == grant
                && operation.role == role
                && manifest
                    .roles
                    .iter()
                    .any(|r| r.role == role && r.service_key == operation.recipient),
            "prior activation does not bind this exact dedicated manager and stopped successor"
        );
        Ok(Self {
            manager: manager.into(),
            deployment: deployment.into(),
            grant: grant.into(),
            role,
            prior,
            request_sha256: digest(bytes),
            intent: hex::encode(intent.digest),
            stream_generation: intent.generation,
            stream_generation_id: hex::encode(intent.generation_id),
            sequence: intent.sequence,
            generation: manifest.generation,
            profile_digest: hex::encode(trust_wire::digest(&manifest.desired()?)),
            consent_digest: hex::encode(trust_wire::digest(&manifest.unsigned_consent(0)?)),
        })
    }
    fn retain(&self, previous: Option<Value>) -> Result<()> {
        if let Some(previous) = previous {
            let previous: Self = serde_json::from_value(previous)?;
            ensure!(
                previous == *self
                    || previous.manager == self.manager
                        && previous.deployment == self.deployment
                        && previous.grant == self.grant
                        && previous.role == self.role
                        && previous.generation == self.prior.generation
                        && previous.generation < self.generation,
                "retained activation successor plan differs"
            );
        }
        Ok(())
    }
    fn arguments(&self) -> Vec<String> {
        bytes(&[
            "--expected-generation",
            &self.stream_generation.to_string(),
            "--expected-generation-id",
            &self.stream_generation_id,
            "--expected-sequence",
            &self.sequence.to_string(),
            "--expected-intent",
            &self.intent,
        ])
    }
}
fn preserve_receipt(
    host: &mut Host<'_>,
    name: &str,
    prior: Attempt,
    request: &[u8],
    initialised: bool,
) -> Result<()> {
    let receipt = prior.export(&host.c.root, name, "Receipt");
    if !receipt.exists() {
        // Before initialization no activation receipt exists. Any later export failure must preserve uncertainty.
        if !initialised {
            return Ok(());
        }
        let result = host.core(&bytes(&[
            "runtime",
            "services",
            "activation-receipt",
            "--if-present",
            "--directory",
            &text(&host.p(name))?,
            "--output",
            &text(&receipt)?,
        ]))?;
        if result["status"] == "ActivationReceiptAbsent" {
            ensure!(
                !receipt.try_exists()?,
                "absent receipt conflicts with retained export"
            );
            return Ok(());
        }
    }
    let report = files::read(&receipt, activation::RECEIPT_LIMIT)?;
    ensure!(
        receipt_request(&report)? == request,
        "retained service receipt belongs to another activation"
    );
    host.artifact(&receipt)
}
pub(super) fn prepare(
    host: &mut Host<'_>,
    name: &str,
    who: &str,
    grant: &str,
    role: u64,
    generation: u64,
) -> Result<()> {
    let Some(prior) = launch(&host.c.root, name, &host.state.results)? else {
        return Ok(());
    };
    ensure!(
        prior.generation <= generation,
        "installed activation generation moved backwards"
    );
    if prior.generation == generation {
        return Ok(());
    }
    let runtime = host.p(name);
    for marker in [
        "Transition.json",
        "RecoveryNeedsConsent.json",
        "PackageCutoverRequired.json",
    ] {
        ensure!(
            !runtime.join(marker).try_exists()?,
            "incomplete or non-serving successor cannot advance activation"
        );
    }
    ensure!(
        !units::active(host, &name.to_ascii_lowercase())?,
        "stop the prior managed service before succession"
    );
    let status = host.core(&bytes(&[
        "runtime",
        "services",
        "status",
        "--directory",
        &text(&runtime)?,
    ]))?;
    let manifest = stopped(&status, generation)?;
    let path = prior.export(&host.c.root, name, "Request");
    let request = files::read(&path, 1_048_576)?;
    ensure!(
        host.state.artifacts.get(&text(&path)?) == Some(&digest(&request)),
        "prior activation export differs from its retained digest"
    );
    let deployment = host.state.ids[&format!("deployment/{name}")].clone();
    let plan = Plan::new(
        who,
        &deployment,
        grant,
        role,
        prior,
        &request,
        &string(&host.state.results[who], "publicKey")?,
        &manifest,
    )?;
    let key = format!("activation-successor/{name}");
    plan.retain(host.remembered(&key))?;
    host.remember(&key, serde_json::to_value(&plan)?)?;
    let mut args = bytes(&["authority-inspection", "deployments", "context"]);
    args.extend(online(host, "Administrator")?);
    args.extend(bytes(&[
        "--grant",
        &host.root_grant()?,
        "--deployment",
        &deployment,
    ]));
    certified(&operator(host, "Administrator", &args)?, &manifest)?;
    preserve_receipt(
        host,
        name,
        prior,
        &request,
        status["initialised"]
            .as_bool()
            .context("service initialization status absent")?,
    )?;
    // Re-probe after the authority exchange; replayed transition output alone does not prove the workload stopped.
    let status = host.core(&bytes(&[
        "runtime",
        "services",
        "status",
        "--directory",
        &text(&runtime)?,
    ]))?;
    ensure!(
        stopped(&status, generation)? == manifest,
        "stopped successor changed during activation review"
    );
    let mut args = bytes(&["authority-inspection", "stream-fence"]);
    args.extend(online(host, who)?);
    args.extend(plan.arguments());
    let result = operator(host, who, &args)?;
    ensure!(
        result["status"] == "StreamFence"
            && matches!(
                result["outcome"].as_str(),
                Some("Applied" | "AlreadyApplied")
            ),
        "exact activation fence did not complete"
    );
    Ok(())
}

#[cfg(test)]
#[path = "../../Tests/Unit/NativeHost/ActivationSuccessorTests.rs"]
mod tests;
