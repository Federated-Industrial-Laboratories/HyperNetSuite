// SPDX-License-Identifier: MIT
//! Predict one route record from certified state and bind registration to that exact result.
use super::*;
fn text(reference: &VersionRef) -> String {
    format!(
        "{}:{}:{}",
        hex::encode(reference.id),
        reference.generation,
        hex::encode(reference.digest)
    )
}
fn next(
    state: &domain::State,
    profile: routes::RegisteredProfile,
    manager: [u8; 32],
    grant: VersionRef,
) -> Result<domain::Record> {
    if let Some(record) = state.records.get(&(165, profile.identity.service)) {
        let old = routes::Service::parse(&record.payload, state.network, state.incarnation)?;
        ensure!(
            !old.withdrawn && old.manager == manager,
            "route prediction cannot revive withdrawal or change manager"
        );
        profile.successor_of(&old.profile)?;
    }
    domain::Record::next(
        state,
        165,
        profile.identity.service,
        routes::Service {
            profile,
            manager,
            grant,
            withdrawn: false,
        }
        .value(),
    )
}
pub(super) fn run(
    c: &mut Client,
    grant: VersionRef,
    profile: routes::RegisteredProfile,
    preview: bool,
    expected: Option<String>,
) -> Result<()> {
    // A pending mutation keeps its exact signed context and must be resolved normally first.
    if let Some(pending) = c.store.resume_ordinary()? {
        ensure!(
            !preview && expected.is_some(),
            "an exact native mutation remains unresolved before route prediction"
        );
        let intent = crate::authority_proof::Intent::from_signed(pending.signed())?;
        let operation = domain::Operation::parse(&intent)?;
        ensure!(
            operation.grant.as_ref() == Some(&grant)
                && matches!(operation.command,
            domain::Command::Route(routes::Command::Register{profile:ref retained}) if retained.envelope==profile.envelope),
            "pending native mutation differs from reviewed route registration"
        );
        let service = profile.identity.service;
        let result = c.execute(
            Some(grant),
            routes::Command::Register {
                profile: Box::new(profile),
            },
        )?;
        ensure!(
            expected.as_deref()
                == Some(text(&result.cache.state.record(165, service)?.reference).as_str()),
            "resolved route differs from predicted record"
        );
        return crate::print_value(
            &json!({"state":"RouteAuthorityResult","certifiedHeight":result.prefix.height(),
            "result":control::diagnostic(result.value),"expectedRecord":expected}),
        );
    }
    let context = c.execute(
        Some(grant.clone()),
        routes::Command::Context {
            action: 26,
            scope: (5, profile.deployment),
        },
    )?;
    let manager = c.key.verifying_key().to_bytes();
    if let Some(expected) = &expected
        && let Some(record) = context
            .cache
            .state
            .records
            .get(&(165, profile.identity.service))
    {
        let current = routes::Service::parse(
            &record.payload,
            context.cache.state.network,
            context.cache.state.incarnation,
        )?;
        if text(&record.reference) == *expected {
            ensure!(
                !current.withdrawn
                    && current.manager == manager
                    && current.grant == grant
                    && current.profile.envelope == profile.envelope,
                "retained route prediction belongs to another effect"
            );
            let reference = crate::authority_membership::reference(&record.reference);
            return crate::print_value(
                &json!({"state":"RouteAuthorityResult","certifiedHeight":context.prefix.height(),
                    "result":[201,1,"RouteRegister",[control::diagnostic(reference)]],"expectedRecord":expected}),
            );
        }
    }
    let record = next(
        &context.cache.state,
        profile.clone(),
        manager,
        grant.clone(),
    )?;
    let predicted = text(&record.reference);
    if preview {
        return crate::print_value(
            &json!({"status":"RouteRegistrationPreview","expectedRecord":predicted,
            "predecessor":record.predecessor.map(hex::encode),"certifiedHeight":context.prefix.height(),
            "profileSha256":hex::encode(Sha256::digest(&profile.envelope)),"registered":false}),
        );
    }
    ensure!(
        expected.as_deref() == Some(predicted.as_str()),
        "certified route context changed after prediction; exact proposal remains retained"
    );
    let result = c.execute(
        Some(grant),
        routes::Command::Register {
            profile: Box::new(profile),
        },
    )?;
    ensure!(
        result
            .cache
            .state
            .record(165, record.reference.id)?
            .reference
            == record.reference,
        "registered route differs from its exact predicted record"
    );
    crate::print_value(
        &json!({"state":"RouteAuthorityResult","certifiedHeight":result.prefix.height(),
        "result":control::diagnostic(result.value),"expectedRecord":predicted}),
    )
}

fn subject(
    intent: &crate::authority_proof::Intent,
    accepted: Option<&std::path::Path>,
    selected_route: Option<&std::path::Path>,
) -> Result<([u8; 32], [u8; 32], u64)> {
    let mut possession_end = None;
    let manifest = if intent.action == "AuthorityDeploymentRegister" {
        let crate::authority_deployments::Operation::Register { offer, .. } =
            crate::authority_deployments::Operation::parse(intent)?
        else {
            anyhow::bail!("pending operation is not deployment registration")
        };
        possession_end = offer.possession_expiry()?;
        offer.manifest
    } else {
        ensure!(
            intent.action == "AuthorityDomain",
            "pending operation is not certificate registration"
        );
        match domain::Operation::parse(intent)?.command {
            domain::Command::Route(routes::Command::Register { profile }) => profile.manifest,
            domain::Command::Stream(domain::streams::Command::Register { registration }) => {
                let accepted = files::read_single(
                    accepted.context("exact accepted application artifact required")?,
                    16384,
                    true,
                )?;
                let value = wire::decode(&accepted)?;
                let fields = value.array(5)?;
                ensure!(
                    fields[0].uint()? == 200
                        && fields[1].uint()? == 1
                        && fields[2].text()? == "ApplicationStreamServiceOffer"
                        && fields[4].bytes()? == registration.envelope,
                    "pending application registration differs from retained consent"
                );
                let binding: domain::streams::local::Binding =
                    serde_json::from_slice(fields[3].bytes()?)?;
                let profile = routes::RegisteredProfile::parse(
                    &files::read_single(
                        selected_route.context("exact signed application route required")?,
                        32768,
                        true,
                    )?,
                    intent.network,
                    intent.incarnation,
                )?;
                binding.registration(&registration, &profile)?;
                profile.manifest
            }
            _ => anyhow::bail!("pending operation is not certificate registration"),
        }
    };
    let deadline = match manifest.transport_interval()? {
        Some((_, end)) => Some(end),
        None => manifest
            .endpoints
            .iter()
            .map(|e| {
                crate::runtime_manifest::certificates::interval(&e.leaf_der)
                    .and_then(|(_, end)| end.checked_mul(1000).context("certificate time overflow"))
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .min(),
    };
    let deadline = deadline
        .into_iter()
        .chain(possession_end)
        .min()
        .context("registration has no finite proof or transport deadline")?;
    Ok((
        manifest.deployment,
        wire::digest(&manifest.desired()?),
        manifest.validity.1.bound(deadline),
    ))
}
pub(super) fn recover(
    online: &Online,
    candidates: &[String],
    accepted: Option<&std::path::Path>,
    selected_route: Option<&std::path::Path>,
) -> Result<()> {
    ensure!(
        !candidates.is_empty() && candidates.len() <= 8,
        "certificate recovery candidate bound differs"
    );
    let candidates = candidates
        .iter()
        .map(|s| {
            let (deployment, profile) = s
                .split_once(':')
                .context("certificate candidate requires deployment:profile")?;
            Ok((id(deployment)?, id(profile)?))
        })
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    let mut c = Client::open(online)?;
    let fencing = c.store.resume_fence()?.is_some();
    let pending = if fencing {
        c.store.fence_subject()?
    } else {
        c.store.resume_ordinary()?
    };
    let Some(pending) = pending else {
        ensure!(!fencing, "retained registration fence has no exact subject");
        return crate::print_value(
            &json!({"status":"NothingPending","state":"CertificateRegistrationRecovery"}),
        );
    };
    let intent = crate::authority_proof::Intent::from_signed(pending.signed())?;
    let (deployment, profile, deadline) = subject(&intent, accepted, selected_route)?;
    ensure!(
        candidates.contains(&(deployment, profile)),
        "pending registration is outside the exact retained certificate transaction"
    );
    if c.clock.health()?.observe()?.wall_ms < deadline {
        return crate::print_value(
            &json!({"status":"Waiting","state":"CertificateRegistrationRecovery","expiresAtMs":deadline}),
        );
    }
    let result = stream_client::fence_local_guarded(
        &c.store.descriptor().clone(),
        &c.socket,
        &c.key,
        &mut c.store,
        &mut c.session,
        || c.clock.health(),
        |metadata| super::recovery_stream(&intent, metadata),
    )?;
    let crate::authority_proof::StreamResponse::Fence { outcome, .. } = result else {
        anyhow::bail!("registration recovery returned another control result")
    };
    let complete = c.store.resume_fence()?.is_none() && c.store.resume_ordinary()?.is_none();
    crate::print_value(
        &json!({"status":if complete{"Recovered"}else{"RecoveryPending"},"state":"CertificateRegistrationRecovery",
        "pendingRequest":hex::encode(intent.digest),"outcome":format!("{outcome:?}"),"committedHeight":c.store.prefix().height()}),
    )
}

#[cfg(test)]
#[path = "../../Tests/Unit/Routing/PrivateRouteRegistrationTests.rs"]
mod tests;
