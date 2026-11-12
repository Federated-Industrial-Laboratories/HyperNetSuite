// SPDX-License-Identifier: MIT
// A fresh quorum read can extend discovery without replacing immutable bootstrap trust.
use super::*;
use serde::{Deserialize, Serialize};

pub const LIMIT: usize = 4 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Certificate {
    schema: String,
    bootstrap: String,
    epochs: Vec<crate::authority_epoch::archive::Activated>,
    request: String,
    challenge: String,
    node: String,
    certificate: String,
    result: String,
    ancestry: Vec<String>,
}
/// This evidence permits offline preparation only; admission still needs fresh owned proofs.
pub fn verify(bootstrap: &Verified, bytes: &[u8], now: u64) -> Result<u64> {
    ensure!(
        bytes.len() <= LIMIT && bootstrap.fully_accepted(),
        "invalid policy certificate bounds"
    );
    let certificate: Certificate = serde_json::from_slice(bytes)?;
    ensure!(
        matches!(
            certificate.schema.as_str(),
            "HyperNetDiscoveryPolicy/1" | "HyperNetNativeAdmissionProof/1"
        ) && certificate.bootstrap == hex::encode(bootstrap.file_digest())
            && certificate.ancestry.len() <= 128,
        "policy certificate bootstrap or schema differs"
    );
    let descriptor =
        crate::authority_epoch::archive::resolve(bootstrap.descriptor(), &certificate.epochs)?
            .descriptor;
    let decode = |value: &str| -> Result<Vec<u8>> {
        ensure!(
            value.len() <= wire::MAXIMUM * 2,
            "policy proof item exceeds its bound"
        );
        Ok(hex::decode(value)?)
    };
    let request = decode(&certificate.request)?;
    let challenge = decode(&certificate.challenge)?;
    let node = decode(&certificate.node)?;
    let quorum = decode(&certificate.certificate)?;
    let result = decode(&certificate.result)?;
    let ancestry = certificate
        .ancestry
        .iter()
        .map(|v| decode(v))
        .collect::<Result<Vec<_>>>()?;
    let mut policy = None;
    let verified = crate::authority_read::verify_response(
        &descriptor,
        &request,
        &challenge,
        crate::authority_read::Response {
            node: &node,
            certificate: &quorum,
            result: &result,
            ancestry: &ancestry,
        },
        |request, result, _| {
            if let crate::authority_read::Query::Admission {
                policy: policy_id,
                claim,
            } = request.query
            {
                let d = crate::authority_admission::Disclosure::parse(
                    &wire::decode(&result.value)?,
                    descriptor.scope().network,
                    descriptor.scope().incarnation,
                    request.requester,
                    policy_id,
                    claim,
                    now,
                )?;
                policy = Some(
                    d.records
                        .iter()
                        .find(|bytes| {
                            wire::decode(bytes).is_ok_and(|v| {
                                v.list(32).is_ok_and(|f| f[0].uint().ok() == Some(100))
                            })
                        })
                        .context("admission proof omits network policy")?
                        .clone(),
                );
                return Ok(d.versions);
            }
            ensure!(
                matches!(request.query, crate::authority_read::Query::PolicyContext),
                "discovery certificate is not a policy read"
            );
            let (p, _, refs) = super::discovery::pair_from_value(
                &wire::decode(&result.value)?,
                descriptor.scope().network,
                descriptor.scope().incarnation,
            )?;
            policy = Some(p);
            Ok(refs)
        },
    )?;
    let latest = now
        .checked_add(crate::authority_governance::UNCERTAINTY_MS)
        .context("policy clock overflow")?;
    ensure!(
        verified.result.disposition == Disposition::Permit
            && verified.statement.evaluated_at_ms <= latest
            && latest < verified.statement.expires_at_ms
            && now >= bootstrap.summary.bootstrap_time_ms,
        "policy certificate is expired, future or refused; fetch a fresh certificate"
    );
    let p = policy.context("certified policy absent")?;
    let value = wire::decode(&p)?;
    let fields = value.array(17)?;
    ensure!(
        fields[1] == V::Uint(2) && fields[4].uint()? > 1,
        "bootstrap discovery requires an explicit persistent policy successor"
    );
    let genesis = Governance::parse(
        descriptor.scope().network,
        descriptor.scope().incarnation,
        bootstrap.governance_records(),
    )?;
    Governance::record_versions(
        descriptor.scope().network,
        descriptor.scope().incarnation,
        std::slice::from_ref(&p),
    )?;
    let roots = crate::authority_governance::policy_roots(fields)?;
    ensure!(
        roots.iter().any(|(_, r)| r.is_some()),
        "policy has no persistent root adoption"
    );
    for (id, exact) in roots {
        let bytes = genesis.record_bytes(102, id)?;
        let original = Governance::record_versions(
            descriptor.scope().network,
            descriptor.scope().incarnation,
            &[bytes.to_vec()],
        )?
        .remove(0);
        ensure!(
            exact.as_ref() == Some(&original)
                || exact.is_none()
                    && genesis.grant_validity(id)?.1 == crate::trust_validity::End::UntilWithdrawn,
            "discovery policy must retain exact persistent bootstrap roots"
        );
    }
    let relay =
        V::Bytes(crate::trust_bootstrap::hex32(&bootstrap.summary.route.relay_domain)?.to_vec());
    ensure!(
        fields[9].list(16)?.contains(&relay)
            && fields[8].uint()? <= bootstrap.summary.route.assurance.number(),
        "current policy no longer allows this bootstrap route"
    );
    fields[4].uint()
}

pub(super) fn encode(
    bootstrap: &Verified,
    store: &Store,
    exchange: &crate::authority_inspection::read_client::Exchange,
    now: u64,
) -> Result<Vec<u8>> {
    let certificate = Certificate {
        schema: "HyperNetDiscoveryPolicy/1".into(),
        bootstrap: hex::encode(bootstrap.file_digest()),
        epochs: store.epoch_archive()?,
        request: hex::encode(&exchange.request),
        challenge: hex::encode(&exchange.challenge),
        node: hex::encode(&exchange.reply.node),
        certificate: hex::encode(&exchange.reply.certificate),
        result: hex::encode(&exchange.reply.result),
        ancestry: exchange.evidence.nodes.iter().map(hex::encode).collect(),
    };
    let bytes = serde_json::to_vec(&certificate)?;
    verify(bootstrap, &bytes, now)?;
    Ok(bytes)
}

#[cfg(test)]
#[path = "../../../Tests/Unit/Authority/Governance/AuthorityPolicyCertificateTests.rs"]
mod tests;
