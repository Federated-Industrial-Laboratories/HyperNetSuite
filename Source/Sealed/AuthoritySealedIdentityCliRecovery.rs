// SPDX-License-Identifier: MIT
// Lost-root recovery uses accepted recipient custody; network authority cannot substitute a root.
use super::rotation::{package, unpack};
use super::*;
use std::collections::BTreeMap;
struct Proposal {
    old: identity::Root,
    new: identity::Root,
    policy: identity::Custody,
    payload: Vec<u8>,
    declaration: Vec<u8>,
}
fn inspect(bytes: &[u8], boot: &Verified) -> Result<Proposal> {
    let f = unpack(bytes, "RecipientRecoveryProposal", boot, 9)?;
    let s = boot.descriptor().scope();
    let old_record = record(f[5].bytes()?, boot)?;
    let old = identity::Root::parse(&identity::payload(&old_record)?, s.network, s.incarnation)?;
    identity::signer(&old_record, old.key)?;
    let new = identity::Root::parse(f[6].bytes()?, s.network, s.incarnation)?;
    let policy = identity::Custody::parse(f[7].bytes()?, s.network, s.incarnation)?;
    let declaration = identity::Recovery::parse(f[8].bytes()?, s.network, s.incarnation)?;
    ensure!(
        old.member == new.member
            && old.reference.generation.checked_add(1) == Some(new.reference.generation)
            && new.key != old.key
            && wire::decode(f[6].bytes()?)?.array(10)?[5].fixed::<32>()? == old.reference.digest
            && policy.member == old.member
            && policy.digest == old.recovery_policy
            && new.recovery_policy == old.recovery_policy
            && declaration.member == old.member
            && declaration.prior_root == old.reference
            && declaration.replacement_root == new.reference
            && declaration.accepted_policy == policy.digest
            && new.valid_from
                == (
                    declaration.snapshot.epoch,
                    declaration.snapshot.height,
                    declaration.snapshot.state
                )
            && declaration.snapshot.references.contains(&old.reference),
        "recipient recovery proposal differs from accepted predecessor or custody"
    );
    Ok(Proposal {
        old,
        new,
        policy,
        payload: f[6].bytes()?.to_vec(),
        declaration: f[8].bytes()?.to_vec(),
    })
}
fn assemble(payload: &[u8], shares: &[Vec<u8>], policy: &identity::Custody) -> Result<Vec<u8>> {
    ensure!(
        (1..=3).contains(&shares.len()),
        "one to three independent recipient recovery shares required"
    );
    let mut signatures = BTreeMap::new();
    for bytes in shares {
        let (p, pairs) = wire::envelope(bytes, 1)?;
        ensure!(
            p == payload,
            "recipient recovery share names another exact proposal"
        );
        for (k, s) in pairs {
            ensure!(
                policy.keys.iter().any(|(_, key)| *key == k) && signatures.insert(k, s).is_none(),
                "unknown or repeated recipient recovery signer"
            );
        }
    }
    ensure!(
        signatures.len() >= policy.threshold,
        "recipient recovery threshold is not met"
    );
    wire::encode(&a(vec![
        V::Uint(0),
        V::Uint(1),
        b(payload),
        a(signatures
            .into_iter()
            .map(|(k, s)| a(vec![b(&k), b(&s)]))
            .collect()),
    ]))
}
pub(super) fn run(command: Command) -> Result<()> {
    match command {
        Command::RecoveryPrepare {
            online,
            capability,
            member,
            new_root_key,
            custody,
            output,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let member = id(&member)?;
            let new_key = id(&new_root_key)?;
            wire::valid_key(&new_key)?;
            ensure!(
                c.store.resume_ordinary()?.is_none(),
                "resolve the pending request before preparing recipient recovery"
            );
            let prior = c.context(107, member, Some(grant.clone()))?;
            let s = c.bootstrap.descriptor().scope();
            let old = identity::Root::parse(&identity::payload(&prior)?, s.network, s.incarnation)?;
            let custody = read(&custody)?;
            let policy = identity::Custody::parse(&custody, s.network, s.incarnation)?;
            ensure!(
                policy.member == member
                    && policy.digest == old.recovery_policy
                    && new_key != old.key,
                "recipient recovery policy or replacement key differs"
            );
            let cache = c.cache()?;
            let records = domain::result::merge(&c.bootstrap, &cache.records)?;
            let governance =
                crate::authority_governance::Governance::parse(s.network, s.incarnation, &records)?;
            let at = c.clock.health()?.observe()?.wall_ms;
            let cap = governance.current_capability(
                grant.id,
                &crate::authority_governance::Requirement {
                    subject: c.key.verifying_key().to_bytes(),
                    actions: &[23],
                    scope: (4, member),
                    namespace: None,
                    usage: [0, 1, 1, 1],
                    evaluated_at_ms: at,
                    expected: &[],
                },
            )?;
            let mut expected = cap.dependencies;
            expected
                .extend(identity::current_member(&governance, s.network, member, at)?.dependencies);
            expected.push(old.reference.clone());
            expected.sort_by_key(VersionRef::index);
            expected.dedup();
            let snapshot = c.snapshot(&expected)?;
            let replacement = wire::encode(&a(vec![
                V::Uint(107),
                V::Uint(1),
                b(&s.network),
                b(&s.incarnation),
                V::Uint(
                    old.reference
                        .generation
                        .checked_add(1)
                        .context("recipient root generation exhausted")?,
                ),
                b(&old.reference.digest),
                b(&member),
                b(&new_key),
                b(&old.recovery_policy),
                snapshot.array(2)?[0].clone(),
            ]))?;
            let new = identity::Root::parse(&replacement, s.network, s.incarnation)?;
            let operation: Digest = rand::random();
            let declaration = wire::encode(&a(vec![
                V::Uint(120),
                V::Uint(1),
                b(&s.network),
                b(&s.incarnation),
                V::Uint(0),
                V::Null,
                b(&operation),
                b(&member),
                reference(&old.reference),
                reference(&new.reference),
                b(&policy.digest),
                snapshot,
            ]))?;
            let bytes = package(
                "RecipientRecoveryProposal",
                &c.bootstrap,
                vec![
                    b(&prior.bytes),
                    b(&replacement),
                    b(&custody),
                    b(&declaration),
                ],
            )?;
            inspect(&bytes, &c.bootstrap)?;
            files::write_new(&output, &bytes)?;
            crate::print_value(
                &json!({"state":"RecipientRecoveryProposed","proposalDigest":hex::encode(wire::digest(&bytes)),"previousRootDigest":hex::encode(old.reference.digest),"replacementRootDigest":hex::encode(new.reference.digest),"threshold":policy.threshold}),
            )
        }
        Command::RecoveryInspect { location, proposal } => {
            let boot = super::super::bootstrap(&location)?;
            let bytes = read(&proposal)?;
            let Proposal {
                old,
                new,
                policy,
                declaration,
                ..
            } = inspect(&bytes, &boot)?;
            let s = boot.descriptor().scope();
            let r = identity::Recovery::parse(&declaration, s.network, s.incarnation)?;
            crate::print_value(
                &json!({"state":"RecipientRecoveryInspected","proposalDigest":hex::encode(wire::digest(&bytes)),"member":hex::encode(old.member),"previousRootDigest":hex::encode(old.reference.digest),"previousRootKey":hex::encode(old.key),"replacementRootDigest":hex::encode(new.reference.digest),"replacementRootKey":hex::encode(new.key),"acceptedCustodyDigest":hex::encode(policy.digest),"custodyKeys":policy.keys.iter().map(|(p,k)|json!({"principal":hex::encode(p),"key":hex::encode(k)})).collect::<Vec<_>>(),"threshold":policy.threshold,"operation":hex::encode(r.operation),"snapshotEpoch":r.snapshot.epoch,"snapshotHeight":r.snapshot.height,"networkUsed":false}),
            )
        }
        Command::RecoverySign {
            location,
            proposal,
            proposal_digest,
            custody_key,
            output,
        } => {
            let boot = super::super::bootstrap(&location)?;
            let bytes = read(&proposal)?;
            ensure!(
                wire::digest(&bytes) == id(&proposal_digest)?,
                "inspected recipient recovery proposal digest differs"
            );
            let Proposal {
                policy,
                declaration,
                ..
            } = inspect(&bytes, &boot)?;
            let key = super::super::domain_cli::signer(&custody_key)?;
            ensure!(
                policy
                    .keys
                    .iter()
                    .any(|(_, k)| *k == key.verifying_key().to_bytes()),
                "key is outside accepted recipient custody"
            );
            files::write_new(&output, &wire::sign_envelope(&declaration, &key)?)?;
            crate::print_value(
                &json!({"state":"RecipientRecoveryShare","proposalDigest":proposal_digest,"networkUsed":false}),
            )
        }
        Command::RecoveryAssemble {
            local,
            proposal,
            proposal_digest,
            share,
            member_key,
            trust_context,
            output,
            recovery_output,
        } => {
            ensure!(
                output != recovery_output,
                "submission and contact recovery output must differ"
            );
            let boot = super::super::bootstrap(&local.location)?;
            let s = boot.descriptor().scope();
            let bytes = read(&proposal)?;
            ensure!(
                wire::digest(&bytes) == id(&proposal_digest)?,
                "inspected recipient recovery proposal digest differs"
            );
            let Proposal {
                old,
                new,
                policy,
                payload,
                declaration,
            } = inspect(&bytes, &boot)?;
            let shares = share.iter().map(|p| read(p)).collect::<Result<Vec<_>>>()?;
            let recovery = assemble(&declaration, &shares, &policy)?;
            let fields = unpack(&bytes, "RecipientRecoveryProposal", &boot, 9)?;
            let replacement = vault(&local.vault, &local.location)?.root_signer(new.member)?;
            ensure!(
                replacement.verifying_key().to_bytes() == new.key,
                "replacement root differs from locally held vault"
            );
            let root = wire::sign_envelope(&payload, &replacement)?;
            identity::verify_successor(
                &old,
                &new,
                &root,
                Some(&recovery),
                Some(fields[7].bytes()?),
                s.network,
                s.incarnation,
            )?;
            let r = identity::Recovery::parse(&declaration, s.network, s.incarnation)?;
            let member_key = super::super::domain_cli::signer(&member_key)?;
            let acceptance = signed(
                121,
                0,
                None,
                vec![
                    b(&r.operation),
                    b(&new.member),
                    reference(&old.reference),
                    reference(&new.reference),
                    b(&wire::digest(&declaration)),
                    b(&id(&trust_context)?),
                ],
                &boot,
                &member_key,
            )?;
            let command = identity::Command::Root {
                root: record(&root, &boot)?,
                acceptance,
                custody: fields[7].bytes()?.to_vec(),
                recovery: Some(recovery.clone()),
            };
            let submission = package("RecipientRootSubmission", &boot, vec![command.value()])?;
            // Retrying publication preserves exactly the same already signed outputs.
            publish(&recovery_output, &recovery)?;
            publish(&output, &submission)?;
            crate::print_value(
                &json!({"state":"RecipientRecoveryReady","rootDigest":hex::encode(new.reference.digest),"recoveryDigest":hex::encode(wire::digest(&declaration)),"networkUsed":false,"next":"root-submit, then each contact uses contact-accept with the recovery and custody evidence"}),
            )
        }
        _ => anyhow::bail!("not a recipient recovery command"),
    }
}
fn publish(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.try_exists()? {
        ensure!(
            read(path)? == bytes,
            "recipient recovery output already contains different bytes"
        );
        Ok(())
    } else {
        files::write_new(path, bytes)
    }
}
#[cfg(test)]
#[path = "../../Tests/Unit/Sealed/AuthoritySealedIdentityCliRecoveryUnitTests.rs"]
mod tests;
