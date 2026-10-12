// SPDX-License-Identifier: MIT
// The admission endpoint prepares public state; separate owner keys approve the exact successor offline.
use super::*;
use ed25519_dalek::Signer;

fn package(tag: &str, bootstrap: &Verified, fields: Vec<V>) -> Result<Vec<u8>> {
    let s = bootstrap.descriptor().scope();
    let mut out = vec![
        V::Uint(200),
        V::Uint(1),
        V::Text(tag.into()),
        b(&s.network),
        b(&s.incarnation),
    ];
    out.extend(fields);
    wire::encode(&a(out))
}
fn unpack(bytes: &[u8], tag: &str, bootstrap: &Verified, length: usize) -> Result<Vec<V>> {
    let s = bootstrap.descriptor().scope();
    let value = wire::decode(bytes)?;
    let fields = value.array(length)?;
    ensure!(
        fields[0].uint()? == 200
            && fields[1].uint()? == 1
            && fields[2].text()? == tag
            && fields[3].fixed::<32>()? == s.network
            && fields[4].fixed::<32>()? == s.incarnation,
        "recipient rotation package context differs"
    );
    Ok(fields.to_vec())
}
fn countersign(payload: &[u8], keys: &[&SigningKey]) -> Result<Vec<u8>> {
    let mut signatures = keys
        .iter()
        .map(|key| {
            let public = key.verifying_key().to_bytes();
            (
                public,
                key.sign(&wire::signature_message(payload, &public))
                    .to_bytes(),
            )
        })
        .collect::<Vec<_>>();
    signatures.sort_by_key(|(key, _)| *key);
    ensure!(
        signatures.windows(2).all(|w| w[0].0 < w[1].0),
        "recipient rotation must use distinct signing keys"
    );
    wire::encode(&a(vec![
        V::Uint(0),
        V::Uint(1),
        b(payload),
        a(signatures
            .iter()
            .map(|(key, signature)| a(vec![b(key), b(signature)]))
            .collect()),
    ]))
}
pub(super) fn run(command: Command) -> Result<()> {
    match command {
        Command::RootPrepare {
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
                "complete the pending authority request before preparing root rotation"
            );
            let prior = c.context(107, member, Some(grant))?;
            let s = c.bootstrap.descriptor().scope();
            let root =
                identity::Root::parse(&identity::payload(&prior)?, s.network, s.incarnation)?;
            let custody = read(&custody)?;
            let policy = identity::Custody::parse(&custody, s.network, s.incarnation)?;
            ensure!(
                policy.member == member
                    && policy.digest == root.recovery_policy
                    && new_key != root.key
                    && !identity::revoked(&c.cache()?.state, &root.reference),
                "root proposal changes accepted custody or uses a revoked root"
            );
            let generation = root
                .reference
                .generation
                .checked_add(1)
                .context("recipient root generation exhausted")?;
            let payload = wire::encode(&a(vec![
                V::Uint(107),
                V::Uint(1),
                b(&s.network),
                b(&s.incarnation),
                V::Uint(generation),
                b(&root.reference.digest),
                b(&member),
                b(&new_key),
                b(&root.recovery_policy),
                c.snapshot(&[])?.array(2)?[0].clone(),
            ]))?;
            identity::Root::parse(&payload, s.network, s.incarnation)?;
            files::write_new(
                &output,
                &package(
                    "RecipientRootProposal",
                    &c.bootstrap,
                    vec![b(&prior.bytes), b(&payload), b(&custody)],
                )?,
            )?;
            crate::print_value(
                &json!({"status":"RecipientRootProposed","member":hex::encode(member),"previousRootDigest":hex::encode(root.reference.digest),"proposedRootDigest":hex::encode(wire::digest(&payload)),"generation":generation}),
            )
        }
        Command::RootSign {
            local,
            prior_vault,
            prior_age_key,
            proposal,
            member_key,
            trust_context,
            output,
        } => {
            let verified = super::super::bootstrap(&local.location)?;
            let s = verified.descriptor().scope();
            let fields = unpack(&read(&proposal)?, "RecipientRootProposal", &verified, 8)?;
            let old_record = record(fields[5].bytes()?, &verified)?;
            let old =
                identity::Root::parse(&identity::payload(&old_record)?, s.network, s.incarnation)?;
            identity::signer(&old_record, old.key)?;
            let new = identity::Root::parse(fields[6].bytes()?, s.network, s.incarnation)?;
            let policy = identity::Custody::parse(fields[7].bytes()?, s.network, s.incarnation)?;
            ensure!(
                policy.member == old.member && policy.digest == old.recovery_policy,
                "root proposal custody differs"
            );
            let new_vault = vault(&local.vault, &local.location)?;
            let prior_vault = vault(
                &VaultArgs {
                    vault: prior_vault,
                    age_key: prior_age_key,
                },
                &local.location,
            )?;
            let prior_key = prior_vault.root_signer(old.member)?;
            let new_key = new_vault.root_signer(new.member)?;
            ensure!(
                prior_key.verifying_key().to_bytes() == old.key
                    && new_key.verifying_key().to_bytes() == new.key,
                "root proposal differs from locally held owner keys"
            );
            let root = countersign(fields[6].bytes()?, &[&prior_key, &new_key])?;
            identity::verify_successor(&old, &new, &root, None, None, s.network, s.incarnation)?;
            let member_key = super::super::domain_cli::signer(&member_key)?;
            let operation: Digest = rand::random();
            let acceptance = signed(
                121,
                0,
                None,
                vec![
                    b(&operation),
                    b(&new.member),
                    reference(&old.reference),
                    reference(&new.reference),
                    V::Null,
                    b(&id(&trust_context)?),
                ],
                &verified,
                &member_key,
            )?;
            let command = identity::Command::Root {
                root: record(&root, &verified)?,
                acceptance,
                custody: fields[7].bytes()?.to_vec(),
                recovery: None,
            };
            files::write_new(
                &output,
                &package("RecipientRootSubmission", &verified, vec![command.value()])?,
            )?;
            crate::print_value(
                &json!({"status":"RecipientRootSigned","member":hex::encode(new.member),"previousRootDigest":hex::encode(old.reference.digest),"rootDigest":hex::encode(new.reference.digest)}),
            )
        }
        Command::RootSubmit {
            online,
            capability,
            submission,
            output,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let fields = unpack(
                &read(&submission)?,
                "RecipientRootSubmission",
                &c.bootstrap,
                6,
            )?;
            let s = c.bootstrap.descriptor().scope();
            let supplied = identity::Command::parse(&fields[5], s.network, s.incarnation)?;
            let identity::Command::Root { root, .. } = &supplied else {
                anyhow::bail!("root submission does not contain a recipient root")
            };
            let expected = root.clone();
            let command = c.prepare(
                "SealedIdentityRoot",
                expected.reference.id,
                Some(grant.clone()),
                |_, _| Ok(supplied.clone()),
            )?;
            ensure!(
                command.value() == supplied.value(),
                "pending root submission differs from supplied owner approval"
            );
            let result = c.action(command, Some(grant))?;
            let actual = result.cache.state.record(107, expected.reference.id)?;
            ensure!(
                actual.bytes == expected.bytes,
                "committed root differs from exact owner approval"
            );
            emit("RecipientRootRotated", actual, &output)
        }
        _ => anyhow::bail!("not a recipient root rotation command"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn root_rotation_keeps_distinct_exact_owner_signatures() {
        let old = SigningKey::from_bytes(&[71; 32]);
        let new = SigningKey::from_bytes(&[72; 32]);
        let payload = wire::encode(&a(vec![V::Uint(200), b(&[73; 32])])).unwrap();
        let signed = countersign(&payload, &[&old, &new]).unwrap();
        let (decoded, signatures) = wire::envelope(&signed, 2).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(signatures.len(), 2);
        assert!(countersign(&payload, &[&old, &old]).is_err());
        let mut changed = signed;
        *changed.last_mut().unwrap() ^= 1;
        assert!(wire::envelope(&changed, 2).is_err());
    }
}
