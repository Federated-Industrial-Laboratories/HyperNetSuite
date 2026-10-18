// SPDX-License-Identifier: MIT
// Finalisers approve exact inspected input, generate fresh encryption and resume only retained ciphertext.
use super::*;
use attempt::Attempt;
pub(super) fn run(command: Command) -> Result<()> {
    match command {
        Command::Finalise {
            online,
            capability,
            vault: vault_args,
            binding: binding_path,
            policy: policy_path,
            submission,
            inspected_digest,
            approve,
            namespace,
            publication: publication_id,
            encryption_generation,
            failure_domains,
            expires_ms,
            attempt_directory,
        } => {
            ensure!(approve, "explicit reviewer approval is required");
            ensure!(
                !attempt_directory.try_exists()?,
                "sealed attempt already exists; resume pages sealed publish"
            );
            let encrypted = files::read_public_single(&submission, crypto::MAXIMUM_CIPHERTEXT)?;
            let inspected = id(&inspected_digest)?;
            ensure!(
                crypto::ciphertext_digest(&encrypted) == inspected,
                "submission differs from explicitly inspected encrypted bytes"
            );
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let vault = vault(&vault_args, &c.bootstrap)?;
            let device = binding(&read(&binding_path)?, &c.bootstrap)?;
            let key = context::own_device(&vault, &device)?;
            let policy = policy(&read(&policy_path)?, &c.bootstrap)?;
            let s = c.bootstrap.descriptor().scope();
            let (n, i) = (s.network, s.incarnation);
            let submitted = data::Submission::open(&key, &encrypted, &device.reference, n, i)?;
            let author = submitted.validate(&policy, now(&c)?)?;
            ensure!(
                policy.namespace == page::namespace_id(&namespace)?,
                "review namespace differs from author policy"
            );
            let publication = id(&publication_id)?;
            if let Some(pending) = c.store.resume_ordinary()? {
                let operation = domain::Operation::parse(&Intent::from_signed(pending.signed())?)?;
                ensure!(
                    operation.grant.as_ref() == Some(&grant),
                    "another reviewer grant has a pending request"
                );
                let allowed = match &operation.command {
                    domain::Command::SealedIdentity(identity::Command::Freeze {
                        roster,
                        scope,
                    }) => roster.reference.id == publication && *scope == (2, policy.object),
                    domain::Command::SealedPublication(publication::Command::Prepare {
                        object,
                        roster,
                        author_grant,
                        namespace: old,
                    }) => {
                        *object == policy.object
                            && roster.id == publication
                            && *author_grant == author.grant
                            && *old == namespace
                    }
                    domain::Command::SealedPublication(publication::Command::Context {
                        object,
                    }) => *object == policy.object,
                    _ => false,
                };
                ensure!(
                    allowed,
                    "another exact operation is pending before sealed finalisation"
                );
                c.domain_action(operation.command, operation.grant)?;
            }
            if c.store.resume_ordinary()?.is_none() {
                context::current_policy(&mut c, &grant, &policy)?;
            }
            let cache = c.cache()?;
            let audience = identity::Audience::parse(
                &identity::payload(cache.state.record(110, policy.audience.id)?)?,
                n,
                i,
            )?;
            ensure!(
                audience.reference == policy.audience,
                "review audience changed"
            );
            context::pinned_audience(&vault, &audience)?;
            let retained = c.cache()?.state.records.get(&(111, publication)).cloned();
            let frozen = if let Some(retained) = retained {
                retained
            } else {
                let command = context::prepare(
                    &c,
                    "SealedIdentityFreeze",
                    publication,
                    &grant,
                    |snapshot| {
                        let cache = c.cache()?;
                        let governance = crate::authority_governance::Governance::parse(
                            n,
                            i,
                            &domain::result::merge(&c.bootstrap, &cache.records)?,
                        )?;
                        let identity::CurrentRoster { roots, devices, .. } = identity::roster(
                            &cache.state,
                            &governance,
                            &audience,
                            now(&c)?,
                            (2, policy.object),
                        )?;
                        let bytes = signed(
                            111,
                            1,
                            None,
                            vec![
                                b(&publication),
                                V::Uint(author.revision),
                                V::Uint(encryption_generation),
                                reference(&audience.reference),
                                a(roots.iter().map(|v| b(v)).collect()),
                                a(devices
                                    .iter()
                                    .map(|(r, d, a_)| a(vec![b(r), b(d), b(a_)]))
                                    .collect()),
                                snapshot.clone(),
                            ],
                            &c.bootstrap,
                            &c.key,
                        )?;
                        Ok(identity::Command::Freeze {
                            roster: identity::signed_record(&bytes, n, i)?,
                            scope: (2, policy.object),
                        }
                        .into())
                    },
                )?;
                let result = c.domain_action(command, Some(grant.clone()))?;
                result.cache.state.record(111, publication)?.clone()
            };
            let roster = identity::Roster::parse(&identity::payload(&frozen)?, n, i)?;
            ensure!(
                roster.publication == publication
                    && roster.revision == author.revision
                    && roster.encryption_generation == encryption_generation
                    && roster.audience == policy.audience,
                "retained roster differs from exact review request"
            );
            identity::signer(&frozen, c.key.verifying_key().to_bytes())?;
            c.domain_action(
                publication::Command::Prepare {
                    object: policy.object,
                    roster: frozen.reference.clone(),
                    author_grant: author.grant.clone(),
                    namespace: namespace.clone(),
                }
                .into(),
                Some(grant.clone()),
            )?;
            let first = context::snapshot(&c, &[])?;
            let build = |snapshot: &V| {
                build(
                    &c,
                    &encrypted,
                    &key,
                    &device.reference,
                    &policy,
                    &roster,
                    &namespace,
                    failure_domains,
                    expires_ms,
                    snapshot,
                )
            };
            let (preview, _) = build(&first)?;
            let refs = context::probe(&c, preview.clone().into(), &grant, &first)?;
            let (command, ciphertext) = build(&context::snapshot(&c, &refs)?)?;
            let attempt = Attempt::create(
                &attempt_directory,
                &c,
                device.device,
                &key,
                inspected,
                &grant,
                &command,
                ciphertext,
            )?;
            let outer = attempt.outer()?;
            crate::print_value(
                &json!({"status":"SealedPublicationFinalised","publication":hex::encode(outer.publication),"object":hex::encode(outer.object),"revision":outer.revision,"encryptionGeneration":outer.encryption_generation,"outerDigest":hex::encode(outer.reference.digest),"ciphertextDigest":hex::encode(outer.ciphertext),"bytes":outer.bytes,"attemptDirectory":attempt_directory}),
            )
        }
        Command::Publish {
            online,
            capability,
            vault: vault_args,
            device,
            attempt_directory,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let vault = vault(&vault_args, &c.bootstrap)?;
            let device = id(&device)?;
            let key = vault.device_identity(device)?;
            let attempt = Attempt::open(&attempt_directory, &c, device, &key)?;
            ensure!(
                attempt.grant()? == grant,
                "publication retry changes exact finaliser grant"
            );
            let outer = attempt.outer()?;
            if let Some(pending) = c.store.resume_ordinary()? {
                let operation = domain::Operation::parse(&Intent::from_signed(pending.signed())?)?;
                if matches!(
                    &operation.command,
                    domain::Command::SealedPublication(publication::Command::Stage { .. })
                ) {
                    ensure!(
                        operation.command.value()
                            == domain::Command::from(attempt.command()?).value()
                            && operation.grant.as_ref() == Some(&grant),
                        "pending staging differs from retained encrypted attempt"
                    );
                    c.domain_action(operation.command, operation.grant)?;
                }
            }
            let mut cache = c.cache()?;
            if let Some(existing) = cache.state.records.get(&(113, outer.publication)) {
                ensure!(
                    existing.reference == outer.reference,
                    "publication identity already holds another exact ciphertext"
                );
            } else {
                c.domain_action(attempt.command()?.into(), Some(grant.clone()))?;
                cache = c.cache()?;
            }
            let state = publication::PublicationState::parse(
                &cache
                    .state
                    .record(publication::PUBLICATION_STATE, outer.publication)?
                    .payload,
            )?;
            ensure!(
                state.outer == outer.reference && state.status < 2,
                "sealed publication was withdrawn or replaced"
            );
            if state.status == 0 {
                let commit_pending = if let Some(pending) = c.store.resume_ordinary()? {
                    let op = domain::Operation::parse(&Intent::from_signed(pending.signed())?)?;
                    matches!(op.command,domain::Command::SealedPublication(publication::Command::Commit{outer:ref expected}) if *expected==outer.reference)
                        && op.grant.as_ref() == Some(&grant)
                } else {
                    false
                };
                if !commit_pending {
                    content_cli::upload_source(
                        &mut c,
                        &grant,
                        &state.placement,
                        attempt.ciphertext(),
                    )?;
                }
                c.domain_action(
                    publication::Command::Commit {
                        outer: outer.reference.clone(),
                    }
                    .into(),
                    Some(grant),
                )?;
            }
            crate::print_value(
                &json!({"status":"SealedPublicationCommitted","publication":hex::encode(outer.publication),"object":hex::encode(outer.object),"revision":outer.revision,"outerDigest":hex::encode(outer.reference.digest),"placement":{"id":hex::encode(state.placement.id),"generation":state.placement.generation,"digest":hex::encode(state.placement.digest)}}),
            )
        }
        _ => anyhow::bail!("not a sealed finalisation command"),
    }
}
#[allow(clippy::too_many_arguments)]
fn build(
    c: &Client,
    encrypted: &[u8],
    key: &age::x25519::Identity,
    device: &VersionRef,
    policy: &publication::ObjectPolicy,
    roster: &identity::Roster,
    namespace: &str,
    failure_domains: u64,
    expires_ms: u64,
    snapshot: &V,
) -> Result<(publication::Command, Vec<u8>)> {
    let s = c.bootstrap.descriptor().scope();
    let (n, i) = (s.network, s.incarnation);
    let submitted = data::Submission::open(key, encrypted, device, n, i)?;
    let author = submitted.validate(policy, now(c)?)?;
    let inner = data::inner(&submitted, roster, &domain::snapshot(snapshot)?, &c.key)?;
    let container = submitted.into_container(inner)?;
    let cache = c.cache()?;
    let mut recipients = Vec::new();
    for (root, digest, admission) in &roster.devices {
        let r = cache
            .state
            .records
            .values()
            .find(|r| r.reference.kind == 108 && r.reference.digest == *digest)
            .context("frozen recipient binding is absent")?;
        let device = identity::Binding::parse(&identity::payload(r)?, n, i)?;
        ensure!(
            device.root.digest == *root
                && cache.state.record(109, *digest)?.reference.digest == *admission,
            "frozen recipient evidence changed"
        );
        recipients.push(crypto::recipient_from_key(device.encryption_key)?);
    }
    let ciphertext = crypto::seal(&container, &recipients, |content| {
        data::verify_approval(content, policy, now(c)?)?;
        Ok(())
    })?;
    let mut consents = policy
        .placement
        .hosts
        .iter()
        .map(|id| {
            let r = cache.state.record(147, *id)?;
            let host = page::Host::parse(&r.payload, n, i)?;
            Ok(wire::digest(&host.profile.envelope))
        })
        .collect::<Result<Vec<_>>>()?;
    consents.sort();
    let bytes = signed(
        113,
        1,
        None,
        vec![
            b(&roster.publication),
            b(&policy.object),
            V::Uint(author.revision),
            V::Uint(roster.encryption_generation),
            reference(&policy.audience),
            b(&roster.reference.digest),
            b(&crypto::ciphertext_digest(&ciphertext)),
            V::Uint(ciphertext.len() as u64),
            policy.placement.value(),
            a(consents.iter().map(|v| b(v)).collect()),
            snapshot.array(2)?[0].clone(),
            b(&container.context.inner_approval_digest),
            snapshot.clone(),
        ],
        &c.bootstrap,
        &c.key,
    )?;
    let outer = publication::Outer::parse(&bytes, n, i)?;
    data::verify_container(&container, &outer, policy, now(c)?)?;
    Ok((
        publication::Command::Stage {
            outer: publication::signed_record(&bytes, n, i)?,
            policy: policy.reference.clone(),
            author_grant: author.grant,
            namespace: namespace.into(),
            failure_domains,
            expires_ms,
        },
        ciphertext,
    ))
}
