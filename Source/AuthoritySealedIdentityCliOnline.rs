// SPDX-License-Identifier: MIT
// Recipient authority changes bind the exact current snapshot and explicit owner evidence.
use super::*;

fn committed(
    c: &mut Client,
    command: identity::Command,
    grant: Option<VersionRef>,
    kind: u64,
    lookup: Digest,
    output: &Path,
) -> Result<()> {
    let result = c.action(command, grant)?;
    emit(
        "RecipientRecordCommitted",
        result.cache.state.record(kind, lookup)?,
        output,
    )
}
pub(super) fn run(command: Command) -> Result<()> {
    match command {
        Command::RootRegister {
            online,
            capability,
            vault: vault_args,
            member,
            member_key,
            custody,
            trust_context,
            output,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let member = id(&member)?;
            let pending = c
                .store
                .resume_ordinary()?
                .map(|pending| domain::Operation::parse(&Intent::from_signed(pending.signed())?))
                .transpose()?;
            if pending.as_ref().is_none_or(|operation| {
                matches!(
                    operation.command,
                    domain::Command::SealedIdentity(identity::Command::Directory { .. })
                )
            }) {
                c.directory(member, &grant)?;
            }
            let trust_context = id(&trust_context)?;
            let vault = vault(&vault_args, &online.location)?;
            let root_key = vault.root_signer(member)?;
            let member_key = super::super::domain_cli::signer(&member_key)?;
            let custody = read(&custody)?;
            let s = c.bootstrap.descriptor().scope();
            let policy = identity::Custody::parse(&custody, s.network, s.incarnation)?;
            ensure!(
                policy.member == member,
                "root custody belongs to another member"
            );
            let operation: Digest = rand::random();
            let command = c.prepare(
                "SealedIdentityRoot",
                member,
                Some(grant.clone()),
                |c, snapshot| {
                    let root = signed(
                        107,
                        1,
                        None,
                        vec![
                            b(&member),
                            b(&root_key.verifying_key().to_bytes()),
                            b(&policy.digest),
                            snapshot.array(2)?[0].clone(),
                        ],
                        &c.bootstrap,
                        &root_key,
                    )?;
                    let root = record(&root, &c.bootstrap)?;
                    let acceptance = signed(
                        121,
                        0,
                        None,
                        vec![
                            b(&operation),
                            b(&member),
                            V::Null,
                            reference(&root.reference),
                            V::Null,
                            b(&trust_context),
                        ],
                        &c.bootstrap,
                        &member_key,
                    )?;
                    Ok(identity::Command::Root {
                        root,
                        acceptance,
                        custody: custody.clone(),
                        recovery: None,
                    })
                },
            )?;
            committed(&mut c, command, Some(grant), 107, member, &output)
        }
        Command::Context {
            online,
            capability,
            kind,
            lookup,
            output,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let record = c.context(kind, id(&lookup)?, Some(grant))?;
            emit("RecipientContextVerified", &record, &output)
        }
        Command::Directory {
            online,
            capability,
            member,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let member = id(&member)?;
            c.directory(member, &grant)?;
            crate::print_value(
                &json!({"status":"RecipientDirectoryVerified","member":hex::encode(member),"committedHeight":c.store.prefix().height()}),
            )
        }
        Command::AudienceSet {
            online,
            capability,
            vault: vault_args,
            audience,
            members,
            excluded,
            read_grant,
            output,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let read_grant = read_grant
                .as_deref()
                .map(|g| c.cache()?.grant(&c.bootstrap, id(g)?))
                .transpose()?
                .unwrap_or_else(|| grant.clone());
            let audience = id(&audience)?;
            let vault = vault(&vault_args, &online.location)?;
            let s = c.bootstrap.descriptor().scope();
            let (n, i) = (s.network, s.incarnation);
            let mut members = members.iter().map(|v| id(v)).collect::<Result<Vec<_>>>()?;
            members.sort();
            ensure!(
                members.windows(2).all(|w| w[0] < w[1]),
                "audience members repeat"
            );
            let mut excluded = excluded.iter().map(|v| id(v)).collect::<Result<Vec<_>>>()?;
            excluded.sort();
            ensure!(
                excluded.windows(2).all(|w| w[0] < w[1]),
                "excluded devices repeat"
            );
            let pending = c.store.resume_ordinary()?.is_some();
            let mut roots = Vec::new();
            let mut acceptances = Vec::new();
            if !pending {
                for member in members {
                    let pinned = vault.contact_root(member)?;
                    let current = c.context(107, member, Some(read_grant.clone()))?;
                    ensure!(
                        current.reference == pinned.reference,
                        "current recipient root differs from independently accepted contact"
                    );
                    let (accepted, signatures) =
                        wire::envelope(&vault.contact_acceptance(member)?, 1)?;
                    let accepted = identity::Acceptance::parse(&accepted, n, i)?;
                    ensure!(
                        signatures[0].0 == vault.trust_key()?
                            && accepted.contact == member
                            && accepted.accepted_root == pinned.reference,
                        "local contact acceptance differs"
                    );
                    let operation: Digest = rand::random();
                    // Local trust evidence is input to separate author consent, never its substitute.
                    acceptances.push(signed(
                        121,
                        0,
                        None,
                        vec![
                            b(&operation),
                            b(&c.key.verifying_key().to_bytes()),
                            V::Null,
                            reference(&pinned.reference),
                            V::Null,
                            b(&accepted.trust_context),
                        ],
                        &c.bootstrap,
                        &c.key,
                    )?);
                    roots.push(pinned.reference);
                }
            }
            let old = c.cache()?.state.records.get(&(110, audience)).cloned();
            let command = c.prepare(
                "SealedIdentityAudience",
                audience,
                Some(grant.clone()),
                |c, snapshot| {
                    let generation = old.as_ref().map_or(Ok(1), |r| {
                        r.reference
                            .generation
                            .checked_add(1)
                            .context("audience generation exhausted")
                    })?;
                    let bytes = signed(
                        110,
                        generation,
                        old.as_ref().map(|r| r.reference.digest),
                        vec![
                            b(&audience),
                            b(&c.key.verifying_key().to_bytes()),
                            a(roots.iter().map(reference).collect()),
                            a(excluded.iter().map(|v| b(v)).collect()),
                            V::Null,
                            V::Bool(false),
                            snapshot.clone(),
                        ],
                        &c.bootstrap,
                        &c.key,
                    )?;
                    Ok(identity::Command::Audience {
                        audience: record(&bytes, &c.bootstrap)?,
                        acceptances: acceptances.clone(),
                    })
                },
            )?;
            committed(&mut c, command, Some(grant), 110, audience, &output)
        }
        Command::Freeze {
            online,
            capability,
            audience,
            publication,
            revision,
            encryption_generation,
            scope: selected_scope,
            read_grant,
            output,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let read_grant = read_grant
                .as_deref()
                .map(|g| c.cache()?.grant(&c.bootstrap, id(g)?))
                .transpose()?
                .unwrap_or_else(|| grant.clone());
            let publication = id(&publication)?;
            let supplied = record(&read(&audience)?, &c.bootstrap)?;
            let s = c.bootstrap.descriptor().scope();
            let scope = scope(&selected_scope, s.network)?;
            let audience = identity::Audience::parse(
                &identity::payload(&supplied)?,
                s.network,
                s.incarnation,
            )?;
            if c.store.resume_ordinary()?.is_none() {
                let current = c.context(110, audience.reference.id, Some(read_grant.clone()))?;
                ensure!(
                    current.reference == audience.reference,
                    "audience changed before roster selection"
                );
                for root in &audience.allowed_roots {
                    c.directory(root.id, &read_grant)?;
                }
            }
            let command = c.prepare(
                "SealedIdentityFreeze",
                publication,
                Some(grant.clone()),
                |c, snapshot| {
                    let cache = c.cache()?;
                    let scope_context = c.bootstrap.descriptor().scope();
                    let governance = crate::authority_governance::Governance::parse(
                        scope_context.network,
                        scope_context.incarnation,
                        &domain::result::merge(&c.bootstrap, &cache.records)?,
                    )?;
                    let identity::CurrentRoster { roots, devices, .. } = identity::roster(
                        &cache.state,
                        &governance,
                        &audience,
                        c.clock.health()?.observe()?.wall_ms,
                        scope,
                    )?;
                    let bytes = signed(
                        111,
                        1,
                        None,
                        vec![
                            b(&publication),
                            V::Uint(revision),
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
                        roster: record(&bytes, &c.bootstrap)?,
                        scope,
                    })
                },
            )?;
            committed(&mut c, command, Some(grant), 111, publication, &output)
        }
        Command::Revoke {
            online,
            capability,
            target,
            output,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let target = record(&read(&target)?, &c.bootstrap)?;
            ensure!(
                target.reference.kind == 109,
                "network authority may withdraw admission only"
            );
            revoke(&mut c, Some(grant), target, &output)
        }
        Command::RootRevoke {
            local,
            socket,
            member,
            target,
            output,
        } => {
            let vault = vault(&local.vault, &local.location)?;
            let key = vault.root_signer(id(&member)?)?;
            let mut c = Client::owned(&local.location, &socket, key)?;
            let target = record(&read(&target)?, &c.bootstrap)?;
            ensure!(
                matches!(target.reference.kind, 107 | 108),
                "root ownership revokes roots or bindings only"
            );
            revoke(&mut c, None, target, &output)
        }
        _ => anyhow::bail!("not an online recipient command"),
    }
}
fn revoke(
    c: &mut Client,
    grant: Option<VersionRef>,
    target: domain::Record,
    output: &Path,
) -> Result<()> {
    if c.store.resume_ordinary()?.is_none() {
        let current = c.context(target.reference.kind, target.reference.id, grant.clone())?;
        ensure!(
            current.reference == target.reference,
            "revocation target changed"
        );
    }
    let lookup = target.reference.digest;
    let command = c.prepare(
        "SealedIdentityRevoke",
        lookup,
        grant.clone(),
        |c, snapshot| {
            let bytes = signed(
                158,
                1,
                None,
                vec![
                    reference(&target.reference),
                    b(&c.key.verifying_key().to_bytes()),
                    snapshot.clone(),
                ],
                &c.bootstrap,
                &c.key,
            )?;
            Ok(identity::Command::Revoke {
                revocation: record(&bytes, &c.bootstrap)?,
            })
        },
    )?;
    committed(c, command, grant, 158, lookup, output)
}
