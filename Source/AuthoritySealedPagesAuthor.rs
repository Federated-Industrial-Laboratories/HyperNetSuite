// SPDX-License-Identifier: MIT
// Author consent fixes exact source, media, audience and storage before encrypted reviewer submission.
use super::*;
use zeroize::Zeroize;
struct PrivateFiles(BTreeMap<String, Vec<u8>>);
impl Drop for PrivateFiles {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}
pub(super) fn run(command: Command) -> Result<()> {
    match command {
        Command::Namespace {
            online,
            capability,
            namespace,
            modes,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let mut modes = modes
                .into_iter()
                .map(|m| match m {
                    Mode::HostReadable => 0,
                    Mode::Sealed => 1,
                })
                .collect::<Vec<_>>();
            modes.sort();
            ensure!(
                modes.windows(2).all(|w| w[0] < w[1]),
                "namespace modes repeat"
            );
            let result = c.domain_action(
                publication::Command::Namespace {
                    namespace: namespace.clone(),
                    modes,
                }
                .into(),
                Some(grant),
            )?;
            crate::print_value(
                &json!({"status":"NamespaceModesCommitted","namespace":namespace,"height":result.prefix.height()}),
            )
        }
        Command::Policy {
            online,
            capability,
            vault: vault_args,
            object,
            namespace,
            audience,
            hosts,
            volumes,
            copies,
            read_grant,
            output,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let read_grant = context::read_grant(&c, read_grant.as_deref(), &grant)?;
            let object = id(&object)?;
            let s = c.bootstrap.descriptor().scope();
            let (n, i) = (s.network, s.incarnation);
            let supplied = identity::signed_record(&read(&audience)?, n, i)?;
            let audience = identity::Audience::parse(&identity::payload(&supplied)?, n, i)?;
            let vault = vault(&vault_args, &c.bootstrap)?;
            context::pinned_audience(&vault, &audience)?;
            ensure!(
                audience.publisher == c.key.verifying_key().to_bytes(),
                "object policy publisher differs from author-owned audience"
            );
            if c.store.resume_ordinary()?.is_none() {
                let current =
                    context::identity_context(&mut c, &read_grant, 110, audience.reference.id)?;
                ensure!(
                    current.reference == audience.reference,
                    "author audience changed"
                );
                c.domain_action(
                    publication::Command::Context { object }.into(),
                    Some(grant.clone()),
                )?;
            }
            let placement = publication::Placement {
                hosts: ids(&hosts)?,
                volumes: ids(&volumes)?,
                backups: vec![],
                copies,
            };
            publication::Placement::parse(&placement.value())?;
            let old = c.cache()?.state.records.get(&(104, object)).cloned();
            let namespace = page::namespace_id(&namespace)?;
            let command =
                context::prepare(&c, "SealedPublicationPolicy", object, &grant, |snapshot| {
                    let generation = old.as_ref().map_or(Ok(1), |r| {
                        r.reference
                            .generation
                            .checked_add(1)
                            .context("object policy generation exhausted")
                    })?;
                    let bytes = signed(
                        104,
                        generation,
                        old.as_ref().map(|r| r.reference.digest),
                        vec![
                            b(&object),
                            b(&namespace),
                            b(&c.key.verifying_key().to_bytes()),
                            reference(&audience.reference),
                            a(vec![V::Uint(1)]),
                            V::Bool(false),
                            placement.value(),
                            snapshot.array(2)?[0].clone(),
                            V::Null,
                            snapshot.clone(),
                        ],
                        &c.bootstrap,
                        &c.key,
                    )?;
                    Ok(publication::Command::Policy {
                        policy: publication::signed_record(&bytes, n, i)?,
                    }
                    .into())
                })?;
            let result = c.domain_action(command, Some(grant))?;
            saved(
                "SealedObjectPolicyCommitted",
                result.cache.state.record(104, object)?,
                &output,
            )
        }
        Command::Submit {
            online,
            capability,
            vault: vault_args,
            policy: policy_path,
            source,
            assets,
            reviewer_binding,
            revision,
            expires_ms,
            read_grant,
            output,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let read_grant = context::read_grant(&c, read_grant.as_deref(), &grant)?;
            let policy = policy(&read(&policy_path)?, &c.bootstrap)?;
            ensure!(
                policy.publisher == c.key.verifying_key().to_bytes(),
                "submission signer is not object publisher"
            );
            context::current_policy(&mut c, &grant, &policy)?;
            let s = c.bootstrap.descriptor().scope();
            let (n, i) = (s.network, s.incarnation);
            let mut vault = vault(&vault_args, &c.bootstrap)?;
            let audience = identity::Audience::parse(
                &identity::payload(c.cache()?.state.record(110, policy.audience.id)?)?,
                n,
                i,
            )?;
            context::pinned_audience(&vault, &audience)?;
            let bytes = read(&reviewer_binding)?;
            let recipient = binding(&bytes, &c.bootstrap)?;
            context::identity_context(&mut c, &read_grant, 107, recipient.member)?;
            let current = context::identity_context(&mut c, &read_grant, 108, recipient.device)?;
            ensure!(
                current.reference == recipient.reference,
                "reviewer device binding changed"
            );
            context::identity_context(&mut c, &read_grant, 109, recipient.reference.digest)?;
            let cache = c.cache()?;
            let at = now(&c)?;
            let governance = crate::authority_governance::Governance::parse(
                n,
                i,
                &domain::result::merge(&c.bootstrap, &cache.records)?,
            )?;
            let recipient = context::reviewer(
                &mut vault,
                &cache.state,
                &governance,
                policy.object,
                at,
                &bytes,
            )?;
            let mut source = Zeroizing::new(files::read_public_single(
                &source,
                crate::markup::MAX_BYTES,
            )?);
            let mut inputs = PrivateFiles(BTreeMap::new());
            ensure!(
                assets.len() <= crypto::MAXIMUM_ASSETS,
                "too many sealed asset mappings"
            );
            let mut total = 0usize;
            for item in assets {
                let (name, path) = item
                    .split_once('=')
                    .context("asset requires AssetId=/explicit/path")?;
                ensure!(
                    !inputs.0.contains_key(name),
                    "duplicate sealed asset mapping"
                );
                let mut bytes = Zeroizing::new(files::read_public_single(
                    Path::new(path),
                    crypto::MAXIMUM_ASSET_BYTES,
                )?);
                total = total
                    .checked_add(bytes.len())
                    .context("sealed asset size overflow")?;
                ensure!(
                    total <= crypto::MAXIMUM_ASSET_BYTES,
                    "sealed assets exceed the complete publication bound"
                );
                inputs.0.insert(name.into(), std::mem::take(&mut *bytes));
            }
            let assets = data::source_assets(&source, &inputs.0)?;
            let author = publication::Author {
                object: policy.object,
                policy: policy.reference.clone(),
                grant,
                revision,
                audience: policy.audience.clone(),
                publisher: c.key.verifying_key().to_bytes(),
                source: crypto::ciphertext_digest(&source),
                assets: assets
                    .iter()
                    .map(|a| (a.id, crypto::ciphertext_digest(&a.bytes)))
                    .collect(),
                expires_ms,
            };
            let signed_author = wire::sign_envelope(&author.payload(n, i)?, &c.key)?;
            let submission = data::Submission::new(
                n,
                i,
                recipient.reference,
                signed_author,
                std::mem::take(&mut *source),
                assets,
            )?;
            submission.validate(&policy, at)?;
            let encrypted = submission.encrypt(recipient.encryption_key)?;
            files::write_new(&output, &encrypted)?;
            crate::print_value(
                &json!({"status":"SealedSubmissionEncrypted","submissionDigest":hex::encode(crypto::ciphertext_digest(&encrypted)),"reviewerDevice":hex::encode(recipient.device),"bytes":encrypted.len()}),
            )
        }
        Command::Withdraw {
            online,
            capability,
            object,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let object = id(&object)?;
            let command = if let Some(pending) = c.store.resume_ordinary()? {
                let op = domain::Operation::parse(&Intent::from_signed(pending.signed())?)?;
                ensure!(
                    matches!(
                        op.command,
                        domain::Command::SealedPublication(publication::Command::Withdraw { .. })
                    ) && op.grant.as_ref() == Some(&grant),
                    "another exact operation is pending"
                );
                if let domain::Command::SealedPublication(publication::Command::Withdraw {
                    outer,
                }) = &op.command
                {
                    let s = c.bootstrap.descriptor().scope();
                    ensure!(
                        publication::Outer::parse(
                            &c.cache()?.state.record(113, outer.id)?.bytes,
                            s.network,
                            s.incarnation
                        )?
                        .object
                            == object,
                        "pending withdrawal belongs to another object"
                    );
                }
                op.command
            } else {
                let result = c.domain_action(
                    publication::Command::Context { object }.into(),
                    Some(grant.clone()),
                )?;
                let head = publication::Head::parse(
                    &result
                        .cache
                        .state
                        .record(publication::OBJECT_HEAD, object)?
                        .payload,
                )?;
                publication::Command::Withdraw {
                    outer: head
                        .published
                        .or(head.pending)
                        .context("sealed object has no current publication")?,
                }
                .into()
            };
            let result = c.domain_action(command, Some(grant))?;
            crate::print_value(
                &json!({"status":"SealedPublicationWithdrawn","object":hex::encode(object),"height":result.prefix.height()}),
            )
        }
        _ => anyhow::bail!("not a sealed author command"),
    }
}
