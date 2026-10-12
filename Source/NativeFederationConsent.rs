// SPDX-License-Identifier: MIT
// Independent pins and exact signed consent precede all bilateral service and publication rights.
use super::*;
use cli::{BridgeCommand, TreatyCommand, TrustCommand};
pub(super) fn pinned(path: &Path, expected: &str) -> Result<(Vec<u8>, Verified)> {
    use sha2::{Digest as _, Sha256};
    let bytes = files::read_public_single(path, wire::MAXIMUM)?;
    ensure!(
        Sha256::digest(&bytes).as_slice() == id(expected)?,
        "foreign bootstrap differs from independently supplied file SHA256"
    );
    let verified = trust_bootstrap::inspect(&bytes, true)?;
    ensure!(
        verified.fully_accepted(),
        "foreign bootstrap is not fully accepted"
    );
    Ok((bytes, verified))
}
fn identity_summary(identity: &fed::NetworkIdentity) -> serde_json::Value {
    json!({"network":hex::encode(identity.network),"incarnation":hex::encode(identity.incarnation),
        "bootstrapFileSha256":hex::encode(identity.file_digest),"bootstrapRecordDigest":hex::encode(identity.fingerprint)})
}
fn accepted_identity(bootstrap: Vec<u8>, identity: fed::NetworkIdentity) -> Action {
    Action::TrustAccept {
        bootstrap,
        identity,
    }
}
pub(super) fn treaty_file(path: &Path) -> Result<fed::Treaty> {
    fed::Treaty::parse(&wire::decode(&files::read_public_single(
        path,
        wire::MAXIMUM,
    )?)?)
}
fn trust_id(identity: &fed::NetworkIdentity) -> Digest {
    accepted_identity(vec![], identity.clone()).resource()
}
fn treaty_summary(t: &fed::Treaty) -> Result<()> {
    crate::print_value(
        &json!({"status":"FederationTreaty","currentAuthority":false,"agreement":hex::encode(t.id),
        "treatyDigest":hex::encode(t.digest()?),"source":identity_summary(&t.source),"destination":identity_summary(&t.destination),
        "sourceBridge":hex::encode(t.source_bridge),"destinationBridge":hex::encode(t.destination_bridge),
        "sourceNamespace":t.source_namespace,"destinationNamespace":t.destination_namespace,
        "mediaProfiles":t.media_profiles,"sourceHosts":t.source_hosts.iter().map(hex::encode).collect::<Vec<_>>(),
        "destinationHosts":t.destination_hosts.iter().map(hex::encode).collect::<Vec<_>>(),"mediaBytes":t.media_bytes,
        "copies":t.copies,"expiresMs":t.expires_ms}),
    )
}
pub(super) fn trust(command: TrustCommand) -> Result<()> {
    match command {
        TrustCommand::Inspect {
            foreign_bootstrap,
            foreign_bootstrap_digest,
        } => {
            let (_, verified) = pinned(&foreign_bootstrap, &foreign_bootstrap_digest)?;
            crate::print_value(
                &json!({"status":"ForeignBootstrapVerified","currentAuthority":false,
                "identity":identity_summary(&fed::NetworkIdentity::verified(&verified))}),
            )
        }
        TrustCommand::Accept {
            access,
            foreign_bootstrap,
            foreign_bootstrap_digest,
            foreign_network,
            foreign_incarnation,
            foreign_fingerprint,
        } => {
            let (bytes, verified) = pinned(&foreign_bootstrap, &foreign_bootstrap_digest)?;
            let identity = fed::NetworkIdentity::verified(&verified);
            ensure!(
                identity.network == id(&foreign_network)?
                    && identity.incarnation == id(&foreign_incarnation)?
                    && identity.fingerprint == id(&foreign_fingerprint)?,
                "foreign bootstrap differs from independently supplied identity pins"
            );
            let command = accepted_identity(bytes, identity);
            let (mut c, grant) = connection::access(access)?;
            if let Some((r, _)) = c.resume(|p| p.value() == command.value())? {
                return summary(&r);
            }
            c.context(22, command.resource(), None, &grant)?;
            summary(&c.action(command, Some(grant), Resolved::default())?.0)
        }
        TrustCommand::Get {
            access,
            trust,
            retained_output,
        } => {
            let (mut c, grant) = connection::maintenance(access)?;
            let trust = id(&trust)?;
            let result = c
                .action(Action::TrustGet { trust }, grant, Resolved::default())?
                .0;
            if let Some(path) = retained_output {
                let body = result.value.array(5)?[4].array(4)?;
                let scope = result.prefix.scope();
                let records = body[1]
                    .list(fed::MAXIMUM_CONTEXT_RECORDS)?
                    .iter()
                    .map(|v| domain::Record::parse(v.bytes()?, scope.network, scope.incarnation))
                    .collect::<Result<Vec<_>>>()?;
                let record = records
                    .iter()
                    .find(|r| r.reference.kind == 157 && r.reference.id == trust)
                    .context("certified trust result omits the exact foreign floor")?;
                let floor = fed::ForeignFloor::parse(&record.payload)?;
                ensure!(floor.trust == trust, "foreign floor identity differs");
                files::write_new(&path, &serde_json::to_vec(&floor.retained)?)?;
            }
            summary(&result)
        }
        TrustCommand::Withdraw { access, trust } => {
            let (mut c, grant) = connection::maintenance(access)?;
            let id = id(&trust)?;
            if let Some((r, _)) =
                c.resume(|p| matches!(p,Action::TrustWithdraw{trust}if trust.id==id))?
            {
                return summary(&r);
            }
            let r = c
                .action(
                    Action::TrustGet { trust: id },
                    grant.clone(),
                    Resolved::default(),
                )?
                .0;
            let trust = r.cache.state.record(150, id)?.reference.clone();
            summary(
                &c.action(Action::TrustWithdraw { trust }, grant, Resolved::default())?
                    .0,
            )
        }
        TrustCommand::Seal {
            access,
            trust,
            terminal,
            history,
        } => {
            let evidence = read(&terminal)?;
            let history = read(&history)?;
            let (mut c, grant) = connection::access(access)?;
            let id = id(&trust)?;
            if let Some((r,_))=c.resume(|p|matches!(p,Action::ForeignSeal{trust,evidence:e,history:h,..}if trust.id==id && *e==evidence && *h==history))? {return summary(&r)}
            let r = c
                .action(
                    Action::TrustGet { trust: id },
                    Some(grant.clone()),
                    Resolved::default(),
                )?
                .0;
            summary(
                &c.action(
                    Action::ForeignSeal {
                        trust: r.cache.state.record(150, id)?.reference.clone(),
                        floor: r.cache.state.record(157, id)?.reference.clone(),
                        evidence,
                        history,
                    },
                    Some(grant),
                    Resolved::default(),
                )?
                .0,
            )
        }
        TrustCommand::Activate {
            access,
            trust,
            ready,
        } => {
            let ready = read(&ready)?;
            let (mut c, grant) = connection::access(access)?;
            let id = id(&trust)?;
            if let Some((r,_))=c.resume(|p|matches!(p,Action::ForeignActivate{trust,ready:r,..}if trust.id==id && *r==ready))? {return summary(&r)}
            let r = c
                .action(
                    Action::TrustGet { trust: id },
                    Some(grant.clone()),
                    Resolved::default(),
                )?
                .0;
            summary(
                &c.action(
                    Action::ForeignActivate {
                        trust: r.cache.state.record(150, id)?.reference.clone(),
                        floor: r.cache.state.record(157, id)?.reference.clone(),
                        ready,
                    },
                    Some(grant),
                    Resolved::default(),
                )?
                .0,
            )
        }
    }
}
pub(super) fn treaty(command: TreatyCommand) -> Result<()> {
    match command {
        TreatyCommand::Create {
            agreement,
            source_bootstrap,
            source_bootstrap_digest,
            destination_bootstrap,
            destination_bootstrap_digest,
            source_bridge,
            destination_bridge,
            source_namespace,
            destination_namespace,
            mut media_profile,
            source_host,
            destination_host,
            media_bytes,
            copies,
            expires_ms,
            output,
        } => {
            let (_, source) = pinned(&source_bootstrap, &source_bootstrap_digest)?;
            let (_, destination) = pinned(&destination_bootstrap, &destination_bootstrap_digest)?;
            let keys = |values: Vec<String>| -> Result<Vec<Digest>> {
                let mut keys = values.iter().map(|s| id(s)).collect::<Result<Vec<_>>>()?;
                keys.sort();
                Ok(keys)
            };
            media_profile.sort();
            let treaty = fed::Treaty {
                id: agreement
                    .as_deref()
                    .map(id)
                    .transpose()?
                    .unwrap_or_else(rand::random),
                source: fed::NetworkIdentity::verified(&source),
                destination: fed::NetworkIdentity::verified(&destination),
                source_bridge: id(&source_bridge)?,
                destination_bridge: id(&destination_bridge)?,
                source_namespace,
                destination_namespace,
                media_profiles: media_profile,
                source_hosts: keys(source_host)?,
                destination_hosts: keys(destination_host)?,
                media_bytes,
                copies,
                expires_ms,
            };
            fed::Treaty::parse(&treaty.value())?;
            ensure!(
                expires_ms > crate::now()?.saturating_mul(1000),
                "treaty already expired"
            );
            files::write_new(&output, &wire::encode(&treaty.value())?)?;
            treaty_summary(&treaty)
        }
        TreatyCommand::Inspect { input } => treaty_summary(&treaty_file(&input)?),
        TreatyCommand::Accept { access, input } => {
            let treaty = treaty_file(&input)?;
            let (mut c, grant) = connection::access(access)?;
            let (n, i) = c.scope();
            let source = treaty.source_side(n, i)?;
            ensure!(
                treaty.local(source) == &fed::NetworkIdentity::verified(&c.bootstrap),
                "treaty local identity differs from independently accepted bootstrap"
            );
            if let Some((r, _)) =
                c.resume(|p| matches!(p,Action::Accept{treaty:t,..}if t.value()==treaty.value()))?
            {
                return summary(&r);
            }
            let foreign_id = trust_id(treaty.foreign(source));
            c.action(
                Action::TrustGet { trust: foreign_id },
                Some(grant.clone()),
                Resolved::default(),
            )?;
            c.context(22, treaty.id, None, &grant)?;
            let foreign = c.cache()?.state.record(150, foreign_id)?.reference.clone();
            summary(
                &c.action(
                    Action::Accept { treaty, foreign },
                    Some(grant),
                    Resolved::default(),
                )?
                .0,
            )
        }
        TreatyCommand::Get { access, agreement } => {
            let (mut c, grant) = connection::maintenance(access)?;
            summary(
                &c.action(
                    Action::Get {
                        agreement: id(&agreement)?,
                    },
                    grant,
                    Resolved::default(),
                )?
                .0,
            )
        }
        TreatyCommand::List { access, after } => {
            let (mut c, grant) = connection::access(access)?;
            summary(
                &c.action(
                    Action::Agreements {
                        after: after.as_deref().map(id).transpose()?,
                    },
                    Some(grant),
                    Resolved::default(),
                )?
                .0,
            )
        }
        TreatyCommand::Withdraw { access, agreement } => {
            let (mut c, grant) = connection::maintenance(access)?;
            let id = id(&agreement)?;
            if let Some((r, _)) =
                c.resume(|p| matches!(p,Action::Withdraw{agreement}if agreement.id==id))?
            {
                return summary(&r);
            }
            let r = c
                .action(
                    Action::Get { agreement: id },
                    grant.clone(),
                    Resolved::default(),
                )?
                .0;
            summary(
                &c.action(
                    Action::Withdraw {
                        agreement: r.cache.state.record(151, id)?.reference.clone(),
                    },
                    grant,
                    Resolved::default(),
                )?
                .0,
            )
        }
    }
}
fn profile_summary(p: &fed::BridgeProfile) -> Result<()> {
    crate::print_value(
        &json!({"status":"BridgeProfile","currentAuthority":false,"service":hex::encode(p.service),
        "operator":hex::encode(p.manifest.operator),"deployment":hex::encode(p.manifest.deployment),"volume":hex::encode(p.volume),
        "stateBytes":p.state_bytes,"agreements":p.agreements.iter().map(|(id,d)|json!({"id":hex::encode(id),"digest":hex::encode(d)})).collect::<Vec<_>>()}),
    )
}
pub(super) fn bridge(command: BridgeCommand) -> Result<()> {
    match command {
        BridgeCommand::Profile {
            location,
            key,
            manifest,
            profile_digest,
            volume,
            treaty,
            state_bytes,
            output,
        } => {
            let bootstrap = control::bootstrap(&location)?;
            let scope = bootstrap.descriptor().scope();
            let manifest = crate::runtime_manifest::Manifest::parse(&files::read_public_single(
                &manifest,
                crate::runtime_manifest::MAXIMUM,
            )?)?;
            ensure!(
                manifest.network == scope.network
                    && manifest.incarnation == scope.incarnation
                    && manifest.bootstrap_digest == bootstrap.file_digest()
                    && wire::digest(&manifest.desired()?) == id(&profile_digest)?,
                "bridge manifest differs from independently reviewed deployment"
            );
            let signer = domain_cli::signer(&key)?;
            ensure!(
                signer.verifying_key().to_bytes() == manifest.operator,
                "bridge profile signer is not its operator"
            );
            let service = *manifest.services().get(&7).context("bridge role7 absent")?;
            let mut agreements = vec![];
            for path in treaty {
                let treaty = treaty_file(&path)?;
                let source = treaty.source_side(scope.network, scope.incarnation)?;
                ensure!(
                    treaty.local(source) == &fed::NetworkIdentity::verified(&bootstrap)
                        && treaty.bridge(source) == service,
                    "bridge profile treaty names another local identity or service"
                );
                agreements.push((treaty.id, treaty.digest()?));
            }
            agreements.sort();
            let mut p = fed::BridgeProfile {
                manifest,
                service,
                volume: id(&volume)?,
                agreements,
                state_bytes,
                envelope: vec![],
            };
            p.envelope = wire::sign_envelope(&p.payload()?, &signer)?;
            fed::BridgeProfile::parse(&p.envelope, scope.network, scope.incarnation)?;
            files::write_new(&output, &p.envelope)?;
            profile_summary(&p)
        }
        BridgeCommand::Inspect { location, input } => {
            let b = control::bootstrap(&location)?;
            let s = b.descriptor().scope();
            let p = fed::BridgeProfile::parse(
                &files::read_public_single(&input, wire::MAXIMUM)?,
                s.network,
                s.incarnation,
            )?;
            ensure!(
                p.manifest.bootstrap_digest == b.file_digest(),
                "bridge profile has another initial pin"
            );
            profile_summary(&p)
        }
        BridgeCommand::Register { access, profile } => {
            let (mut c, grant) = connection::access(access)?;
            let (n, i) = c.scope();
            let p = fed::BridgeProfile::parse(
                &files::read_public_single(&profile, wire::MAXIMUM)?,
                n,
                i,
            )?;
            if let Some((r, _)) = c.resume(
                |old| matches!(old,Action::BridgeRegister{profile}if profile.envelope==p.envelope),
            )? {
                return summary(&r);
            }
            c.context(26, p.manifest.deployment, None, &grant)?;
            summary(
                &c.action(
                    Action::BridgeRegister { profile: p },
                    Some(grant),
                    Resolved::default(),
                )?
                .0,
            )
        }
        BridgeCommand::Get { access, service } => {
            let (mut c, grant) = connection::maintenance(access)?;
            summary(
                &c.action(
                    Action::BridgeGet {
                        service: id(&service)?,
                    },
                    grant,
                    Resolved::default(),
                )?
                .0,
            )
        }
        BridgeCommand::Withdraw { access, service } => {
            let (mut c, grant) = connection::maintenance(access)?;
            let id = id(&service)?;
            if let Some((r, _)) =
                c.resume(|p| matches!(p,Action::BridgeWithdraw{bridge}if bridge.id==id))?
            {
                return summary(&r);
            }
            let r = c
                .action(
                    Action::BridgeGet { service: id },
                    grant.clone(),
                    Resolved::default(),
                )?
                .0;
            summary(
                &c.action(
                    Action::BridgeWithdraw {
                        bridge: r.cache.state.record(152, id)?.reference.clone(),
                    },
                    grant,
                    Resolved::default(),
                )?
                .0,
            )
        }
        BridgeCommand::Sync {
            route,
            directory,
            agreement,
            source_page_id,
        } => exchange::sync(
            &route,
            &directory,
            id(&agreement)?,
            source_page_id.as_deref().map(raw).transpose()?,
        ),
    }
}
pub(super) fn share(command: Command) -> Result<()> {
    match command {
        Command::ShareSign {
            access,
            selection,
            output,
        } => {
            let (mut c, grant) = connection::access(access)?;
            let agreement = id(&selection.agreement)?;
            let page = raw(&selection.source_page_id)?;
            let r = c.page_context(agreement, page, 4, &grant)?;
            let ledger =
                page::Ledger::parse(&r.cache.state.record(140, page::page_id(&page)?)?.payload)?;
            let publication = ledger
                .published
                .context("Page has no approved publication")?;
            let (n, i) = c.scope();
            let approved =
                page::Review::parse(&r.cache.state.record(142, publication.id)?.payload, n, i)?;
            let revision = page::Revision::parse(
                &r.cache
                    .state
                    .record(141, approved.statement.revision.id)?
                    .payload,
                n,
                i,
            )?;
            ensure!(
                revision.author.intent.requester == c.key.verifying_key().to_bytes(),
                "only the original source author can share"
            );
            let mut share = fed::Share {
                agreement,
                page,
                publication,
                revision: approved.statement.revision,
                author: c.key.verifying_key().to_bytes(),
                grant,
                statement: vec![],
                allowed: true,
                withdrawal_generation: 0,
            };
            share.statement = c.statement(
                "FederationShareStatement",
                share.identity()?,
                revision.author.intent.revision,
                wire::encode(&share.statement_value())?,
            )?;
            fed::Share::parse(&share.value(), n, i)?;
            files::write_new(&output, &wire::encode(&share.value())?)?;
            crate::print_value(
                &json!({"status":"ShareConsentSaved","agreement":hex::encode(agreement),"sourcePage":hex::encode(page),
                "share":hex::encode(share.identity()?),"sourceRevision":reference(&share.revision)?,"output":output,"currentAuthority":false}),
            )
        }
        Command::Share { online, input } => {
            let mut c = Client::new(&online)?;
            let (n, i) = c.scope();
            let share = fed::Share::parse(
                &wire::decode(&files::read_public_single(&input, wire::MAXIMUM)?)?,
                n,
                i,
            )?;
            ensure!(
                share.author == c.key.verifying_key().to_bytes(),
                "share signer differs from requester"
            );
            if let Some((r, _)) =
                c.resume(|p| matches!(p,Action::Share{share:s}if s.statement==share.statement))?
            {
                return summary(&r);
            }
            c.page_context(share.agreement, share.page, 4, &share.grant)?;
            let grant = share.grant.clone();
            summary(
                &c.action(Action::Share { share }, Some(grant), Resolved::default())?
                    .0,
            )
        }
        Command::ShareStatus { access, selection } => {
            let (mut c, grant) = connection::maintenance(access)?;
            summary(
                &c.action(
                    Action::ShareStatus {
                        agreement: id(&selection.agreement)?,
                        page: raw(&selection.source_page_id)?,
                    },
                    grant,
                    Resolved::default(),
                )?
                .0,
            )
        }
        Command::Unshare { access, selection } => {
            let (mut c, grant) = connection::maintenance(access)?;
            let agreement = id(&selection.agreement)?;
            let page = raw(&selection.source_page_id)?;
            let share_id = fed::share_id(agreement, page)?;
            if let Some((r, _)) =
                c.resume(|p| matches!(p,Action::Unshare{share}if share.id==share_id))?
            {
                return summary(&r);
            }
            let r = c
                .action(
                    Action::ShareStatus { agreement, page },
                    grant.clone(),
                    Resolved::default(),
                )?
                .0;
            summary(
                &c.action(
                    Action::Unshare {
                        share: r.cache.state.record(153, share_id)?.reference.clone(),
                    },
                    grant,
                    Resolved::default(),
                )?
                .0,
            )
        }
        _ => unreachable!(),
    }
}
