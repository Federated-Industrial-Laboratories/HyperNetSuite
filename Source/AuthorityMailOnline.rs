// SPDX-License-Identifier: MIT
// Participant requests recheck current mailbox grants and each explicitly selected opaque store.
use super::*;
pub(super) fn run(command: Command) -> Result<()> {
    match command {
        Command::Profile {
            location,
            manifest,
            profile_digest,
            key,
            volume,
            state_bytes,
            maximum_payload,
            maximum_lifetime_ms,
            output,
        } => {
            let b = control::bootstrap(&location)?;
            let scope = b.descriptor().scope();
            let manifest = crate::runtime_manifest::Manifest::parse(&files::read_public_single(
                &manifest,
                crate::runtime_manifest::MAXIMUM,
            )?)?;
            ensure!(
                manifest.network == scope.network
                    && manifest.incarnation == scope.incarnation
                    && manifest.bootstrap_digest == b.file_digest()
                    && wire::digest(&manifest.desired()?) == id(&profile_digest)?,
                "manifest differs from independently accepted deployment"
            );
            let key = domain_cli::signer(&key)?;
            ensure!(
                key.verifying_key().to_bytes() == manifest.operator,
                "mail profile signer is not operator"
            );
            let role = manifest
                .roles
                .iter()
                .find(|r| r.role == 3)
                .context("mail role absent")?;
            ensure!(
                role.bind_endpoint_ids.is_empty() && role.outbound_endpoint_ids.is_empty(),
                "mail requires the private local control route"
            );
            let mut p = mail::Profile {
                service: role.service_key,
                manifest,
                endpoint: None,
                volume: id(&volume)?,
                state_bytes,
                maximum_payload,
                maximum_lifetime_ms,
                envelope: vec![],
            };
            p.envelope = wire::sign_envelope(&p.payload()?, &key)?;
            mail::Profile::parse(&p.envelope, scope.network, scope.incarnation)?;
            files::write_new(&output, &p.envelope)?;
            crate::print_value(
                &json!({"status":"MailProfileSigned","service":hex::encode(p.service),"deployment":hex::encode(p.manifest.deployment),"currentPermission":false}),
            )
        }
        Command::Register {
            online,
            capability,
            profile,
        } => {
            let mut c = Client::manager(&online)?;
            let scope = c.bootstrap.descriptor().scope();
            let p = mail::Profile::parse(
                &files::read_public_single(&profile, crate::runtime_manifest::MAXIMUM + 1024)?,
                scope.network,
                scope.incarnation,
            )?;
            let g = c.capability(capability)?;
            if c.pending()?.as_ref().is_some_and(|op| {
                !matches!(op.command, domain::Command::Mail(Action::Register { .. }))
            }) {
                c.resume_metadata(|cmd|matches!(cmd,Action::Context{action:26,resource,..}if *resource==p.manifest.deployment))?;
            }
            if c.pending()?.is_none() {
                c.action(
                    Action::Context {
                        action: 26,
                        scope_kind: 5,
                        resource: p.manifest.deployment,
                    },
                    g.clone(),
                )?;
            }
            let result = c.action(Action::Register { profile: p }, g)?;
            summary(result)
        }
        Command::Withdraw { online, service } => {
            let mut c = Client::manager(&online)?;
            let service = id(&service)?;
            let generation = if let Some(op) = c.pending()? {
                let domain::Command::Mail(Action::Withdraw {
                    service: s,
                    generation,
                }) = op.command
                else {
                    anyhow::bail!("another request is pending")
                };
                ensure!(s == service, "another store withdrawal is pending");
                generation
            } else {
                c.action(Action::Service { service }, None)?;
                c.cache()?.state.record(136, service)?.reference.generation
            };
            summary(c.action(
                Action::Withdraw {
                    service,
                    generation,
                },
                None,
            )?)
        }
        Command::Hosts {
            online,
            capability,
            after,
        } => {
            let mut c = Client::manager(&online)?;
            let g = c.capability(capability)?;
            let result = c.action(
                Action::Services {
                    network: c.bootstrap.descriptor().scope().network,
                    after: after.as_deref().map(id).transpose()?,
                },
                g,
            )?;
            let f = result.value.array(5)?;
            let body = f[4].array(4)?;
            let services=body[1].list(mail::MAXIMUM_CONTEXT_RECORDS)?.iter().map(|v|{let r=domain::Record::parse(v.bytes()?,c.bootstrap.descriptor().scope().network,c.bootstrap.descriptor().scope().incarnation)?;let s=mail::Service::parse(&r.payload,c.bootstrap.descriptor().scope().network,c.bootstrap.descriptor().scope().incarnation)?;Ok(json!({"service":hex::encode(r.reference.id),"generation":r.reference.generation,"deployment":hex::encode(s.profile.manifest.deployment),"withdrawn":s.withdrawn,"maximumPayload":s.profile.maximum_payload,"maximumLifetimeMs":s.profile.maximum_lifetime_ms}))}).collect::<Result<Vec<_>>>()?;
            crate::print_value(
                &json!({"services":services,"next":if body[3]==V::Null{None}else{Some(hex::encode(body[3].bytes()?))}}),
            )
        }
        Command::Publish {
            online,
            capability,
            vault,
            mailbox,
        } => {
            let (_, mut v) = open(&online.location, &vault, false)?;
            let mut c = Client::manager(&online)?;
            let p = publication(&v, &mailbox)?;
            let address = p.id()?;
            let private = v.mailbox(&mailbox)?.private;
            let manager = hex::encode(c.key.verifying_key().to_bytes());
            ensure!(
                v.mailbox(&mailbox)?
                    .manager
                    .as_ref()
                    .is_none_or(|old| old == &manager),
                "mailbox belongs to another admitted manager"
            );
            let g = c.capability(capability)?;
            if c.pending()?.as_ref().is_some_and(|op| {
                !matches!(op.command, domain::Command::Mail(Action::Publish { .. }))
            }) {
                c.resume_metadata(|cmd| match cmd {
                    Action::Context {
                        action: 15,
                        resource,
                        ..
                    } => *resource == address,
                    Action::Get { address: a, .. } => *a == address,
                    Action::Service { service } => {
                        p.manifest.storage_hosts.contains(&hex::encode(service))
                    }
                    _ => false,
                })?;
            }
            if c.pending()?.is_none() {
                c.action(
                    Action::Context {
                        action: 15,
                        scope_kind: 2,
                        resource: address,
                    },
                    g.clone(),
                )?;
                for h in &p.manifest.storage_hosts {
                    c.action(Action::Service { service: id(h)? }, g.clone())?;
                }
                if p.manifest.generation > 1 {
                    c.action(
                        Action::Get {
                            address,
                            source: None,
                        },
                        g.clone(),
                    )?;
                }
            }
            let result = c.action(
                Action::Publish {
                    publication: p,
                    private,
                },
                g,
            )?;
            v.mailbox_mut(&mailbox)?.manager = Some(manager);
            v.save()?;
            summary(result)
        }
        Command::DeviceInitialise {
            location,
            vault,
            mailbox,
        } => {
            let (b, v) = open(&location, &vault, false)?;
            let key = signer(&v.mailbox(&mailbox)?.request)?;
            let clock = control::clock(&location, b.descriptor().voters())?;
            files::create_directory(&location.directory)?;
            let store = Store::initialise(
                &location.directory,
                b.descriptor().clone(),
                key.verifying_key().to_bytes(),
                clock.health()?,
            )?;
            crate::authority_inspection::ContextState::bootstrap(&b, &store)?.save(&store)?;
            crate::print_value(
                &json!({"status":"MailDeviceInitialised","requester":hex::encode(store.requester()),"epoch":store.descriptor().scope().epoch}),
            )
        }
        Command::Sync { online } => {
            let (mut c, mut v) = device(&online)?;
            let address = id(&v.mailbox(&online.mailbox)?.address)?;
            c.resume_metadata(|cmd| matches!(cmd,Action::Get{address:a,..}if *a==address))?;
            let m = sync(&mut c, &mut v, &online.mailbox)?;
            crate::print_value(
                &json!({"status":"MailboxCurrent","address":m.publication.manifest.address_id,"generation":m.publication.manifest.generation,"private":m.private}),
            )
        }
        Command::Refill { online, count } => {
            let (mut c, mut v) = device(&online)?;
            refill(&mut c, &mut v, &online.mailbox, count)?;
            crate::print_value(
                &json!({"status":"MailPackagesPublished","availableLocal":v.mailbox(&online.mailbox)?.packages.iter().filter(|p|p.published).count()}),
            )
        }
        Command::ContactVerify {
            online,
            address,
            owner_key,
        } => {
            let (mut c, mut v) = device(&online)?;
            let source = id(&v.mailbox(&online.mailbox)?.address)?;
            let target = id(&address)?;
            mail::objects::native(&owner_key)?;
            c.resume_metadata(
                |cmd| matches!(cmd,Action::Get{address:a,..}if *a==source || *a==target),
            )?;
            sync(&mut c, &mut v, &online.mailbox)?;
            let m = c.refresh(target, Some(source))?;
            v.contact(
                &serde_json::from_slice(&m.publication.bytes)?,
                Some(&owner_key),
            )?;
            crate::print_value(
                &json!({"status":"MailContactVerified","address":address,"ownerKey":owner_key}),
            )
        }
        Command::Send {
            online,
            transport,
            message,
        } => {
            let (mut c, mut v) = device(&online)?;
            send(&mut c, &mut v, &online.mailbox, &transport, id(&message)?)
        }
        Command::Inbox {
            online,
            transport,
            after,
        } => receive(
            &online,
            &transport,
            Effect::List,
            None,
            after.as_deref().map(id).transpose()?,
        ),
        Command::Read {
            online,
            transport,
            message,
        } => receive(
            &online,
            &transport,
            Effect::Fetch,
            Some(id(&message)?),
            None,
        ),
        Command::Delete {
            online,
            transport,
            message,
        } => receive(
            &online,
            &transport,
            Effect::Delete,
            Some(id(&message)?),
            None,
        ),
        _ => anyhow::bail!("not an online mail operation"),
    }
}
fn receive(
    o: &DeviceOnline,
    t: &Transport,
    kind: Effect,
    message: Option<Digest>,
    after: Option<Digest>,
) -> Result<()> {
    let (mut c, mut v) = device(o)?;
    crate::print_value(&receive_value(
        &mut c, &mut v, &o.mailbox, t, kind, message, after,
    )?)
}
pub(super) fn receive_value(
    c: &mut Client,
    v: &mut Vault,
    label: &str,
    t: &Transport,
    kind: Effect,
    message: Option<Digest>,
    after: Option<Digest>,
) -> Result<serde_json::Value> {
    let address = id(&v.mailbox(label)?.address)?;
    c.resume_metadata(|cmd| {
        matches!(cmd,Action::Get{address:a,..}if *a==address)
            || matches!(cmd,Action::ClaimGet{id}if Some(*id)==message)
    })?;
    let command = if let Some(request) = mail_client::pending(&c.store)? {
        let command = request.command().clone();
        ensure!(
            command.value()
                == effect(
                    address,
                    id(&t.service)?,
                    kind,
                    message,
                    None,
                    0,
                    None,
                    after
                )
                .value(),
            "another mail effect is pending"
        );
        command
    } else {
        sync(c, v, label)?;
        if let Some(message) = message {
            c.action(Action::ClaimGet { id: message }, None)?;
        }
        effect(
            address,
            id(&t.service)?,
            kind,
            message,
            None,
            0,
            None,
            after,
        )
    };
    let cache = c.cache()?;
    let claim = message
        .map(|id| mail::Claim::parse(&cache.state.record(139, id)?.payload))
        .transpose()?;
    let package = if kind == Effect::Fetch {
        let claim = claim.as_ref().context("mail claim absent")?;
        let device = &v.mailbox(label)?.device.device_id;
        Some(
            claim
                .packages
                .iter()
                .map(|r| mail::Inventory::parse(&cache.state.record(138, r.id)?.payload))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .find(|p| p.package.device_id == *device)
                .context("this device was not a recipient of this letter")?
                .package
                .reference,
        )
    } else {
        None
    };
    let result=c.effect(t,command,&[],|_,bytes,receipt|{
        let response=wire::decode(bytes)?;let f=response.array(9)?;
        match kind {
            Effect::Fetch=>{let cipher:protocol::Ciphertext=serde_json::from_slice(f[8].bytes()?)?;let letter=v.archive(label,&cipher,package.as_deref().unwrap(),claim.as_ref().unwrap().created_ms/1000,receipt)?;Ok(serde_json::to_value(letter)?)},
            Effect::List=>{let items=f[8].list(16)?.iter().map(|e|{let e=e.array(4)?;Ok(json!({"message":hex::encode(e[0].bytes()?),"ciphertextDigest":hex::encode(e[1].bytes()?),"bytes":e[2].uint()?,"expiresMs":e[3].uint()?}))}).collect::<Result<Vec<_>>>()?;let next=if items.len()==16{items.last().unwrap()["message"].clone()}else{serde_json::Value::Null};Ok(json!({"messages":items,"next":next}))},
            Effect::Delete=>Ok(json!({"status":"StoredMailDeleted","message":message.map(hex::encode),"localArchiveRetained":true})),
            _=>anyhow::bail!("invalid mailbox read effect"),
        }
    })?;
    Ok(result)
}
