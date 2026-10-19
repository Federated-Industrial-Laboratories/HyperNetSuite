// SPDX-License-Identifier: MIT
// Claims, immutable ciphertext and received archives are persisted before their next step.
use super::*;
pub(super) fn id(s: &str) -> Result<Digest> {
    mail::objects::hex_id(s)
}
pub(super) fn signer(i: &Identity) -> Result<SigningKey> {
    let secret = zeroize::Zeroizing::new(id(&i.secret_key)?);
    let key = SigningKey::from_bytes(&secret);
    ensure!(
        hex::encode(key.verifying_key().to_bytes()) == i.public_key,
        "mail request key differs"
    );
    Ok(key)
}
pub(super) fn open(
    location: &Location,
    v: &VaultLocation,
    create: bool,
) -> Result<(Verified, Vault)> {
    let b = control::bootstrap(location)?;
    let s = b.descriptor().scope();
    let vault = if create {
        Vault::initialise(
            &v.vault,
            &v.age_key,
            s.network,
            s.incarnation,
            b.fingerprint(),
        )?
    } else {
        Vault::open(
            &v.vault,
            &v.age_key,
            s.network,
            s.incarnation,
            b.fingerprint(),
        )?
    };
    Ok((b, vault))
}
pub(super) fn local_device(
    address: &str,
    expires: u64,
    permissions: Vec<String>,
) -> Result<Mailbox> {
    let request = protocol::new_identity();
    let (secret, public) = crypto::signer()?;
    let device = protocol::Device {
        device_id: protocol::device_id(address, &request.public_key)?,
        request_key: request.public_key.clone(),
        mls_signature_key: public,
        permissions,
        expires,
    };
    Ok(Mailbox {
        address: address.into(),
        owner: None,
        request,
        signer: secret,
        device,
        manifest: None,
        packages: vec![],
        manager: None,
        private: false,
    })
}
pub(super) fn publication(v: &Vault, label: &str) -> Result<mail::objects::Publication> {
    let signed = v
        .mailbox(label)?
        .manifest
        .as_ref()
        .context("mailbox has no owner-signed manifest")?;
    mail::objects::Publication::parse(&serde_json::to_vec(signed)?, v.data.network)
}
pub(super) fn revise(
    v: &mut Vault,
    label: &str,
    change: impl FnOnce(&mut protocol::Manifest) -> Result<()>,
) -> Result<()> {
    let n = hex::encode(v.data.network);
    let old = v
        .mailbox(label)?
        .manifest
        .as_ref()
        .context("mailbox has no manifest")?
        .clone();
    let mut m = protocol::manifest(&n, &old)?;
    ensure!(!m.deleted, "deleted mailbox cannot be reused");
    m.generation = m
        .generation
        .checked_add(1)
        .context("mailbox revision exhausted")?;
    m.previous_digest = Some(protocol::object_digest(&old)?);
    change(&mut m)?;
    let signed = protocol::sign(
        protocol::MANIFEST,
        &n,
        v.mailbox(label)?
            .owner
            .as_ref()
            .context("only the mailbox owner can change this manifest")?,
        &m,
    )?;
    mail::objects::Publication::parse(&serde_json::to_vec(&signed)?, v.data.network)?;
    v.mailbox_mut(label)?.manifest = Some(signed);
    v.save()
}
#[path = "AuthorityMailConnection.rs"]
mod connection;
pub(super) use connection::Client;
pub(super) fn device(online: &DeviceOnline) -> Result<(Client, Vault)> {
    device_checked(online, None)
}
pub(super) fn device_for_fetch(online: &DeviceOnline, message: Digest) -> Result<(Client, Vault)> {
    device_checked(online, Some(message))
}
fn device_checked(online: &DeviceOnline, message: Option<Digest>) -> Result<(Client, Vault)> {
    let (_, mut v) = open(&online.location, &online.vault, false)?;
    if let Some(message) = message {
        v.require_fetch(&hex::encode(message))?;
    }
    let c = Client::new(
        &online.location,
        &online.socket,
        signer(&v.mailbox(&online.mailbox)?.request)?,
    )?;
    let pending = match c.pending()?.map(|operation| operation.command) {
        Some(domain::Command::Mail(Action::Execute {
            effect: Effect::Fetch,
            message: Some(message),
            ..
        })) => Some(hex::encode(message)),
        _ => None,
    };
    v.sync_pending_fetch(&online.mailbox, pending.as_deref())?;
    Ok((c, v))
}
pub(super) fn sync(c: &mut Client, v: &mut Vault, label: &str) -> Result<mail::Mailbox> {
    let address = id(&v.mailbox(label)?.address)?;
    let m = c.refresh(address, None)?;
    let signed: protocol::Signed = serde_json::from_slice(&m.publication.bytes)?;
    v.set_manifest(label, signed)?;
    Ok(m)
}
#[allow(
    clippy::too_many_arguments,
    reason = "Keep protocol inputs, state and validation callbacks explicit."
)]
pub(super) fn effect(
    address: Digest,
    service: Digest,
    kind: Effect,
    message: Option<Digest>,
    claim: Option<Digest>,
    bytes: u64,
    digest: Option<Digest>,
    after: Option<Digest>,
) -> Action {
    Action::Execute {
        address,
        service,
        effect: kind,
        message,
        claim,
        bytes,
        digest,
        after,
    }
}
pub(super) fn summary(result: domain_client::ResultState) -> Result<()> {
    let f = result.value.array(5)?;
    let body = f[4].array(4)?;
    crate::print_value(
        &json!({"status":"MailQuorumResult","action":body[0].text()?,"height":result.prefix.height(),"records":body[1].list(mail::MAXIMUM_CONTEXT_RECORDS)?.len(),"next":if body[3]==V::Null {None}else{Some(hex::encode(body[3].bytes()?))}}),
    )
}
pub(super) fn refill(c: &mut Client, v: &mut Vault, label: &str, count: usize) -> Result<()> {
    let address = id(&v.mailbox(label)?.address)?;
    c.resume_metadata(
        |cmd| matches!(cmd, Action::Get{address:a,..}|Action::Package{address:a,..} if *a==address),
    )?;
    let m = sync(c, v, label)?;
    let now = crate::now()?;
    v.mailbox_mut(label)?.packages.retain(|p| p.expires > now);
    let n = hex::encode(v.data.network);
    let b = v.mailbox(label)?;
    let generation = m.publication.manifest.generation;
    ensure!(
        (1..=8).contains(&count),
        "package count must be one through eight"
    );
    if !b.packages.iter().any(|p| !p.published) {
        let (private, _) = crypto::make_packages(
            &n,
            &b.address,
            &b.device,
            &b.signer,
            count,
            b.device.expires,
        )?;
        v.mailbox_mut(label)?.packages.extend(private);
        v.save()?;
    }
    loop {
        let Some(index) = v.mailbox(label)?.packages.iter().position(|p| !p.published) else {
            break;
        };
        let b = v.mailbox(label)?;
        let p = crypto::public_package(&b.device.device_id, &b.packages[index])?;
        let package: mail::objects::Package = serde_json::from_value(serde_json::to_value(&p)?)?;
        let address = id(&b.address)?;
        let lookup = package.id(v.data.network, v.data.incarnation, address)?;
        let cached = c.cache()?;
        let existing = cached
            .state
            .records
            .get(&(138, lookup))
            .map(|r| mail::Inventory::parse(&r.payload))
            .transpose()?;
        if let Some(old) = existing {
            ensure!(
                old.package == package,
                "retained public package differs from private key"
            );
        } else {
            c.action(Action::Package { address, package }, None)?;
        }
        let p = &mut v.mailbox_mut(label)?.packages[index];
        p.published = true;
        p.generation = generation;
        v.save()?;
    }
    Ok(())
}
pub(super) fn claim(
    c: &mut Client,
    v: &mut Vault,
    label: &str,
    message: Digest,
) -> Result<mail::Claim> {
    let name = hex::encode(message);
    let job = v
        .data
        .outgoing
        .get(&name)
        .context("outbox message absent")?;
    ensure!(job.mailbox == label, "message belongs to another mailbox");
    ensure!(
        v.data
            .outgoing
            .get(&name)
            .context("outbox message absent")?
            .mailbox
            == label,
        "message belongs to another mailbox"
    );
    let source = id(&v.mailbox(label)?.address)?;
    let target = id(&job.recipient)?;
    if c.cache()?.state.records.contains_key(&(139, message)) {
        c.action(Action::ClaimGet { id: message }, None)?;
    } else {
        let sender = sync(c, v, label)?;
        let recipient = c.refresh(target, Some(source))?;
        let signed: protocol::Signed = serde_json::from_slice(&recipient.publication.bytes)?;
        v.contact(&signed, None)?;
        let job = v.data.outgoing.get(&name).unwrap();
        let cache = c.cache()?;
        forms::guard_mailboxes(
            job,
            &sender,
            &cache.state.record(137, source)?.reference,
            &recipient,
            &cache.state.record(137, target)?.reference,
        )?;
        if let Some(consent) = &job.send_consent {
            consent.mailboxes(
                &sender,
                &cache.state.record(137, source)?.reference,
                &recipient,
                &cache.state.record(137, target)?.reference,
            )?;
        }
        let packages = if job.packages.is_empty() {
            let mut after = None;
            let mut chosen = BTreeMap::new();
            loop {
                let result = c.action(
                    Action::Inventory {
                        address: target,
                        source: Some(source),
                        after,
                    },
                    None,
                )?;
                let value = result.value.array(5)?;
                let body = value[4].array(4)?;
                for r in body[1].list(mail::MAXIMUM_CONTEXT_RECORDS)? {
                    let record =
                        domain::Record::parse(r.bytes()?, v.data.network, v.data.incarnation)?;
                    if record.reference.kind == 138 {
                        let inventory = mail::Inventory::parse(&record.payload)?;
                        chosen
                            .entry(inventory.package.device_id)
                            .or_insert(record.reference);
                    }
                }
                if body[3] == V::Null {
                    break;
                }
                after = Some(body[3].fixed()?);
            }
            let mut refs = chosen.into_values().collect::<Vec<_>>();
            refs.sort_by_key(VersionRef::index);
            let job = v.data.outgoing.get_mut(&name).unwrap();
            job.packages = refs
                .iter()
                .map(|r| {
                    Ok(hex::encode(wire::encode(
                        &crate::authority_membership::reference(r),
                    )?))
                })
                .collect::<Result<_>>()?;
            job.sender_manifest = Some(serde_json::from_slice(&sender.publication.bytes)?);
            job.recipient_manifest = Some(signed);
            v.save()?;
            refs
        } else {
            job.packages
                .iter()
                .map(|p| domain::version(&wire::decode(&hex::decode(p)?)?))
                .collect::<Result<Vec<_>>>()?
        };
        let expires = v
            .data
            .outgoing
            .get(&name)
            .unwrap()
            .expires
            .checked_mul(1000)
            .context("mail expiry overflow")?;
        c.action(
            Action::Claim {
                id: message,
                sender: source,
                recipient: target,
                packages,
                expires,
            },
            None,
        )?;
    }
    let cache = c.cache()?;
    let claim = mail::Claim::parse(&cache.state.record(139, message)?.payload)?;
    forms::guard_claim(v.data.outgoing.get(&name).unwrap(), &claim)?;
    if let Some(consent) = &v.data.outgoing.get(&name).unwrap().send_consent {
        consent.claim(&claim)?;
    }
    if v.data.outgoing.get(&name).unwrap().claim.is_some() {
        return Ok(claim);
    }
    ensure!(
        cache.state.record(137, claim.sender.id)?.reference == claim.sender
            && cache.state.record(137, claim.recipient.id)?.reference == claim.recipient,
        "mailbox changed after claim; this unsent claim cannot be reconstructed"
    );
    let sender = mail::Mailbox::parse(
        &cache.state.record(137, claim.sender.id)?.payload,
        v.data.network,
    )?;
    let recipient = mail::Mailbox::parse(
        &cache.state.record(137, claim.recipient.id)?.payload,
        v.data.network,
    )?;
    ensure!(
        claim.device == c.key.verifying_key().to_bytes(),
        "claim belongs to another sender"
    );
    let sender_device = sender
        .publication
        .device(claim.device, "Send", claim.created_ms)?
        .device_id
        .clone();
    let packages = claim
        .packages
        .iter()
        .map(|r| {
            let p = mail::Inventory::parse(&cache.state.record(138, r.id)?.payload)?.package;
            Ok(serde_json::from_value(serde_json::to_value(p)?)?)
        })
        .collect::<Result<Vec<protocol::Package>>>()?;
    let wire_claim = protocol::Claim {
        version: 1,
        network: hex::encode(v.data.network),
        sender_address: hex::encode(claim.sender.id),
        sender_device,
        claim_id: name.clone(),
        recipient_address: hex::encode(claim.recipient.id),
        recipient_generation: claim.recipient.generation,
        recipient_manifest_digest: hex::encode(recipient.publication.digest),
        expires: claim.expires / 1000,
        packages,
    };
    let job = v.data.outgoing.get_mut(&name).unwrap();
    job.claim = Some(wire_claim);
    job.sender_manifest = Some(serde_json::from_slice(&sender.publication.bytes)?);
    job.recipient_manifest = Some(serde_json::from_slice(&recipient.publication.bytes)?);
    v.save()?;
    Ok(claim)
}
pub(super) fn send(
    c: &mut Client,
    v: &mut Vault,
    label: &str,
    t: &Transport,
    message: Digest,
) -> Result<()> {
    crate::print_value(&send_value(c, v, label, t, message)?)
}
pub(super) fn send_value(
    c: &mut Client,
    v: &mut Vault,
    label: &str,
    t: &Transport,
    message: Digest,
) -> Result<serde_json::Value> {
    let name = hex::encode(message);
    forms::validate_outgoing(
        v.data
            .outgoing
            .get(&name)
            .context("outbox message absent")?,
    )?;
    if let Some(consent) = &v.data.outgoing.get(&name).unwrap().send_consent {
        consent.validate(v.data.outgoing.get(&name).unwrap(), &t.service)?;
    }
    let source = id(&v.mailbox(label)?.address)?;
    let target = id(&v
        .data
        .outgoing
        .get(&name)
        .context("outbox message absent")?
        .recipient)?;
    c.resume_metadata(|cmd| match cmd {
        Action::Claim { id, .. } | Action::Bind { id, .. } | Action::ClaimGet { id } => {
            *id == message
        }
        Action::Get { address, .. } | Action::Inventory { address, .. } => {
            *address == source || *address == target
        }
        _ => false,
    })?;
    let pending = mail_client::pending(&c.store)?;
    // A retained serving packet resumes before new metadata requests can occupy this device's stream.
    if let Some(request) = pending {
        let job = v
            .data
            .outgoing
            .get(&name)
            .context("outbox message absent")?;
        let cipher = job
            .ciphertext
            .as_ref()
            .context("pending mail lacks retained ciphertext")?;
        let bytes = serde_json::to_vec(cipher)?;
        let command = request.command().clone();
        ensure!(
            matches!(&command,Action::Execute{message:Some(i),effect:Effect::Put,service,..}if *i==message && *service==id(&t.service)?),
            "another mail effect is pending"
        );
        c.effect(t, command, &bytes, |_, _, r| {
            v.data
                .outgoing
                .get_mut(&name)
                .context("outbox message absent")?
                .receipts
                .insert(t.service.clone(), hex::encode(r));
            v.save()
        })?;
        return stored_value(v, &name);
    }
    let retained = claim(c, v, label, message)?;
    if v.data.outgoing.get(&name).unwrap().ciphertext.is_none() {
        let job = v.data.outgoing.get(&name).unwrap();
        let claim = job.claim.as_ref().context("mail claim absent")?;
        let letter = crypto::Letter {
            route: protocol::Route {
                version: 1,
                profile: protocol::PROFILE.into(),
                network: claim.network.clone(),
                message_id: name.clone(),
                replacement: 0,
                sender_address: claim.sender_address.clone(),
                sender_device: claim.sender_device.clone(),
                recipient_address: claim.recipient_address.clone(),
                recipient_generation: claim.recipient_generation,
                recipient_manifest_digest: claim.recipient_manifest_digest.clone(),
                claim_id: name.clone(),
                expires: claim.expires,
            },
            subject: job.subject.clone(),
            body: job.body.clone(),
        };
        let cipher = crypto::seal(
            &v.mailbox(label)?.signer,
            claim,
            job.sender_manifest
                .as_ref()
                .context("sender manifest missing")?,
            job.recipient_manifest
                .as_ref()
                .context("recipient manifest missing")?,
            &letter,
        )?;
        v.data.outgoing.get_mut(&name).unwrap().ciphertext = Some(cipher);
        v.save()?;
    }
    let bytes = serde_json::to_vec(
        v.data
            .outgoing
            .get(&name)
            .unwrap()
            .ciphertext
            .as_ref()
            .unwrap(),
    )?;
    if retained.binding.is_none() {
        c.action(
            Action::Bind {
                id: message,
                bytes: bytes.len() as u64,
                digest: wire::digest(&bytes),
            },
            None,
        )?;
    }
    if retained.binding.is_some() {
        ensure!(
            retained.payload_digest == Some(wire::digest(&bytes))
                && retained.payload_bytes == bytes.len() as u64,
            "retained ciphertext differs from immutable mail binding"
        );
    }
    let address = retained.recipient.id;
    let service = id(&t.service)?;
    if !v
        .data
        .outgoing
        .get(&name)
        .unwrap()
        .receipts
        .contains_key(&t.service)
    {
        c.effect(
            t,
            effect(
                address,
                service,
                Effect::Put,
                Some(message),
                Some(message),
                bytes.len() as u64,
                Some(wire::digest(&bytes)),
                None,
            ),
            &bytes,
            |_, _, r| {
                v.data
                    .outgoing
                    .get_mut(&name)
                    .context("outbox message absent")?
                    .receipts
                    .insert(t.service.clone(), hex::encode(r));
                v.save()
            },
        )?;
    }
    stored_value(v, &name)
}
pub(super) fn stored_value(v: &Vault, name: &str) -> Result<serde_json::Value> {
    let job = v.data.outgoing.get(name).context("outbox message absent")?;
    let recipient = protocol::manifest(
        &hex::encode(v.data.network),
        job.recipient_manifest.as_ref().unwrap(),
    )?;
    Ok(
        json!({"status":"MailStored","message":name,"confirmedCopies":job.receipts.len(),"requiredCopies":recipient.required_copies,"delivered":job.receipts.len()>=usize::from(recipient.required_copies)}),
    )
}
