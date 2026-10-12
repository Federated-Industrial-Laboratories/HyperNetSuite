// SPDX-License-Identifier: MIT
// Owner operations produce signed mailbox revisions without opening a network route.
use super::*;
fn label(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 64
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "mailbox label must use one through64 letters, digits, hyphens or underscores"
    );
    Ok(())
}
fn hosts(values: Vec<String>, copies: u16, private: bool) -> Result<Vec<String>> {
    ensure!(
        (1..=4).contains(&values.len()) && copies > 0 && usize::from(copies) <= values.len(),
        "invalid mail copy count"
    );
    ensure!(
        !private || (values.len() == 1 && copies == 1),
        "private mail requires one explicitly selected store"
    );
    let mut out = values
        .into_iter()
        .map(|s| Ok(hex::encode(mail::objects::native(&s)?)))
        .collect::<Result<Vec<_>>>()?;
    out.sort();
    ensure!(out.windows(2).all(|p| p[0] != p[1]), "duplicate mail store");
    Ok(out)
}
pub(super) fn run(command: Command) -> Result<()> {
    match command {
        Command::Init { location, vault } => {
            open(&location, &vault, true)?;
            crate::print_value(&json!({"status":"MailVaultInitialised"}))
        }
        Command::AddressCreate {
            location,
            vault,
            mailbox,
            hosts: input,
            copies,
            private,
            expires,
            retention,
        } => {
            label(&mailbox)?;
            let (_, mut v) = open(&location, &vault, false)?;
            ensure!(
                !v.data.mailboxes.contains_key(&mailbox),
                "mailbox label exists"
            );
            ensure!(expires > crate::now()?, "mailbox expiry is not future");
            let n = hex::encode(v.data.network);
            let owner = protocol::new_identity();
            let address = protocol::address_id(&n, &owner.public_key)?;
            let mut b = local_device(
                &address,
                expires,
                vec!["Read".into(), "Send".into(), "Delete".into()],
            )?;
            let m = protocol::Manifest {
                version: 1,
                network: n.clone(),
                address_id: address.clone(),
                owner_key: owner.public_key.clone(),
                generation: 1,
                previous_digest: None,
                expires,
                devices: vec![b.device.clone()],
                storage_hosts: hosts(input, copies, private)?,
                required_copies: copies,
                retention_seconds: retention,
                deleted: false,
            };
            let signed = protocol::sign(protocol::MANIFEST, &n, &owner, &m)?;
            mail::objects::Publication::parse(&serde_json::to_vec(&signed)?, v.data.network)?;
            b.owner = Some(owner);
            b.private = private;
            b.manifest = Some(signed);
            v.data.mailboxes.insert(mailbox.clone(), b);
            v.save()?;
            crate::print_value(
                &json!({"status":"MailboxDraft","mailbox":mailbox,"address":address,"ownerKey":m.owner_key,"device":m.devices[0].device_id,"requestKey":m.devices[0].request_key,"published":false}),
            )
        }
        Command::Placement {
            location,
            vault,
            mailbox,
            hosts: input,
            copies,
            private,
        } => {
            let (_, mut v) = open(&location, &vault, false)?;
            let selected = hosts(input, copies, private)?;
            revise(&mut v, &mailbox, |m| {
                m.storage_hosts = selected;
                m.required_copies = copies;
                Ok(())
            })?;
            v.mailbox_mut(&mailbox)?.private = private;
            v.save()?;
            draft(&v, &mailbox)
        }
        Command::AddressRenew {
            location,
            vault,
            mailbox,
            expires,
        } => {
            ensure!(expires > crate::now()?, "mailbox expiry is not future");
            let (_, mut v) = open(&location, &vault, false)?;
            revise(&mut v, &mailbox, |m| {
                m.expires = expires;
                Ok(())
            })?;
            draft(&v, &mailbox)
        }
        Command::DeviceCreate {
            location,
            vault,
            mailbox,
            address,
            expires,
            permissions,
            output,
        } => {
            label(&mailbox)?;
            id(&address)?;
            ensure!(expires > crate::now()?, "device expiry is not future");
            ensure!(
                !permissions.is_empty()
                    && permissions.len() <= 3
                    && permissions
                        .iter()
                        .all(|p| matches!(p.as_str(), "Read" | "Send" | "Delete"))
                    && permissions
                        .iter()
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                        == permissions.len(),
                "invalid device rights"
            );
            let (_, mut v) = open(&location, &vault, false)?;
            ensure!(
                !v.data.mailboxes.contains_key(&mailbox),
                "mailbox label exists"
            );
            let b = local_device(&address, expires, permissions)?;
            let bytes = serde_json::to_vec(&b.device)?;
            let device = b.device.clone();
            v.data.mailboxes.insert(mailbox, b);
            v.save()?;
            files::write_new(&output, &bytes)?;
            crate::print_value(
                &json!({"status":"MailDeviceCreated","device":device,"enrolled":false}),
            )
        }
        Command::DeviceExport {
            location,
            vault,
            mailbox,
            output,
        } => {
            let (_, v) = open(&location, &vault, false)?;
            let binding = &v.mailbox(&mailbox)?.device;
            files::write_new(&output, &serde_json::to_vec(binding)?)?;
            crate::print_value(&json!({"status":"MailDeviceExported","device":binding}))
        }
        Command::DeviceEnrol {
            location,
            vault,
            mailbox,
            binding,
        } => {
            let d: protocol::Device =
                serde_json::from_slice(&files::read_public_single(&binding, 4096)?)?;
            let (_, mut v) = open(&location, &vault, false)?;
            revise(&mut v, &mailbox, |m| {
                ensure!(d.expires > crate::now()?, "device expired");
                m.devices.push(d);
                Ok(())
            })?;
            draft(&v, &mailbox)
        }
        Command::DeviceRenew {
            location,
            vault,
            mailbox,
            device,
            expires,
        } => {
            id(&device)?;
            ensure!(expires > crate::now()?, "device expiry is not future");
            let (_, mut v) = open(&location, &vault, false)?;
            revise(&mut v, &mailbox, |m| {
                m.devices
                    .iter_mut()
                    .find(|d| d.device_id == device)
                    .context("device absent")?
                    .expires = expires;
                Ok(())
            })?;
            draft(&v, &mailbox)
        }
        Command::DeviceRevoke {
            location,
            vault,
            mailbox,
            device,
        } => {
            id(&device)?;
            let (_, mut v) = open(&location, &vault, false)?;
            revise(&mut v, &mailbox, |m| {
                ensure!(
                    m.devices.iter().any(|d| d.device_id == device),
                    "device absent"
                );
                m.devices.retain(|d| d.device_id != device);
                Ok(())
            })?;
            draft(&v, &mailbox)
        }
        Command::AddressDelete {
            location,
            vault,
            mailbox,
        } => {
            let (_, mut v) = open(&location, &vault, false)?;
            revise(&mut v, &mailbox, |m| {
                m.deleted = true;
                m.devices.clear();
                m.storage_hosts.clear();
                m.required_copies = 0;
                Ok(())
            })?;
            draft(&v, &mailbox)
        }
        Command::Compose {
            location,
            vault,
            mailbox,
            recipient,
            subject,
            body_file,
            expires,
        } => {
            let (_, mut v) = open(&location, &vault, false)?;
            v.mailbox(&mailbox)?;
            id(&recipient)?;
            ensure!(
                v.data.contacts.contains_key(&recipient),
                "verify recipient owner before composing"
            );
            ensure!(
                subject.len() <= 512 && expires > crate::now()?,
                "invalid subject length or expiry"
            );
            let body = String::from_utf8(files::read_single(&body_file, 32768, true)?)?;
            let message = crate::random_hex::<32>();
            v.data.outgoing.insert(
                message.clone(),
                Outgoing {
                    mailbox,
                    recipient,
                    id: message.clone(),
                    expires,
                    subject,
                    body,
                    packages: vec![],
                    claim: None,
                    sender_manifest: None,
                    recipient_manifest: None,
                    ciphertext: None,
                    receipts: BTreeMap::new(),
                    form_consent: None,
                },
            );
            v.save()?;
            crate::print_value(&json!({"status":"MailComposed","message":message,"sent":false}))
        }
        Command::Addresses { location, vault } => {
            let (_, v) = open(&location, &vault, false)?;
            crate::print_value(
                &json!({"mailboxes":v.data.mailboxes.iter().map(|(label,b)|json!({"mailbox":label,"address":b.address,"device":b.device,"ownerHeld":b.owner.is_some(),"private":b.private})).collect::<Vec<_>>()}),
            )
        }
        Command::Outbox { location, vault } => {
            let (_, v) = open(&location, &vault, false)?;
            crate::print_value(
                &json!({"messages":v.data.outgoing.values().map(|m|json!({"message":m.id,"mailbox":m.mailbox,"recipient":m.recipient,"expires":m.expires,"claimed":m.claim.is_some(),"encrypted":m.ciphertext.is_some(),"stores":m.receipts.keys().collect::<Vec<_>>()})).collect::<Vec<_>>()}),
            )
        }
        Command::ArchiveDisclose {
            location,
            vault,
            arguments,
        } => {
            let (_, v) = open(&location, &vault, false)?;
            crate::print_value(&disclosure::export(&v, arguments)?)
        }
        Command::ArchiveRead {
            location,
            vault,
            message,
        } => {
            id(&message)?;
            let (_, v) = open(&location, &vault, false)?;
            crate::print_value(&serde_json::to_value(
                &v.data
                    .archive
                    .get(&message)
                    .context("archived message absent")?
                    .letter,
            )?)
        }
        Command::ArchiveDelete {
            location,
            vault,
            message,
        } => {
            id(&message)?;
            let (_, mut v) = open(&location, &vault, false)?;
            ensure!(
                v.data.archive.remove(&message).is_some(),
                "archived message absent"
            );
            v.save()?;
            crate::print_value(&json!({"status":"LocalMailDeleted","message":message}))
        }
        _ => anyhow::bail!("not a local mail operation"),
    }
}
fn draft(v: &Vault, mailbox: &str) -> Result<()> {
    let p = publication(v, mailbox)?;
    crate::print_value(
        &json!({"status":"MailboxDraft","mailbox":mailbox,"address":p.manifest.address_id,"generation":p.manifest.generation,"published":false}),
    )
}
