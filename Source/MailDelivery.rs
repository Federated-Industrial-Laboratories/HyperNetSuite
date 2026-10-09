// SPDX-License-Identifier: MIT
// Durable asynchronous delivery and verification of the original signed admission.
use crate::{
    Config, Identity,
    mail::{hosts, operation, own_manifest, receipt, refresh, selected_host},
    mail_crypto as crypto, mail_protocol as wire,
    mail_vault::{Archived, Contact, Vault},
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
pub(super) fn retry(v: &mut Vault, c: &Config, id: &str) -> Result<Value> {
    let label = v
        .data
        .outbox
        .get(id)
        .context("unknown outbox message")?
        .mailbox
        .clone();
    let own = refresh(v, c, &label)?;
    let request = duplicate_identity(&v.mailbox(&label)?.request);
    hosts(v, c, &request)?;
    if v.data.outbox[id].ciphertext.is_none() {
        let address = v.data.outbox[id].recipient.clone();
        let contact = v
            .data
            .contacts
            .get(&address)
            .context("verify recipient owner fingerprint before sending")?
            .clone();
        let signed = wire::address_get(c, &request, &address)?;
        let recipient = wire::manifest(&c.network, &signed)?;
        ensure!(
            recipient.owner_key == contact.owner_key
                && recipient.generation >= contact.generation
                && !recipient.deleted,
            "contact key changed, rolled back or was deleted"
        );
        if recipient.generation == contact.generation {
            ensure!(
                wire::object_digest(&signed)? == contact.manifest_digest,
                "contact manifest fork"
            );
        }
        let now = crate::now()?;
        let expected_expiry = v.data.outbox[id].expires;
        if expected_expiry == 0 {
            let expiry = default_expiry(
                &recipient,
                own.expires,
                v.mailbox(&label)?.device.expires,
                now,
            )?;
            v.data.outbox.get_mut(id).unwrap().expires = expiry;
        }
        ensure!(v.data.outbox[id].expires > now, "queued mail expired");
        ensure!(
            v.data.outbox[id].expires <= recipient.expires
                && v.data.outbox[id].expires <= now.saturating_add(recipient.retention_seconds),
            "queued expiry conflicts with current recipient policy"
        );
        let stale = v.data.outbox[id]
            .recipient_manifest
            .as_ref()
            .is_some_and(|old| wire::object_digest(old).ok() != wire::object_digest(&signed).ok());
        if stale {
            let item = v.data.outbox.get_mut(id).unwrap();
            item.claim_id = crate::random_hex::<16>();
            item.claim = None;
        }
        v.data.contacts.insert(
            address.clone(),
            Contact {
                address: address.clone(),
                owner_key: recipient.owner_key.clone(),
                generation: recipient.generation,
                manifest_digest: wire::object_digest(&signed)?,
            },
        );
        v.data.outbox.get_mut(id).unwrap().recipient_manifest = Some(signed.clone());
        v.commit()?;
        if v.data.outbox[id].claim.is_none() {
            let item = &v.data.outbox[id];
            let result = wire::authority(
                c,
                &request,
                json!({"type":"MailKeyPackagesClaim","senderAddress":own.address_id,"senderDevice":v.mailbox(&label)?.device.device_id,"recipientAddress":address,"recipientManifestDigest":wire::object_digest(&signed)?,"claimId":item.claim_id,"expires":item.expires}),
            )?;
            let claim: wire::Claim = serde_json::from_value(result["claim"].clone())?;
            v.data.outbox.get_mut(id).unwrap().claim = Some(claim);
            v.commit()?;
        }
        let item = &v.data.outbox[id];
        let route = wire::Route {
            version: 1,
            profile: wire::PROFILE.into(),
            network: c.network.clone(),
            message_id: id.into(),
            replacement: 0,
            sender_address: own.address_id.clone(),
            sender_device: v.mailbox(&label)?.device.device_id.clone(),
            recipient_address: address,
            recipient_generation: recipient.generation,
            recipient_manifest_digest: wire::object_digest(&signed)?,
            claim_id: item.claim_id.clone(),
            expires: item.expires,
        };
        let letter = crypto::Letter {
            route,
            subject: item.subject.clone(),
            body: item.body.clone(),
        };
        let cipher = crypto::seal(
            &v.mailbox(&label)?.signer,
            item.claim.as_ref().unwrap(),
            own_manifest(v, &label)?,
            &signed,
            &letter,
        )?;
        v.data.outbox.get_mut(id).unwrap().ciphertext = Some(cipher);
        v.data.outbox.get_mut(id).unwrap().state = "Prepared".into();
        v.commit()?;
    }
    let cipher = v.data.outbox[id].ciphertext.as_ref().unwrap().clone();
    let recipient = wire::manifest(&c.network, &cipher.recipient_manifest)?;
    let bytes = serde_json::to_vec(&cipher)?;
    let mut errors = Vec::new();
    for key in &recipient.storage_hosts {
        if v.data.outbox[id].receipts.contains_key(key) {
            continue;
        }
        let result = (|| -> Result<wire::Signed> {
            let h = selected_host(v, c, &recipient, key)?;
            v.data.outbox.get_mut(id).unwrap().state = "Sending".into();
            v.commit()?;
            deliver_prepared(
                c,
                v.mailbox(&label)?,
                &own,
                &h,
                &cipher,
                &bytes,
                |op, payload| wire::store(c, &h, op, payload),
                || wire::address_get(c, &request, &recipient.address_id),
            )
        })();
        match result {
            Ok(s) => {
                v.data
                    .outbox
                    .get_mut(id)
                    .unwrap()
                    .receipts
                    .insert(key.clone(), s);
                v.commit()?;
            }
            Err(e) => errors.push(json!({"host":key,"error":format!("{e:#}")})),
        }
    }
    let item = v.data.outbox.get_mut(id).unwrap();
    let complete = item.receipts.len() == recipient.storage_hosts.len();
    item.state = if complete {
        "Stored"
    } else if item.receipts.is_empty() {
        "Queued"
    } else {
        "Partial"
    }
    .into();
    let durable = item.receipts.len() >= recipient.required_copies as usize;
    let result = json!({"messageId":id,"state":item.state,"durable":durable,"requiredCopies":recipient.required_copies,"storedHosts":item.receipts.keys().collect::<Vec<_>>(),"errors":errors});
    v.commit()?;
    Ok(result)
}
// Use exactly the live receiving set used by MLS and the authority's prekey claim.
fn default_expiry(
    recipient: &wire::Manifest,
    sender_expires: u64,
    device_expires: u64,
    now: u64,
) -> Result<u64> {
    let mut live = recipient
        .devices
        .iter()
        .filter(|d| d.expires > now && d.permissions.iter().any(|p| p == "Read"));
    let first = live.next().context("recipient has no live Read device")?;
    Ok(live.fold(
        now.saturating_add(recipient.retention_seconds)
            .min(recipient.expires)
            .min(sender_expires)
            .min(device_expires)
            .min(first.expires),
        |expiry, d| expiry.min(d.expires),
    ))
}
fn stored_receipt(
    c: &Config,
    h: &wire::Host,
    signed: &wire::Signed,
    cipher: &wire::Ciphertext,
    hash: &str,
) -> Result<()> {
    let r = receipt(c, h, signed, &cipher.route.message_id, Some(hash))?;
    ensure!(
        r.status == "Stored"
            && r.recipient_address == cipher.route.recipient_address
            && r.recipient_generation == cipher.route.recipient_generation
            && r.replacement == cipher.route.replacement
            && r.expires == cipher.route.expires
            && r.recorded_at < r.expires,
        "store receipt does not confirm these retained ciphertext bytes and route"
    );
    Ok(())
}
// A lost Put response is resolved before applying conditions for any new upload.
#[allow(clippy::too_many_arguments)]
fn deliver_prepared(
    c: &Config,
    actor: &crate::mail_vault::Mailbox,
    own: &wire::Manifest,
    host: &wire::Host,
    cipher: &wire::Ciphertext,
    bytes: &[u8],
    mut exchange: impl FnMut(&wire::Signed, Option<&[u8]>) -> Result<Value>,
    current_recipient: impl FnOnce() -> Result<wire::Signed>,
) -> Result<wire::Signed> {
    let id = &cipher.route.message_id;
    let hash = wire::digest(bytes);
    let query = operation(
        c,
        actor,
        own,
        host,
        "Receipt",
        Some(id),
        Some(hash.clone()),
        0,
        Some(cipher.route.clone()),
    )?;
    let response = exchange(&query, None)
        .context("receipt reconciliation remains unresolved; no upload attempted")?;
    let receipt_value = response
        .get("receipt")
        .context("receipt reconciliation omitted its result; no upload attempted")?;
    if !receipt_value.is_null() {
        let signed: wire::Signed = serde_json::from_value(receipt_value.clone())?;
        stored_receipt(c, host, &signed, cipher, &hash)?;
        return Ok(signed);
    }
    ensure!(
        cipher.route.expires > crate::now()?,
        "store has no retained receipt and queued mail expired"
    );
    ensure!(
        wire::object_digest(&cipher.sender_manifest)?
            == wire::object_digest(
                actor
                    .manifest
                    .as_ref()
                    .context("missing current sender manifest")?
            )?,
        "store has no retained receipt and prepared sender roster changed; no upload attempted"
    );
    let current = current_recipient()?;
    wire::manifest(&c.network, &current)?;
    ensure!(
        wire::object_digest(&current)? == wire::object_digest(&cipher.recipient_manifest)?,
        "store has no retained receipt and prepared recipient roster or placement changed; no upload attempted"
    );
    let op = operation(
        c,
        actor,
        own,
        host,
        "Put",
        Some(id),
        Some(hash.clone()),
        bytes.len() as u64,
        Some(cipher.route.clone()),
    )?;
    let response = exchange(&op, Some(bytes))?;
    let signed: wire::Signed = serde_json::from_value(response["receipt"].clone())?;
    stored_receipt(c, host, &signed, cipher, &hash)?;
    Ok(signed)
}
pub(super) fn duplicate_identity(key: &Identity) -> Identity {
    Identity {
        secret_key: key.secret_key.clone(),
        public_key: key.public_key.clone(),
    }
}
pub(super) fn inbox(v: &mut Vault, c: &Config, mailbox: &str, local: bool) -> Result<Value> {
    let address = v.mailbox(mailbox)?.address.clone();
    if local {
        return Ok(
            json!({"source":"LocalArchive","messages":v.data.archive.values().filter(|a|a.letter.route.recipient_address==address).map(|a|json!({"messageId":a.letter.route.message_id,"senderAddress":a.letter.route.sender_address,"subject":a.letter.subject,"origin":a.origin})).collect::<Vec<_>>()}),
        );
    }
    let m = refresh(v, c, mailbox)?;
    let request = duplicate_identity(&v.mailbox(mailbox)?.request);
    hosts(v, c, &request)?;
    let mut results = Vec::new();
    for key in &m.storage_hosts {
        let outcome = (|| -> Result<Value> {
            let h = selected_host(v, c, &m, key)?;
            let mut after = None;
            let mut entries = Vec::new();
            for _ in 0..9 {
                let op = operation(c, v.mailbox(mailbox)?, &m, &h, "List", None, None, 0, None)?;
                let mut body: wire::Operation =
                    wire::verify(wire::OPERATION, &c.network, &request.public_key, &op)?;
                body.after = after.clone();
                let op = wire::sign(wire::OPERATION, &c.network, &request, &body)?;
                let result = wire::store(c, &h, &op, None)?;
                for entry in result["entries"]
                    .as_array()
                    .context("missing mail list entries")?
                {
                    let s: wire::Signed = serde_json::from_value(entry.clone())?;
                    let r: wire::Receipt =
                        wire::verify(wire::RECEIPT, &c.network, &h.host_key, &s)?;
                    receipt(c, &h, &s, &r.message_id, None)?;
                    ensure!(
                        r.recipient_address == m.address_id,
                        "mail list returned another address"
                    );
                    entries.push(json!({"messageId":r.message_id,"digest":r.payload_digest,"status":r.status,"expires":r.expires}));
                    ensure!(entries.len() <= 512, "mail list exceeds quota");
                }
                let next = result["next"].as_str().map(str::to_owned);
                if next.is_none() {
                    return Ok(json!({"host":key,"entries":entries}));
                }
                ensure!(next != after, "mail list cursor did not advance");
                after = next;
            }
            bail!("mail list exceeded pagination bound")
        })();
        results.push(match outcome {
            Ok(x) => x,
            Err(e) => json!({"host":key,"error":format!("{e:#}")}),
        });
    }
    Ok(json!({"source":"SelectedStores","hosts":results}))
}
#[allow(clippy::too_many_arguments)]
pub(super) fn historical(
    v: &Vault,
    c: &Config,
    h: &wire::Host,
    cipher: &wire::Ciphertext,
    raw: &[u8],
    original: &wire::Signed,
    admission: &wire::Signed,
    stored: &wire::Signed,
) -> Result<u64> {
    let route = &cipher.route;
    let sender = wire::manifest(&c.network, &cipher.sender_manifest)?;
    let dev = sender
        .devices
        .iter()
        .find(|d| d.device_id == route.sender_device)
        .context("historical sender absent")?;
    let op: wire::Operation =
        wire::verify(wire::OPERATION, &c.network, &dev.request_key, original)?;
    let hash = wire::digest(raw);
    ensure!(
        op.version == 1
            && op.network == c.network
            && op.action == "Put"
            && op.address_id == sender.address_id
            && op.device_id == dev.device_id
            && op.manifest_generation == sender.generation
            && op.manifest_digest == wire::object_digest(&cipher.sender_manifest)?
            && op.host_key == h.host_key
            && op.message_id.as_deref() == Some(&route.message_id)
            && op.payload_digest.as_deref() == Some(&hash)
            && op.payload_bytes == raw.len() as u64
            && op.route.as_ref() == Some(route)
            && op.after.is_none(),
        "historical Put signature does not bind this ciphertext"
    );
    let p: wire::Permission = wire::verify(
        wire::PERMISSION,
        &c.network,
        &v.data.authority_signer,
        admission,
    )?;
    let r = receipt(c, h, stored, &route.message_id, Some(&hash))?;
    ensure!(
        p.version == 1
            && p.network == c.network
            && p.authority_epoch > 0
            && p.authority_revision > 0
            && p.host_key == h.host_key
            && p.host_generation == r.host_generation
            && p.operation_digest == wire::signed_digest(wire::OPERATION, original)?
            && p.address_id == op.address_id
            && p.manifest_generation == op.manifest_generation
            && p.manifest_digest == op.manifest_digest
            && p.expires > p.issued_at
            && p.expires <= p.issued_at.saturating_add(5)
            && r.recorded_at >= p.issued_at
            && r.recorded_at <= p.expires
            && op.issued_at <= p.issued_at.saturating_add(30)
            && op.issued_at.saturating_add(60) >= p.issued_at
            && r.recorded_at < route.expires
            && r.recipient_address == route.recipient_address
            && r.recipient_generation == route.recipient_generation
            && r.replacement == route.replacement
            && r.expires == route.expires
            && r.status == "Stored",
        "invalid original mail admission"
    );
    let contact = v
        .data
        .contacts
        .get(&sender.address_id)
        .context("verify sender owner fingerprint before reading first contact")?;
    ensure!(
        contact.owner_key == sender.owner_key,
        "sender owner fingerprint differs from verified contact"
    );
    Ok(r.recorded_at)
}
pub(super) fn read(
    v: &mut Vault,
    c: &Config,
    mailbox: &str,
    host_key: &str,
    id: &str,
) -> Result<Value> {
    crate::protocol::hex_bytes::<16>(id)?;
    let m = refresh(v, c, mailbox)?;
    let request = duplicate_identity(&v.mailbox(mailbox)?.request);
    hosts(v, c, &request)?;
    let h = selected_host(v, c, &m, host_key)?;
    let op = operation(
        c,
        v.mailbox(mailbox)?,
        &m,
        &h,
        "Fetch",
        Some(id),
        None,
        0,
        None,
    )?;
    let result = wire::store(c, &h, &op, None)?;
    let raw = wire::decode(
        result["payload"].as_str().context("missing mail payload")?,
        131072,
    )?;
    let cipher: wire::Ciphertext = serde_json::from_slice(&raw)?;
    ensure!(
        cipher.route.message_id == id && cipher.route.recipient_address == m.address_id,
        "store returned another letter"
    );
    let original = serde_json::from_value(result["operation"].clone())?;
    let admission = serde_json::from_value(result["admission"].clone())?;
    let stored = serde_json::from_value(result["receipt"].clone())?;
    let at = historical(v, c, &h, &cipher, &raw, &original, &admission, &stored)?;
    let key = format!(
        "{}/{}/{}",
        m.address_id,
        v.mailbox(mailbox)?.device.device_id,
        id
    );
    let hash = wire::digest(&raw);
    if let Some(existing) = v.data.archive.get(&key) {
        let old = existing
            .receipt
            .as_ref()
            .context("archive entry has no delivery provenance")?;
        let r: wire::Receipt = wire::verify(wire::RECEIPT, &c.network, &old.public_key, old)?;
        ensure!(
            r.payload_digest == hash,
            "different ciphertext reused an archived message ID"
        );
    } else {
        let b = v.mailbox(mailbox)?;
        let found = b
            .packages
            .iter()
            .enumerate()
            .find_map(|(i, p)| {
                crypto::open(&cipher, p, &b.device.device_id, at)
                    .ok()
                    .map(|letter| (i, letter))
            })
            .context("no unspent local KeyPackage can open this letter")?;
        let (index, letter) = found;
        v.data.archive.insert(
            key.clone(),
            Archived {
                letter,
                admission: Some(admission),
                receipt: Some(stored),
                origin: "Received".into(),
            },
        );
        v.mailbox_mut(mailbox)?.packages.remove(index);
        v.commit()?;
    }
    let op = operation(
        c,
        v.mailbox(mailbox)?,
        &m,
        &h,
        "Acknowledge",
        Some(id),
        Some(hash.clone()),
        0,
        None,
    )?;
    let acknowledgement = match wire::store(c, &h, &op, None) {
        Ok(result) => {
            let s: wire::Signed = serde_json::from_value(result["receipt"].clone())?;
            let r = receipt(c, &h, &s, id, Some(&hash))?;
            ensure!(r.status == "Received", "invalid receipt acknowledgement");
            json!({"status":"Received"})
        }
        Err(e) => json!({"status":"Pending","error":format!("{e:#}")}),
    };
    Ok(
        json!({"source":"AuthenticatedDelivery","letter":v.data.archive[&key].letter,"acknowledgement":acknowledgement}),
    )
}
pub(super) fn refill(v: &mut Vault, c: &Config, mailbox: &str, count: usize) -> Result<Value> {
    ensure!((1..=8).contains(&count), "refill count must be 1..8");
    let m = refresh(v, c, mailbox)?;
    let now = crate::now()?;
    v.mailbox_mut(mailbox)?.packages.retain(|p| p.expires > now);
    let b = v.mailbox(mailbox)?;
    ensure!(
        m.devices
            .iter()
            .any(|d| d == &b.device && d.permissions.iter().any(|p| p == "Read")),
        "current Read device grant required"
    );
    let unpublished = b
        .packages
        .iter()
        .any(|p| !p.published && p.generation == m.generation);
    if !unpublished {
        ensure!(
            b.packages
                .iter()
                .filter(|p| p.generation == m.generation)
                .count()
                + count
                <= 32
                && b.packages.len() + count <= 256,
            "local prekey quota reached; consume mail before refilling"
        );
        let (mut private, _) = crypto::make_packages(
            &c.network,
            &b.address,
            &b.device,
            &b.signer,
            count,
            m.expires.min(b.device.expires),
        )?;
        for p in &mut private {
            p.generation = m.generation;
        }
        v.mailbox_mut(mailbox)?.packages.extend(private);
        v.commit()?;
    }
    let b = v.mailbox(mailbox)?;
    let selected = b
        .packages
        .iter()
        .filter(|p| !p.published && p.generation == m.generation)
        .take(8)
        .map(|p| crypto::public_package(&b.device.device_id, p))
        .collect::<Result<Vec<_>>>()?;
    wire::authority(
        c,
        &b.request,
        json!({"type":"MailKeyPackagesPublish","addressId":b.address,"deviceId":b.device.device_id,"manifestGeneration":m.generation,"packages":selected}),
    )?;
    for p in &mut v.mailbox_mut(mailbox)?.packages {
        if selected.iter().any(|s| s.reference == p.reference) {
            p.published = true;
        }
    }
    v.commit()?;
    Ok(json!({"published":selected.len(),"privatePackages":v.mailbox(mailbox)?.packages.len()}))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::mail_vault::Mailbox;
    fn address(network: &str, host: &str, expires: u64) -> (Identity, Mailbox, wire::Signed) {
        let owner = wire::new_identity();
        let id = wire::address_id(network, &owner.public_key).unwrap();
        let mut actor =
            crate::mail::local_device(network, &id, expires, vec!["Read".into(), "Send".into()])
                .unwrap();
        let manifest = wire::Manifest {
            version: 1,
            network: network.into(),
            address_id: id,
            owner_key: owner.public_key.clone(),
            generation: 1,
            previous_digest: None,
            expires,
            devices: vec![actor.device.clone()],
            storage_hosts: vec![host.into()],
            required_copies: 1,
            retention_seconds: 3600,
            deleted: false,
        };
        let signed = wire::sign(wire::MANIFEST, network, &owner, &manifest).unwrap();
        actor.manifest = Some(signed.clone());
        (owner, actor, signed)
    }
    fn renewed(network: &str, owner: &Identity, old: &wire::Signed) -> wire::Signed {
        let mut m = wire::manifest(network, old).unwrap();
        m.generation += 1;
        m.previous_digest = Some(wire::object_digest(old).unwrap());
        m.expires += 1;
        wire::sign(wire::MANIFEST, network, owner, &m).unwrap()
    }
    struct Fixture {
        config: Config,
        host: wire::Host,
        host_key: Identity,
        sender_owner: Identity,
        actor: Mailbox,
        cipher: wire::Ciphertext,
        recipient_owner: Identity,
    }
    impl Fixture {
        fn new() -> Self {
            let network = "71".repeat(32);
            let now = crate::now().unwrap();
            let host_key = wire::new_identity();
            let (sender_owner, actor, sender) = address(&network, &host_key.public_key, now + 300);
            let (recipient_owner, recipient_actor, recipient) =
                address(&network, &host_key.public_key, now + 300);
            let route = wire::Route {
                version: 1,
                profile: wire::PROFILE.into(),
                network: network.clone(),
                message_id: "72".repeat(16),
                replacement: 0,
                sender_address: actor.address.clone(),
                sender_device: actor.device.device_id.clone(),
                recipient_address: recipient_actor.address.clone(),
                recipient_generation: 1,
                recipient_manifest_digest: wire::object_digest(&recipient).unwrap(),
                claim_id: "73".repeat(16),
                expires: now + 120,
            };
            let host = wire::Host {
                version: 1,
                network: network.clone(),
                host_key: host_key.public_key.clone(),
                generation: 2,
                services: vec!["Mail".into()],
                endpoint: "https://store.example/".into(),
                address: "127.0.0.1:443".into(),
                ca_digest: "74".repeat(32),
                certificate_digest: "75".repeat(32),
                authority_endpoint: "https://authority.example/".into(),
                authority_address: "127.0.0.1:444".into(),
                authority_signer: "76".repeat(32),
                memory_bytes: 536870912,
                pids: 32,
                cpu_quota: 100000,
                cpu_period: 100000,
                state_bytes: 8388608,
                expires: now + 300,
            };
            let config = Config {
                application: false,
                network,
                endpoint: "https://authority.example/".into(),
                ca_certificate: "UnusedCA".into(),
                identity: "UnusedIdentity".into(),
                client_certificate: None,
                client_key: None,
            };
            Self {
                config,
                host,
                host_key,
                sender_owner,
                actor,
                cipher: wire::Ciphertext {
                    route,
                    sender_manifest: sender,
                    recipient_manifest: recipient,
                    welcome: "AA".into(),
                    message: "AQ".into(),
                },
                recipient_owner,
            }
        }
        fn receipt(&self, bytes: &[u8]) -> wire::Signed {
            let r = &self.cipher.route;
            wire::sign(
                wire::RECEIPT,
                &self.config.network,
                &self.host_key,
                &wire::Receipt {
                    version: 1,
                    network: r.network.clone(),
                    host_key: self.host_key.public_key.clone(),
                    host_generation: 1,
                    message_id: r.message_id.clone(),
                    replacement: r.replacement,
                    payload_digest: wire::digest(bytes),
                    recipient_address: r.recipient_address.clone(),
                    recipient_generation: r.recipient_generation,
                    status: "Stored".into(),
                    recorded_at: crate::now().unwrap(),
                    expires: r.expires,
                },
            )
            .unwrap()
        }
    }
    #[test]
    fn default_expiry_uses_live_readers_and_rejects_no_live_recipient() {
        let f = Fixture::new();
        let now = crate::now().unwrap();
        let mut m = wire::manifest(&f.config.network, &f.cipher.recipient_manifest).unwrap();
        m.devices[0].expires = now + 100;
        let mut expired = crate::mail::local_device(
            &f.config.network,
            &m.address_id,
            now + 100,
            vec!["Read".into()],
        )
        .unwrap();
        expired.device.expires = now - 1;
        let sender_only = crate::mail::local_device(
            &f.config.network,
            &m.address_id,
            now + 10,
            vec!["Send".into()],
        )
        .unwrap();
        m.devices
            .extend([expired.device.clone(), sender_only.device.clone()]);
        let signed = wire::sign(wire::MANIFEST, &f.config.network, &f.recipient_owner, &m).unwrap();
        wire::manifest(&f.config.network, &signed).unwrap();
        assert_eq!(
            default_expiry(&m, now + 200, now + 150, now).unwrap(),
            now + 100
        );
        m.devices[0].expires = now;
        assert!(default_expiry(&m, now + 200, now + 150, now).is_err());
    }
    #[test]
    fn lost_put_receipt_survives_sender_and_recipient_renewal_without_upload() {
        for renew_sender in [false, true] {
            let mut f = Fixture::new();
            if renew_sender {
                f.actor.manifest = Some(renewed(
                    &f.config.network,
                    &f.sender_owner,
                    &f.cipher.sender_manifest,
                ));
            }
            let current_recipient = renewed(
                &f.config.network,
                &f.recipient_owner,
                &f.cipher.recipient_manifest,
            );
            let bytes = serde_json::to_vec(&f.cipher).unwrap();
            let original = bytes.clone();
            let signed = f.receipt(&bytes);
            let own =
                wire::manifest(&f.config.network, f.actor.manifest.as_ref().unwrap()).unwrap();
            let mut actions = Vec::new();
            let result = deliver_prepared(
                &f.config,
                &f.actor,
                &own,
                &f.host,
                &f.cipher,
                &bytes,
                |op, payload| {
                    let op: wire::Operation = wire::verify(
                        wire::OPERATION,
                        &f.config.network,
                        &f.actor.request.public_key,
                        op,
                    )?;
                    assert!(payload.is_none());
                    assert!(op.route.as_ref() == Some(&f.cipher.route));
                    assert_eq!(op.payload_digest, Some(wire::digest(&bytes)));
                    assert_eq!(op.manifest_generation, own.generation);
                    actions.push(op.action);
                    Ok(json!({"receipt":signed}))
                },
                || {
                    let _ = &current_recipient;
                    panic!(
                        "a stored receipt must be reconciled before reading a new recipient roster"
                    )
                },
            )
            .unwrap();
            assert_eq!(
                wire::signed_digest(wire::RECEIPT, &result).unwrap(),
                wire::signed_digest(wire::RECEIPT, &signed).unwrap()
            );
            assert_eq!(actions, vec!["Receipt"]);
            assert_eq!(bytes, original);
        }
    }
    #[test]
    fn absent_or_untrusted_receipt_cannot_bypass_fresh_upload_constraints() {
        for sender_changed in [false, true] {
            let mut f = Fixture::new();
            if sender_changed {
                f.actor.manifest = Some(renewed(
                    &f.config.network,
                    &f.sender_owner,
                    &f.cipher.sender_manifest,
                ));
            }
            let current = renewed(
                &f.config.network,
                &f.recipient_owner,
                &f.cipher.recipient_manifest,
            );
            let own =
                wire::manifest(&f.config.network, f.actor.manifest.as_ref().unwrap()).unwrap();
            let bytes = serde_json::to_vec(&f.cipher).unwrap();
            let mut calls = 0;
            assert!(
                deliver_prepared(
                    &f.config,
                    &f.actor,
                    &own,
                    &f.host,
                    &f.cipher,
                    &bytes,
                    |op, payload| {
                        calls += 1;
                        let op: wire::Operation = wire::verify(
                            wire::OPERATION,
                            &f.config.network,
                            &f.actor.request.public_key,
                            op,
                        )?;
                        assert_eq!(op.action, "Receipt");
                        assert!(payload.is_none());
                        Ok(json!({"receipt":null}))
                    },
                    || Ok(current)
                )
                .is_err()
            );
            assert_eq!(calls, 1);
        }
        let f = Fixture::new();
        let own = wire::manifest(&f.config.network, f.actor.manifest.as_ref().unwrap()).unwrap();
        let bytes = serde_json::to_vec(&f.cipher).unwrap();
        let forged = f.receipt(b"different ciphertext");
        let mut calls = 0;
        assert!(
            deliver_prepared(
                &f.config,
                &f.actor,
                &own,
                &f.host,
                &f.cipher,
                &bytes,
                |_, payload| {
                    calls += 1;
                    assert!(payload.is_none());
                    Ok(json!({"receipt":forged}))
                },
                || panic!("mismatched receipt must not lead to upload")
            )
            .is_err()
        );
        assert_eq!(calls, 1);
        assert!(
            deliver_prepared(
                &f.config,
                &f.actor,
                &own,
                &f.host,
                &f.cipher,
                &bytes,
                |_, payload| {
                    assert!(payload.is_none());
                    bail!("response lost")
                },
                || panic!("unresolved receipt must not lead to upload")
            )
            .is_err()
        );
    }
    #[test]
    fn confirmed_absence_uploads_only_exact_retained_bytes() {
        let f = Fixture::new();
        let own = wire::manifest(&f.config.network, f.actor.manifest.as_ref().unwrap()).unwrap();
        let bytes = serde_json::to_vec(&f.cipher).unwrap();
        let signed = f.receipt(&bytes);
        let mut actions = Vec::new();
        deliver_prepared(
            &f.config,
            &f.actor,
            &own,
            &f.host,
            &f.cipher,
            &bytes,
            |op, payload| {
                let op: wire::Operation = wire::verify(
                    wire::OPERATION,
                    &f.config.network,
                    &f.actor.request.public_key,
                    op,
                )?;
                actions.push(op.action.clone());
                if op.action == "Receipt" {
                    assert!(payload.is_none());
                    Ok(json!({"receipt":null}))
                } else {
                    assert_eq!(op.action, "Put");
                    assert_eq!(payload, Some(bytes.as_slice()));
                    assert_eq!(op.payload_bytes, bytes.len() as u64);
                    Ok(json!({"receipt":signed}))
                }
            },
            || Ok(f.cipher.recipient_manifest.clone()),
        )
        .unwrap();
        assert_eq!(actions, vec!["Receipt", "Put"]);
    }
}
