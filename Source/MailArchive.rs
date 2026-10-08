// SPDX-License-Identifier: MIT
// Explicit encrypted history export; active MLS state is never restored from an archive.
use crate::{
    Config, Identity,
    mail::{label, local_device},
    mail_crypto as crypto, mail_protocol as wire,
    mail_vault::{self, Archived, Vault},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};
const DOMAIN: &[u8] = b"HyperNet/MailArchive/1\0";
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Contents {
    version: u32,
    network: String,
    address_id: String,
    manifest: wire::Signed,
    records: BTreeMap<String, Archived>,
    owner_recovery: Option<Identity>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Attestation {
    version: u32,
    network: String,
    address_id: String,
    manifest_digest: String,
    content_digest: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Archive {
    contents: Contents,
    attestation: wire::Signed,
}
pub fn export(
    v: &Vault,
    c: &Config,
    mailbox: &str,
    recipient: &str,
    path: &Path,
    recovery: bool,
) -> Result<Value> {
    let b = v.mailbox(mailbox)?;
    let manifest = b
        .manifest
        .as_ref()
        .context("registered manifest required for export")?
        .clone();
    let mut records = v
        .data
        .archive
        .iter()
        .filter(|(_, a)| {
            a.letter.route.recipient_address == b.address
                || a.letter.route.sender_address == b.address
        })
        .map(|(k, a)| (k.clone(), a.clone()))
        .collect::<BTreeMap<_, _>>();
    for out in v.data.outbox.values().filter(|o| o.mailbox == mailbox) {
        if let Some(cipher) = &out.ciphertext {
            records
                .entry(format!("Sent/{}", out.message_id))
                .or_insert_with(|| Archived {
                    letter: crypto::Letter {
                        route: cipher.route.clone(),
                        subject: out.subject.clone(),
                        body: out.body.clone(),
                    },
                    admission: None,
                    receipt: None,
                    origin: format!("Sent:{}", out.state),
                });
        }
    }
    let owner = if recovery {
        let key = b
            .owner
            .as_ref()
            .context("this device does not hold the owner recovery key")?;
        Some(Identity {
            secret_key: key.secret_key.clone(),
            public_key: key.public_key.clone(),
        })
    } else {
        None
    };
    let contents = Contents {
        version: 1,
        network: c.network.clone(),
        address_id: b.address.clone(),
        manifest,
        records,
        owner_recovery: owner,
    };
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&contents)?);
    let attestation = wire::sign(
        DOMAIN,
        &c.network,
        b.owner.as_ref().unwrap_or(&b.request),
        &Attestation {
            version: 1,
            network: c.network.clone(),
            address_id: b.address.clone(),
            manifest_digest: wire::object_digest(&contents.manifest)?,
            content_digest: wire::digest(&bytes),
        },
    )?;
    let archive = Archive {
        contents,
        attestation,
    };
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&archive)?);
    ensure!(
        bytes.len() <= mail_vault::MAX_VAULT,
        "mail archive exceeds size limit"
    );
    let encrypted = crypto::encrypt_age(recipient, &bytes)?;
    mail_vault::write_new(path, &encrypted)?;
    Ok(
        json!({"addressId":b.address,"records":archive.contents.records.len(),"includesOwnerRecovery":recovery,"recipient":recipient}),
    )
}
fn load(v: &Vault, c: &Config, path: &Path, expected: &str) -> Result<Archive> {
    crate::protocol::hex_bytes::<32>(expected)?;
    let encrypted = mail_vault::read_private(path, mail_vault::MAX_VAULT + 65536)?;
    let plain = crypto::decrypt_age(v.age_identity(), &encrypted, mail_vault::MAX_VAULT)?;
    let archive: Archive = serde_json::from_slice(&plain)?;
    let content = &archive.contents;
    ensure!(
        content.version == 1
            && content.network == c.network
            && content.address_id == expected
            && content.records.len() <= 1024,
        "archive identity or quota mismatch"
    );
    let m = wire::manifest(&c.network, &content.manifest)?;
    ensure!(
        m.address_id == expected,
        "archive manifest belongs to another address"
    );
    ensure!(
        archive.attestation.public_key == m.owner_key
            || m.devices
                .iter()
                .any(|d| d.request_key == archive.attestation.public_key
                    && d.permissions.iter().any(|p| p == "Read" || p == "Send")),
        "archive signer was not an authorised device or owner"
    );
    let a: Attestation = wire::verify(
        DOMAIN,
        &c.network,
        &archive.attestation.public_key,
        &archive.attestation,
    )?;
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(content)?);
    ensure!(
        a.version == 1
            && a.network == c.network
            && a.address_id == expected
            && a.manifest_digest == wire::object_digest(&content.manifest)?
            && a.content_digest == wire::digest(&bytes),
        "archive attestation mismatch"
    );
    for r in content.records.values() {
        ensure!(
            r.letter.route.network == c.network
                && (r.letter.route.recipient_address == expected
                    || r.letter.route.sender_address == expected)
                && r.letter.subject.len() <= 512
                && r.letter.body.len() <= 32768,
            "archive contains invalid letter"
        );
    }
    if let Some(key) = &content.owner_recovery {
        ensure!(
            key.public_key == m.owner_key
                && wire::address_id(&c.network, &key.public_key)? == expected,
            "recovery owner differs from archive owner"
        );
        let _: wire::Signed = wire::sign(DOMAIN, &c.network, key, &a)?;
    }
    Ok(archive)
}
pub fn import(v: &mut Vault, c: &Config, path: &Path, expected: &str) -> Result<Value> {
    let archive = load(v, c, path, expected)?;
    let count = archive.contents.records.len();
    let digest = wire::signed_digest(DOMAIN, &archive.attestation)?;
    for (key, mut record) in archive.contents.records {
        record.origin = "ImportedArchive".into();
        v.data
            .archive
            .entry(format!("Import/{digest}/{key}"))
            .or_insert(record);
    }
    v.commit()?;
    Ok(json!({"addressId":expected,"importedRecords":count,"activeKeysRestored":false}))
}
pub fn recover(
    v: &mut Vault,
    c: &Config,
    mailbox: &str,
    path: &Path,
    expected: &str,
) -> Result<Value> {
    label(mailbox)?;
    ensure!(
        !v.data.mailboxes.contains_key(mailbox),
        "recovery mailbox label exists"
    );
    let mut archive = load(v, c, path, expected)?;
    let owner = archive
        .contents
        .owner_recovery
        .take()
        .context("archive does not contain explicitly exported owner recovery material")?;
    let signed = wire::address_get(c, &owner, expected)?;
    let mut m = wire::manifest(&c.network, &signed)?;
    ensure!(
        !m.deleted,
        "deleted addresses cannot be recovered for fresh mail"
    );
    let now = crate::now()?;
    let can_enrol = m.expires > now && m.devices.len() < 8;
    let mut b = local_device(
        &c.network,
        expected,
        if m.expires > now {
            m.expires
        } else {
            now.saturating_add(604800)
        },
        vec!["Read".into(), "Send".into(), "Delete".into()],
    )?;
    b.owner = Some(owner);
    b.manifest = Some(signed.clone());
    if !can_enrol {
        v.data.mailboxes.insert(mailbox.into(), b);
        v.commit()?;
        return Ok(
            json!({"mailbox":mailbox,"addressId":expected,"deviceId":v.mailbox(mailbox)?.device.device_id,"ownerRecovered":true,"freshDeviceEnrolled":false,"oldPrekeysRestored":false,"historyImported":false,"next":"Renew the address or revoke an old device, then device-export and device-enrol the fresh binding"}),
        );
    }
    m.devices.push(b.device.clone());
    m.generation += 1;
    m.previous_digest = Some(wire::object_digest(&signed)?);
    let new = wire::sign(wire::MANIFEST, &c.network, b.owner.as_ref().unwrap(), &m)?;
    v.data.mailboxes.insert(mailbox.into(), b);
    v.commit()?;
    wire::authority(
        c,
        v.mailbox(mailbox)?.owner.as_ref().unwrap(),
        json!({"type":"MailAddressUpdate","addressId":expected,"expectedGeneration":m.generation-1,"manifest":new}),
    )?;
    v.set_manifest(mailbox, new)?;
    Ok(
        json!({"mailbox":mailbox,"addressId":expected,"deviceId":v.mailbox(mailbox)?.device.device_id,"freshDeviceEnrolled":true,"oldPrekeysRestored":false,"historyImported":false}),
    )
}
