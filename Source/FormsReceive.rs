// SPDX-License-Identifier: MIT
// Anchor typed form intake to independently accepted publications and authenticated mail.
use super::{Settings, Submission, bounded, form, own, publication};
use crate::{
    Config, mail_crypto::Letter, mail_delivery, mail_vault::Vault, markup, page_proof::Descriptor,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Accepted {
    pub network: String,
    pub recipient_address: String,
    pub descriptor: Descriptor,
    pub form_id: String,
    pub schema_digest: String,
    pub bundle_digest: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LedgerEntry {
    pub payload_digest: String,
    pub accepted_record: String,
}
fn record_key(descriptor: &Descriptor, form_id: &str) -> Result<String> {
    super::payload_digest(&(descriptor, form_id))
}
pub fn accept(
    c: &Config,
    reader: &Config,
    settings: &Settings,
    page_id: &str,
    form_id: &str,
) -> Result<Value> {
    ensure!(
        c.network == reader.network,
        "accepted form cannot cross networks"
    );
    let (descriptor, bundle) = publication(reader, page_id)?;
    let f = form(&c.network, &descriptor, &bundle, form_id)?;
    let mut v = Vault::open(&settings.vault, &settings.key, &c.network)?;
    let receiver = own(&mut v, c, &settings.mailbox, "Read")?;
    ensure!(
        f.recipient == receiver.address_id && f.owner == receiver.owner_key,
        "form does not target this receiving mailbox and owner"
    );
    let key = record_key(&descriptor, form_id)?;
    ensure!(
        v.data.accepted_forms.contains_key(&key) || v.data.accepted_forms.len() < 128,
        "accepted form quota reached"
    );
    let record = Accepted {
        network: c.network.clone(),
        recipient_address: receiver.address_id,
        descriptor,
        form_id: form_id.into(),
        schema_digest: f.schema_digest,
        bundle_digest: super::payload_digest(&bundle)?,
    };
    v.data.accepted_forms.insert(key.clone(), record.clone());
    v.commit()?;
    Ok(json!({"acceptedRecord":key,"record":record}))
}
fn validated(v: &mut Vault, network: &str, address: &str, letter: &Letter) -> Result<Value> {
    ensure!(
        letter.body.len() <= 32768,
        "form mail body exceeds its bound"
    );
    let payload_digest = super::payload_digest(&(&letter.route, &letter.body))?;
    if let Some(previous) = v.data.form_ledger.get(&letter.route.message_id) {
        ensure!(
            previous.payload_digest == payload_digest,
            "different form payload reused a submission ID"
        );
    }
    let value: Value = match serde_json::from_str(&letter.body) {
        Ok(value) => value,
        Err(_) => return Ok(json!({"status":"Unrecognised","messageId":letter.route.message_id})),
    };
    if value.get("profile").and_then(Value::as_str) != Some(super::PROFILE) {
        return Ok(json!({"status":"Unrecognised","messageId":letter.route.message_id}));
    }
    let s: Submission = serde_json::from_str(&letter.body)?;
    bounded(&s)?;
    let route = &letter.route;
    ensure!(
        s.network == network
            && route.network == network
            && s.submission_id == route.message_id
            && s.sender_address == route.sender_address
            && s.sender_device == route.sender_device
            && s.recipient_address == route.recipient_address
            && s.recipient_address == address
            && s.recipient_manifest_digest == route.recipient_manifest_digest
            && s.expires == route.expires,
        "form submission does not match authenticated mail route"
    );
    let f = form(network, &s.descriptor, &s.bundle, &s.form_id)?;
    ensure!(
        f.recipient == address && f.schema_digest == s.schema_digest,
        "form submission changed its recipient or schema"
    );
    markup::forms::validate_values(&f, &s.values).map_err(anyhow::Error::msg)?;
    let key = record_key(&s.descriptor, &s.form_id)?;
    let Some(accepted) = v.data.accepted_forms.get(&key) else {
        return Ok(
            json!({"status":"Unrecognised","messageId":route.message_id,"reason":"PublicationNotAccepted"}),
        );
    };
    ensure!(
        accepted.network == network
            && accepted.recipient_address == address
            && accepted.descriptor == s.descriptor
            && accepted.form_id == s.form_id
            && accepted.schema_digest == s.schema_digest
            && accepted.bundle_digest == super::payload_digest(&s.bundle)?,
        "submission differs from independently accepted publication"
    );
    // Hash the exact received body and authenticated route, not a re-encoded values object.
    let duplicate = if let Some(previous) = v.data.form_ledger.get(&s.submission_id) {
        ensure!(
            previous.payload_digest == payload_digest && previous.accepted_record == key,
            "different form payload reused a submission ID"
        );
        true
    } else {
        ensure!(
            v.data.form_ledger.len() < 1024,
            "form submission ledger quota reached"
        );
        v.data.form_ledger.insert(
            s.submission_id.clone(),
            LedgerEntry {
                payload_digest,
                accepted_record: key.clone(),
            },
        );
        v.commit()?;
        false
    };
    Ok(
        json!({"status":"Accepted","duplicate":duplicate,"acceptedRecord":key,
        "submissionId":s.submission_id,"network":s.network,"senderAddress":s.sender_address,
        "senderDevice":s.sender_device,"recipientAddress":s.recipient_address,
        "descriptor":s.descriptor,"formId":s.form_id,"schemaDigest":s.schema_digest,"values":s.values,
        "businessProcessing":"NotPerformed"}),
    )
}
pub fn receive(
    c: &Config,
    settings: &Settings,
    host: Option<&str>,
    message_id: &str,
    local: bool,
) -> Result<Value> {
    crate::protocol::hex_bytes::<16>(message_id)?;
    let mut v = Vault::open(&settings.vault, &settings.key, &c.network)?;
    if !local {
        mail_delivery::read(
            &mut v,
            c,
            &settings.mailbox,
            host.context("--host is required")?,
            message_id,
        )?;
    }
    let mailbox = v.mailbox(&settings.mailbox)?;
    let address = mailbox.address.clone();
    let key = format!("{}/{}/{}", address, mailbox.device.device_id, message_id);
    let record = v
        .data
        .archive
        .get(&key)
        .context("message has not been authenticated for this receiving device")?;
    ensure!(
        record.origin == "Received" && record.admission.is_some() && record.receipt.is_some(),
        "imported archive data is not authenticated form intake"
    );
    let letter = record.letter.clone();
    validated(&mut v, &c.network, &address, &letter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mail_protocol as wire;
    use crate::{
        forms::Submission,
        page_proof::{Bundle, Envelope},
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;

    fn proof(seed: u8, command: Value) -> Envelope {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let payload = serde_json::to_vec(
            &json!({"version":1,"requestId":"02".repeat(16),"issuedAt":1,"command":command}),
        )
        .unwrap();
        let public = key.verifying_key().to_bytes();
        let mut bytes = b"HyperNet/Request/1\0".to_vec();
        bytes.extend([1; 32]);
        bytes.extend(public);
        bytes.extend(&payload);
        Envelope {
            network: "01".repeat(32),
            public_key: hex::encode(public),
            payload: URL_SAFE_NO_PAD.encode(payload),
            signature: hex::encode(key.sign(&bytes).to_bytes()),
        }
    }
    fn fixture() -> (Submission, Letter) {
        let owner = "05".repeat(32);
        let recipient = wire::address_id(&"01".repeat(32), &owner).unwrap();
        let source = format!(
            "HyperNetPage/2\n# Contact\n@Form {{\"id\":\"Contact\",\"label\":\"Contact\",\"profile\":\"HyperNetFormMail/1\",\"recipient\":\"{recipient}\",\"owner\":\"{owner}\"}}\n@Field {{\"id\":\"Name\",\"label\":\"Name\",\"kind\":\"Text\",\"maxBytes\":40,\"required\":true}}\n@Submit {{\"label\":\"Send\"}}\n@End\n"
        );
        let submitted = proof(
            3,
            json!({"type":"PageSubmit","pageId":"04".repeat(16),"expectedVersion":0,"namespace":"News","audience":"Members","profile":markup::PROFILE,"digest":wire::digest(source.as_bytes()),"body":source}),
        );
        let (page, source_digest) =
            crate::page_proof::submission(&"01".repeat(32), &submitted).unwrap();
        let approval = proof(
            5,
            json!({"type":"PageReview","pageId":page.page_id,"expectedVersion":1,"revision":1,"digest":page.digest,"profile":markup::PROFILE,"author":submitted.public_key,"namespace":"News","audience":"Members","submissionDigest":source_digest,"decision":"Approve"}),
        );
        let (_, approval_digest) =
            crate::page_proof::envelope::<Value>(&"01".repeat(32), &approval).unwrap();
        let descriptor = Descriptor {
            page_id: page.page_id,
            publication_version: 2,
            revision: 1,
            author: submitted.public_key.clone(),
            reviewer: approval.public_key.clone(),
            namespace: "News".into(),
            audience: "Members".into(),
            profile: markup::PROFILE.into(),
            digest: page.digest,
            submission_digest: source_digest,
            approval_digest,
        };
        let bundle = Bundle {
            submission: submitted,
            approval,
        };
        let f = form(&"01".repeat(32), &descriptor, &bundle, "Contact").unwrap();
        let s = Submission {
            profile: super::super::PROFILE.into(),
            submission_id: "08".repeat(16),
            network: "01".repeat(32),
            sender_address: "09".repeat(32),
            sender_device: "10".repeat(32),
            recipient_address: recipient,
            recipient_manifest_digest: "11".repeat(32),
            expires: 100,
            descriptor,
            bundle,
            form_id: f.id,
            schema_digest: f.schema_digest,
            values: BTreeMap::from([("Name".into(), json!("Ada"))]),
        };
        let letter = Letter {
            route: wire::Route {
                version: 1,
                profile: wire::PROFILE.into(),
                network: s.network.clone(),
                message_id: s.submission_id.clone(),
                replacement: 0,
                sender_address: s.sender_address.clone(),
                sender_device: s.sender_device.clone(),
                recipient_address: s.recipient_address.clone(),
                recipient_generation: 1,
                recipient_manifest_digest: s.recipient_manifest_digest.clone(),
                claim_id: "12".repeat(16),
                expires: s.expires,
            },
            subject: "Contact".into(),
            body: bounded(&s).unwrap(),
        };
        (s, letter)
    }
    #[test]
    fn receiver_anchor_route_schema_and_durable_replay_are_required() {
        let root = std::env::temp_dir().join(format!("HyperNetForms{}", crate::random_hex::<16>()));
        let keyfile = root.with_extension("Identity");
        let (s, mut letter) = fixture();
        let mut v = Vault::initialise(&root, &keyfile, &s.network, &"13".repeat(32)).unwrap();
        assert_eq!(
            validated(&mut v, &s.network, &s.recipient_address, &letter).unwrap()["status"],
            "Unrecognised"
        );
        let key = record_key(&s.descriptor, &s.form_id).unwrap();
        v.data.accepted_forms.insert(
            key,
            Accepted {
                network: s.network.clone(),
                recipient_address: s.recipient_address.clone(),
                descriptor: s.descriptor.clone(),
                form_id: s.form_id.clone(),
                schema_digest: s.schema_digest.clone(),
                bundle_digest: super::super::payload_digest(&s.bundle).unwrap(),
            },
        );
        let result = validated(&mut v, &s.network, &s.recipient_address, &letter).unwrap();
        assert_eq!(result["status"], "Accepted");
        assert_eq!(result["duplicate"], false);
        drop(v);
        let mut v = Vault::open(&root, &keyfile, &s.network).unwrap();
        assert_eq!(
            validated(&mut v, &s.network, &s.recipient_address, &letter).unwrap()["duplicate"],
            true
        );
        let mut changed = s.clone();
        changed.values.insert("Name".into(), json!("Different"));
        letter.body = bounded(&changed).unwrap();
        assert!(validated(&mut v, &s.network, &s.recipient_address, &letter).is_err());
        changed = s.clone();
        changed.schema_digest = "14".repeat(32);
        letter.body = bounded(&changed).unwrap();
        assert!(validated(&mut v, &s.network, &s.recipient_address, &letter).is_err());
        letter.body = bounded(&s).unwrap();
        letter.route.sender_address = "15".repeat(32);
        assert!(validated(&mut v, &s.network, &s.recipient_address, &letter).is_err());
        letter.body = "{\"profile\":\"HyperNetFormSubmission/2\"}".into();
        assert!(validated(&mut v, &s.network, &s.recipient_address, &letter).is_err());
        letter.route.message_id = "17".repeat(16);
        assert_eq!(
            validated(&mut v, &s.network, &s.recipient_address, &letter).unwrap()["status"],
            "Unrecognised"
        );
        drop(v);
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_file(keyfile).unwrap();
    }
}
