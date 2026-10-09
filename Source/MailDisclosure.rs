// SPDX-License-Identifier: MIT
// Export one explicitly selected archived letter without keys, vaults or recovery material.
use crate::{
    Config, adapter_files as files, mail_crypto::Letter, mail_protocol as wire, mail_vault::Vault,
};
use anyhow::{Context, Result, ensure};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::PathBuf;
#[derive(Args)]
pub struct Arguments {
    #[arg(long)]
    pub mailbox: String,
    #[arg(long)]
    pub address: String,
    #[arg(long)]
    pub message_id: String,
    #[arg(long)]
    pub recipient: String,
    #[arg(long)]
    pub purpose: String,
    #[arg(long)]
    pub expires: u64,
    #[arg(long)]
    pub consent_disclosure: bool,
    #[arg(long)]
    pub output: PathBuf,
    #[arg(long)]
    pub receipt: PathBuf,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Metadata {
    version: u32,
    kind: String,
    network: String,
    disclosure_id: String,
    address_id: String,
    message_id: String,
    recipient: String,
    purpose: String,
    issued_at: u64,
    expires: u64,
    consent_disclosure: bool,
    content_digest: String,
    origin: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LetterDisclosure {
    disclosure: Metadata,
    letter: Letter,
}
pub fn export(v: &Vault, c: &Config, args: Arguments) -> Result<Value> {
    ensure!(
        args.consent_disclosure,
        "--consent-disclosure is required to release plaintext"
    );
    files::label(&args.recipient)?;
    files::purpose(&args.purpose)?;
    crate::protocol::hex_bytes::<32>(&args.address)?;
    crate::protocol::hex_bytes::<16>(&args.message_id)?;
    let now = crate::now()?;
    files::lifetime(now, args.expires, now)?;
    let mailbox = v.mailbox(&args.mailbox)?;
    ensure!(
        mailbox.address == args.address,
        "mailbox differs from selected address"
    );
    let mut matches = v.data.archive.values().filter(|a| {
        a.letter.route.message_id == args.message_id
            && (a.letter.route.recipient_address == args.address
                || a.letter.route.sender_address == args.address)
    });
    let record = matches
        .next()
        .context("selected letter is not in the local archive")?;
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&record.letter)?);
    for other in matches {
        ensure!(
            serde_json::to_vec(&other.letter)? == *bytes,
            "ambiguous archived message; conflicting copies cannot be disclosed"
        );
    }
    ensure!(
        record.letter.route.network == c.network
            && record.letter.subject.len() <= 512
            && record.letter.body.len() <= 32768,
        "invalid archived letter"
    );
    let metadata = Metadata {
        version: 1,
        kind: "MailLetter".into(),
        network: c.network.clone(),
        disclosure_id: crate::random_hex::<16>(),
        address_id: args.address.clone(),
        message_id: args.message_id.clone(),
        recipient: args.recipient,
        purpose: args.purpose,
        issued_at: now,
        expires: args.expires,
        consent_disclosure: true,
        content_digest: wire::digest(&bytes),
        origin: record.origin.clone(),
    };
    let receipt = files::sign(c, &mailbox.request, &metadata)?;
    let disclosure = LetterDisclosure {
        disclosure: metadata,
        letter: record.letter.clone(),
    };
    // Save provenance before plaintext leaves the vault; neither file replaces existing data.
    files::write(&args.receipt, &receipt)?;
    files::lifetime(now, args.expires, crate::now()?)?;
    files::write(&args.output, &disclosure)?;
    Ok(json!({"addressId":args.address,"messageId":args.message_id,
        "recipient":disclosure.disclosure.recipient,"contentDigest":disclosure.disclosure.content_digest,
        "output":args.output,"receipt":args.receipt,"activeKeysExported":false,
        "source":"LocalArchive","expires":args.expires}))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{mail_vault::Archived, transfer_files};
    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn native_message_id_discloses_only_selected_archived_letter() {
        let root = Fixture(std::env::temp_dir().join(format!(
            "HyperNetMailDisclosure{}",
            crate::random_hex::<16>()
        )));
        transfer_files::create_directory(&root.0).unwrap();
        let c = Config {
            application: false,
            network: "01".repeat(32),
            endpoint: "https://example.test".into(),
            ca_certificate: "Unused".into(),
            identity: "Unused".into(),
            client_certificate: None,
            client_key: None,
        };
        let address = "02".repeat(32);
        let now = crate::now().unwrap();
        let message_id = crate::random_hex::<16>();
        let mut vault = Vault::initialise(
            &root.0.join("Vault"),
            &root.0.join("Key"),
            &c.network,
            &"03".repeat(32),
        )
        .unwrap();
        vault.data.mailboxes.insert(
            "Personal".into(),
            crate::mail::local_device(&c.network, &address, now + 300, vec!["Read".into()])
                .unwrap(),
        );
        let letter = Letter {
            route: wire::Route {
                version: 1,
                profile: wire::PROFILE.into(),
                network: c.network.clone(),
                message_id: message_id.clone(),
                replacement: 0,
                sender_address: "04".repeat(32),
                sender_device: "05".repeat(32),
                recipient_address: address.clone(),
                recipient_generation: 1,
                recipient_manifest_digest: "06".repeat(32),
                claim_id: crate::random_hex::<16>(),
                expires: now + 300,
            },
            subject: "Selected subject".into(),
            body: "Selected text".into(),
        };
        vault.data.archive.insert(
            message_id.clone(),
            Archived {
                letter: letter.clone(),
                admission: None,
                receipt: None,
                origin: "ImportedArchive".into(),
            },
        );
        let mut other = letter.clone();
        other.route.message_id = crate::random_hex::<16>();
        other.subject = "Unselected subject".into();
        other.body = "Unselected text".into();
        vault.data.archive.insert(
            other.route.message_id.clone(),
            Archived {
                letter: other,
                admission: None,
                receipt: None,
                origin: "ImportedArchive".into(),
            },
        );
        vault.commit().unwrap();
        drop(vault);
        let vault = Vault::open(&root.0.join("Vault"), &root.0.join("Key"), &c.network).unwrap();
        let output = root.0.join("Letter.json");
        let receipt = root.0.join("Receipt.json");
        export(
            &vault,
            &c,
            Arguments {
                mailbox: "Personal".into(),
                address: address.clone(),
                message_id: message_id.clone(),
                recipient: "LocalClassifier".into(),
                purpose: "Classify this letter".into(),
                expires: now + 300,
                consent_disclosure: true,
                output: output.clone(),
                receipt: receipt.clone(),
            },
        )
        .unwrap();
        let disclosed: LetterDisclosure = files::read(&output, files::MAX_FILE).unwrap();
        assert_eq!(disclosed.letter.route.message_id, message_id);
        assert_eq!(disclosed.letter.subject, letter.subject);
        assert_eq!(disclosed.letter.body, letter.body);
        let signed: wire::Signed = files::read(&receipt, files::MAX_FILE).unwrap();
        let metadata =
            files::verify::<Metadata>(&c, &vault.mailbox("Personal").unwrap().request, &signed)
                .unwrap()
                .disclosure;
        assert_eq!(
            metadata.content_digest,
            wire::digest(&serde_json::to_vec(&letter).unwrap())
        );
        assert_eq!(metadata.origin, "ImportedArchive");
        assert!(
            export(
                &vault,
                &c,
                Arguments {
                    mailbox: "Personal".into(),
                    address,
                    message_id: "07".repeat(32),
                    recipient: "LocalClassifier".into(),
                    purpose: "Classify this letter".into(),
                    expires: now + 300,
                    consent_disclosure: true,
                    output: root.0.join("Invalid.json"),
                    receipt: root.0.join("InvalidReceipt.json")
                }
            )
            .is_err()
        );
        assert!(!root.0.join("Invalid.json").exists());
        assert!(!root.0.join("InvalidReceipt.json").exists());
    }
}
