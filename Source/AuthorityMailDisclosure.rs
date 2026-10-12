// SPDX-License-Identifier: MIT
// A local release names one archived letter and persists consent provenance before plaintext output.
use super::*;
use crate::adapter_files as disclosure;
use serde::{Deserialize, Serialize};
#[derive(Args)]
pub(super) struct Arguments {
    #[arg(long)]
    mailbox: String,
    #[arg(long)]
    address: String,
    #[arg(long)]
    message: String,
    #[arg(long)]
    recipient: String,
    #[arg(long)]
    purpose: String,
    #[arg(long)]
    expires: u64,
    #[arg(long)]
    consent_disclosure: bool,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    receipt: PathBuf,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Metadata {
    version: u32,
    kind: String,
    network: String,
    incarnation: String,
    bootstrap: String,
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
    letter: crypto::Letter,
}
pub(super) fn export(v: &Vault, args: Arguments) -> Result<serde_json::Value> {
    ensure!(
        args.consent_disclosure,
        "--consent-disclosure is required to release plaintext"
    );
    disclosure::label(&args.recipient)?;
    disclosure::purpose(&args.purpose)?;
    id(&args.address)?;
    id(&args.message)?;
    let now = crate::now()?;
    disclosure::lifetime(now, args.expires, now)?;
    ensure!(
        args.output != args.receipt,
        "plaintext and receipt require distinct destinations"
    );
    let mailbox = v.mailbox(&args.mailbox)?;
    ensure!(
        mailbox.address == args.address,
        "mailbox differs from selected address"
    );
    let archived = v
        .data
        .archive
        .get(&args.message)
        .context("selected letter is absent from the local archive")?;
    let letter = &archived.letter;
    ensure!(
        letter.route.message_id == args.message
            && letter.route.recipient_address == args.address
            && letter.route.network == hex::encode(v.data.network)
            && letter.subject.len() <= 512
            && letter.body.len() <= 32768,
        "archived letter differs from exact selected mailbox"
    );
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(letter)?);
    let metadata = Metadata {
        version: 1,
        kind: "MailLetter".into(),
        network: hex::encode(v.data.network),
        incarnation: hex::encode(v.data.incarnation),
        bootstrap: hex::encode(v.data.bootstrap),
        disclosure_id: crate::random_hex::<16>(),
        address_id: args.address.clone(),
        message_id: args.message.clone(),
        recipient: args.recipient,
        purpose: args.purpose,
        issued_at: now,
        expires: args.expires,
        consent_disclosure: true,
        content_digest: protocol::digest(&bytes),
        origin: "LocalArchive".into(),
    };
    let receipt = protocol::sign(
        disclosure::RECEIPT_DOMAIN,
        &metadata.network,
        &mailbox.request,
        &disclosure::DisclosureReceipt {
            version: 1,
            network: metadata.network.clone(),
            signer: mailbox.request.public_key.clone(),
            job_digest: protocol::digest(&serde_json::to_vec(&metadata)?),
            disclosure: &metadata,
        },
    )?;
    let released = LetterDisclosure {
        disclosure: metadata,
        letter: letter.clone(),
    };
    // Open both no-overwrite destinations before writing provenance or releasing plaintext.
    let receipt_destination = files::Destination::open(&args.receipt)?;
    let output_destination = files::Destination::open(&args.output)?;
    let proof = serde_json::to_vec_pretty(&receipt)?;
    let body = zeroize::Zeroizing::new(serde_json::to_vec_pretty(&released)?);
    ensure!(
        proof.len() <= disclosure::MAX_FILE && body.len() <= disclosure::MAX_FILE,
        "disclosure exceeds its bound"
    );
    receipt_destination.publish(&proof)?;
    disclosure::lifetime(now, args.expires, crate::now()?)?;
    output_destination.publish(&body)?;
    Ok(
        json!({"status":"ArchivedMailDisclosed","address":args.address,"message":args.message,
        "recipient":released.disclosure.recipient,"contentDigest":released.disclosure.content_digest,
        "output":args.output,"receipt":args.receipt,"activeKeysExported":false,"source":"LocalArchive","expires":args.expires}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Root(PathBuf);
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn mail_disclosure_requires_consent_and_exports_only_the_selected_letter() {
        let root = Root(std::env::temp_dir().join(format!(
            "HyperNetMailDisclosure{}",
            crate::random_hex::<16>()
        )));
        files::create_directory(&root.0).unwrap();
        let n = [31; 32];
        let incarnation = [32; 32];
        let now = crate::now().unwrap();
        let address = hex::encode([33; 32]);
        let message = hex::encode([34; 32]);
        let mut v = Vault::initialise(
            &root.0.join("Vault"),
            &root.0.join("Vault.key"),
            n,
            incarnation,
            [35; 32],
        )
        .unwrap();
        v.data.mailboxes.insert(
            "Reader".into(),
            local_device(&address, now + 600, vec!["Read".into()]).unwrap(),
        );
        let letter = crypto::Letter {
            route: protocol::Route {
                version: 1,
                profile: protocol::PROFILE.into(),
                network: hex::encode(n),
                message_id: message.clone(),
                replacement: 0,
                sender_address: hex::encode([36; 32]),
                sender_device: hex::encode([37; 32]),
                recipient_address: address.clone(),
                recipient_generation: 1,
                recipient_manifest_digest: hex::encode([38; 32]),
                claim_id: message.clone(),
                expires: now + 600,
            },
            subject: "Selected letter".into(),
            body: "One chosen archived message.".into(),
        };
        let mut other = letter.clone();
        other.route.message_id = hex::encode([39; 32]);
        other.body = "Unselected private message".into();
        for l in [letter.clone(), other] {
            v.data.archive.insert(
                l.route.message_id.clone(),
                vault::Archived {
                    ciphertext_digest: hex::encode([40; 32]),
                    letter: l,
                    receipt: hex::encode(b"verified historic receipt"),
                    received_by: BTreeMap::from([(
                        v.mailbox("Reader").unwrap().device.device_id.clone(),
                        hex::encode(b"verified historic receipt"),
                    )]),
                },
            );
        }
        v.save().unwrap();
        drop(v);
        let v = Vault::open(
            &root.0.join("Vault"),
            &root.0.join("Vault.key"),
            n,
            incarnation,
            [35; 32],
        )
        .unwrap();
        let arguments = |message: String, consent: bool, stem: &str| Arguments {
            mailbox: "Reader".into(),
            address: address.clone(),
            message,
            recipient: "LocalClassifier".into(),
            purpose: "Classify this selected letter".into(),
            expires: now + 300,
            consent_disclosure: consent,
            output: root.0.join(format!("{stem}.json")),
            receipt: root.0.join(format!("{stem}Receipt.json")),
        };
        assert!(export(&v, arguments(message.clone(), false, "NoConsent")).is_err());
        assert!(!root.0.join("NoConsent.json").exists());
        assert!(export(&v, arguments(hex::encode([55; 32]), true, "Absent")).is_err());
        assert!(!root.0.join("AbsentReceipt.json").exists());
        export(&v, arguments(message.clone(), true, "Selected")).unwrap();
        let result: LetterDisclosure =
            disclosure::read(&root.0.join("Selected.json"), disclosure::MAX_FILE).unwrap();
        assert_eq!(result.letter.body, letter.body);
        assert_eq!(result.letter.route.message_id, message);
        assert_eq!(result.disclosure.incarnation, hex::encode(incarnation));
        let proof: protocol::Signed =
            disclosure::read(&root.0.join("SelectedReceipt.json"), disclosure::MAX_FILE).unwrap();
        let key = &v.mailbox("Reader").unwrap().request.public_key;
        let receipt: disclosure::DisclosureReceipt<Metadata> =
            protocol::verify(disclosure::RECEIPT_DOMAIN, &hex::encode(n), key, &proof).unwrap();
        assert_eq!(
            receipt.disclosure.content_digest,
            protocol::digest(&serde_json::to_vec(&letter).unwrap())
        );
        assert_eq!(
            receipt.job_digest,
            protocol::digest(&serde_json::to_vec(&receipt.disclosure).unwrap())
        );
        assert!(export(&v, arguments(message, true, "Selected")).is_err());
        let raw =
            files::read_single(&root.0.join("Selected.json"), disclosure::MAX_FILE, true).unwrap();
        let text = std::str::from_utf8(&raw).unwrap();
        assert!(!text.contains("Unselected private message"));
        assert!(!text.contains("secretKey"));
    }
}
