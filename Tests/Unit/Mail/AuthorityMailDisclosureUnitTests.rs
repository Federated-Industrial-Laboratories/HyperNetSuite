// SPDX-License-Identifier: MIT
// Unit tests for AuthorityMailDisclosure.
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
