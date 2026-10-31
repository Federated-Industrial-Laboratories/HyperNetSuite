// SPDX-License-Identifier: MIT
// Native signed publications and real MLS letters preserve explicit consent and durable replay identity.
use super::*;
use crate::{
    authority_deployment_tests as fixture,
    authority_domains::{Record, State, page},
    authority_objects::{Class, Reference},
};
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn directory() -> Directory {
    let path = std::env::temp_dir().join(format!("HyperNetForms{}", crate::random_hex::<16>()));
    files::create_directory(&path).unwrap();
    Directory(path)
}
fn reference(kind: u64, id: Digest) -> VersionRef {
    VersionRef {
        kind,
        id,
        generation: 1,
        digest: [91; 32],
    }
}
fn mailbox() -> Mailbox {
    let owner = protocol::new_identity();
    let n = hex::encode([20; 32]);
    let address = protocol::address_id(&n, &owner.public_key).unwrap();
    let mut b = workflow::local_device(
        &address,
        crate::now().unwrap() + 600,
        vec!["Read".into(), "Send".into()],
    )
    .unwrap();
    let m = protocol::Manifest {
        version: 1,
        network: n.clone(),
        address_id: address,
        owner_key: owner.public_key.clone(),
        generation: 1,
        previous_digest: None,
        expires: crate::now().unwrap() + 600,
        devices: vec![b.device.clone()],
        storage_hosts: vec![hex::encode(fixture::key(101).verifying_key().to_bytes())],
        required_copies: 1,
        retention_seconds: 600,
        deleted: false,
    };
    b.manifest = Some(protocol::sign(protocol::MANIFEST, &n, &owner, &m).unwrap());
    b.owner = Some(owner);
    b.private = true;
    b
}
fn native(b: &Mailbox) -> mail::Mailbox {
    mail::Mailbox {
        publication: mail::objects::Publication::parse(
            &serde_json::to_vec(b.manifest.as_ref().unwrap()).unwrap(),
            [20; 32],
        )
        .unwrap(),
        manager: fixture::key(5).verifying_key().to_bytes(),
        grant: reference(102, [23; 32]),
        private: true,
        creation: [81; 32],
    }
}
fn prepared(sender: &Mailbox, recipient: &Mailbox) -> (Prepared, Record, Record) {
    let n = [20; 32];
    let i = [21; 32];
    let state = State::empty(n, i);
    let grant = reference(102, [23; 32]);
    let now = crate::now().unwrap();
    let owner = &recipient.owner.as_ref().unwrap().public_key;
    let source = format!(
        "HyperNetPage/2\n# Contact\n@Form {{\"id\":\"Contact\",\"label\":\"Contact\",\"profile\":\"HyperNetFormMail/1\",\"recipient\":\"{}\",\"owner\":\"{owner}\"}}\n@Field {{\"id\":\"Name\",\"label\":\"Name\",\"kind\":\"Text\",\"maxBytes\":40,\"required\":true}}\n@Submit {{\"label\":\"Send\"}}\n@End\n",
        recipient.address
    );
    let sr = Reference::for_bytes(Class::PageSource, source.as_bytes()).unwrap();
    let page_id = [71; 16];
    let page_key = page::page_id(&page_id).unwrap();
    let parameters = page::objects::Author::parameters(
        page_id,
        "Books",
        source.as_bytes(),
        &grant,
        None,
        (now + 600) * 1000,
    )
    .unwrap();
    let signed = fixture::signed(
        &fixture::key(5),
        "PageAuthorStatement",
        page_key,
        1,
        wire::decode(&parameters).unwrap(),
        vec![],
    );
    let author = page::objects::Author::parse(&signed, n, i).unwrap();
    let revision = page::Revision::from_source(author.clone(), source.as_bytes()).unwrap();
    let rr = Record::next(&state, 141, revision.identity().unwrap(), revision.value()).unwrap();
    let parameters = page::objects::Reviewer::parameters(
        &rr.reference,
        &sr,
        author.intent.requester,
        author.intent.digest,
        &grant,
        None,
        true,
        0,
        None,
        now * 1000 + page::REVIEW_LIFETIME_MS,
    )
    .unwrap();
    let signed = fixture::signed(
        &fixture::key(5),
        "PageReviewStatement",
        page_key,
        1,
        wire::decode(&parameters).unwrap(),
        vec![],
    );
    let reviewer = page::objects::Reviewer::parse(&signed, n, i).unwrap();
    let bytes =
        page::objects::Bundle::encode(source.as_bytes(), &author.bytes, &reviewer.bytes).unwrap();
    let bundle = page::objects::Bundle::parse(&bytes, n, i).unwrap();
    let br = Reference::for_bytes(Class::PageBundle, &bytes).unwrap();
    let approval = page::Review {
        statement: reviewer,
        bundle: Some(br.clone()),
        recorded_ms: now * 1000,
    };
    let ar = Record::next(&state, 142, rr.reference.id, approval.value()).unwrap();
    let ledger = page::Ledger {
        raw_page: page_id,
        author: author.intent.requester,
        namespace: "Books".into(),
        last_revision: 1,
        pending: None,
        published: Some(ar.reference.clone()),
    };
    let lr = Record::next(&state, 140, page_key, ledger.value()).unwrap();
    let identity = PublicationIdentity {
        network: hex::encode(n),
        incarnation: hex::encode(i),
        page: hex::encode(page_id),
        ledger: publication::reference(&lr.reference).unwrap(),
        revision: publication::reference(&rr.reference).unwrap(),
        approval: publication::reference(&ar.reference).unwrap(),
        bundle: hex::encode(br.canonical()),
    };
    identity.validate(&bundle).unwrap();
    let sender_native = native(sender);
    let recipient_native = native(recipient);
    let sender_record = Record::next(
        &state,
        137,
        id(&sender.address).unwrap(),
        sender_native.value(),
    )
    .unwrap();
    let recipient_record = Record::next(
        &state,
        137,
        id(&recipient.address).unwrap(),
        recipient_native.value(),
    )
    .unwrap();
    let form = model::form(&bundle, "Contact").unwrap();
    let r = Review {
        review_id: crate::random_hex::<32>(),
        submission_id: crate::random_hex::<32>(),
        publication: identity,
        sender_address: sender.address.clone(),
        sender_device: sender.device.device_id.clone(),
        sender_request_key: sender.request.public_key.clone(),
        sender_record: publication::reference(&sender_record.reference).unwrap(),
        sender_manifest_digest: hex::encode(sender_native.publication.digest),
        recipient_address: recipient.address.clone(),
        recipient_owner: owner.clone(),
        recipient_record: publication::reference(&recipient_record.reference).unwrap(),
        recipient_manifest_digest: hex::encode(recipient_native.publication.digest),
        recipient_generation: 1,
        form_id: form.id,
        form_label: form.label,
        schema_digest: form.schema_digest,
        values: BTreeMap::from([("Name".into(), json!("Ada"))]),
        expires: now + 300,
        storage_hosts: recipient_native.publication.manifest.storage_hosts,
        required_copies: 1,
        retention_seconds: 600,
        private: true,
    };
    (
        Prepared {
            review: r,
            mailbox: "Sender".into(),
            bundle: B64.encode(bytes),
        },
        sender_record,
        recipient_record,
    )
}
#[test]
fn native_form_confirmation_persists_exact_consent_and_rejects_changed_mailbox_policy() {
    let root = directory();
    let path = root.0.join("Vault");
    let key = root.0.join("Vault.key");
    let sender = mailbox();
    let recipient = mailbox();
    let (draft, sender_record, recipient_record) = prepared(&sender, &recipient);
    let review = draft.review.clone();
    let mut v = Vault::initialise(&path, &key, [20; 32], [21; 32], [22; 32]).unwrap();
    v.data
        .form_drafts
        .insert(review.review_id.clone(), draft.clone());
    v.save().unwrap();
    assert!(v.data.outgoing.is_empty());
    let job = draft.outgoing().unwrap();
    guard_mailboxes(
        &job,
        &native(&sender),
        &sender_record.reference,
        &native(&recipient),
        &recipient_record.reference,
    )
    .unwrap();
    let mut changed_mailbox = native(&recipient);
    changed_mailbox.private = false;
    let old_manifest = recipient.manifest.as_ref().unwrap();
    let mut manifest = protocol::manifest(&hex::encode([20; 32]), old_manifest).unwrap();
    manifest.generation += 1;
    manifest.previous_digest = Some(protocol::object_digest(old_manifest).unwrap());
    let signed = protocol::sign(
        protocol::MANIFEST,
        &hex::encode([20; 32]),
        recipient.owner.as_ref().unwrap(),
        &manifest,
    )
    .unwrap();
    changed_mailbox.publication =
        mail::objects::Publication::parse(&serde_json::to_vec(&signed).unwrap(), [20; 32]).unwrap();
    let mut state = State::empty([20; 32], [21; 32]);
    state
        .records
        .insert(recipient_record.reference.index(), recipient_record.clone());
    let changed = Record::next(
        &state,
        137,
        recipient_record.reference.id,
        changed_mailbox.value(),
    )
    .unwrap();
    assert!(
        guard_mailboxes(
            &job,
            &native(&sender),
            &sender_record.reference,
            &changed_mailbox,
            &changed.reference
        )
        .is_err()
    );
    let claim = mail::Claim {
        sender: sender_record.reference,
        recipient: recipient_record.reference,
        device: id(&sender.request.public_key).unwrap(),
        packages: vec![reference(138, [51; 32])],
        expires: review.expires * 1000,
        creation: [52; 32],
        payload_digest: None,
        payload_bytes: 0,
        binding: None,
        placement: vec![],
        created_ms: crate::now().unwrap() * 1000,
    };
    guard_claim(&job, &claim).unwrap();
    let mut different = claim.clone();
    different.recipient = changed.reference;
    assert!(guard_claim(&job, &different).is_err());
    // Failure to publish the encrypted snapshot cannot expose an in-memory confirmed message.
    std::fs::rename(path.join("Vault.age"), path.join("Saved.age")).unwrap();
    std::fs::create_dir(path.join("Vault.age")).unwrap();
    assert!(
        operations::commit_confirmation(&mut v, &review.review_id, draft.outgoing().unwrap())
            .is_err()
    );
    assert!(v.data.outgoing.is_empty());
    assert!(v.data.form_drafts.contains_key(&review.review_id));
    std::fs::remove_dir(path.join("Vault.age")).unwrap();
    std::fs::rename(path.join("Saved.age"), path.join("Vault.age")).unwrap();
    operations::commit_confirmation(&mut v, &review.review_id, job).unwrap();
    drop(v);
    let mut v = Vault::open(&path, &key, [20; 32], [21; 32], [22; 32]).unwrap();
    assert!(v.data.form_drafts.is_empty());
    let job = v.data.outgoing.get_mut(&review.submission_id).unwrap();
    validate_outgoing(job).unwrap();
    assert!(job.ciphertext.is_none());
    job.body.push(' ');
    assert!(validate_outgoing(job).is_err());
    let mut invalid = draft;
    invalid
        .review
        .values
        .insert("Name".into(), json!("x".repeat(41)));
    assert!(invalid.outgoing().is_err());
}
#[test]
fn native_form_mls_intake_reopens_and_records_exact_replay_before_values() {
    let root = directory();
    let path = root.0.join("Vault");
    let key = root.0.join("Vault.key");
    let sender = mailbox();
    let mut recipient = mailbox();
    let (draft, _, _) = prepared(&sender, &recipient);
    let (private, packages) = crypto::make_packages(
        &hex::encode([20; 32]),
        &recipient.address,
        &recipient.device,
        &recipient.signer,
        1,
        draft.review.expires,
    )
    .unwrap();
    recipient.packages = private;
    let claim = protocol::Claim {
        version: 1,
        network: hex::encode([20; 32]),
        sender_address: sender.address.clone(),
        sender_device: sender.device.device_id.clone(),
        claim_id: draft.review.submission_id.clone(),
        recipient_address: recipient.address.clone(),
        recipient_generation: 1,
        recipient_manifest_digest: draft.review.recipient_manifest_digest.clone(),
        expires: draft.review.expires,
        packages,
    };
    let letter = crypto::Letter {
        route: protocol::Route {
            version: 1,
            profile: protocol::PROFILE.into(),
            network: claim.network.clone(),
            message_id: claim.claim_id.clone(),
            replacement: 0,
            sender_address: claim.sender_address.clone(),
            sender_device: claim.sender_device.clone(),
            recipient_address: claim.recipient_address.clone(),
            recipient_generation: 1,
            recipient_manifest_digest: claim.recipient_manifest_digest.clone(),
            claim_id: claim.claim_id.clone(),
            expires: claim.expires,
        },
        subject: "Contact".into(),
        body: body(&draft.submission()).unwrap(),
    };
    let cipher = crypto::seal(
        &sender.signer,
        &claim,
        sender.manifest.as_ref().unwrap(),
        recipient.manifest.as_ref().unwrap(),
        &letter,
    )
    .unwrap();
    let device = recipient.device.device_id.clone();
    let mut v = Vault::initialise(&path, &key, [20; 32], [21; 32], [22; 32]).unwrap();
    v.data.mailboxes.insert("Recipient".into(), recipient);
    v.save().unwrap();
    v.archive(
        "Recipient",
        &cipher,
        &claim.packages[0].reference,
        crate::now().unwrap(),
        b"verified typed serving receipt",
    )
    .unwrap();
    assert_eq!(
        operations::validate_archived(&mut v, "Recipient", &claim.claim_id).unwrap()["status"],
        "Unrecognised"
    );
    assert!(v.data.form_ledger.is_empty());
    let accepted = Accepted {
        publication: draft.review.publication.clone(),
        form_id: draft.review.form_id.clone(),
        schema_digest: draft.review.schema_digest.clone(),
        recipient_address: draft.review.recipient_address.clone(),
        recipient_owner: draft.review.recipient_owner.clone(),
    };
    v.data.accepted_forms.insert(
        accepted_key(
            &accepted.publication,
            &accepted.form_id,
            &accepted.recipient_address,
        )
        .unwrap(),
        accepted,
    );
    v.save().unwrap();
    assert_eq!(
        operations::validate_archived(&mut v, "Recipient", &claim.claim_id).unwrap()["duplicate"],
        false
    );
    drop(v);
    let mut v = Vault::open(&path, &key, [20; 32], [21; 32], [22; 32]).unwrap();
    assert_eq!(
        operations::validate_archived(&mut v, "Recipient", &claim.claim_id).unwrap()["duplicate"],
        true
    );
    assert!(v.mailbox("Recipient").unwrap().packages.is_empty());
    let mut conflict = letter.clone();
    conflict.body.push(' ');
    assert!(operations::validate_received(&mut v, &conflict).is_err());
    assert_eq!(v.data.form_ledger.len(), 1);
    v.data
        .archive
        .get_mut(&claim.claim_id)
        .unwrap()
        .received_by
        .remove(&device);
    assert!(operations::validate_archived(&mut v, "Recipient", &claim.claim_id).is_err());
}
