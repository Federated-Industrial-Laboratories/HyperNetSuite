// SPDX-License-Identifier: MIT
// Reviewed form drafts become immutable outbox consent before any network submission.
use super::*;
fn same_network(p: &PageClient, c: &Client, v: &Vault) -> Result<()> {
    let ps = p.store.descriptor().scope();
    let ms = c.store.descriptor().scope();
    ensure!(
        ps.network == ms.network
            && ps.incarnation == ms.incarnation
            && ps.network == v.data.network
            && ps.incarnation == v.data.incarnation
            && p.store.requester() != c.store.requester(),
        "forms require the same network and a separate scoped Mail device requester"
    );
    Ok(())
}
fn current_pair(
    c: &mut Client,
    v: &mut Vault,
    label: &str,
    target: Digest,
) -> Result<(mail::Mailbox, VersionRef, mail::Mailbox, VersionRef)> {
    let source = id(&v.mailbox(label)?.address)?;
    c.resume_metadata(
        |cmd| matches!(cmd,Action::Get{address,..}if *address==source || *address==target),
    )?;
    let sender = sync(c, v, label)?;
    sender.publication.device(
        c.key.verifying_key().to_bytes(),
        "Send",
        c.clock.health()?.observe()?.wall_ms,
    )?;
    let recipient = c.refresh(target, Some(source))?;
    v.contact(&serde_json::from_slice(&recipient.publication.bytes)?, None)?;
    let cache = c.cache()?;
    Ok((
        sender,
        cache.state.record(137, source)?.reference.clone(),
        recipient,
        cache.state.record(137, target)?.reference.clone(),
    ))
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare(
    p: &mut PageClient,
    grant: &VersionRef,
    o: &DeviceOnline,
    expected: &PublicationIdentity,
    form_id: &str,
    values: BTreeMap<String, Value>,
    expires: u64,
) -> Result<Review> {
    let publication = publication::fetch(p, grant, expected.page_id()?)?;
    ensure!(
        publication.identity == *expected,
        "displayed Page changed before form preparation"
    );
    let form = model::form(&publication.bundle, form_id)?;
    markup::forms::validate_values(&form, &values).map_err(anyhow::Error::msg)?;
    let (mut c, mut v) = device(o)?;
    same_network(p, &c, &v)?;
    let (sender, sender_ref, recipient, recipient_ref) =
        current_pair(&mut c, &mut v, &o.mailbox, id(&form.recipient)?)?;
    ensure!(
        recipient.publication.manifest.owner_key == form.owner,
        "form recipient owner differs from independently verified Mail contact"
    );
    let now = crate::now()?;
    let sender_device = sender.publication.device(
        c.key.verifying_key().to_bytes(),
        "Send",
        now.saturating_mul(1000),
    )?;
    let recipient_device_expiry = recipient
        .publication
        .manifest
        .devices
        .iter()
        .filter(|d| d.permissions.iter().any(|p| p == "Read") && d.expires > now)
        .map(|d| d.expires)
        .min()
        .context("recipient has no current receiving device")?;
    ensure!(
        expires > now
            && expires <= sender_device.expires
            && expires <= recipient_device_expiry
            && expires <= sender.publication.manifest.expires
            && expires <= recipient.publication.manifest.expires
            && expires <= now.saturating_add(recipient.publication.manifest.retention_seconds),
        "form expiry exceeds current Mail policy"
    );
    let review = Review {
        review_id: crate::random_hex::<32>(),
        submission_id: crate::random_hex::<32>(),
        publication: publication.identity,
        sender_address: v.mailbox(&o.mailbox)?.address.clone(),
        sender_device: v.mailbox(&o.mailbox)?.device.device_id.clone(),
        sender_request_key: hex::encode(c.key.verifying_key().to_bytes()),
        sender_record: publication::reference(&sender_ref)?,
        sender_manifest_digest: hex::encode(sender.publication.digest),
        recipient_address: form.recipient,
        recipient_owner: form.owner,
        recipient_record: publication::reference(&recipient_ref)?,
        recipient_manifest_digest: hex::encode(recipient.publication.digest),
        recipient_generation: recipient.publication.manifest.generation,
        form_id: form.id,
        form_label: form.label,
        schema_digest: form.schema_digest,
        values,
        expires,
        storage_hosts: recipient.publication.manifest.storage_hosts,
        required_copies: recipient.publication.manifest.required_copies,
        retention_seconds: recipient.publication.manifest.retention_seconds,
        private: recipient.private,
    };
    let draft = Prepared {
        review: review.clone(),
        mailbox: o.mailbox.clone(),
        bundle: B64.encode(&publication.bundle.bytes),
    };
    body(&draft.submission())?;
    v.data.form_drafts.insert(review.review_id.clone(), draft);
    v.save()?;
    Ok(review)
}
pub(crate) fn confirm(
    p: &mut PageClient,
    grant: &VersionRef,
    o: &DeviceOnline,
    review_id: &str,
    consent: bool,
) -> Result<Review> {
    ensure!(
        consent,
        "explicit confirmation of every form value is required"
    );
    id(review_id)?;
    let (mut c, mut v) = device(o)?;
    same_network(p, &c, &v)?;
    if let Some(job) = v.data.outgoing.values().find(|j| {
        j.form_consent
            .as_ref()
            .is_some_and(|f| f.review.review_id == review_id)
    }) {
        ensure!(
            job.mailbox == o.mailbox,
            "confirmed form belongs to another mailbox"
        );
        validate_outgoing(job)?;
        return Ok(job.form_consent.as_ref().unwrap().review.clone());
    }
    let draft = v
        .data
        .form_drafts
        .get(review_id)
        .context("form review is absent or cancelled")?
        .clone();
    ensure!(
        draft.mailbox == o.mailbox
            && draft.review.expires > crate::now()?
            && draft.review.sender_request_key == hex::encode(c.key.verifying_key().to_bytes()),
        "form review expired or belongs to another device"
    );
    let (sender, sender_ref, recipient, recipient_ref) = current_pair(
        &mut c,
        &mut v,
        &o.mailbox,
        id(&draft.review.recipient_address)?,
    )?;
    let job = draft.outgoing()?;
    guard_mailboxes(&job, &sender, &sender_ref, &recipient, &recipient_ref)?;
    let publication = publication::fetch(p, grant, draft.review.publication.page_id()?)?;
    ensure!(
        publication.identity == draft.review.publication
            && B64.encode(&publication.bundle.bytes) == draft.bundle,
        "Page publication changed after form review"
    );
    commit_confirmation(&mut v, review_id, job)?;
    Ok(draft.review)
}
pub(super) fn commit_confirmation(v: &mut Vault, review_id: &str, job: Outgoing) -> Result<()> {
    validate_outgoing(&job)?;
    ensure!(
        v.data.form_drafts.contains_key(review_id) && !v.data.outgoing.contains_key(&job.id),
        "form draft or message identity changed"
    );
    let message = job.id.clone();
    let draft = v.data.form_drafts.remove(review_id).unwrap();
    v.data.outgoing.insert(message.clone(), job);
    if let Err(error) = v.save() {
        v.data.outgoing.remove(&message);
        v.data.form_drafts.insert(review_id.into(), draft);
        return Err(error);
    }
    Ok(())
}
pub(crate) fn send(o: &DeviceOnline, t: &Transport, message: &str) -> Result<Value> {
    let (mut c, mut v) = device(o)?;
    let job = v
        .data
        .outgoing
        .get(message)
        .context("confirmed form absent")?;
    ensure!(
        job.mailbox == o.mailbox && job.form_consent.is_some(),
        "message is not a confirmed form for this mailbox"
    );
    validate_outgoing(job)?;
    workflow::send_value(&mut c, &mut v, &o.mailbox, t, id(message)?)
}
pub(crate) fn accept(
    p: &mut PageClient,
    grant: &VersionRef,
    o: &DeviceOnline,
    page_id: [u8; 16],
    form_id: &str,
) -> Result<Value> {
    let publication = publication::fetch(p, grant, page_id)?;
    let form = model::form(&publication.bundle, form_id)?;
    let (mut c, mut v) = device(o)?;
    same_network(p, &c, &v)?;
    let address = id(&v.mailbox(&o.mailbox)?.address)?;
    c.resume_metadata(|cmd| matches!(cmd,Action::Get{address:a,..}if *a==address))?;
    let own = sync(&mut c, &mut v, &o.mailbox)?;
    own.publication.device(
        c.key.verifying_key().to_bytes(),
        "Read",
        c.clock.health()?.observe()?.wall_ms,
    )?;
    ensure!(
        form.recipient == v.mailbox(&o.mailbox)?.address
            && form.owner == own.publication.manifest.owner_key,
        "form does not target this receiving mailbox and owner"
    );
    let record = Accepted {
        publication: publication.identity,
        form_id: form.id,
        schema_digest: form.schema_digest,
        recipient_address: form.recipient,
        recipient_owner: form.owner,
    };
    let key = accepted_key(
        &record.publication,
        &record.form_id,
        &record.recipient_address,
    )?;
    v.data.accepted_forms.insert(key.clone(), record.clone());
    v.save()?;
    Ok(json!({"status":"FormPublicationAccepted","acceptedRecord":key,"record":record}))
}
pub(crate) fn receive(
    o: &DeviceOnline,
    t: Option<&Transport>,
    message: &str,
    local: bool,
) -> Result<Value> {
    id(message)?;
    let mut v = if local {
        open(&o.location, &o.vault, false)?.1
    } else {
        let (mut c, mut v) = device(o)?;
        online::receive_value(
            &mut c,
            &mut v,
            &o.mailbox,
            t.context("Mail transport is required")?,
            Effect::Fetch,
            Some(id(message)?),
            None,
        )?;
        v
    };
    validate_archived(&mut v, &o.mailbox, message)
}
pub(super) fn validate_archived(v: &mut Vault, label: &str, message: &str) -> Result<Value> {
    let mailbox = v.mailbox(label)?;
    let archived = v
        .data
        .archive
        .get(message)
        .context("letter has not been authenticated for this receiving device")?;
    ensure!(
        archived
            .received_by
            .get(&mailbox.device.device_id)
            .is_some_and(|r| !r.is_empty())
            && archived.letter.route.recipient_address == mailbox.address,
        "local archive is not authenticated for this receiving mailbox and device"
    );
    let letter = archived.letter.clone();
    validate_received(v, &letter)
}
pub(super) fn validate_received(v: &mut Vault, letter: &crypto::Letter) -> Result<Value> {
    ensure!(
        letter.body.len() <= 32768,
        "form Mail body exceeds its bound"
    );
    let payload_digest = protocol::digest(&serde_json::to_vec(&(&letter.route, &letter.body))?);
    let route = &letter.route;
    if let Some(old) = v.data.form_ledger.get(&route.message_id) {
        ensure!(
            old.payload_digest == payload_digest,
            "conflicting form payload reused a submission identity"
        );
    }
    let unrecognised = || json!({"status":"Unrecognised","message":route.message_id,"businessProcessing":"NotPerformed"});
    let value: Value = match serde_json::from_str(&letter.body) {
        Ok(v) => v,
        Err(_) => return Ok(unrecognised()),
    };
    if value.get("profile").and_then(Value::as_str) != Some(PROFILE) {
        return Ok(unrecognised());
    }
    let s: Submission = serde_json::from_value(value)?;
    let bundle = bundle(&s)?;
    let form = model::form(&bundle, &s.form_id)?;
    ensure!(
        s.publication.network == hex::encode(v.data.network)
            && s.publication.incarnation == hex::encode(v.data.incarnation)
            && route.network == s.publication.network
            && route.message_id == s.submission_id
            && route.claim_id == s.submission_id
            && route.sender_address == s.sender_address
            && route.sender_device == s.sender_device
            && route.recipient_address == s.recipient_address
            && route.recipient_manifest_digest == s.recipient_manifest_digest
            && route.expires == s.expires,
        "form submission differs from authenticated Mail route"
    );
    let key = accepted_key(&s.publication, &s.form_id, &s.recipient_address)?;
    let Some(accepted) = v.data.accepted_forms.get(&key) else {
        return Ok(unrecognised());
    };
    ensure!(
        accepted.recipient_owner == form.owner
            && accepted.schema_digest == s.schema_digest
            && accepted.recipient_address == s.recipient_address,
        "form differs from independently accepted publication"
    );
    let duplicate = if let Some(old) = v.data.form_ledger.get(&s.submission_id) {
        ensure!(
            old.accepted_record == key && old.payload_digest == payload_digest,
            "form replay ledger differs"
        );
        true
    } else {
        v.data.form_ledger.insert(
            s.submission_id.clone(),
            LedgerEntry {
                payload_digest,
                accepted_record: key.clone(),
            },
        );
        if let Err(error) = v.save() {
            v.data.form_ledger.remove(&s.submission_id);
            return Err(error);
        }
        false
    };
    Ok(
        json!({"status":"Accepted","duplicate":duplicate,"acceptedRecord":key,"submissionId":s.submission_id,"publication":s.publication,"formId":s.form_id,"schemaDigest":s.schema_digest,"senderAddress":s.sender_address,"senderDevice":s.sender_device,"recipientAddress":s.recipient_address,"values":s.values,"businessProcessing":"NotPerformed"}),
    )
}
