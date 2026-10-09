// SPDX-License-Identifier: MIT
// Explicitly reviewed structured submissions over authenticated encrypted mail.
use crate::{
    Config, mail, mail_delivery, mail_protocol as wire,
    mail_vault::{self, Outbox, Vault},
    markup::{self, forms::Form},
    page_proof::{self, Bundle, Descriptor},
    protocol,
};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[path = "FormsReceive.rs"]
mod receive;
pub use receive::{Accepted, LedgerEntry};

pub const PROFILE: &str = "HyperNetFormSubmission/1";
const MAX_BUNDLE: usize = 20 * 1024;
const MAX_VALUES: usize = 8 * 1024;
const MAX_METADATA: usize = 2 * 1024;

#[derive(Clone)]
pub struct Settings {
    pub vault: PathBuf,
    pub key: PathBuf,
    pub mailbox: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Review {
    pub review_id: String,
    pub submission_id: String,
    pub network: String,
    pub sender_address: String,
    pub sender_device: String,
    pub recipient_address: String,
    pub recipient_owner: String,
    pub descriptor: Descriptor,
    pub form_id: String,
    pub form_label: String,
    pub schema_digest: String,
    pub values: BTreeMap<String, Value>,
    pub expires: u64,
    pub storage_hosts: Vec<String>,
    pub required_copies: u16,
    pub retention_seconds: u64,
    pub recipient_generation: u64,
    pub recipient_manifest_digest: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Prepared {
    pub review: Review,
    pub mailbox: String,
    pub bundle: Bundle,
    pub recipient_manifest: wire::Signed,
    pub sender_manifest_digest: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Consent {
    pub review_id: String,
    pub sender_manifest_digest: String,
    pub recipient_manifest_digest: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Submission {
    pub profile: String,
    pub submission_id: String,
    pub network: String,
    pub sender_address: String,
    pub sender_device: String,
    pub recipient_address: String,
    pub recipient_manifest_digest: String,
    pub expires: u64,
    pub descriptor: Descriptor,
    pub bundle: Bundle,
    pub form_id: String,
    pub schema_digest: String,
    pub values: BTreeMap<String, Value>,
}
impl Prepared {
    fn submission(&self) -> Submission {
        let r = &self.review;
        Submission {
            profile: PROFILE.into(),
            submission_id: r.submission_id.clone(),
            network: r.network.clone(),
            sender_address: r.sender_address.clone(),
            sender_device: r.sender_device.clone(),
            recipient_address: r.recipient_address.clone(),
            recipient_manifest_digest: r.recipient_manifest_digest.clone(),
            expires: r.expires,
            descriptor: r.descriptor.clone(),
            bundle: self.bundle.clone(),
            form_id: r.form_id.clone(),
            schema_digest: r.schema_digest.clone(),
            values: r.values.clone(),
        }
    }
}
fn payload_digest(value: &impl Serialize) -> Result<String> {
    Ok(wire::digest(&serde_json::to_vec(value)?))
}
fn bounded(submission: &Submission) -> Result<String> {
    let bundle = serde_json::to_vec(&submission.bundle)?;
    let values = serde_json::to_vec(&submission.values)?;
    let body = serde_json::to_string(submission)?;
    ensure!(bundle.len() <= MAX_BUNDLE, "form page proof exceeds 20 KiB");
    ensure!(values.len() <= MAX_VALUES, "form values exceed 8 KiB");
    ensure!(
        body.len().saturating_sub(bundle.len() + values.len()) <= MAX_METADATA,
        "form envelope metadata exceeds 2 KiB"
    );
    ensure!(
        body.len() <= 32768,
        "form submission exceeds mail body bound"
    );
    Ok(body)
}
fn form(network: &str, descriptor: &Descriptor, bundle: &Bundle, id: &str) -> Result<Form> {
    ensure!(
        serde_json::to_vec(bundle)?.len() <= MAX_BUNDLE,
        "form page proof exceeds 20 KiB"
    );
    let source = page_proof::verify(network, descriptor, bundle)?;
    let document = markup::parse(&source).map_err(anyhow::Error::msg)?;
    document
        .forms
        .into_iter()
        .find(|f| f.id == id)
        .context("form is absent from this publication")
}
pub fn publication(c: &Config, page_id: &str) -> Result<(Descriptor, Bundle)> {
    protocol::hex_bytes::<16>(page_id)?;
    let identity = crate::load_identity(&c.identity)?;
    let reply = protocol::send(
        c,
        &identity,
        &crate::random_hex::<16>(),
        crate::now()?,
        json!({"type":"PageRead","pageId":page_id}),
    )?;
    page_proof::fresh(&reply["result"])?;
    let descriptor: Descriptor = serde_json::from_value(reply["result"]["descriptor"].clone())?;
    let bundle: Bundle = serde_json::from_value(reply["result"]["bundle"].clone())?;
    ensure!(
        descriptor.page_id == page_id,
        "authority returned another page"
    );
    page_proof::verify(&c.network, &descriptor, &bundle)?;
    Ok((descriptor, bundle))
}
fn own(v: &mut Vault, c: &Config, mailbox: &str, permission: &str) -> Result<wire::Manifest> {
    let m = mail::refresh(v, c, mailbox)?;
    let now = crate::now()?;
    let b = v.mailbox(mailbox)?;
    ensure!(
        !m.deleted
            && m.expires > now
            && m.devices.iter().any(|d| d.device_id == b.device.device_id
                && d.request_key == b.request.public_key
                && d.mls_signature_key == b.device.mls_signature_key
                && d.expires > now
                && d.permissions.iter().any(|p| p == permission)),
        "mail device lacks current required permission"
    );
    Ok(m)
}
fn destination(
    v: &Vault,
    c: &Config,
    mailbox: &str,
    form: &Form,
) -> Result<(wire::Signed, wire::Manifest)> {
    let contact = v
        .data
        .contacts
        .get(&form.recipient)
        .context("verify recipient owner fingerprint before preparing a form")?;
    ensure!(
        contact.owner_key == form.owner,
        "form recipient differs from pinned contact owner"
    );
    let signed = wire::address_get(c, &v.mailbox(mailbox)?.request, &form.recipient)?;
    let m = wire::manifest(&c.network, &signed)?;
    ensure!(
        m.address_id == form.recipient
            && m.owner_key == form.owner
            && !m.deleted
            && m.expires > crate::now()?
            && m.generation >= contact.generation,
        "form recipient is inactive, changed or rolled back"
    );
    ensure!(
        m.generation != contact.generation
            || wire::object_digest(&signed)? == contact.manifest_digest,
        "form recipient manifest fork"
    );
    Ok((signed, m))
}
#[allow(clippy::too_many_arguments)]
pub fn prepare(
    c: &Config,
    reader: &Config,
    settings: &Settings,
    expected: &Descriptor,
    form_id: &str,
    values: BTreeMap<String, Value>,
    expires: Option<u64>,
) -> Result<Review> {
    ensure!(
        c.network == reader.network,
        "form submission cannot cross networks"
    );
    let (descriptor, bundle) = publication(reader, &expected.page_id)?;
    ensure!(
        &descriptor == expected,
        "page changed; reload before preparing a form"
    );
    let form = form(&c.network, &descriptor, &bundle, form_id)?;
    markup::forms::validate_values(&form, &values).map_err(anyhow::Error::msg)?;
    let mut v = Vault::open(&settings.vault, &settings.key, &c.network)?;
    ensure!(
        v.data.form_reviews.len() < 64,
        "form review quota reached; discard an unused review"
    );
    let sender = own(&mut v, c, &settings.mailbox, "Send")?;
    let (signed, recipient) = destination(&v, c, &settings.mailbox, &form)?;
    let max_expiry = mail_delivery::default_expiry(
        &recipient,
        sender.expires,
        v.mailbox(&settings.mailbox)?.device.expires,
        crate::now()?,
    )?;
    let expires = expires.unwrap_or(max_expiry);
    ensure!(
        expires > crate::now()? && expires <= max_expiry,
        "form expiry exceeds current mailbox or device policy"
    );
    let review = Review {
        review_id: crate::random_hex::<16>(),
        submission_id: crate::random_hex::<16>(),
        network: c.network.clone(),
        sender_address: sender.address_id,
        sender_device: v.mailbox(&settings.mailbox)?.device.device_id.clone(),
        recipient_address: form.recipient,
        recipient_owner: form.owner,
        descriptor,
        form_id: form.id,
        form_label: form.label,
        schema_digest: form.schema_digest,
        values,
        expires,
        storage_hosts: recipient.storage_hosts,
        required_copies: recipient.required_copies,
        retention_seconds: recipient.retention_seconds,
        recipient_generation: recipient.generation,
        recipient_manifest_digest: wire::object_digest(&signed)?,
    };
    let prepared = Prepared {
        review: review.clone(),
        mailbox: settings.mailbox.clone(),
        bundle,
        recipient_manifest: signed,
        sender_manifest_digest: wire::object_digest(mail::own_manifest(&v, &settings.mailbox)?)?,
    };
    bounded(&prepared.submission())?;
    v.data
        .form_reviews
        .insert(review.review_id.clone(), prepared);
    v.commit()?;
    Ok(review)
}
pub fn confirm(c: &Config, reader: &Config, settings: &Settings, review_id: &str) -> Result<Value> {
    ensure!(
        c.network == reader.network,
        "form submission cannot cross networks"
    );
    protocol::hex_bytes::<16>(review_id)?;
    let mut v = Vault::open(&settings.vault, &settings.key, &c.network)?;
    let prepared = v
        .data
        .form_reviews
        .get(review_id)
        .context("unknown review; use forms retry for an already queued submission")?
        .clone();
    ensure!(
        prepared.mailbox == settings.mailbox,
        "review belongs to another sending mailbox"
    );
    let r = &prepared.review;
    let (descriptor, bundle) = publication(reader, &r.descriptor.page_id)?;
    ensure!(
        descriptor == r.descriptor && payload_digest(&bundle)? == payload_digest(&prepared.bundle)?,
        "page changed; prepare and review a new submission"
    );
    let f = form(&c.network, &descriptor, &bundle, &r.form_id)?;
    markup::forms::validate_values(&f, &r.values).map_err(anyhow::Error::msg)?;
    own(&mut v, c, &settings.mailbox, "Send")?;
    ensure!(
        wire::object_digest(mail::own_manifest(&v, &settings.mailbox)?)?
            == prepared.sender_manifest_digest,
        "sending mailbox changed; prepare and review a new submission"
    );
    let (signed, _) = destination(&v, c, &settings.mailbox, &f)?;
    ensure!(
        wire::object_digest(&signed)? == r.recipient_manifest_digest,
        "recipient policy changed; prepare and review a new submission"
    );
    ensure!(r.expires > crate::now()?, "reviewed submission expired");
    let body = bounded(&prepared.submission())?;
    ensure!(
        !v.data.outbox.contains_key(&r.submission_id),
        "submission ID already exists"
    );
    let item = Outbox {
        mailbox: settings.mailbox.clone(),
        recipient: r.recipient_address.clone(),
        claim_id: crate::random_hex::<16>(),
        message_id: r.submission_id.clone(),
        expires: r.expires,
        subject: format!("HyperNet form {}", r.form_id),
        body,
        claim: None,
        recipient_manifest: Some(prepared.recipient_manifest.clone()),
        ciphertext: None,
        receipts: BTreeMap::new(),
        state: "Queued".into(),
        form_consent: Some(Consent {
            review_id: review_id.into(),
            sender_manifest_digest: prepared.sender_manifest_digest,
            recipient_manifest_digest: r.recipient_manifest_digest.clone(),
        }),
    };
    v.data.outbox.insert(r.submission_id.clone(), item);
    v.data.form_reviews.remove(review_id);
    v.commit()?;
    delivery(&mut v, c, &r.submission_id)
}
fn delivery(v: &mut Vault, c: &Config, id: &str) -> Result<Value> {
    match mail_delivery::retry(v, c, id) {
        Ok(value) => Ok(value),
        Err(error) => {
            let item = &v.data.outbox[id];
            let signed = item
                .ciphertext
                .as_ref()
                .map(|c| &c.recipient_manifest)
                .or(item.recipient_manifest.as_ref())
                .context("form outbox lacks recipient policy")?;
            let recipient = wire::manifest(&c.network, signed)?;
            let stored: Vec<_> = recipient
                .storage_hosts
                .iter()
                .filter(|host| item.receipts.contains_key(*host))
                .collect();
            Ok(json!({"messageId":id,"state":item.state,
                "durable":stored.len() >= recipient.required_copies as usize,
                "requiredCopies":recipient.required_copies,"storedHosts":stored,
                "retryConfirmed":false,"error":format!("{error:#}")}))
        }
    }
}
pub fn retry(c: &Config, settings: &Settings, message_id: &str) -> Result<Value> {
    protocol::hex_bytes::<16>(message_id)?;
    let mut v = Vault::open(&settings.vault, &settings.key, &c.network)?;
    let item = v
        .data
        .outbox
        .get(message_id)
        .context("unknown form submission")?;
    ensure!(
        item.form_consent.is_some() && item.mailbox == settings.mailbox,
        "not a form submission for this sending mailbox"
    );
    delivery(&mut v, c, message_id)
}

/// Remove a review without sending mail or changing an already queued submission.
pub fn discard(c: &Config, settings: &Settings, review_id: &str) -> Result<()> {
    protocol::hex_bytes::<16>(review_id)?;
    let mut v = Vault::open(&settings.vault, &settings.key, &c.network)?;
    let record = v
        .data
        .form_reviews
        .get(review_id)
        .context("unknown form review")?;
    ensure!(
        record.mailbox == settings.mailbox,
        "review belongs to another sending mailbox"
    );
    v.data.form_reviews.remove(review_id);
    v.commit()
}

#[derive(Args)]
pub struct Arguments {
    #[arg(long, global = true)]
    vault: Option<PathBuf>,
    #[arg(long, global = true)]
    key: Option<PathBuf>,
    #[arg(long, global = true)]
    reader_config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Independently verify and accept this exact published form for a receiving mailbox.
    Accept {
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        page_id: String,
        #[arg(long)]
        form_id: String,
    },
    /// Retain an immutable encrypted review without sending mail.
    Prepare {
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        page_id: String,
        #[arg(long)]
        form_id: String,
        #[arg(long)]
        values: PathBuf,
        #[arg(long)]
        expires: Option<u64>,
    },
    /// List retained review identifiers without printing their field values.
    Reviews,
    /// Show a retained review without sending mail.
    Review {
        #[arg(long)]
        review_id: String,
    },
    /// Discard an unsubmitted local review.
    Discard {
        #[arg(long)]
        review_id: String,
    },
    /// Confirm one retained review and durably queue its exact submission.
    Submit {
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        review_id: String,
        #[arg(long)]
        confirm: bool,
    },
    /// Reconcile delivery of an existing submission without creating another message.
    Retry {
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        message_id: String,
    },
    /// Read authenticated mail and return typed values only for an accepted form publication.
    Receive {
        #[arg(long)]
        mailbox: String,
        #[arg(long, required_unless_present = "local")]
        host: Option<String>,
        #[arg(long)]
        message_id: String,
        #[arg(long, conflicts_with = "host")]
        local: bool,
    },
    Accepted,
}
pub fn run(path: Option<&Path>, args: Arguments) -> Result<()> {
    let c = mail::config(path)?;
    let vault = args.vault.as_deref().context("--vault is required")?;
    let key = args.key.as_deref().context("--key is required")?;
    let settings = |mailbox: String| Settings {
        vault: vault.into(),
        key: key.into(),
        mailbox,
    };
    let reader = || mail::config(args.reader_config.as_deref().or(path));
    let value = match args.command {
        Command::Prepare {
            mailbox,
            page_id,
            form_id,
            values,
            expires,
        } => {
            let reader = reader()?;
            let (descriptor, _) = publication(&reader, &page_id)?;
            let values: BTreeMap<String, Value> =
                serde_json::from_slice(&mail_vault::read_private(&values, MAX_VALUES)?)?;
            serde_json::to_value(prepare(
                &c,
                &reader,
                &settings(mailbox),
                &descriptor,
                &form_id,
                values,
                expires,
            )?)?
        }
        Command::Accept {
            mailbox,
            page_id,
            form_id,
        } => receive::accept(&c, &reader()?, &settings(mailbox), &page_id, &form_id)?,
        Command::Submit {
            mailbox,
            review_id,
            confirm: approved,
        } => {
            ensure!(
                approved,
                "--confirm is required after reviewing the retained submission"
            );
            confirm(&c, &reader()?, &settings(mailbox), &review_id)?
        }
        Command::Retry {
            mailbox,
            message_id,
        } => retry(&c, &settings(mailbox), &message_id)?,
        Command::Receive {
            mailbox,
            host,
            message_id,
            local,
        } => receive::receive(&c, &settings(mailbox), host.as_deref(), &message_id, local)?,
        Command::Reviews => {
            let v = Vault::open(vault, key, &c.network)?;
            json!({"reviews":v.data.form_reviews.values().map(|record| json!({
                "reviewId":record.review.review_id,"submissionId":record.review.submission_id,
                "mailbox":record.mailbox,"pageId":record.review.descriptor.page_id,
                "formId":record.review.form_id,"expires":record.review.expires,
            })).collect::<Vec<_>>()})
        }
        Command::Review { review_id } => {
            let v = Vault::open(vault, key, &c.network)?;
            serde_json::to_value(
                &v.data
                    .form_reviews
                    .get(&review_id)
                    .context("unknown form review")?
                    .review,
            )?
        }
        Command::Discard { review_id } => {
            let mut v = Vault::open(vault, key, &c.network)?;
            ensure!(
                v.data.form_reviews.remove(&review_id).is_some(),
                "unknown form review"
            );
            v.commit()?;
            json!({"discardedReview":review_id})
        }
        Command::Accepted => {
            let v = Vault::open(vault, key, &c.network)?;
            json!({"accepted":v.data.accepted_forms})
        }
    };
    crate::print_value(&value)
}
