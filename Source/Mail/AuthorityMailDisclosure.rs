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
#[path = "../../Tests/Unit/Mail/AuthorityMailDisclosureUnitTests.rs"]
mod tests;
