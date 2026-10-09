// SPDX-License-Identifier: MIT
// Explicit recipient acceptance precedes encrypted, resumable selected-store transfers.
use crate::{
    Config, Identity, mail_protocol as signed, transfer_files as files, transfer_protocol as wire,
    transfer_vault::{self, Vault},
};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
#[derive(Args)]
pub struct Arguments {
    /// Dedicated private transfer state directory.
    #[arg(long, global = true)]
    vault: Option<PathBuf>,
    /// Dedicated native age identity file.
    #[arg(long, global = true)]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Initialise encrypted local state and a new native age receiving identity.
    Init {
        #[arg(long)]
        authority_key: String,
    },
    /// Sign exact transfer host consent from a complete JSON specification.
    HostConsent {
        #[arg(long)]
        spec: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    HostRegister {
        #[arg(long)]
        consent: PathBuf,
    },
    HostWithdraw {
        #[arg(long)]
        expected_generation: u64,
    },
    Hosts,
    /// Encrypt a regular file and register its immutable metadata; no bulk upload occurs.
    Offer {
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        recipient_age: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        expires: u64,
        #[arg(long)]
        label: Option<String>,
    },
    /// Repeat registration of a durably saved offer after an uncertain response.
    Register {
        #[arg(long)]
        transfer_id: String,
    },
    List,
    /// List encrypted outgoing jobs, including offers whose registration response was lost.
    Outbox,
    Inspect {
        #[arg(long)]
        transfer_id: String,
    },
    /// Verify the receiving age identity and select one consenting store.
    Accept {
        #[arg(long)]
        transfer_id: String,
        #[arg(long)]
        host: String,
        #[arg(long)]
        destination: String,
        #[arg(long)]
        expires: Option<u64>,
    },
    /// Upload or resume exact saved ciphertext after recipient acceptance.
    #[command(alias = "resume")]
    Send {
        #[arg(long)]
        transfer_id: String,
        /// Stop after this many chunks; zero uploads all remaining chunks.
        #[arg(long, default_value_t = 0)]
        max_chunks: u64,
    },
    Status {
        #[arg(long)]
        transfer_id: String,
    },
    /// Resume download, verify all bytes and publish to a new explicit local file.
    Receive {
        #[arg(long)]
        transfer_id: String,
        #[arg(long)]
        destination: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Permanently cancel this offer at authority.
    Cancel {
        #[arg(long)]
        transfer_id: String,
    },
    /// Remove the complete or partial ciphertext at its selected store.
    Delete {
        #[arg(long)]
        transfer_id: String,
    },
    /// Remove local encrypted state for a cancelled, expired or deleted transfer.
    Forget {
        #[arg(long)]
        transfer_id: String,
    },
}
fn load(path: Option<&Path>) -> Result<(Config, Identity)> {
    let config: Config = serde_json::from_slice(&crate::files::read_bounded(
        path.context("--config is required")?,
        false,
    )?)?;
    crate::checked_key(&config.network)?;
    let identity = crate::load_identity(&config.identity)?;
    Ok((config, identity))
}
fn label(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
        "opaque labels must contain 1-64 letters, digits, hyphens or underscores"
    );
    Ok(())
}
pub fn run(path: Option<&Path>, arguments: Arguments) -> Result<()> {
    let (config, identity) = load(path)?;
    let result = match arguments.command {
        Command::HostConsent { spec, output } => {
            let host: wire::HostConsent =
                serde_json::from_slice(&crate::files::read_bounded(&spec, false)?)?;
            ensure!(
                host.host_key == identity.public_key && host.network == config.network,
                "host specification belongs to another identity or network"
            );
            let envelope = signed::sign(wire::HOST, &config.network, &identity, &host)?;
            wire::host(&config, &envelope, &host.authority_signer)?;
            files::write_new(&output, &serde_json::to_vec_pretty(&envelope)?)?;
            json!({"consent":output,"hostKey":host.host_key,"generation":host.generation,"workerMemoryBytes":host.memory_bytes,"gateMemoryBytes":134217728u64,"gatePids":32,"gateCpuQuota":50000,"gateVolatileBytes":8388608})
        }
        Command::HostRegister { consent } => {
            let envelope = signed::read_signed(&consent)?;
            let h: wire::HostConsent =
                signed::verify(wire::HOST, &config.network, &identity.public_key, &envelope)?;
            wire::host(&config, &envelope, &h.authority_signer)?;
            signed::authority(
                &config,
                &identity,
                json!({"type":"TransferHostRegister","consent":envelope}),
            )?
        }
        Command::HostWithdraw {
            expected_generation,
        } => signed::authority(
            &config,
            &identity,
            json!({"type":"TransferHostWithdraw","hostKey":identity.public_key,"expectedGeneration":expected_generation}),
        )?,
        Command::Hosts => json!({"hosts":wire::hosts(&config, &identity)?}),
        Command::List => {
            let mut entries = Vec::new();
            let mut after: Option<String> = None;
            loop {
                let result = signed::authority(
                    &config,
                    &identity,
                    json!({"type":"TransferOfferList","after":after}),
                )?;
                let page = result["transfers"]
                    .as_array()
                    .context("missing transfer list")?;
                ensure!(
                    page.len() <= 16 && entries.len() + page.len() <= 256,
                    "transfer directory exceeds its bound"
                );
                let mut previous = after.clone();
                for item in page {
                    let r = wire::record(&config, item)?;
                    ensure!(
                        previous.as_ref().is_none_or(|p| r.body.transfer_id > *p),
                        "transfer directory cursor did not advance"
                    );
                    previous = Some(r.body.transfer_id);
                    entries.push(item.clone());
                }
                if result["next"].is_null() {
                    break;
                }
                let next = result["next"]
                    .as_str()
                    .context("invalid transfer cursor")?
                    .to_owned();
                ensure!(
                    !page.is_empty() && previous.as_ref() == Some(&next),
                    "transfer directory cursor differs from its last entry"
                );
                after = Some(next);
            }
            json!({"transfers":entries})
        }
        Command::Inspect { transfer_id } => {
            json!({"transfer":wire::get(&config, &identity, &transfer_id)?})
        }
        Command::Cancel { transfer_id } => {
            let r = wire::get(&config, &identity, &transfer_id)?;
            signed::authority(
                &config,
                &identity,
                json!({"type":"TransferOfferCancel","transferId":transfer_id,"offerDigest":r.offer_digest}),
            )?
        }
        command => {
            let directory = arguments.vault.as_deref().context("--vault is required")?;
            let key = arguments.key.as_deref().context("--key is required")?;
            if let Command::Init { authority_key } = command {
                let vault = Vault::initialise(
                    directory,
                    key,
                    &config,
                    &identity.public_key,
                    &authority_key,
                )?;
                return crate::print_value(
                    &json!({"ageRecipient":vault.recipient(),"authoritySigner":authority_key,"vault":directory}),
                );
            }
            let mut vault = Vault::open(directory, key, &config, &identity.public_key)?;
            match command {
                Command::Offer {
                    recipient,
                    recipient_age,
                    file,
                    expires,
                    label: chosen_label,
                } => {
                    crate::checked_key(&recipient)?;
                    ensure!(
                        recipient != identity.public_key,
                        "sender and recipient must be different members"
                    );
                    ensure!(
                        expires > crate::now()?
                            && expires <= crate::now()?.saturating_add(wire::MAX_LIFETIME),
                        "offer expiry must be within seven days"
                    );
                    let id = crate::random_hex::<16>();
                    let label_value = chosen_label.unwrap_or_else(|| id.clone());
                    label(&label_value)?;
                    let bytes = zeroize::Zeroizing::new(files::read(
                        &file,
                        wire::MAX_FILE as usize,
                        false,
                    )?);
                    let file_name = file
                        .file_name()
                        .and_then(|s| s.to_str())
                        .context("file name must be UTF-8")?;
                    let mut offer = wire::Offer {
                        version: 1,
                        network: config.network.clone(),
                        transfer_id: id.clone(),
                        sender_key: identity.public_key.clone(),
                        recipient_key: recipient,
                        recipient_encryption_key: recipient_age,
                        payload_bytes: 0,
                        payload_digest: String::new(),
                        file_bytes: bytes.len() as u64,
                        label: label_value,
                        expires,
                    };
                    let ciphertext = transfer_vault::seal(&offer, file_name, &bytes)?;
                    offer.payload_bytes = ciphertext.len() as u64;
                    offer.payload_digest = signed::digest(&ciphertext);
                    let envelope = signed::sign(wire::OFFER, &config.network, &identity, &offer)?;
                    vault.data.outgoing.insert(
                        id.clone(),
                        transfer_vault::Job {
                            offer: envelope,
                            ciphertext: signed::encode(&ciphertext),
                            receipt: None,
                        },
                    );
                    vault.commit()?;
                    register(&config, &identity, &vault, &id)?
                }
                Command::Outbox => {
                    json!({"outgoing":vault.data.outgoing.keys().collect::<Vec<_>>()})
                }
                Command::Register { transfer_id } => {
                    register(&config, &identity, &vault, &transfer_id)?
                }
                Command::Accept {
                    transfer_id,
                    host,
                    destination,
                    expires,
                } => {
                    label(&destination)?;
                    let r = wire::get(&config, &identity, &transfer_id)?;
                    wire::active(&r)?;
                    ensure!(
                        r.body.recipient_key == identity.public_key
                            && r.body.recipient_encryption_key == vault.recipient(),
                        "offer does not target this member and verified age identity"
                    );
                    let consent = wire::hosts(&config, &identity)?
                        .into_iter()
                        .find(|h| h.public_key == host)
                        .context("selected store is unavailable")?;
                    let h = wire::host(&config, &consent, &vault.data.authority_signer)?;
                    let expiry = expires.unwrap_or(r.body.expires.min(h.expires));
                    ensure!(
                        expiry > crate::now()? && expiry <= r.body.expires && expiry <= h.expires,
                        "acceptance exceeds consent or offer lifetime"
                    );
                    let acceptance = wire::Acceptance {
                        version: 1,
                        network: config.network.clone(),
                        transfer_id,
                        offer_digest: r.offer_digest,
                        host_key: host,
                        destination,
                        expires: expiry,
                    };
                    let envelope =
                        signed::sign(wire::ACCEPTANCE, &config.network, &identity, &acceptance)?;
                    signed::authority(
                        &config,
                        &identity,
                        json!({"type":"TransferOfferAccept","acceptance":envelope}),
                    )?
                }
                Command::Send {
                    transfer_id,
                    max_chunks,
                } => send(&config, &identity, &mut vault, &transfer_id, max_chunks)?,
                Command::Status { transfer_id } => {
                    let r = wire::get(&config, &identity, &transfer_id)?;
                    if r.accepted.is_none() || r.cancelled {
                        json!({"transfer":r})
                    } else {
                        let h = wire::selected_host(
                            &config,
                            &identity,
                            &r,
                            &vault.data.authority_signer,
                        )?;
                        let result = request(&config, &identity, &h, &r, "Status", 0, 0, None)?;
                        let (_, receipt) = wire::receipt(&config, &h, &r, &result)?;
                        json!({"transfer":r,"receipt":receipt})
                    }
                }
                Command::Receive {
                    transfer_id,
                    destination,
                    output,
                } => receive(
                    &config,
                    &identity,
                    &mut vault,
                    &transfer_id,
                    &destination,
                    &output,
                )?,
                Command::Delete { transfer_id } => {
                    let r = wire::get(&config, &identity, &transfer_id)?;
                    ensure!(
                        r.body.recipient_key == identity.public_key,
                        "only the recipient can delete stored ciphertext"
                    );
                    let h =
                        wire::selected_host(&config, &identity, &r, &vault.data.authority_signer)?;
                    let result = request(&config, &identity, &h, &r, "Delete", 0, 0, None)?;
                    let (_, receipt) = wire::receipt(&config, &h, &r, &result)?;
                    ensure!(
                        receipt.status == "Deleted",
                        "store did not confirm deletion"
                    );
                    json!({"receipt":receipt})
                }
                Command::Forget { transfer_id } => {
                    crate::protocol::hex_bytes::<16>(&transfer_id)?;
                    let now = crate::now()?;
                    let outgoing_expired = if let Some(job) = vault.data.outgoing.get(&transfer_id)
                    {
                        let offer: wire::Offer = signed::verify(
                            wire::OFFER,
                            &config.network,
                            &identity.public_key,
                            &job.offer,
                        )?;
                        ensure!(
                            offer.network == config.network
                                && offer.transfer_id == transfer_id
                                && offer.sender_key == identity.public_key,
                            "saved transfer context mismatch"
                        );
                        offer.expires <= now
                    } else {
                        false
                    };
                    let incoming_expired = vault
                        .data
                        .incoming
                        .get(&transfer_id)
                        .is_some_and(|d| d.expires <= now);
                    // Authority may prune expired records; local signed expiry still permits cleanup.
                    if !outgoing_expired && !incoming_expired {
                        let r = wire::get(&config, &identity, &transfer_id)?;
                        let inactive = r.cancelled
                            || r.body.expires <= now
                            || r.accepted.as_ref().is_some_and(|a| a.expires <= now);
                        if !inactive {
                            let h = wire::selected_host(
                                &config,
                                &identity,
                                &r,
                                &vault.data.authority_signer,
                            )?;
                            let result = request(&config, &identity, &h, &r, "Status", 0, 0, None)?;
                            ensure!(
                                wire::receipt(&config, &h, &r, &result)?.1.status == "Deleted",
                                "cancel or delete this live transfer before forgetting its recovery state"
                            );
                        }
                    }
                    vault.data.outgoing.remove(&transfer_id);
                    vault.data.incoming.remove(&transfer_id);
                    vault.commit()?;
                    json!({"transferId":transfer_id,"localStateRemoved":true})
                }
                _ => unreachable!(),
            }
        }
    };
    crate::print_value(&result)
}
fn register(config: &Config, identity: &Identity, vault: &Vault, id: &str) -> Result<Value> {
    let job = vault
        .data
        .outgoing
        .get(id)
        .context("unknown saved transfer; list the local vault or inspect the offer")?;
    let result = signed::authority(
        config,
        identity,
        json!({"type":"TransferOfferCreate","offer":job.offer}),
    )
    .with_context(|| {
        format!("offer {id} is saved; retry with transfers register --transfer-id {id}")
    })?;
    let r = wire::record(config, &result["transfer"])?;
    ensure!(
        r.body.transfer_id == id
            && r.offer_digest == signed::signed_digest(wire::OFFER, &job.offer)?,
        "authority returned another offer"
    );
    Ok(result)
}
#[allow(clippy::too_many_arguments)]
fn request(
    config: &Config,
    identity: &Identity,
    h: &wire::HostConsent,
    r: &wire::TransferRecord,
    action: &str,
    offset: u64,
    bytes: u64,
    payload: Option<&[u8]>,
) -> Result<Value> {
    let op = wire::operation(config, identity, h, r, action, offset, bytes, payload)?;
    wire::store(config, h, &op, payload)
}
fn send(
    config: &Config,
    identity: &Identity,
    vault: &mut Vault,
    id: &str,
    maximum: u64,
) -> Result<Value> {
    register(config, identity, vault, id)?;
    let r = wire::get(config, identity, id)?;
    ensure!(
        r.body.sender_key == identity.public_key,
        "only sender can upload"
    );
    let job = vault
        .data
        .outgoing
        .get(id)
        .context("unknown saved transfer")?;
    ensure!(
        signed::signed_digest(wire::OFFER, &job.offer)? == r.offer_digest,
        "saved offer differs from authority"
    );
    let ciphertext = signed::decode(&job.ciphertext, wire::MAX_FILE as usize)?;
    ensure!(
        ciphertext.len() as u64 == r.body.payload_bytes
            && signed::digest(&ciphertext) == r.body.payload_digest,
        "saved ciphertext integrity failure"
    );
    let h = wire::selected_host(config, identity, &r, &vault.data.authority_signer)?;
    let result = request(config, identity, &h, &r, "Status", 0, 0, None)?;
    let (mut envelope, mut receipt) = wire::receipt(config, &h, &r, &result)?;
    ensure!(
        receipt.status != "Deleted",
        "transfer is permanently deleted at selected store"
    );
    let mut chunks = 0;
    while receipt.stored_bytes < r.body.payload_bytes && (maximum == 0 || chunks < maximum) {
        let offset = receipt.stored_bytes;
        let end = (offset + wire::CHUNK).min(r.body.payload_bytes);
        let part = &ciphertext[offset as usize..end as usize];
        let result = request(
            config,
            identity,
            &h,
            &r,
            "Put",
            offset,
            part.len() as u64,
            Some(part),
        )?;
        (envelope, receipt) = wire::receipt(config, &h, &r, &result)?;
        ensure!(
            receipt.stored_bytes == end && receipt.status == "Staging",
            "store acknowledged another upload prefix"
        );
        chunks += 1;
    }
    if receipt.stored_bytes == r.body.payload_bytes && receipt.status != "Complete" {
        let result = request(config, identity, &h, &r, "Commit", 0, 0, None)?;
        (envelope, receipt) = wire::receipt(config, &h, &r, &result)?;
        ensure!(
            receipt.status == "Complete",
            "store did not commit complete ciphertext"
        );
    }
    vault
        .data
        .outgoing
        .get_mut(id)
        .context("missing saved transfer")?
        .receipt = Some(envelope);
    vault.commit()?;
    Ok(
        json!({"transferId":id,"receipt":receipt,"chunksUploaded":chunks,"complete":receipt.status == "Complete"}),
    )
}
fn receive(
    config: &Config,
    identity: &Identity,
    vault: &mut Vault,
    id: &str,
    destination: &str,
    output: &Path,
) -> Result<Value> {
    let target = files::Destination::open(output)?;
    let r = wire::get(config, identity, id)?;
    ensure!(
        r.body.recipient_key == identity.public_key
            && r.body.recipient_encryption_key == vault.recipient(),
        "recipient identity mismatch"
    );
    let accepted = r.accepted.as_ref().context("accept the transfer first")?;
    ensure!(
        accepted.destination == destination,
        "destination label differs from explicit acceptance"
    );
    let h = wire::selected_host(config, identity, &r, &vault.data.authority_signer)?;
    let result = request(config, identity, &h, &r, "Status", 0, 0, None)?;
    ensure!(
        wire::receipt(config, &h, &r, &result)?.1.status == "Complete",
        "transfer is not complete at the selected store"
    );
    let mut bytes = if let Some(partial) = vault.data.incoming.get(id) {
        ensure!(
            partial.offer_digest == r.offer_digest && partial.host_key == h.host_key,
            "saved download belongs to another offer or host"
        );
        signed::decode(&partial.ciphertext, wire::MAX_FILE as usize)?
    } else {
        Vec::new()
    };
    ensure!(
        bytes.len() as u64 <= r.body.payload_bytes,
        "saved download is oversized"
    );
    while (bytes.len() as u64) < r.body.payload_bytes {
        let offset = bytes.len() as u64;
        let count = wire::CHUNK.min(r.body.payload_bytes - offset);
        let result = request(config, identity, &h, &r, "Fetch", offset, count, None)?;
        ensure!(
            wire::receipt(config, &h, &r, &result)?.1.status == "Complete"
                && result["offset"].as_u64() == Some(offset),
            "download receipt or offset mismatch"
        );
        let part = signed::decode(
            result["payload"]
                .as_str()
                .context("missing transfer chunk")?,
            wire::CHUNK as usize,
        )?;
        ensure!(part.len() as u64 == count, "download chunk size mismatch");
        bytes.extend_from_slice(&part);
        vault.data.incoming.insert(
            id.into(),
            transfer_vault::Download {
                expires: accepted.expires,
                offer_digest: r.offer_digest.clone(),
                host_key: h.host_key.clone(),
                ciphertext: signed::encode(&bytes),
            },
        );
        vault.commit()?;
    }
    let (header, plaintext) = transfer_vault::unseal(&r.body, &vault.key, &bytes)?;
    // Revalidate after download and decryption; cached bytes never bypass current policy.
    let current = wire::get(config, identity, id)?;
    wire::active(&current)?;
    ensure!(
        current.offer_digest == r.offer_digest
            && serde_json::to_value(&current.accepted)? == serde_json::to_value(&r.accepted)?,
        "transfer policy changed during download"
    );
    let result = request(config, identity, &h, &r, "Status", 0, 0, None)?;
    ensure!(
        wire::receipt(config, &h, &r, &result)?.1.status == "Complete",
        "transfer no longer available"
    );
    target.publish(&plaintext)?;
    vault.data.incoming.remove(id);
    vault.commit()?;
    Ok(
        json!({"transferId":id,"output":output,"fileName":header.file_name,"fileBytes":header.file_bytes,"verified":true}),
    )
}
