// SPDX-License-Identifier: MIT
// Independent private-mail commands and explicit local recovery workflows.
use crate::mail_delivery::{duplicate_identity, inbox, read, refill, retry};
use crate::{
    Config, Identity, files, mail_crypto as crypto, mail_protocol as wire,
    mail_vault::{self, Contact, Mailbox, Outbox, Vault},
};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
#[derive(Args)]
pub struct Arguments {
    #[arg(long, global = true)]
    vault: Option<PathBuf>,
    #[arg(long, global = true)]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Release one selected local letter to a named recipient with explicit consent.
    ArchiveDisclose(crate::mail_disclosure::Arguments),
    /// Create encrypted local mail state and a separate age identity file.
    Init {
        #[arg(long)]
        authority_key: String,
    },
    /// Sign exact host resources; the separate Gate adds 128 MiB, 32 PIDs and 0.5 CPU.
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
    Hosts {
        #[arg(long)]
        mailbox: Option<String>,
    },
    AddressCreate {
        #[arg(long)]
        mailbox: String,
        #[arg(long = "host", required = true)]
        hosts: Vec<String>,
        #[arg(long, default_value_t = 1)]
        copies: u16,
        #[arg(long)]
        expires: u64,
        #[arg(long, default_value_t = 86400)]
        retention: u64,
    },
    AddressRegister {
        #[arg(long)]
        mailbox: String,
    },
    AddressRenew {
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        expires: u64,
    },
    DeviceRenew {
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        device_id: String,
        #[arg(long)]
        expires: u64,
    },
    ArchiveList {
        #[arg(long)]
        address: String,
    },
    ArchiveRead {
        #[arg(long)]
        address: String,
        #[arg(long)]
        message_id: String,
    },
    ArchiveDelete {
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        message_id: String,
    },
    AddressShow {
        #[arg(long)]
        mailbox: String,
    },
    Addresses,
    Placement {
        #[arg(long)]
        mailbox: String,
        #[arg(long = "host", required = true)]
        hosts: Vec<String>,
        #[arg(long, default_value_t = 1)]
        copies: u16,
    },
    AddressDelete {
        #[arg(long)]
        mailbox: String,
    },
    /// Generate a separate child device; only the public binding is exported.
    DeviceCreate {
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        address: String,
        #[arg(long)]
        expires: u64,
        #[arg(long = "permission", required = true)]
        permissions: Vec<String>,
        #[arg(long)]
        output: PathBuf,
    },
    DeviceExport {
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        output: PathBuf,
    },
    DeviceEnrol {
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        binding: PathBuf,
    },
    DeviceRevoke {
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        device_id: String,
    },
    ContactVerify {
        #[arg(long)]
        mailbox: Option<String>,
        #[arg(long)]
        address: String,
        #[arg(long)]
        owner_fingerprint: String,
    },
    Refill {
        #[arg(long)]
        mailbox: String,
        #[arg(long, default_value_t = 8)]
        count: usize,
    },
    Send {
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        subject_file: PathBuf,
        #[arg(long)]
        body: PathBuf,
        #[arg(long)]
        expires: Option<u64>,
    },
    Outbox,
    Retry {
        #[arg(long)]
        message_id: String,
    },
    /// Remove only this sender's queued copy; delivered copies remain.
    Cancel {
        #[arg(long)]
        message_id: String,
    },
    Inbox {
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        local: bool,
    },
    Read {
        #[arg(long)]
        mailbox: String,
        #[arg(long, required_unless_present = "local")]
        host: Option<String>,
        #[arg(long)]
        message_id: String,
        #[arg(long, conflicts_with = "host")]
        local: bool,
    },
    Delete {
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        host: String,
        #[arg(long)]
        message_id: String,
        #[arg(long)]
        digest: String,
    },
    ArchiveExport {
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        include_owner_recovery: bool,
    },
    ArchiveImport {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        expected_address: String,
    },
    OwnerRecover {
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        expected_address: String,
    },
}
pub(super) fn config(path: Option<&Path>) -> Result<Config> {
    Ok(serde_json::from_slice(&files::read_bounded(
        path.context("--config is required")?,
        false,
    )?)?)
}
pub(super) fn label(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        "mailbox label must contain 1..64 letters, digits, underscore or hyphen"
    );
    Ok(())
}
pub(super) fn output(value: Value) -> Result<()> {
    crate::print_value(&value)
}
pub(super) fn local_device(
    network: &str,
    address: &str,
    expires: u64,
    permissions: Vec<String>,
) -> Result<Mailbox> {
    ensure!(
        expires > crate::now()? && expires <= crate::now()?.saturating_add(604800),
        "device lifetime must be within seven days"
    );
    ensure!(
        !permissions.is_empty()
            && permissions
                .iter()
                .all(|p| matches!(p.as_str(), "Read" | "Send" | "Delete")),
        "device scope must be Read, Send or Delete"
    );
    crate::protocol::hex_bytes::<32>(network)?;
    let request = wire::new_identity();
    let (signer, mls_signature_key) = crypto::signer()?;
    let device = wire::Device {
        device_id: wire::device_id(address, &request.public_key)?,
        request_key: request.public_key.clone(),
        mls_signature_key,
        permissions,
        expires,
    };
    Ok(Mailbox {
        address: address.into(),
        owner: None,
        request,
        signer,
        device,
        manifest: None,
        packages: Vec::new(),
    })
}
pub(super) fn refresh(v: &mut Vault, c: &Config, mailbox: &str) -> Result<wire::Manifest> {
    let signed = {
        let b = v.mailbox(mailbox)?;
        wire::address_get(c, b.owner.as_ref().unwrap_or(&b.request), &b.address)?
    };
    v.set_manifest(mailbox, signed)
}
pub(super) fn own_manifest<'a>(v: &'a Vault, mailbox: &str) -> Result<&'a wire::Signed> {
    v.mailbox(mailbox)?
        .manifest
        .as_ref()
        .context("mail device is not enrolled; owner must approve its public binding")
}
pub(super) fn show(v: &Vault, mailbox: &str) -> Result<Value> {
    let b = v.mailbox(mailbox)?;
    Ok(
        json!({"mailbox":mailbox,"addressId":b.address,"deviceId":b.device.device_id,"requestKey":b.device.request_key,"mlsSignatureKey":b.device.mls_signature_key,"ownerAvailable":b.owner.is_some(),"manifest":b.manifest}),
    )
}
pub(super) fn update(
    v: &mut Vault,
    c: &Config,
    mailbox: &str,
    mut m: wire::Manifest,
) -> Result<()> {
    let old = own_manifest(v, mailbox)?;
    let previous = wire::manifest(&c.network, old)?;
    m.previous_digest = Some(wire::object_digest(old)?);
    m.generation = previous
        .generation
        .checked_add(1)
        .context("manifest generation exhausted")?;
    let owner = v
        .mailbox(mailbox)?
        .owner
        .as_ref()
        .context("owner key required")?;
    let signed = wire::sign(wire::MANIFEST, &c.network, owner, &m)?;
    wire::authority(
        c,
        owner,
        json!({"type":if m.deleted{"MailAddressDelete"}else{"MailAddressUpdate"},"addressId":m.address_id,"expectedGeneration":previous.generation,"manifest":signed}),
    )?;
    v.set_manifest(mailbox, signed)?;
    Ok(())
}
pub(super) fn hosts(v: &mut Vault, c: &Config, key: &Identity) -> Result<()> {
    let result = wire::authority(c, key, json!({"type":"MailHosts"}))?;
    wire::fresh_directory(&result)?;
    ensure!(
        result["authoritySigner"].as_str() == Some(&v.data.authority_signer),
        "mail authority signer differs from pinned key"
    );
    for value in result["hosts"]
        .as_array()
        .context("missing mail host directory")?
    {
        let signed: wire::Signed = serde_json::from_value(value.clone())?;
        let h = wire::host(c, &signed, &v.data.authority_signer)?;
        if let Some(old) = v.data.hosts.get(&h.host_key) {
            let prev = wire::verify::<wire::Host>(wire::HOST, &c.network, &old.public_key, old);
            if let Ok(prev) = prev {
                ensure!(h.generation >= prev.generation, "mail host rollback");
                if h.generation == prev.generation {
                    ensure!(
                        wire::signed_digest(wire::HOST, &signed)?
                            == wire::signed_digest(wire::HOST, old)?,
                        "mail host consent fork"
                    );
                }
            }
        }
        v.data.hosts.insert(h.host_key.clone(), signed);
    }
    v.commit()
}
pub(super) fn selected_host(
    v: &Vault,
    c: &Config,
    m: &wire::Manifest,
    key: &str,
) -> Result<wire::Host> {
    ensure!(
        m.storage_hosts.iter().any(|h| h == key),
        "host is outside user-selected mailbox placement"
    );
    wire::host(
        c,
        v.data
            .hosts
            .get(key)
            .context("mail host is not configured; refresh hosts")?,
        &v.data.authority_signer,
    )
}
#[allow(clippy::too_many_arguments)]
pub(super) fn operation(
    c: &Config,
    b: &Mailbox,
    m: &wire::Manifest,
    h: &wire::Host,
    action: &str,
    id: Option<&str>,
    digest: Option<String>,
    bytes: u64,
    route: Option<wire::Route>,
) -> Result<wire::Signed> {
    wire::sign(
        wire::OPERATION,
        &c.network,
        &b.request,
        &wire::Operation {
            version: 1,
            network: c.network.clone(),
            operation_id: crate::random_hex::<16>(),
            issued_at: crate::now()?,
            host_key: h.host_key.clone(),
            action: action.into(),
            address_id: b.address.clone(),
            device_id: b.device.device_id.clone(),
            message_id: id.map(str::to_owned),
            manifest_generation: m.generation,
            manifest_digest: wire::object_digest(
                b.manifest.as_ref().context("missing own manifest")?,
            )?,
            payload_digest: digest,
            payload_bytes: bytes,
            after: None,
            route,
        },
    )
}
pub(super) fn receipt(
    c: &Config,
    h: &wire::Host,
    s: &wire::Signed,
    id: &str,
    digest: Option<&str>,
) -> Result<wire::Receipt> {
    let r: wire::Receipt = wire::verify(wire::RECEIPT, &c.network, &h.host_key, s)?;
    ensure!(
        r.version == 1
            && r.network == c.network
            && r.host_key == h.host_key
            && r.host_generation > 0
            && r.host_generation <= h.generation
            && r.message_id == id
            && digest.is_none_or(|d| r.payload_digest == d)
            && matches!(r.status.as_str(), "Stored" | "Received" | "Deleted"),
        "invalid mail store receipt"
    );
    Ok(r)
}
pub(super) fn text(path: &Path, max: usize) -> Result<String> {
    let bytes = files::read_bounded(path, true)?;
    ensure!(bytes.len() <= max, "mail text exceeds limit");
    Ok(String::from_utf8(bytes)?)
}
pub fn run(path: Option<&Path>, args: Arguments) -> Result<()> {
    let c = config(path)?;
    match &args.command {
        Command::HostConsent { spec, output: path } => {
            let host: wire::Host = serde_json::from_slice(&files::read_bounded(spec, false)?)?;
            let key = crate::load_identity(&c.identity)?;
            ensure!(
                host.host_key == key.public_key && host.network == c.network,
                "host consent does not match configured host identity"
            );
            let signed = wire::sign(wire::HOST, &c.network, &key, &host)?;
            wire::host(&c, &signed, &host.authority_signer)?;
            mail_vault::write_new(path, &serde_json::to_vec_pretty(&signed)?)?;
            return output(
                json!({"hostKey":host.host_key,"consentDigest":wire::signed_digest(wire::HOST,&signed)?,"workerLimits":{"memoryBytes":host.memory_bytes,"pids":host.pids,"cpuQuota":host.cpu_quota,"cpuPeriod":host.cpu_period,"stateBytes":host.state_bytes},"additionalGateLimits":{"memoryBytes":134217728,"pids":32,"cpuQuota":50000,"cpuPeriod":100000,"volatileStateBytes":8388608}}),
            );
        }
        Command::HostRegister { consent } => {
            let key = crate::load_identity(&c.identity)?;
            return output(wire::authority(
                &c,
                &key,
                json!({"type":"MailHostRegister","consent":wire::read_signed(consent)?}),
            )?);
        }
        Command::HostWithdraw {
            expected_generation,
        } => {
            let key = crate::load_identity(&c.identity)?;
            return output(wire::authority(
                &c,
                &key,
                json!({"type":"MailHostWithdraw","hostKey":key.public_key,"expectedGeneration":expected_generation}),
            )?);
        }
        Command::Hosts { mailbox: None } if args.vault.is_none() => {
            let key = crate::load_identity(&c.identity)?;
            return output(wire::authority(&c, &key, json!({"type":"MailHosts"}))?);
        }
        _ => {}
    }
    let directory = args.vault.as_deref().context("--vault is required")?;
    let key = args.key.as_deref().context("--key is required")?;
    if let Command::Init { authority_key } = args.command {
        let v = Vault::initialise(directory, key, &c.network, &authority_key)?;
        return output(
            json!({"ageRecipient":v.age_recipient(),"authoritySigner":v.data.authority_signer}),
        );
    }
    let mut v = Vault::open(directory, key, &c.network)?;
    let value = match args.command {
        Command::ArchiveDisclose(arguments) => crate::mail_disclosure::export(&v, &c, arguments)?,
        Command::Hosts { mailbox } => {
            let identity = directory_key(&v, &c, mailbox.as_deref())?;
            hosts(&mut v, &c, &identity)?;
            json!({"hosts":v.data.hosts})
        }
        Command::Addresses => {
            json!({"mailboxes":v.data.mailboxes.keys().map(|l|show(&v,l)).collect::<Result<Vec<_>>>()?})
        }
        Command::AddressRegister { mailbox } => {
            let member = crate::load_identity(&c.identity)?;
            let signed = own_manifest(&v, &mailbox)?.clone();
            let current = wire::manifest(&c.network, &signed)?;
            ensure!(
                current.generation == 1,
                "address-register only retries original registration"
            );
            if let Err(error) = wire::authority(
                &c,
                &member,
                json!({"type":"MailAddressCreate","manifest":signed}),
            ) {
                let actual =
                    wire::address_get(&c, &member, &current.address_id).map_err(|_| error)?;
                ensure!(
                    wire::object_digest(&actual)? == wire::object_digest(&signed)?,
                    "registered address differs from pending creation"
                );
            }
            show(&v, &mailbox)?
        }
        Command::AddressRenew { mailbox, expires } => {
            ensure!(
                expires > crate::now()? && expires <= crate::now()?.saturating_add(604800),
                "renewal must be within seven days"
            );
            let mut m = refresh(&mut v, &c, &mailbox)?;
            ensure!(
                m.devices.iter().all(|d| d.expires <= expires),
                "address must outlive its devices"
            );
            m.expires = expires;
            update(&mut v, &c, &mailbox, m)?;
            show(&v, &mailbox)?
        }
        Command::DeviceRenew {
            mailbox,
            device_id,
            expires,
        } => {
            let mut m = refresh(&mut v, &c, &mailbox)?;
            ensure!(
                expires > crate::now()? && expires <= m.expires,
                "device must expire within address lifetime"
            );
            m.devices
                .iter_mut()
                .find(|d| d.device_id == device_id)
                .context("unknown device")?
                .expires = expires;
            update(&mut v, &c, &mailbox, m)?;
            show(&v, &mailbox)?
        }
        Command::ArchiveList { address } => {
            json!({"source":"LocalArchive","addressId":address,"records":v.data.archive.values().filter(|a|a.letter.route.recipient_address==address||a.letter.route.sender_address==address).map(|a|json!({"messageId":a.letter.route.message_id,"senderAddress":a.letter.route.sender_address,"subject":a.letter.subject,"origin":a.origin})).collect::<Vec<_>>()})
        }
        Command::ArchiveRead {
            address,
            message_id,
        } => {
            let record = v
                .data
                .archive
                .values()
                .find(|a| {
                    a.letter.route.message_id == message_id
                        && (a.letter.route.recipient_address == address
                            || a.letter.route.sender_address == address)
                })
                .context("letter is not in the local archive")?;
            json!({"source":"LocalArchive","origin":record.origin,"letter":record.letter})
        }
        Command::ArchiveDelete {
            mailbox,
            message_id,
        } => {
            let address = v.mailbox(&mailbox)?.address.clone();
            let before = v.data.archive.len();
            v.data.archive.retain(|_, a| {
                a.letter.route.message_id != message_id
                    || (a.letter.route.recipient_address != address
                        && a.letter.route.sender_address != address)
            });
            v.commit()?;
            json!({"deletedLocalRecords":before-v.data.archive.len(),"remoteCopiesUnchanged":true})
        }
        Command::AddressShow { mailbox } => {
            refresh(&mut v, &c, &mailbox)?;
            show(&v, &mailbox)?
        }
        Command::AddressCreate {
            mailbox,
            hosts: selected,
            copies,
            expires,
            retention,
        } => {
            label(&mailbox)?;
            ensure!(
                !v.data.mailboxes.contains_key(&mailbox),
                "mailbox label already exists; use address-show to recover registration status"
            );
            let member = crate::load_identity(&c.identity)?;
            hosts(&mut v, &c, &member)?;
            ensure!(
                (60..=604800).contains(&retention)
                    && !selected.is_empty()
                    && selected.len() <= 4
                    && copies > 0
                    && copies as usize <= selected.len(),
                "invalid mailbox placement or retention"
            );
            let owner = wire::new_identity();
            let address = wire::address_id(&c.network, &owner.public_key)?;
            let mut b = local_device(
                &c.network,
                &address,
                expires,
                vec!["Read".into(), "Send".into(), "Delete".into()],
            )?;
            let m = wire::Manifest {
                version: 1,
                network: c.network.clone(),
                address_id: address,
                owner_key: owner.public_key.clone(),
                generation: 1,
                previous_digest: None,
                expires,
                devices: vec![b.device.clone()],
                storage_hosts: selected,
                required_copies: copies,
                retention_seconds: retention,
                deleted: false,
            };
            for h in &m.storage_hosts {
                selected_host(&v, &c, &m, h)?;
            }
            let signed = wire::sign(wire::MANIFEST, &c.network, &owner, &m)?;
            b.owner = Some(owner);
            b.manifest = Some(signed.clone());
            v.data.mailboxes.insert(mailbox.clone(), b);
            v.commit()?;
            wire::authority(
                &c,
                &member,
                json!({"type":"MailAddressCreate","manifest":signed}),
            )?;
            show(&v, &mailbox)?
        }
        Command::Placement {
            mailbox,
            hosts: selected,
            copies,
        } => {
            let mut m = refresh(&mut v, &c, &mailbox)?;
            let request = duplicate_identity(&v.mailbox(&mailbox)?.request);
            hosts(&mut v, &c, &request)?;
            m.storage_hosts = selected;
            m.required_copies = copies;
            ensure!(
                !m.storage_hosts.is_empty()
                    && m.storage_hosts.len() <= 4
                    && copies > 0
                    && copies as usize <= m.storage_hosts.len(),
                "invalid mailbox placement"
            );
            for h in &m.storage_hosts {
                selected_host(&v, &c, &m, h)?;
            }
            update(&mut v, &c, &mailbox, m)?;
            show(&v, &mailbox)?
        }
        Command::AddressDelete { mailbox } => {
            let mut m = refresh(&mut v, &c, &mailbox)?;
            m.deleted = true;
            m.devices.clear();
            m.storage_hosts.clear();
            m.required_copies = 0;
            update(&mut v, &c, &mailbox, m)?;
            show(&v, &mailbox)?
        }
        Command::DeviceCreate {
            mailbox,
            address,
            expires,
            permissions,
            output: path,
        } => {
            label(&mailbox)?;
            ensure!(
                !v.data.mailboxes.contains_key(&mailbox),
                "mailbox label already exists"
            );
            crate::protocol::hex_bytes::<32>(&address)?;
            let b = local_device(&c.network, &address, expires, permissions)?;
            let binding = serde_json::to_vec_pretty(&b.device)?;
            v.data.mailboxes.insert(mailbox.clone(), b);
            v.commit()?;
            mail_vault::write_new(&path, &binding)?;
            show(&v, &mailbox)?
        }
        Command::DeviceExport {
            mailbox,
            output: path,
        } => {
            let b = v.mailbox(&mailbox)?;
            mail_vault::write_new(&path, &serde_json::to_vec_pretty(&b.device)?)?;
            json!({"mailbox":mailbox,"device":b.device})
        }
        Command::DeviceEnrol { mailbox, binding } => {
            let mut m = refresh(&mut v, &c, &mailbox)?;
            let device: wire::Device =
                serde_json::from_slice(&files::read_bounded(&binding, false)?)?;
            ensure!(
                m.devices.len() < 8 && !m.devices.iter().any(|d| d.device_id == device.device_id),
                "device already enrolled or device quota reached"
            );
            m.devices.push(device);
            update(&mut v, &c, &mailbox, m)?;
            show(&v, &mailbox)?
        }
        Command::DeviceRevoke { mailbox, device_id } => {
            let mut m = refresh(&mut v, &c, &mailbox)?;
            ensure!(
                m.devices.iter().any(|d| d.device_id == device_id),
                "unknown device"
            );
            m.devices.retain(|d| d.device_id != device_id);
            update(&mut v, &c, &mailbox, m)?;
            show(&v, &mailbox)?
        }
        Command::ContactVerify {
            mailbox,
            address,
            owner_fingerprint,
        } => {
            ensure!(
                wire::address_id(&c.network, &owner_fingerprint)? == address,
                "owner fingerprint does not derive this address"
            );
            let identity = directory_key(&v, &c, mailbox.as_deref())?;
            let signed = wire::address_get(&c, &identity, &address)?;
            let m = wire::manifest(&c.network, &signed)?;
            ensure!(
                m.owner_key == owner_fingerprint && !m.deleted && m.expires > crate::now()?,
                "contact is inactive or has another owner"
            );
            if let Some(old) = v.data.contacts.get(&address) {
                ensure!(
                    m.generation >= old.generation
                        && (m.generation != old.generation
                            || wire::object_digest(&signed)? == old.manifest_digest),
                    "contact rollback or fork"
                );
            }
            v.data.contacts.insert(
                address.clone(),
                Contact {
                    address: address.clone(),
                    owner_key: owner_fingerprint,
                    generation: m.generation,
                    manifest_digest: wire::object_digest(&signed)?,
                },
            );
            v.commit()?;
            json!({"verifiedAddress":address,"generation":m.generation})
        }
        Command::Refill { mailbox, count } => refill(&mut v, &c, &mailbox, count)?,
        Command::Send {
            mailbox,
            to,
            subject_file,
            body,
            expires,
        } => {
            v.mailbox(&mailbox)?;
            crate::protocol::hex_bytes::<32>(&to)?;
            let id = crate::random_hex::<16>();
            let item = Outbox {
                mailbox,
                recipient: to,
                claim_id: crate::random_hex::<16>(),
                message_id: id.clone(),
                expires: expires.unwrap_or(0),
                subject: text(&subject_file, 512)?,
                body: text(&body, 32768)?,
                claim: None,
                recipient_manifest: None,
                ciphertext: None,
                receipts: BTreeMap::new(),
                state: "Queued".into(),
                form_consent: None,
            };
            v.data.outbox.insert(id.clone(), item);
            v.commit()?;
            match retry(&mut v, &c, &id) {
                Ok(value) => value,
                Err(e) => {
                    json!({"messageId":id,"state":v.data.outbox[&id].state,"durable":false,"error":format!("{e:#}")})
                }
            }
        }
        Command::Retry { message_id } => retry(&mut v, &c, &message_id)?,
        Command::Outbox => {
            json!({"messages":v.data.outbox.values().map(|o|json!({"messageId":o.message_id,"mailbox":o.mailbox,"recipientAddress":o.recipient,"state":o.state,"expires":o.expires,"storedHosts":o.receipts.keys().collect::<Vec<_>>()})).collect::<Vec<_>>()})
        }
        Command::Cancel { message_id } => {
            let item = v
                .data
                .outbox
                .remove(&message_id)
                .context("unknown outbox message")?;
            v.commit()?;
            json!({"messageId":message_id,"cancelledLocalCopy":true,"previouslyStoredHosts":item.receipts.keys().collect::<Vec<_>>()})
        }
        Command::Inbox { mailbox, local } => inbox(&mut v, &c, &mailbox, local)?,
        Command::Read {
            mailbox,
            host,
            message_id,
            local,
        } => {
            if local {
                let address = &v.mailbox(&mailbox)?.address;
                let found = v
                    .data
                    .archive
                    .values()
                    .find(|a| {
                        a.letter.route.message_id == message_id
                            && (&a.letter.route.recipient_address == address
                                || &a.letter.route.sender_address == address)
                    })
                    .context("letter is not in this local archive")?;
                json!({"source":"LocalArchive","origin":found.origin,"letter":found.letter})
            } else {
                read(
                    &mut v,
                    &c,
                    &mailbox,
                    host.as_deref().context("--host is required")?,
                    &message_id,
                )?
            }
        }
        Command::Delete {
            mailbox,
            host,
            message_id,
            digest,
        } => {
            let m = refresh(&mut v, &c, &mailbox)?;
            let request = duplicate_identity(&v.mailbox(&mailbox)?.request);
            hosts(&mut v, &c, &request)?;
            let h = selected_host(&v, &c, &m, &host)?;
            let op = operation(
                &c,
                v.mailbox(&mailbox)?,
                &m,
                &h,
                "Delete",
                Some(&message_id),
                Some(digest.clone()),
                0,
                None,
            )?;
            let result = wire::store(&c, &h, &op, None)?;
            let signed: wire::Signed = serde_json::from_value(result["receipt"].clone())?;
            ensure!(
                receipt(&c, &h, &signed, &message_id, Some(&digest))?.status == "Deleted",
                "invalid deletion receipt"
            );
            json!({"receipt":signed})
        }
        Command::ArchiveExport {
            mailbox,
            recipient,
            output: path,
            include_owner_recovery,
        } => crate::mail_archive::export(
            &v,
            &c,
            &mailbox,
            &recipient,
            &path,
            include_owner_recovery,
        )?,
        Command::ArchiveImport {
            input,
            expected_address,
        } => crate::mail_archive::import(&mut v, &c, &input, &expected_address)?,
        Command::OwnerRecover {
            mailbox,
            input,
            expected_address,
        } => crate::mail_archive::recover(&mut v, &c, &mailbox, &input, &expected_address)?,
        Command::Init { .. }
        | Command::HostConsent { .. }
        | Command::HostRegister { .. }
        | Command::HostWithdraw { .. } => unreachable!(),
    };
    output(value)
}

fn directory_key(v: &Vault, c: &Config, mailbox: Option<&str>) -> Result<Identity> {
    if let Some(label) = mailbox {
        let b = v.mailbox(label)?;
        Ok(duplicate_identity(b.owner.as_ref().unwrap_or(&b.request)))
    } else {
        crate::load_identity(&c.identity)
    }
}
