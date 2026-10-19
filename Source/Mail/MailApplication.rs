// SPDX-License-Identifier: MIT
// One native Mail worker serialises selected-network operations and retains uncertain sends.
use super::*;
use crate::networks::application::Connection;
#[path = "MailApplicationModel.rs"]
pub(crate) mod model;
pub(crate) use model::*;
#[path = "../Graphical/Mail.rs"]
mod graphical;

#[derive(Args)]
pub struct Arguments {
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    vault: PathBuf,
    #[arg(long)]
    age_key: PathBuf,
    #[arg(long)]
    mailbox: Option<String>,
}
pub(crate) fn run(arguments: Arguments) -> Result<()> {
    graphical::run(arguments)
}
pub(crate) struct Application {
    connection: Connection,
    access: VaultLocation,
}
impl Application {
    pub(crate) fn open(arguments: &Arguments) -> Result<Self> {
        Ok(Self {
            connection: Connection::open(&arguments.profile)?,
            access: VaultLocation {
                vault: arguments.vault.clone(),
                age_key: arguments.age_key.clone(),
            },
        })
    }
    fn vault(&self) -> Result<Vault> {
        Ok(open(&self.connection.location(), &self.access, false)?.1)
    }
    fn online(&self, mailbox: &str) -> DeviceOnline {
        DeviceOnline {
            location: self.connection.mail_location(mailbox),
            vault: self.access.clone(),
            mailbox: mailbox.into(),
            socket: self.connection.online().socket,
        }
    }
    fn transport(&self, service: &str) -> Result<Transport> {
        let route = self
            .connection
            .routes(4)
            .into_iter()
            .find(|r| r.subject == service)
            .context("selected mailbox store has no retained Mail route")?;
        Ok(Transport::socket(id(service)?, route.path))
    }
    pub(crate) fn overview(&self) -> Result<Overview> {
        let v = self.vault()?;
        let mut value = Overview::default();
        for (label, b) in &v.data.mailboxes {
            let stores = b
                .manifest
                .as_ref()
                .map(|signed| protocol::manifest(&hex::encode(v.data.network), signed))
                .transpose()?
                .map(|m| m.storage_hosts)
                .unwrap_or_default();
            value.mailboxes.push(MailboxInfo {
                label: label.clone(),
                address: b.address.clone(),
                private: b.private,
                stores,
            });
        }
        value.contacts = v
            .data
            .contacts
            .iter()
            .map(|(address, c)| ContactInfo {
                address: address.clone(),
                owner: c.owner.clone(),
                generation: c.generation,
            })
            .collect();
        value.outbox = v
            .data
            .outgoing
            .values()
            .map(|job| {
                let required_copies = job
                    .recipient_manifest
                    .as_ref()
                    .map(|signed| protocol::manifest(&hex::encode(v.data.network), signed))
                    .transpose()?
                    .map(|m| m.required_copies)
                    .or_else(|| {
                        job.send_consent
                            .as_ref()
                            .map(|consent| consent.required_copies)
                    });
                Ok(OutgoingInfo {
                    message: job.id.clone(),
                    mailbox: job.mailbox.clone(),
                    recipient: job.recipient.clone(),
                    subject: job.subject.clone(),
                    copies: job.receipts.len(),
                    required_copies,
                    state: if !job.receipts.is_empty() {
                        if required_copies
                            .is_some_and(|required| job.receipts.len() >= usize::from(required))
                        {
                            "Stored"
                        } else {
                            "Partial"
                        }
                    } else if job.ciphertext.is_some() {
                        "Pending"
                    } else if job.claim.is_some() || !job.packages.is_empty() {
                        "Claimed"
                    } else {
                        "Draft"
                    },
                })
            })
            .collect::<Result<Vec<_>>>()?;
        value.archive = v
            .data
            .archive
            .iter()
            .map(|(id, archived)| {
                let letter = &archived.letter;
                MessageInfo {
                    id: id.clone(),
                    mailbox: value
                        .mailboxes
                        .iter()
                        .find(|b| b.address == letter.route.recipient_address)
                        .map(|b| b.label.clone())
                        .unwrap_or_default(),
                    subject: Some(letter.subject.clone()),
                    sender: Some(letter.route.sender_address.clone()),
                    bytes: None,
                    expires: letter.route.expires,
                }
            })
            .collect();
        value.stores = self
            .connection
            .routes(4)
            .into_iter()
            .map(|r| r.subject)
            .collect();
        value.stores.sort();
        value.stores.dedup();
        Ok(value)
    }
    pub(crate) fn execute(&mut self, request: Request) -> Result<Response> {
        let (detail, status) = match request {
            Request::Refresh => (Detail::None, "Ready".into()),
            Request::Inbox {
                mailbox,
                store,
                after,
            } => {
                let (mut c, mut v) = device(&self.online(&mailbox))?;
                let result = online::receive_value(
                    &mut c,
                    &mut v,
                    &mailbox,
                    &self.transport(&store)?,
                    Effect::List,
                    None,
                    after.as_deref().map(id).transpose()?,
                )?;
                let messages = result["messages"]
                    .as_array()
                    .context("invalid inbox response")?
                    .iter()
                    .map(|m| {
                        Ok(MessageInfo {
                            id: text(m, "message")?,
                            mailbox: mailbox.clone(),
                            subject: None,
                            sender: None,
                            bytes: m["bytes"].as_u64(),
                            expires: m["expiresMs"].as_u64().context("missing message expiry")?
                                / 1000,
                        })
                    })
                    .collect::<Result<_>>()?;
                (
                    Detail::Inbox(Inbox {
                        messages,
                        next: result["next"].as_str().map(str::to_owned),
                    }),
                    "Inbox updated".into(),
                )
            }
            Request::Read {
                mailbox,
                store,
                message,
            } => {
                let (mut c, mut v) = device_for_fetch(&self.online(&mailbox), id(&message)?)?;
                let result = online::receive_value(
                    &mut c,
                    &mut v,
                    &mailbox,
                    &self.transport(&store)?,
                    Effect::Fetch,
                    Some(id(&message)?),
                    None,
                )?;
                (
                    Detail::Letter(Box::new(serde_json::from_value(result)?)),
                    "Saved to local archive".into(),
                )
            }
            Request::ArchiveRead { message } => {
                let v = self.vault()?;
                let letter = v
                    .data
                    .archive
                    .get(&message)
                    .context("archived message absent")?
                    .letter
                    .clone();
                (Detail::Letter(Box::new(letter)), "Local archive".into())
            }
            Request::ArchiveDelete { message } => {
                let mut v = self.vault()?;
                v.delete_archive(&message)?;
                (
                    Detail::None,
                    "Readable copy permanently deleted; stored copy unchanged".into(),
                )
            }
            Request::RemoteDelete {
                mailbox,
                store,
                message,
            } => {
                let (mut c, mut v) = device(&self.online(&mailbox))?;
                online::receive_value(
                    &mut c,
                    &mut v,
                    &mailbox,
                    &self.transport(&store)?,
                    Effect::Delete,
                    Some(id(&message)?),
                    None,
                )?;
                (
                    Detail::None,
                    "Stored copy deleted; local archive retained".into(),
                )
            }
            Request::Compose { mailbox, draft } => {
                let mut v = self.vault()?;
                let message = compose(&mut v, mailbox, draft)?;
                (Detail::Composed(message), "Draft saved".into())
            }
            Request::Review { message, store } => {
                let review = self.review(&message, &store)?;
                (Detail::Review(Box::new(review)), "Review message".into())
            }
            Request::Send { review } => {
                let t = self.transport(&review.consent.store)?;
                let (mut c, mut v) = device(&self.online(&review.mailbox))?;
                let job = v
                    .data
                    .outgoing
                    .get_mut(&review.message)
                    .context("outbox message absent")?;
                review.consent.validate(job, &t.service)?;
                ensure!(
                    job.mailbox == review.mailbox && job.recipient == review.recipient,
                    "review belongs to another mailbox or recipient"
                );
                job.send_consent = Some(review.consent.clone());
                v.save()?;
                let result = send_value(&mut c, &mut v, &review.mailbox, &t, id(&review.message)?)?;
                let copies = result["confirmedCopies"]
                    .as_u64()
                    .context("missing storage acknowledgement")?;
                let required = result["requiredCopies"]
                    .as_u64()
                    .context("missing storage requirement")?;
                (
                    Detail::None,
                    format!("Stored: {copies} of {required} required copies"),
                )
            }
            Request::VerifyContact {
                mailbox,
                address,
                owner,
            } => {
                mail::objects::native(&owner)?;
                let (mut c, mut v) = device(&self.online(&mailbox))?;
                let source = id(&v.mailbox(&mailbox)?.address)?;
                let target = id(&address)?;
                c.resume_metadata(|cmd| matches!(cmd, Action::Get{address,..} if *address == source || *address == target))?;
                sync(&mut c, &mut v, &mailbox)?;
                let current = c.refresh(target, Some(source))?;
                v.contact(
                    &serde_json::from_slice(&current.publication.bytes)?,
                    Some(&owner),
                )?;
                (Detail::None, "Contact verified".into())
            }
            Request::Refill { mailbox } => {
                let (mut c, mut v) = device(&self.online(&mailbox))?;
                refill(&mut c, &mut v, &mailbox, 4)?;
                (Detail::None, "Receive keys published".into())
            }
        };
        Ok(Response {
            overview: self.overview()?,
            detail,
            status,
        })
    }
    fn review(&self, message: &str, store: &str) -> Result<Review> {
        self.transport(store)?;
        let mut v = self.vault()?;
        let job = v
            .data
            .outgoing
            .get(message)
            .context("outbox message absent")?;
        let label = job.mailbox.clone();
        let online = self.online(&label);
        let mut c = Client::new(
            &online.location,
            &online.socket,
            signer(&v.mailbox(&label)?.request)?,
        )?;
        let source = id(&v.mailbox(&label)?.address)?;
        let target = id(&job.recipient)?;
        if c.pending()?.as_ref().is_some_and(|op| matches!(&op.command,
            domain::Command::Mail(Action::Get { address, .. }) if *address == source || *address == target)) {
            c.resume_metadata(|cmd| matches!(cmd, Action::Get { address, .. } if *address == source || *address == target))?;
        }
        let retained = job.claim.is_some() || !job.packages.is_empty() || c.pending()?.is_some();
        let consent = if retained {
            let mut consent = job
                .send_consent
                .clone()
                .context("pending CLI or form message requires its original CLI workflow")?;
            if consent.store != store {
                ensure!(
                    c.pending()?.is_none(),
                    "resume the pending operation on its original store first"
                );
                let manifest = protocol::manifest(
                    &hex::encode(v.data.network),
                    job.recipient_manifest
                        .as_ref()
                        .context("retained recipient manifest absent")?,
                )?;
                ensure!(
                    manifest
                        .storage_hosts
                        .iter()
                        .any(|selected| selected == store),
                    "selected store is not in the confirmed recipient placement"
                );
                consent.store = store.into();
            }
            consent.validate(job, store)?;
            consent
        } else {
            let sender = sync(&mut c, &mut v, &label)?;
            let recipient = c.refresh(target, Some(source))?;
            v.contact(&serde_json::from_slice(&recipient.publication.bytes)?, None)?;
            ensure!(
                recipient
                    .publication
                    .manifest
                    .storage_hosts
                    .iter()
                    .any(|s| s == store),
                "selected store is not in the recipient's current placement"
            );
            let cache = c.cache()?;
            let job = v.data.outgoing.get(message).unwrap();
            application_consent::SendConsent {
                content_digest: application_consent::content(job)?,
                sender_record: application_consent::reference(
                    &cache.state.record(137, source)?.reference,
                )?,
                recipient_record: application_consent::reference(
                    &cache.state.record(137, target)?.reference,
                )?,
                sender_manifest: hex::encode(sender.publication.digest),
                recipient_manifest: hex::encode(recipient.publication.digest),
                recipient_owner: recipient.publication.manifest.owner_key.clone(),
                recipient_generation: recipient.publication.manifest.generation,
                store: store.into(),
                required_copies: recipient.publication.manifest.required_copies,
            }
        };
        let job = v.data.outgoing.get(message).unwrap();
        Ok(Review {
            mailbox: label.clone(),
            message: message.into(),
            sender: v.mailbox(&label)?.address.clone(),
            recipient: job.recipient.clone(),
            subject: job.subject.clone(),
            body: job.body.clone(),
            expires: job.expires,
            consent,
        })
    }
}
fn text(value: &serde_json::Value, name: &str) -> Result<String> {
    Ok(value[name]
        .as_str()
        .with_context(|| format!("missing {name}"))?
        .into())
}
fn compose(v: &mut Vault, mailbox: String, draft: Draft) -> Result<String> {
    v.mailbox(&mailbox)?;
    id(&draft.recipient)?;
    ensure!(
        v.data.contacts.contains_key(&draft.recipient),
        "verify the recipient owner before composing"
    );
    ensure!(
        draft.subject.len() <= 512 && draft.body.len() <= 32768 && !draft.body.is_empty(),
        "subject must fit 512 bytes; message must contain 1 through 32768 bytes"
    );
    ensure!(
        (1..=168).contains(&draft.retention_hours),
        "message expiry must be 1 through 168 hours"
    );
    let message = crate::random_hex::<32>();
    let expires = crate::now()?
        .checked_add(u64::from(draft.retention_hours) * 3600)
        .context("expiry overflow")?;
    v.data.outgoing.insert(
        message.clone(),
        Outgoing {
            mailbox,
            recipient: draft.recipient.clone(),
            id: message.clone(),
            expires,
            subject: draft.subject.clone(),
            body: draft.body.clone(),
            packages: vec![],
            claim: None,
            sender_manifest: None,
            recipient_manifest: None,
            ciphertext: None,
            receipts: BTreeMap::new(),
            form_consent: None,
            send_consent: None,
        },
    );
    v.save()?;
    Ok(message)
}
