// SPDX-License-Identifier: MIT
// Typed application operations retain exact transfer offers and use the selected network routes.
use super::*;
use crate::networks::application::Connection;

#[derive(Args, Clone)]
pub struct Arguments {
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    vault: PathBuf,
    #[arg(long)]
    age_key: PathBuf,
    #[arg(long)]
    sender_grant: Option<String>,
    #[arg(long)]
    recipient_grant: Option<String>,
    #[arg(long, requires = "sender_grant")]
    sender_grant_record: Option<PathBuf>,
    #[arg(long, requires = "recipient_grant")]
    recipient_grant_record: Option<PathBuf>,
}
#[derive(Clone)]
pub(crate) struct Draft {
    pub file: PathBuf,
    pub recipient: String,
    pub recipient_age: String,
    pub label: String,
    pub expires: u64,
}
#[derive(Clone)]
pub(crate) struct AcceptanceReview {
    pub agreement: Agreement,
    pub service: String,
    pub destination: String,
    pub expires: u64,
}
#[derive(Clone)]
pub(crate) enum Request {
    Local,
    Initialise,
    List {
        action: u64,
        after: Option<String>,
    },
    Stores {
        after: Option<String>,
    },
    Inspect(String),
    Prepare(Draft),
    Publish(Offer),
    Accept(AcceptanceReview),
    Send(String),
    Receive {
        agreement: Agreement,
        output: PathBuf,
    },
    Status(String),
    Cancel(String),
    Delete(String),
    Forget(String),
    Recover {
        digest: Digest,
        output: Option<PathBuf>,
    },
}
#[derive(Clone)]
pub(crate) struct Pending {
    pub digest: Digest,
    pub operation: String,
    pub transfer: String,
    pub fields: Vec<(&'static str, String)>,
    pub needs_output: bool,
}
pub(crate) struct Local {
    pub recipient_age: String,
    pub participant: String,
    pub offers: Vec<Offer>,
    pub pending: Option<Pending>,
}
#[derive(Clone)]
pub(crate) struct Host {
    pub service: String,
    pub route: Option<String>,
    pub state_bytes: u64,
    pub maximum_payload: u64,
    pub maximum_lifetime_ms: u64,
    pub withdrawn: bool,
}
pub(crate) enum Response {
    Local(Local),
    Offers {
        offers: Vec<Agreement>,
        next: Option<String>,
    },
    Hosts {
        hosts: Vec<Host>,
        next: Option<String>,
    },
    Agreement(Box<Agreement>),
    Prepared(Box<Offer>),
    Done(String),
}
pub(crate) struct Application {
    connection: Connection,
    arguments: Arguments,
}
impl Application {
    pub(crate) fn open(arguments: Arguments) -> Result<Self> {
        Ok(Self {
            connection: Connection::open(&arguments.profile)?,
            arguments,
        })
    }
    fn vault(&self) -> VaultLocation {
        VaultLocation {
            vault: self.arguments.vault.clone(),
            age_key: self.arguments.age_key.clone(),
        }
    }
    fn grant(&self, action: u64) -> Result<Capability> {
        let grant = if action == 18 {
            &self.arguments.sender_grant
        } else {
            &self.arguments.recipient_grant
        };
        Ok(Capability::supplied(
            grant.clone().context(if action == 18 {
                "sending requires --sender-grant from the accepted network"
            } else {
                "receiving requires --recipient-grant from the accepted network"
            })?,
            if action == 18 {
                self.arguments.sender_grant_record.clone()
            } else {
                self.arguments.recipient_grant_record.clone()
            },
        ))
    }
    fn transport(&self, agreement: &Agreement) -> Result<Transport> {
        let service = hex::encode(
            agreement
                .acceptance
                .as_ref()
                .context("recipient has not accepted this offer")?
                .service
                .id,
        );
        let routes = self.connection.routes(5);
        let route = routes
            .iter()
            .find(|route| route.subject == service)
            .context("selected store has no approved private route in this profile")?;
        Ok(Transport {
            service_socket: Some(route.path.clone()),
            service_directory: None,
            core: PathBuf::new(),
        })
    }
    fn local(&self, create: bool) -> Result<Response> {
        let location = self.connection.location();
        let key = self.connection.key();
        let v = storage(&location, &key, &self.vault(), create)?;
        let accepted = control::bootstrap(&location)?;
        let store = Store::open(&location.directory, accepted.descriptor().clone())?;
        let pending = pending_operation(&store)?.map(|(intent, operation)| -> Result<Pending> {
            let domain::Command::Transfer(command) = operation.command else {
                anyhow::bail!("another application has a retained operation; recover it in that application first");
            };
            let needs_output = matches!(command, Action::Execute { effect: Effect::Fetch, .. });
            let mut fields = vec![("Operation", command.name().to_string()), ("Resource", hex::encode(command.resource())), ("Intent", hex::encode(intent.digest))];
            match &command {
                Action::Accept { service, destination, expires, .. } => fields.extend([("Store", hex::encode(service)), ("Destination label", destination.clone()), ("Expiry", expires.to_string())]),
                Action::Offer { offer } => fields.extend([("Recipient", hex::encode(offer.recipient)), ("Recipient age key", offer.encryption_key.clone()), ("Label", offer.label.clone()), ("Ciphertext digest", hex::encode(offer.payload_digest))]),
                Action::Execute { effect, offset, bytes, .. } => fields.extend([("Effect", effect.name().into()), ("Offset", offset.to_string()), ("Bytes", bytes.to_string())]),
                _ => {},
            }
            Ok(Pending { digest: intent.digest, operation: command.name().into(), transfer: hex::encode(command.resource()), fields, needs_output })
        }).transpose()?;
        Ok(Response::Local(Local {
            recipient_age: v.recipient(),
            participant: hex::encode(domain_cli::signer(&key)?.verifying_key().to_bytes()),
            offers: v.outbox()?,
            pending,
        }))
    }
    pub(crate) fn execute(
        &mut self,
        request: Request,
        progress: impl FnMut(u64, u64) -> Result<()>,
    ) -> Result<Response> {
        match request {
            Request::Local => self.local(false),
            Request::Initialise => self.local(true),
            Request::Forget(transfer) => {
                let mut vault = storage(
                    &self.connection.location(),
                    &self.connection.key(),
                    &self.vault(),
                    false,
                )?;
                vault.forget(id(&transfer)?)?;
                drop(vault);
                self.local(false)
            }
            other => {
                let mut c = Client::open(self.connection.online())?;
                self.online(&mut c, other, progress)
            }
        }
    }
    fn online(
        &self,
        c: &mut Client,
        request: Request,
        progress: impl FnMut(u64, u64) -> Result<()>,
    ) -> Result<Response> {
        match request {
            Request::Recover { digest, output } => {
                let (intent, operation) =
                    pending_operation(&c.store)?.context("no retained operation remains")?;
                ensure!(
                    intent.digest == digest,
                    "retained operation differs from the reviewed intent"
                );
                let domain::Command::Transfer(command) = operation.command else {
                    anyhow::bail!("retained operation belongs to another application")
                };
                match command {
                    Action::Execute {
                        id: transfer,
                        effect: Effect::Put | Effect::Commit,
                        ..
                    } => self.online(c, Request::Send(hex::encode(transfer)), progress),
                    Action::Execute {
                        id: transfer,
                        effect: Effect::Fetch,
                        ..
                    } => {
                        let agreement = c.agreement(transfer)?;
                        self.online(
                            c,
                            Request::Receive {
                                agreement,
                                output: output
                                    .context("choose a new download path for recovery")?,
                            },
                            progress,
                        )
                    }
                    Action::Execute {
                        id: transfer,
                        effect: Effect::Status,
                        ..
                    } => self.effect(c, &hex::encode(transfer), Effect::Status),
                    Action::Execute {
                        id: transfer,
                        effect: Effect::Delete,
                        ..
                    } => self.effect(c, &hex::encode(transfer), Effect::Delete),
                    command => {
                        c.action(command, operation.grant)?;
                        Ok(Response::Done(
                            "Retained operation reconciled. Refresh the selected list.".into(),
                        ))
                    }
                }
            }
            Request::List { action, after } => {
                ensure!(
                    matches!(action, 18 | 19),
                    "invalid transfer listing permission"
                );
                let grant = c.capability(Some(self.grant(action)?))?;
                let result = c.action(
                    Action::List {
                        network: c.bootstrap.descriptor().scope().network,
                        action,
                        after: after.map(|v| id(&v)).transpose()?,
                    },
                    grant,
                )?;
                let (records, next) = records(&result)?;
                let offers = records
                    .iter()
                    .filter(|r| r.reference.kind == 135)
                    .map(|r| {
                        Agreement::parse(
                            &r.payload,
                            result.cache.state.network,
                            result.cache.state.incarnation,
                        )
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(Response::Offers { offers, next })
            }
            Request::Stores { after } => {
                let grant = c.capability(Some(self.grant(19)?))?;
                let result = c.action(
                    Action::Services {
                        network: c.bootstrap.descriptor().scope().network,
                        action: 19,
                        after: after.map(|v| id(&v)).transpose()?,
                    },
                    grant,
                )?;
                let (records, next) = records(&result)?;
                let routes = self.connection.routes(5);
                let hosts = records
                    .iter()
                    .filter(|r| r.reference.kind == 134)
                    .map(|r| {
                        let service = transfer::Service::parse(
                            &r.payload,
                            result.cache.state.network,
                            result.cache.state.incarnation,
                        )?;
                        let name = hex::encode(service.profile.service);
                        Ok(Host {
                            route: routes
                                .iter()
                                .find(|route| route.subject == name)
                                .map(|route| route.service.clone()),
                            service: name,
                            state_bytes: service.profile.state_bytes,
                            maximum_payload: service.profile.maximum_payload,
                            maximum_lifetime_ms: service.profile.maximum_lifetime_ms,
                            withdrawn: service.withdrawn,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(Response::Hosts { hosts, next })
            }
            Request::Inspect(transfer) => {
                let transfer = id(&transfer)?;
                Ok(Response::Agreement(Box::new(c.refresh(transfer)?)))
            }
            Request::Prepare(draft) => {
                ensure!(
                    !c.pending()?,
                    "recover the pending operation before preparing another offer"
                );
                let _ = self.grant(18)?;
                let mut v = c.vault(&self.vault())?;
                let plain = zeroize::Zeroizing::new(files::read_public_single(
                    &draft.file,
                    transfer::MAXIMUM_PAYLOAD as usize,
                )?);
                let scope = c.bootstrap.descriptor().scope();
                let mut offer = Offer {
                    network: scope.network,
                    incarnation: scope.incarnation,
                    id: rand::random(),
                    sender: c.store.requester(),
                    recipient: id(&draft.recipient)?,
                    encryption_key: draft.recipient_age,
                    payload_bytes: 0,
                    payload_digest: [0; 32],
                    file_bytes: plain.len() as u64,
                    label: draft.label,
                    expires: draft.expires,
                    envelope: vec![],
                };
                let name = draft
                    .file
                    .file_name()
                    .and_then(|v| v.to_str())
                    .context("file name is not UTF-8")?;
                let cipher = vault::seal(&offer, name, &plain)?;
                offer.payload_bytes = cipher.len() as u64;
                offer.payload_digest = wire::digest(&cipher);
                let signed = wire::sign_envelope(&offer.payload()?, &c.key)?;
                let offer = Offer::parse(&signed, scope.network, scope.incarnation)?;
                v.insert(&offer, &cipher)?;
                Ok(Response::Prepared(Box::new(offer)))
            }
            Request::Publish(reviewed) => {
                let v = c.vault(&self.vault())?;
                let (offer, _) = v.outgoing(reviewed.id)?;
                ensure!(
                    offer.envelope == reviewed.envelope,
                    "retained offer differs from the reviewed offer"
                );
                let grant = c.capability(Some(self.grant(18)?))?;
                if !c.pending()? {
                    c.action(
                        Action::Context {
                            action: 18,
                            scope_kind: 2,
                            resource: offer.id,
                        },
                        grant.clone(),
                    )?;
                }
                let transfer = offer.id;
                c.action(Action::Offer { offer }, grant)?;
                Ok(Response::Agreement(Box::new(c.agreement(transfer)?)))
            }
            Request::Accept(review) => {
                let v = c.vault(&self.vault())?;
                let transfer = review.agreement.offer.id;
                let a = c.refresh(transfer)?;
                ensure!(
                    a.offer.envelope == review.agreement.offer.envelope,
                    "offer differs from the reviewed offer"
                );
                ensure!(
                    a.offer.recipient == c.store.requester()
                        && a.offer.encryption_key == v.recipient(),
                    "offer is not bound to this recipient's independently retained encryption key"
                );
                let service = id(&review.service)?;
                ensure!(
                    self.connection
                        .routes(5)
                        .iter()
                        .any(|route| route.subject == review.service),
                    "selected store has no approved private route"
                );
                let grant = c.capability(Some(self.grant(19)?))?;
                if !c.pending()? {
                    c.action(
                        Action::Service {
                            service,
                            action: 19,
                        },
                        grant.clone(),
                    )?;
                }
                c.action(
                    Action::Accept {
                        id: transfer,
                        service,
                        destination: review.destination,
                        expires: review.expires,
                    },
                    grant,
                )?;
                Ok(Response::Agreement(Box::new(c.agreement(transfer)?)))
            }
            Request::Send(transfer) => {
                let transfer = id(&transfer)?;
                let a = c.refresh(transfer)?;
                let v = c.vault(&self.vault())?;
                let t = self.transport(&a)?;
                effect_message(send_progress(c, &v, &t, transfer, 0, progress)?)
            }
            Request::Receive { agreement, output } => {
                let transfer = agreement.offer.id;
                let a = c.refresh(transfer)?;
                ensure!(
                    a.offer.envelope == agreement.offer.envelope,
                    "offer differs from the reviewed download"
                );
                let destination = agreement
                    .acceptance
                    .as_ref()
                    .context("offer has no accepted destination")?
                    .destination
                    .clone();
                let t = self.transport(&a)?;
                let mut v = c.vault(&self.vault())?;
                let result =
                    receive_progress(c, &mut v, &t, transfer, &destination, &output, 0, progress)?;
                ensure!(
                    result.complete,
                    "download is incomplete; resume the same transfer"
                );
                Ok(Response::Done(format!(
                    "Saved {} bytes to {}",
                    result.file_bytes.unwrap_or(0),
                    output.display()
                )))
            }
            Request::Cancel(transfer) => {
                let transfer = id(&transfer)?;
                c.refresh(transfer)?;
                c.action(Action::Cancel { id: transfer }, None)?;
                Ok(Response::Agreement(Box::new(c.agreement(transfer)?)))
            }
            Request::Status(transfer) => self.effect(c, &transfer, Effect::Status),
            Request::Delete(transfer) => self.effect(c, &transfer, Effect::Delete),
            _ => anyhow::bail!("invalid online transfer operation"),
        }
    }
    fn effect(&self, c: &mut Client, transfer: &str, effect: Effect) -> Result<Response> {
        let transfer = id(transfer)?;
        let a = c.refresh(transfer)?;
        let t = self.transport(&a)?;
        effect_message(fresh_effect(c, &t, transfer, effect)?)
    }
}
fn records(result: &domain_client::ResultState) -> Result<(Vec<domain::Record>, Option<String>)> {
    let value = result.value.array(5)?;
    let body = value[4].array(4)?;
    let records = body[1]
        .list(16)?
        .iter()
        .map(|raw| {
            domain::Record::parse(
                raw.bytes()?,
                result.cache.state.network,
                result.cache.state.incarnation,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let next = if body[3] == V::Null {
        None
    } else {
        Some(hex::encode(body[3].bytes()?))
    };
    Ok((records, next))
}
fn effect_message(value: V) -> Result<Response> {
    let fields = value.array(12)?;
    Ok(Response::Done(format!(
        "{}: {} bytes stored; committed: {}; deleted: {}",
        fields[5].text()?,
        fields[8].uint()?,
        fields[9].boolean()?,
        fields[10].boolean()?
    )))
}

fn pending_operation(
    store: &Store,
) -> Result<Option<(crate::authority_proof::Intent, domain::Operation)>> {
    store
        .resume_ordinary()?
        .map(|pending| {
            let intent = crate::authority_proof::Intent::from_signed(pending.signed())?;
            let operation = domain::Operation::parse(&intent)?;
            Ok((intent, operation))
        })
        .transpose()
}
