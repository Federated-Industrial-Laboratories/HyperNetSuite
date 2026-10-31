// SPDX-License-Identifier: MIT
// Separate prepare, review, confirm and send commands make form consent inspectable and resumable.
use super::*;
#[derive(Args)]
pub struct Arguments {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Prepare {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[command(flatten)]
        mail: Access,
        #[arg(long)]
        page: String,
        #[arg(long)]
        form: String,
        #[arg(long)]
        values: PathBuf,
        #[arg(long)]
        expires: u64,
    },
    Reviews {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        mail: Access,
    },
    Accepted {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        mail: Access,
    },
    Review {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        mail: Access,
        #[arg(long)]
        review: String,
    },
    Cancel {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        mail: Access,
        #[arg(long)]
        review: String,
    },
    Confirm {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[command(flatten)]
        mail: Access,
        #[arg(long)]
        review: String,
        #[arg(long)]
        confirm_submission: bool,
    },
    Send {
        #[command(flatten)]
        online: DeviceOnline,
        #[command(flatten)]
        transport: Transport,
        #[arg(long)]
        message: String,
    },
    Accept {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        capability: Capability,
        #[command(flatten)]
        mail: Access,
        #[arg(long)]
        page: String,
        #[arg(long)]
        form: String,
    },
    Receive {
        #[command(flatten)]
        online: DeviceOnline,
        #[command(flatten)]
        transport: Transport,
        #[arg(long)]
        message: String,
    },
    ReceiveLocal {
        #[command(flatten)]
        location: Location,
        #[command(flatten)]
        mail: Access,
        #[arg(long)]
        message: String,
    },
}
fn raw_page(s: &str) -> Result<[u8; 16]> {
    let bytes = hex::decode(s)?;
    ensure!(hex::encode(&bytes) == s, "Page identity is not canonical");
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Page identity must contain 16 bytes"))
}
pub fn run(configuration: Option<&Path>, args: Arguments) -> Result<()> {
    ensure!(
        configuration.is_none(),
        "forms use independent authority pins and explicit private sockets; --config is not accepted"
    );
    let value = match args.command {
        Command::Prepare {
            online,
            capability,
            mail,
            page,
            form,
            values,
            expires,
        } => {
            let values: BTreeMap<String, Value> = serde_json::from_slice(&files::read_single(
                &values,
                markup::forms::MAX_VALUES_BYTES,
                true,
            )?)?;
            let o = mail.device(&online.location, &online.socket);
            let mut p = PageClient::new(&online)?;
            let g = p.grant(capability)?;
            let publication = publication::fetch(&mut p, &g, raw_page(&page)?)?;
            let r = prepare(
                &mut p,
                &g,
                &o,
                &publication.identity,
                &form,
                values,
                expires,
            )?;
            json!({"status":"FormPrepared","review":r,"sent":false})
        }
        Command::Reviews { location, mail } => {
            let (_, v) = open(
                &location,
                &VaultLocation {
                    vault: mail.vault,
                    age_key: mail.age_key,
                },
                false,
            )?;
            json!({"reviews":v.data.form_drafts.values().filter(|d|d.mailbox==mail.mailbox).map(|d|json!({"reviewId":d.review.review_id,"submissionId":d.review.submission_id,"page":d.review.publication.page,"form":d.review.form_id,"expires":d.review.expires})).collect::<Vec<_>>()})
        }
        Command::Accepted { location, mail } => {
            let (_, v) = open(
                &location,
                &VaultLocation {
                    vault: mail.vault,
                    age_key: mail.age_key,
                },
                false,
            )?;
            let address = &v.mailbox(&mail.mailbox)?.address;
            json!({"accepted":v.data.accepted_forms.iter().filter(|(_,r)|&r.recipient_address==address).map(|(id,r)|json!({"acceptedRecord":id,"record":r})).collect::<Vec<_>>()})
        }
        Command::Review {
            location,
            mail,
            review,
        } => {
            id(&review)?;
            let (_, v) = open(
                &location,
                &VaultLocation {
                    vault: mail.vault,
                    age_key: mail.age_key,
                },
                false,
            )?;
            if let Some(d) = v.data.form_drafts.get(&review) {
                ensure!(d.mailbox == mail.mailbox, "form belongs to another mailbox");
                json!({"status":"FormPrepared","review":d.review,"sent":false})
            } else {
                let j = v
                    .data
                    .outgoing
                    .values()
                    .find(|j| {
                        j.mailbox == mail.mailbox
                            && j.form_consent
                                .as_ref()
                                .is_some_and(|c| c.review.review_id == review)
                    })
                    .context("form review absent")?;
                validate_outgoing(j)?;
                json!({"status":"FormConfirmed","review":j.form_consent.as_ref().unwrap().review,"stores":j.receipts.keys().collect::<Vec<_>>()})
            }
        }
        Command::Cancel {
            location,
            mail,
            review,
        } => {
            id(&review)?;
            let (_, mut v) = open(
                &location,
                &VaultLocation {
                    vault: mail.vault,
                    age_key: mail.age_key,
                },
                false,
            )?;
            ensure!(
                v.data
                    .form_drafts
                    .get(&review)
                    .is_some_and(|d| d.mailbox == mail.mailbox),
                "unconfirmed form draft absent"
            );
            v.data.form_drafts.remove(&review);
            v.save()?;
            json!({"status":"FormDraftCancelled","review":review})
        }
        Command::Confirm {
            online,
            capability,
            mail,
            review,
            confirm_submission,
        } => {
            let o = mail.device(&online.location, &online.socket);
            let mut p = PageClient::new(&online)?;
            let g = p.grant(capability)?;
            let r = confirm(&mut p, &g, &o, &review, confirm_submission)?;
            json!({"status":"FormConfirmed","message":r.submission_id,"review":r,"sent":false})
        }
        Command::Send {
            online,
            transport,
            message,
        } => send(&online, &transport, &message)?,
        Command::Accept {
            online,
            capability,
            mail,
            page,
            form,
        } => {
            let o = mail.device(&online.location, &online.socket);
            let mut p = PageClient::new(&online)?;
            let g = p.grant(capability)?;
            accept(&mut p, &g, &o, raw_page(&page)?, &form)?
        }
        Command::Receive {
            online,
            transport,
            message,
        } => receive(&online, Some(&transport), &message, false)?,
        Command::ReceiveLocal {
            location,
            mail,
            message,
        } => receive(&mail.device(&location, Path::new("")), None, &message, true)?,
    };
    crate::print_value(&value)
}

#[cfg(test)]
#[path = "../../Tests/Unit/Forms/AuthorityFormsCliTests.rs"]
mod tests;
