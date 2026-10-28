// SPDX-License-Identifier: MIT
// Named application services and a private local agent expose reusable authenticated duplex streams.
use crate::{
    authority_domains::{self as domain, streams},
    authority_inspection_cli::{self as control, domain_cli::Online},
    authority_proof::{Digest, VersionRef},
    transfer_files as files, trust_bootstrap,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use serde_json::json;
use std::path::{Path, PathBuf};
#[path = "ApplicationStreamsAgent.rs"]
mod agent;
#[path = "ApplicationStreamsClient.rs"]
mod client;
use crate::{local_stream_ipc as ipc, mapped_ingress as ingress};
#[path = "ApplicationStreamsOffer.rs"]
mod offer;
#[derive(Subcommand)]
pub enum Command {
    /// Sign an exact finite service offer as its owner.
    Offer(offer::Arguments),
    /// Inspect a service offer and authenticate its owner's independent key pin.
    InspectOffer(offer::Inspection),
    /// Approve the exact offer as its endpoint operator.
    Accept(offer::Acceptance),
    /// Build the Core endpoint configuration from exact accepted service consent.
    EndpointConfig(offer::EndpointConfiguration),
    /// Register the exact owner and operator consent.
    Register {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        grant: String,
        #[arg(long)]
        accepted: PathBuf,
    },
    /// Fetch the current service and one of this principal's bounded session slots.
    Lookup {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        grant: String,
        #[arg(long)]
        service: String,
        #[arg(long, default_value_t = 0)]
        slot: u64,
    },
    /// Withdraw a service generation permanently as its owner.
    Withdraw {
        #[command(flatten)]
        online: Online,
        /// Service ID, or exact ID:generation:digest.
        #[arg(long)]
        service: String,
    },
    /// Run the local application companion with private control and ingress sockets.
    Agent(agent::Arguments),
    #[command(hide = true)]
    IngressHelper(ingress::Arguments),
    /// Inspect the local companion's finite connections and targets.
    Status {
        #[arg(long)]
        directory: PathBuf,
    },
    /// Cancel one exact local connection.
    Cancel {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        id: String,
    },
    /// Connect a named target through the local companion; payload uses standard input/output.
    Connect {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        service: String,
        #[arg(long)]
        protocol: Option<String>,
    },
    /// Accept one authenticated incoming stream; peer context is printed on standard error.
    Receive {
        #[arg(long)]
        directory: PathBuf,
    },
}
pub fn id(value: &str) -> Result<Digest> {
    trust_bootstrap::hex32(value)
}
fn reference(value: &str, kind: u64) -> Result<VersionRef> {
    let f = value.split(':').collect::<Vec<_>>();
    ensure!(f.len() == 3, "reference must be ID:generation:digest");
    let r = VersionRef {
        kind,
        id: id(f[0])?,
        generation: f[1].parse()?,
        digest: id(f[2])?,
    };
    ensure!(r.generation > 0, "reference generation is zero");
    Ok(r)
}
fn emit(result: &crate::authority_inspection::domain_client::ResultState) -> Result<()> {
    crate::print_value(
        &json!({"status":"Committed","height":result.prefix.height(),"result":control::diagnostic(result.value.clone())}),
    )
}
pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Offer(a) => offer::create(a),
        Command::InspectOffer(a) => offer::inspect(a),
        Command::Accept(a) => offer::accept(a),
        Command::EndpointConfig(a) => offer::endpoint_config(a),
        Command::Agent(a) => agent::run(a),
        Command::IngressHelper(a) => ingress::run(a),
        Command::Status { directory } => {
            crate::print_value(&ipc::call(&directory, json!({"version":1,"action":"status"}))?.0)
        }
        Command::Cancel { directory, id } => crate::print_value(
            &ipc::call(&directory, json!({"version":1,"action":"cancel","id":id}))?.0,
        ),
        Command::Connect {
            directory,
            service,
            protocol,
        } => ipc::stdio(
            &directory,
            json!({"version":1,"action":"connect","service":service,"protocol":protocol,"timeoutMs":30000}),
        ),
        Command::Receive { directory } => ipc::stdio(
            &directory,
            json!({"version":1,"action":"accept","timeoutMs":60000}),
        ),
        Command::Register {
            online,
            grant,
            accepted,
        } => {
            let mut c = client::Client::new(&online)?;
            let artifact = offer::Artifact::parse(
                &c.bootstrap,
                &files::read_single(&accepted, 16384, true)?,
                true,
            )?;
            let grant = c.grant(&grant)?;
            c.context(&grant, artifact.registration.id, streams::MANAGE)?;
            // Fetch the exact endorsed route before mutation preflight.
            if c.store.resume_ordinary()?.is_none() {
                c.execute(
                    Some(grant.clone()),
                    domain::Command::Route(domain::routes::Command::Lookup {
                        service: artifact.registration.route.id,
                    }),
                )?;
            }
            emit(&c.stream(
                Some(grant),
                streams::Command::Register {
                    registration: artifact.registration,
                },
            )?)
        }
        Command::Lookup {
            online,
            grant,
            service,
            slot,
        } => {
            let mut c = client::Client::new(&online)?;
            let grant = c.grant(&grant)?;
            emit(&c.stream(
                Some(grant),
                streams::Command::Lookup {
                    service: id(&service)?,
                    slot,
                },
            )?)
        }
        Command::Withdraw { online, service } => {
            let mut c = client::Client::new(&online)?;
            let selected = if service.contains(':') {
                Some(reference(&service, 172)?)
            } else {
                None
            };
            let service = selected
                .as_ref()
                .map_or_else(|| id(&service), |r| Ok(r.id))?;
            let target = if let Some(pending) = c.store.resume_ordinary()? {
                let intent = crate::authority_proof::Intent::from_signed(pending.signed())?;
                let operation = domain::Operation::parse(&intent)?;
                let domain::Command::Stream(streams::Command::Withdraw { service: target }) =
                    operation.command
                else {
                    anyhow::bail!("another exact operation remains pending");
                };
                ensure!(
                    target.id == service,
                    "pending withdrawal names another service"
                );
                target
            } else {
                let context = c.stream(None, streams::Command::Lookup { service, slot: 0 })?;
                context.cache.state.record(172, service)?.reference.clone()
            };
            ensure!(
                selected.is_none_or(|r| r == target),
                "service changed from the explicitly selected generation"
            );
            emit(&c.stream(None, streams::Command::Withdraw { service: target })?)
        }
    }
}
