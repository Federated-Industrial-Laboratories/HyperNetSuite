// SPDX-License-Identifier: MIT
// Bilateral agreement, exact sharing, local review and independently verified reading.
use crate::{
    Config, Identity, bridge_consent,
    federation_proof::{self as proof, Publication, Treaty},
    files, markup,
    page_proof::{Bundle, Descriptor, Envelope},
    protocol, reader, share_withdrawal,
};
use anyhow::{Context, Result, bail, ensure};
use clap::{Subcommand, ValueEnum};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

#[derive(Clone, ValueEnum)]
pub enum Decision {
    Approve,
    Reject,
}
#[derive(Subcommand)]
pub enum Command {
    /// Validate public treaty terms and show the exact agreement digest.
    Treaty {
        file: PathBuf,
    },
    /// Accept an immutable treaty as the local administrator.
    Accept {
        #[arg(long)]
        treaty: PathBuf,
    },
    Agreements,
    /// Permanently withdraw the local agreement; renegotiation needs a new identifier.
    Withdraw {
        #[arg(long)]
        agreement: String,
        #[arg(long)]
        expected_version: u64,
    },
    /// Sign exact bridge consent with both isolated service identities, entirely offline.
    SignConsent {
        #[arg(long)]
        spec: PathBuf,
        #[arg(long)]
        treaty: PathBuf,
        #[arg(long)]
        source_identity: PathBuf,
        #[arg(long)]
        destination_identity: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Register the same signed bridge consent independently at each network.
    Register {
        #[arg(long)]
        consent: PathBuf,
        #[arg(long)]
        certificate: String,
    },
    /// Withdraw network bridge consent after stopping the local bridge.
    WithdrawConsent,
    /// Allow an exact publication, or durably request author withdrawal.
    Share {
        #[arg(long)]
        agreement: String,
        #[arg(long)]
        page_id: String,
        #[arg(long)]
        withdraw: bool,
    },
    /// Retry a saved withdrawal; unbound offline intents need explicit generation confirmation.
    RetryWithdrawal {
        #[arg(long)]
        agreement: String,
        #[arg(long)]
        page_id: String,
        #[arg(long)]
        expected_generation: Option<u64>,
    },
    /// Read own share generation even when the publication or agreement is inactive.
    ShareStatus {
        #[arg(long)]
        agreement: String,
        #[arg(long)]
        page_id: String,
    },
    Queue {
        #[arg(long)]
        agreement: String,
        #[arg(long)]
        after: Option<String>,
    },
    Inspect {
        #[arg(long)]
        agreement: String,
        #[arg(long)]
        page_id: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        tui: bool,
        #[arg(long)]
        ascii: bool,
    },
    Review {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, value_enum)]
        decision: Decision,
    },
    WithdrawPage {
        #[arg(long)]
        agreement: String,
        #[arg(long)]
        page_id: String,
        #[arg(long)]
        expected_version: u64,
    },
    List {
        #[arg(long)]
        agreement: String,
        #[arg(long)]
        after: Option<String>,
    },
    Read {
        #[arg(long)]
        agreement: String,
        #[arg(long)]
        page_id: String,
        #[arg(long)]
        tui: bool,
        #[arg(long)]
        ascii: bool,
    },
}

fn call(config: &Config, identity: &Identity, command: Value) -> Result<Value> {
    protocol::send(
        config,
        identity,
        &crate::random_hex::<16>(),
        crate::now()?,
        command,
    )
}
fn treaty_file(path: &Path) -> Result<Treaty> {
    let treaty: Treaty = serde_json::from_slice(&files::read_bounded(path, false)?)?;
    treaty.validate()?;
    Ok(treaty)
}
pub(crate) fn agreements(config: &Config, identity: &Identity) -> Result<Value> {
    call(config, identity, json!({"type":"FederationAgreements"}))
}
fn accepted(config: &Config, identity: &Identity, agreement: &str) -> Result<Treaty> {
    protocol::hex_bytes::<16>(agreement)?;
    let response = agreements(config, identity)?;
    let records = response["result"]["entries"]
        .as_array()
        .context("missing agreement inventory")?;
    for record in records {
        let treaty: Treaty = serde_json::from_value(record["treaty"].clone())?;
        if treaty.agreement_id == agreement {
            ensure!(
                record["active"] == true && record["digest"].as_str() == Some(&treaty.digest()?),
                "agreement is inactive or inconsistent"
            );
            return Ok(treaty);
        }
    }
    bail!("agreement is not accepted by this network")
}
pub(crate) fn load(
    config: &Config,
    identity: &Identity,
    agreement: &str,
    page: &str,
) -> Result<Publication> {
    protocol::hex_bytes::<16>(agreement)?;
    protocol::hex_bytes::<16>(page)?;
    let response = call(
        config,
        identity,
        json!({"type":"FederationRead","agreementId":agreement,"pageId":page}),
    )?;
    proof::read(&config.network, agreement, page, &response["result"])
}

fn pending(network: &str, record: &Value) -> Result<(Treaty, Descriptor, String, String)> {
    ensure!(
        record["network"].as_str() == Some(network),
        "review record belongs to another destination"
    );
    let inspection = &record["inspection"];
    let treaty: Treaty = serde_json::from_value(inspection["treaty"].clone())?;
    ensure!(
        treaty.destination_network == network
            && inspection["agreementDigest"].as_str() == Some(&treaty.digest()?),
        "review treaty identity mismatch"
    );
    let pending = &inspection["pending"];
    let descriptor: Descriptor = serde_json::from_value(pending["descriptor"].clone())?;
    let bundle: Bundle = serde_json::from_value(pending["bundle"].clone())?;
    let share: Envelope = serde_json::from_value(pending["authorShare"].clone())?;
    let (body, _) = proof::artifact(&treaty, &descriptor, &bundle, &share)?;
    let digest = proof::descriptor_digest(&descriptor)?;
    ensure!(
        inspection["pageId"].as_str() == Some(&descriptor.page_id)
            && pending["descriptorDigest"].as_str() == Some(&digest),
        "review descriptor mismatch"
    );
    Ok((treaty, descriptor, digest, body))
}

pub fn run(config_path: Option<&Path>, command: Command) -> Result<()> {
    match command {
        Command::Treaty { file } => {
            let treaty = treaty_file(&file)?;
            return crate::print_value(&json!({"treaty":treaty,"digest":treaty.digest()?}));
        }
        Command::SignConsent {
            spec,
            treaty,
            source_identity,
            destination_identity,
            output,
        } => {
            return bridge_consent::sign(
                &spec,
                &treaty,
                &source_identity,
                &destination_identity,
                &output,
            );
        }
        _ => {}
    }
    let config: Config = serde_json::from_slice(&files::read_bounded(
        config_path.context("--config is required")?,
        false,
    )?)?;
    let identity = crate::load_identity(&config.identity)?;
    let listing_kind = if matches!(&command, Command::Queue { .. }) {
        "FederationQueue"
    } else {
        "FederationList"
    };
    let request = match command {
        Command::Treaty { .. } | Command::SignConsent { .. } => unreachable!(),
        Command::Accept { treaty } => {
            let treaty = treaty_file(&treaty)?;
            ensure!(
                treaty.source_network == config.network
                    || treaty.destination_network == config.network,
                "configuration is outside treaty"
            );
            json!({"type":"FederationAccept","treaty":treaty})
        }
        Command::Agreements => json!({"type":"FederationAgreements"}),
        Command::Withdraw {
            agreement,
            expected_version,
        } => {
            protocol::hex_bytes::<16>(&agreement)?;
            json!({"type":"FederationWithdraw","agreementId":agreement,"expectedVersion":expected_version})
        }
        Command::Register {
            consent,
            certificate,
        } => bridge_consent::registration(
            &consent,
            &config.network,
            &identity.public_key,
            &certificate,
        )?,
        Command::WithdrawConsent => json!({"type":"BridgeWithdraw"}),
        Command::RetryWithdrawal {
            agreement,
            page_id,
            expected_generation,
        } => {
            return share_withdrawal::run(
                &config,
                &identity,
                &agreement,
                &page_id,
                true,
                expected_generation,
            );
        }
        Command::ShareStatus { agreement, page_id } => {
            return crate::print_value(&share_withdrawal::status(
                &config, &identity, &agreement, &page_id,
            )?);
        }
        Command::Share {
            agreement,
            page_id,
            withdraw,
        } => {
            if withdraw {
                return share_withdrawal::run(
                    &config, &identity, &agreement, &page_id, false, None,
                );
            }
            let pending =
                share_withdrawal::Pending::lock(&config, &identity, &agreement, &page_id)?;
            pending.require_resolved()?;
            let status = share_withdrawal::status(&config, &identity, &agreement, &page_id)?;
            let treaty = accepted(&config, &identity, &agreement)?;
            ensure!(
                treaty.source_network == config.network,
                "only the source author can share native content"
            );
            protocol::hex_bytes::<16>(&page_id)?;
            let response = call(
                &config,
                &identity,
                json!({"type":"PageRead","pageId":page_id}),
            )?;
            crate::page_proof::fresh(&response["result"])?;
            let descriptor: Descriptor =
                serde_json::from_value(response["result"]["descriptor"].clone())?;
            let bundle: Bundle = serde_json::from_value(response["result"]["bundle"].clone())?;
            crate::page_proof::verify(&config.network, &descriptor, &bundle)?;
            ensure!(
                descriptor.page_id == page_id
                    && descriptor.author == identity.public_key
                    && descriptor.namespace == treaty.source_namespace,
                "only the exact source author can share an in-scope publication"
            );
            let request = json!({"type":"FederationShare","agreementId":agreement,"agreementDigest":treaty.digest()?,"pageId":page_id,"publicationVersion":descriptor.publication_version,"descriptorDigest":proof::descriptor_digest(&descriptor)?,"allow":true,"expectedGeneration":status["generation"]});
            return crate::print_value(&call(&config, &identity, request)?);
        }
        Command::Queue { agreement, after } | Command::List { agreement, after } => {
            protocol::hex_bytes::<16>(&agreement)?;
            if let Some(id) = &after {
                protocol::hex_bytes::<16>(id)?;
            }
            json!({"type":listing_kind,"agreementId":agreement,"after":after})
        }
        Command::Inspect {
            agreement,
            page_id,
            output,
            tui,
            ascii,
        } => {
            protocol::hex_bytes::<16>(&agreement)?;
            protocol::hex_bytes::<16>(&page_id)?;
            let response = call(
                &config,
                &identity,
                json!({"type":"FederationInspect","agreementId":agreement,"pageId":page_id}),
            )?;
            let record = json!({"network":config.network,"inspection":response["result"]});
            if record["inspection"]["pending"].is_null() {
                files::write_new(&output, &serde_json::to_vec_pretty(&record)?)?;
                return crate::print_value(&response);
            }
            let (treaty, descriptor, digest, body) = pending(&config.network, &record)?;
            ensure!(
                treaty.agreement_id == agreement && descriptor.page_id == page_id,
                "authority returned another pending page"
            );
            files::write_new(&output, &serde_json::to_vec_pretty(&record)?)?;
            let document = markup::parse(&body).map_err(anyhow::Error::msg)?;
            reader::show(
                &document,
                &[
                    "UNAPPROVED imported page; local review is required.".into(),
                    format!(
                        "Source network {} | author {} | namespace {}",
                        treaty.source_network, descriptor.author, descriptor.namespace
                    ),
                    format!(
                        "Local namespace {} | agreement {} | exact descriptor {}",
                        treaty.destination_namespace, agreement, digest
                    ),
                ],
                tui,
                ascii,
            )?;
            return Ok(());
        }
        Command::Review { input, decision } => {
            let record: Value = serde_json::from_slice(&files::read_bounded(&input, true)?)?;
            let (treaty, descriptor, digest, _) = pending(&config.network, &record)?;
            json!({"type":"FederationReview","agreementId":treaty.agreement_id,"pageId":descriptor.page_id,"expectedVersion":record["inspection"]["version"].as_u64().context("missing review version")?,"descriptorDigest":digest,"decision":match decision {Decision::Approve=>"Approve",Decision::Reject=>"Reject"}})
        }
        Command::WithdrawPage {
            agreement,
            page_id,
            expected_version,
        } => {
            protocol::hex_bytes::<16>(&agreement)?;
            protocol::hex_bytes::<16>(&page_id)?;
            json!({"type":"FederationPageWithdraw","agreementId":agreement,"pageId":page_id,"expectedVersion":expected_version})
        }
        Command::Read {
            agreement,
            page_id,
            tui,
            ascii,
        } => {
            return crate::navigation::browse(
                &config,
                &identity,
                crate::navigation::Location::Federated { agreement, page_id },
                None,
                tui,
                ascii,
            );
        }
    };
    crate::print_value(&call(&config, &identity, request)?)
}
