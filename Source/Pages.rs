// SPDX-License-Identifier: MIT
// Independent author, moderator and reader workflows over the public Pages API.
use crate::{
    Config, Identity, files, markup,
    page_proof::{self, Bundle, Descriptor, Envelope},
    protocol, reader,
};
use anyhow::{Context, Result, bail, ensure};
use clap::{Subcommand, ValueEnum};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Clone, ValueEnum)]
pub enum Decision {
    Approve,
    Reject,
}

#[derive(Subcommand)]
pub enum Command {
    /// Validate and display a local draft without publishing or executing it.
    Preview {
        file: PathBuf,
        #[arg(long)]
        tui: bool,
        #[arg(long)]
        ascii: bool,
    },
    /// Save a signed retry record before submitting a draft for manual review.
    Submit {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        page_id: Option<String>,
        #[arg(long, default_value_t = 0)]
        expected_version: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// List own pending submissions, or all pending submissions for an administrator.
    Queue {
        #[arg(long)]
        namespace: Option<String>,
        #[arg(long)]
        after: Option<String>,
    },
    /// Retain an exact pending review record and display its unapproved content.
    Inspect {
        #[arg(long)]
        page_id: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        tui: bool,
        #[arg(long)]
        ascii: bool,
    },
    /// Make a manual decision about the exact retained review record.
    Review {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, value_enum)]
        decision: Decision,
    },
    /// Withdraw both current publication and pending replacement using a version check.
    Withdraw {
        #[arg(long)]
        page_id: String,
        #[arg(long)]
        expected_version: u64,
    },
    List {
        #[arg(long)]
        namespace: Option<String>,
        #[arg(long)]
        after: Option<String>,
    },
    /// Read a verified current publication; optionally require a specific replica.
    Read {
        #[arg(long)]
        page_id: String,
        #[arg(long)]
        replica: Option<String>,
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

fn body(path: &Path) -> Result<String> {
    let text = String::from_utf8(files::read_bounded(path, false)?)
        .context("page must be strict UTF-8")?;
    markup::validate(&text).map_err(anyhow::Error::msg)?;
    Ok(text)
}

fn listing(
    config: &Config,
    identity: &Identity,
    kind: &str,
    namespace: Option<String>,
    after: Option<String>,
) -> Result<()> {
    ensure!(
        !config.application || namespace.is_some(),
        "application listings require --namespace"
    );
    if let Some(value) = &namespace {
        ensure!(markup::namespace(value), "invalid namespace");
    }
    if let Some(value) = &after {
        protocol::hex_bytes::<16>(value)?;
    }
    crate::print_value(&call(
        config,
        identity,
        json!({"type":kind,"namespace":namespace,"after":after}),
    )?)
}

fn pending(network: &str, record: &Value) -> Result<(page_proof::Submission, String, Envelope)> {
    ensure!(
        record["network"].as_str() == Some(network),
        "review record belongs to another network"
    );
    let inspection = &record["inspection"];
    let pending = &inspection["pending"];
    let envelope: Envelope = serde_json::from_value(pending["submission"].clone())
        .context("no pending submission in record")?;
    let (source, digest) = page_proof::submission(network, &envelope)?;
    ensure!(
        inspection["pageId"].as_str() == Some(&source.page_id)
            && inspection["author"].as_str() == Some(&envelope.public_key)
            && inspection["namespace"].as_str() == Some(&source.namespace)
            && pending["revision"].as_u64() == source.expected_version.checked_add(1)
            && pending["digest"].as_str() == Some(&source.digest)
            && pending["profile"].as_str() == Some(&source.profile)
            && pending["audience"].as_str() == Some(&source.audience)
            && pending["submissionDigest"].as_str() == Some(&digest),
        "review metadata does not match signed source"
    );
    Ok((source, digest, envelope))
}

fn descriptor(config: &Config, identity: &Identity, page_id: &str) -> Result<Descriptor> {
    let mut after: Option<String> = None;
    for _ in 0..8 {
        let reply = call(
            config,
            identity,
            json!({"type":"PageList","namespace":null,"after":after}),
        )?;
        page_proof::fresh(&reply["result"])?;
        let entries: Vec<Descriptor> = serde_json::from_value(reply["result"]["entries"].clone())?;
        if let Some(entry) = entries.into_iter().find(|entry| entry.page_id == page_id) {
            return Ok(entry);
        }
        match reply["result"]["next"].as_str() {
            None => break,
            Some(next) => {
                protocol::hex_bytes::<16>(next)?;
                after = Some(next.into());
            }
        }
    }
    bail!("page is not currently published")
}

pub(crate) fn read(
    config: &Config,
    identity: &Identity,
    page_id: &str,
    replica: Option<&str>,
) -> Result<(Descriptor, String, u64)> {
    protocol::hex_bytes::<16>(page_id)?;
    ensure!(
        !config.application || replica.is_none(),
        "application grants do not include replica tickets"
    );
    let reply = if let Some(replica) = replica {
        protocol::hex_bytes::<32>(replica)?;
        let entry = descriptor(config, identity, page_id)?;
        let request = call(
            config,
            identity,
            json!({"type":"PageReplicaRequest","pageId":page_id,
            "replicaDeviceKey":replica,"publicationVersion":entry.publication_version}),
        )?;
        let ticket = request["result"]["ticketId"]
            .as_str()
            .context("replica ticket is missing")?;
        protocol::hex_bytes::<32>(ticket)?;
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            ensure!(Instant::now() < deadline, "replica read deadline exceeded");
            let response = call(
                config,
                identity,
                json!({"type":"PageReplicaResult","ticketId":ticket}),
            )?;
            ensure!(
                response["result"]["ticketId"].as_str() == Some(ticket),
                "replica ticket mismatch"
            );
            match response["result"]["state"].as_str() {
                Some("Ready") => {
                    ensure!(
                        response["result"]["descriptor"]["publicationVersion"].as_u64()
                            == Some(entry.publication_version),
                        "replica publication changed"
                    );
                    break response;
                }
                Some("Pending") => std::thread::sleep(Duration::from_millis(200)),
                _ => bail!("invalid replica result"),
            }
        }
    } else {
        call(
            config,
            identity,
            json!({"type":"PageRead","pageId":page_id}),
        )?
    };
    let revision = page_proof::fresh(&reply["result"])?;
    let descriptor: Descriptor = serde_json::from_value(reply["result"]["descriptor"].clone())?;
    let bundle: Bundle = serde_json::from_value(reply["result"]["bundle"].clone())?;
    ensure!(
        descriptor.page_id == page_id,
        "authority returned another page"
    );
    let body = page_proof::verify(&config.network, &descriptor, &bundle)?;
    Ok((descriptor, body, revision))
}

pub fn run(config_path: Option<&Path>, command: Command) -> Result<()> {
    if let Command::Preview { file, tui, ascii } = command {
        let source = body(&file)?;
        let document = markup::parse(&source).map_err(anyhow::Error::msg)?;
        reader::show(
            &document,
            &["UNAPPROVED local draft; no authority lookup or publication.".into()],
            tui,
            ascii,
        )?;
        return Ok(());
    }
    let config: Config = serde_json::from_slice(&files::read_bounded(
        config_path.context("--config is required")?,
        false,
    )?)?;
    let identity = crate::load_identity(&config.identity)?;
    match command {
        Command::Preview { .. } => unreachable!(),
        Command::Submit {
            file,
            namespace,
            page_id,
            expected_version,
            output,
        } => {
            ensure!(markup::namespace(&namespace), "invalid namespace");
            let body = body(&file)?;
            let digest = hex::encode(Sha256::digest(body.as_bytes()));
            let request = if output.exists() {
                let value: Value = serde_json::from_slice(&files::read_bounded(&output, true)?)?;
                let proof: Envelope = serde_json::from_value(value.clone())?;
                let (saved, _) = page_proof::submission(&config.network, &proof)?;
                ensure!(
                    proof.public_key == identity.public_key
                        && saved.body == body
                        && saved.namespace == namespace
                        && saved.expected_version == expected_version
                        && page_id.as_ref().is_none_or(|id| *id == saved.page_id),
                    "saved submission does not match this draft; use a new output file"
                );
                value
            } else {
                let page_id = page_id.unwrap_or_else(crate::random_hex::<16>);
                protocol::hex_bytes::<16>(&page_id)?;
                let value = protocol::signed(
                    &config,
                    &identity,
                    &crate::random_hex::<16>(),
                    crate::now()?,
                    json!({"type":"PageSubmit","pageId":page_id,"expectedVersion":expected_version,
                        "namespace":namespace,"audience":"Members","profile":markup::PROFILE,"digest":digest,"body":body}),
                )?;
                files::write_new(&output, &serde_json::to_vec_pretty(&value)?)?;
                value
            };
            let proof: Envelope = serde_json::from_value(request.clone())?;
            let (source, _) = page_proof::submission(&config.network, &proof)?;
            eprintln!(
                "Signed submission retained; page ID {}. Inspect this ID to recover an uncertain result.",
                source.page_id
            );
            crate::print_value(&protocol::send_envelope(&config, &request)?)?;
        }
        Command::Queue { namespace, after } => {
            listing(&config, &identity, "PageQueue", namespace, after)?
        }
        Command::List { namespace, after } => {
            listing(&config, &identity, "PageList", namespace, after)?
        }
        Command::Inspect {
            page_id,
            output,
            tui,
            ascii,
        } => {
            protocol::hex_bytes::<16>(&page_id)?;
            let reply = call(
                &config,
                &identity,
                json!({"type":"PageInspect","pageId":page_id}),
            )?;
            let record = json!({"network":config.network,"inspection":reply["result"]});
            if record["inspection"]["pending"].is_null() {
                files::write_new(&output, &serde_json::to_vec_pretty(&record)?)?;
                return crate::print_value(&reply);
            }
            let (source, digest, _) = pending(&config.network, &record)?;
            files::write_new(&output, &serde_json::to_vec_pretty(&record)?)?;
            let document = markup::parse(&source.body).map_err(anyhow::Error::msg)?;
            reader::show(
                &document,
                &[
                    "UNAPPROVED submission. Review this exact retained record.".into(),
                    format!(
                        "Page {} | version {} | source SHA256 {} | proof {}",
                        source.page_id, record["inspection"]["version"], source.digest, digest
                    ),
                ],
                tui,
                ascii,
            )?;
        }
        Command::Review { input, decision } => {
            let record: Value = serde_json::from_slice(&files::read_bounded(&input, true)?)?;
            let (source, digest, proof) = pending(&config.network, &record)?;
            let version = record["inspection"]["version"]
                .as_u64()
                .context("missing review version")?;
            let decision = match decision {
                Decision::Approve => "Approve",
                Decision::Reject => "Reject",
            };
            let mut command = json!({"type":"PageReview","pageId":source.page_id,
                "expectedVersion":version,"revision":source.expected_version+1,"digest":source.digest,"profile":source.profile,
                "author":proof.public_key,"namespace":source.namespace,"audience":source.audience,
                "submissionDigest":digest,"decision":decision});
            crate::applications::manual_review(&config, &identity, &mut command)?;
            crate::print_value(&call(&config, &identity, command)?)?;
        }
        Command::Withdraw {
            page_id,
            expected_version,
        } => {
            protocol::hex_bytes::<16>(&page_id)?;
            crate::print_value(&call(
                &config,
                &identity,
                json!({"type":"PageWithdraw","pageId":page_id,"expectedVersion":expected_version}),
            )?)?;
        }
        Command::Read {
            page_id,
            replica,
            tui,
            ascii,
        } => crate::navigation::browse(
            &config,
            &identity,
            crate::navigation::Location::Native(page_id),
            replica.as_deref(),
            tui,
            ascii,
        )?,
    }
    Ok(())
}
