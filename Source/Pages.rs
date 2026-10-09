// SPDX-License-Identifier: MIT
// Independent author, moderator and reader workflows over the public Pages API.
use crate::{
    Config, Identity, files, markup,
    page_proof::{self, Bundle, Descriptor, Envelope},
    protocol, reader,
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
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

fn form_bundle_preflight(source: &str, submission: &Value) -> Result<()> {
    if markup::parse(source)
        .map_err(anyhow::Error::msg)?
        .forms
        .is_empty()
    {
        return Ok(());
    }
    // Reserve the complete largest accepted approval envelope, including application metadata.
    let bound =
        serde_json::to_vec(&json!({"submission":submission,"approval":null}))?.len() - 4 + 4096;
    ensure!(
        bound <= markup::forms::MAX_BUNDLE_BYTES,
        "form page exceeds the 20 KiB bundle limit with the maximum approval; shorten the draft"
    );
    Ok(())
}

fn preview_form_bound(source: &str) -> Result<()> {
    let command = json!({"type":"PageSubmit","pageId":"0".repeat(32),"expectedVersion":u64::MAX,
        "namespace":"N".repeat(32),"audience":"Members","profile":markup::PROFILE,
        "digest":"0".repeat(64),"body":source});
    let payload = serde_json::to_vec(
        &json!({"version":1,"requestId":"0".repeat(32),"issuedAt":u64::MAX,"command":command}),
    )?;
    let submission = json!({"network":"0".repeat(64),"publicKey":"0".repeat(64),
        "payload":URL_SAFE_NO_PAD.encode(payload),"signature":"0".repeat(128)});
    form_bundle_preflight(source, &submission)
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

#[derive(Clone)]
pub struct Catalogue {
    pub entries: Vec<Descriptor>,
    pub next: Option<String>,
    pub revision: u64,
}

fn catalogue_result(
    result: &Value,
    namespace: Option<&str>,
    after: Option<&str>,
) -> Result<Catalogue> {
    let revision = page_proof::fresh(result)?;
    let entries: Vec<Descriptor> = serde_json::from_value(result["entries"].clone())?;
    ensure!(entries.len() <= 32, "catalogue exceeds its entry bound");
    let mut previous = after;
    for entry in &entries {
        for value in [
            &entry.author,
            &entry.reviewer,
            &entry.digest,
            &entry.submission_digest,
            &entry.approval_digest,
        ] {
            protocol::hex_bytes::<32>(value)?;
        }
        protocol::hex_bytes::<16>(&entry.page_id)?;
        ensure!(
            entry.profile == markup::PROFILE
                && entry.audience == "Members"
                && markup::namespace(&entry.namespace)
                && namespace.is_none_or(|scope| scope == entry.namespace)
                && entry.revision > 0
                && entry.publication_version > entry.revision
                && previous.is_none_or(|cursor| cursor < entry.page_id.as_str()),
            "invalid catalogue publication or cursor"
        );
        previous = Some(&entry.page_id);
    }
    let next: Option<String> = serde_json::from_value(
        result
            .get("next")
            .context("catalogue cursor is missing")?
            .clone(),
    )?;
    if let Some(next) = &next {
        protocol::hex_bytes::<16>(next)?;
        ensure!(
            entries.len() == 32 && previous == Some(next.as_str()),
            "invalid catalogue continuation"
        );
    }
    Ok(Catalogue {
        entries,
        next,
        revision,
    })
}

pub fn catalogue(
    config: &Config,
    identity: &Identity,
    namespace: Option<&str>,
    after: Option<&str>,
) -> Result<Catalogue> {
    ensure!(
        !config.application || namespace.is_some(),
        "application listings require --namespace"
    );
    if let Some(namespace) = namespace {
        ensure!(markup::namespace(namespace), "invalid namespace");
    }
    if let Some(after) = after {
        protocol::hex_bytes::<16>(after)?;
    }
    let reply = call(
        config,
        identity,
        json!({"type":"PageList","namespace":namespace,"after":after}),
    )?;
    catalogue_result(&reply["result"], namespace, after)
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
        let catalogue = catalogue(config, identity, None, after.as_deref())?;
        if let Some(entry) = catalogue
            .entries
            .into_iter()
            .find(|entry| entry.page_id == page_id)
        {
            return Ok(entry);
        }
        match catalogue.next {
            None => break,
            Some(next) => after = Some(next),
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
        preview_form_bound(&source)?;
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
                form_bundle_preflight(&body, &value)?;
                files::write_new(&output, &serde_json::to_vec_pretty(&value)?)?;
                value
            };
            form_bundle_preflight(&body, &request)?;
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

#[cfg(test)]
mod catalogue_tests {
    use super::*;
    fn entry(id: u64) -> Value {
        json!({"pageId":format!("{id:032x}"), "publicationVersion":2, "revision":1,
            "author":"01".repeat(32), "reviewer":"02".repeat(32), "namespace":"News",
            "audience":"Members", "profile":markup::PROFILE, "digest":"03".repeat(32),
            "submissionDigest":"04".repeat(32), "approvalDigest":"05".repeat(32)})
    }
    fn result(count: u64) -> Value {
        json!({"entries":(1..=count).map(entry).collect::<Vec<_>>(),"next":null,
            "authorityRevision":1,"validUntil":crate::now().unwrap()+5})
    }
    #[test]
    fn catalogue_enforces_current_scope_order_freshness_and_continuation() {
        let mut good = result(32);
        good["next"] = json!(format!("{:032x}", 32));
        assert!(catalogue_result(&good, Some("News"), None).is_ok());
        for field in [
            "profile",
            "namespace",
            "audience",
            "author",
            "reviewer",
            "digest",
            "submissionDigest",
            "approvalDigest",
            "pageId",
        ] {
            let mut bad = good.clone();
            bad["entries"][0][field] = json!("bad");
            assert!(
                catalogue_result(&bad, Some("News"), None).is_err(),
                "{field}"
            );
        }
        for (field, value) in [("revision", 0), ("publicationVersion", 1)] {
            let mut bad = good.clone();
            bad["entries"][0][field] = json!(value);
            assert!(catalogue_result(&bad, None, None).is_err());
        }
        let mut bad = good.clone();
        bad["entries"][1] = bad["entries"][0].clone();
        assert!(catalogue_result(&bad, None, None).is_err());
        assert!(catalogue_result(&good, None, Some(&format!("{:032x}", 1))).is_err());
        assert!(catalogue_result(&result(33), None, None).is_err());
        let mut bad = result(1);
        bad["next"] = json!(format!("{:032x}", 1));
        assert!(catalogue_result(&bad, None, None).is_err());
        let mut bad = good.clone();
        bad["next"] = json!(format!("{:032x}", 31));
        assert!(catalogue_result(&bad, None, None).is_err());
        let mut bad = good.clone();
        bad["validUntil"] = json!(crate::now().unwrap() - 1);
        assert!(catalogue_result(&bad, None, None).is_err());
        assert!(catalogue_result(&result(0), None, None).is_ok());
    }
    #[test]
    fn author_lint_reserves_complete_approval_only_for_form_pages() {
        let form = format!(
            "@Form {{\"id\":\"Reply\",\"label\":\"Reply\",\"profile\":\"HyperNetFormMail/1\",\"recipient\":\"{}\",\"owner\":\"{}\"}}\n@Field {{\"id\":\"Answer\",\"label\":\"Answer\",\"kind\":\"Text\",\"maxBytes\":128}}\n@Submit {{\"label\":\"Review\"}}\n@End\n",
            "01".repeat(32),
            "02".repeat(32)
        );
        let large = format!(": {}\n", "x".repeat(490)).repeat(29);
        assert!(preview_form_bound(&format!("{}\n# Form\n{form}", markup::PROFILE)).is_ok());
        assert!(
            preview_form_bound(&format!("{}\n# Form\n{form}{large}", markup::PROFILE)).is_err()
        );
        assert!(preview_form_bound(&format!("{}\n# Ordinary\n{large}", markup::PROFILE)).is_ok());
    }
}
