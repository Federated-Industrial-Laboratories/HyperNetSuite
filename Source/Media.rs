// SPDX-License-Identifier: MIT
// Explicit author, reviewer and reader workflows for immutable page media.
use crate::{
    Config, Identity, files, mail_protocol as signed, markup, media_protocol as wire, page_proof,
    pages, protocol, transfer_files,
};
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

#[derive(Subcommand)]
pub enum Command {
    /// Convert one local PNG, JPEG or supported SVG in an isolated worker.
    Import(crate::media_import::ImportArgs),
    /// Export validated canonical geometry as a minimal static SVG.
    ExportSvg {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// List explicitly consented page media hosts and the copy policy.
    Hosts,
    /// Sign a separate page media host consent document using this host identity.
    HostConsent {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    HostRegister {
        #[arg(long)]
        input: PathBuf,
    },
    HostWithdraw {
        #[arg(long)]
        host_key: String,
        #[arg(long)]
        expected_generation: u64,
    },
    /// Set the administrator's minimum durable copies for subsequent submissions.
    PolicySet {
        #[arg(long)]
        minimum_copies: u16,
    },
    /// Resume exact submitted media into its selected consented stores.
    Upload {
        #[arg(long)]
        submission: PathBuf,
        #[arg(long)]
        asset: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        host: Option<String>,
    },
    /// Verify pending media, save it locally and attest this exact review reference.
    Inspect {
        #[arg(long)]
        federated: bool,
        #[arg(long)]
        review: PathBuf,
        #[arg(long)]
        asset: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        host: Option<String>,
    },
    /// Explicitly fetch one asset from a currently approved page reference.
    Read {
        #[arg(long)]
        agreement: Option<String>,
        #[arg(long)]
        page_id: String,
        #[arg(long)]
        asset: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        host: Option<String>,
    },
    /// Copy an approved asset into another host in the author's exact manifest.
    Replicate {
        #[arg(long)]
        page_id: String,
        #[arg(long)]
        asset: String,
        #[arg(long)]
        source_host: String,
        #[arg(long)]
        destination_host: String,
    },
}

pub fn reference(
    page_id: &str,
    revision: u64,
    source_digest: &str,
    namespace: &str,
    body: &str,
    asset_id: &str,
) -> Result<wire::Reference> {
    protocol::hex_bytes::<16>(page_id)?;
    protocol::hex_bytes::<32>(source_digest)?;
    ensure!(
        revision > 0 && markup::namespace(namespace),
        "invalid page media reference"
    );
    ensure!(
        signed::digest(body.as_bytes()) == source_digest,
        "media source digest mismatch"
    );
    let document = markup::parse(body).map_err(anyhow::Error::msg)?;
    let asset = document
        .assets
        .into_iter()
        .find(|a| a.id == asset_id)
        .context("asset is absent from exact page")?;
    Ok(wire::Reference {
        agreement_id: None,
        storage_hosts: asset.hosts.clone(),
        page_id: page_id.into(),
        revision,
        source_digest: source_digest.into(),
        namespace: namespace.into(),
        asset,
    })
}
pub fn image_asset(document: &markup::Document, target: &str) -> Result<markup::media::Asset> {
    fn find<'a>(nodes: &'a [markup::Node], target: &str) -> Option<&'a str> {
        for node in nodes {
            if node.id.as_deref() == Some(target)
                && let markup::Kind::Image { asset, .. } = &node.kind
            {
                return Some(asset);
            }
            if let Some(asset) = find(&node.children, target) {
                return Some(asset);
            }
        }
        None
    }
    let id = find(&document.nodes, target).context("reveal target is not an image")?;
    document
        .assets
        .iter()
        .find(|a| a.id == id)
        .cloned()
        .context("image manifest is absent")
}
pub fn local_show(
    document: &markup::Document,
    metadata: &[String],
    tui: bool,
    ascii: bool,
    graphics: &crate::terminal_graphics::Options,
    media: &[String],
) -> Result<()> {
    let mut inputs = std::collections::BTreeMap::new();
    for mapping in media {
        let (id, path) = mapping
            .split_once('=')
            .context("--media requires AssetId=/explicit/path")?;
        ensure!(
            document.assets.iter().any(|a| a.id == id)
                && !path.is_empty()
                && inputs.insert(id.to_owned(), PathBuf::from(path)).is_none(),
            "unknown, duplicate or empty media mapping"
        );
    }
    let session = crate::reader::Session::new(tui, ascii)?;
    session.configure_graphics(graphics)?;
    let mut view = crate::page_view::View::new();
    let mut status =
        String::from("Local preview; images require explicit reveal and a selected local file");
    loop {
        match session.show(
            document,
            metadata,
            &mut view,
            &status,
            crate::reader::Mode::Preview,
        )? {
            crate::reader::Action::Reveal(target) => {
                let result = (|| {
                    let asset = image_asset(document, &target)?;
                    let path = inputs
                        .get(&asset.id)
                        .context("no explicit --media mapping for this asset")?;
                    let bytes =
                        transfer_files::read(path, markup::media::MAX_PAGE_BYTES as usize, false)?;
                    let pixels = crate::media_import::render_asset(&asset, &bytes)?;
                    session.install_image(&asset, pixels)?;
                    view.revealed.insert(asset.id);
                    Ok::<_, anyhow::Error>(())
                })();
                status = match result {
                    Ok(()) => {
                        "Verified local media revealed; terminal support may require alt fallback"
                            .into()
                    }
                    Err(error) => {
                        crate::reader::bounded_status(&format!("Could not reveal: {error:#}"))
                    }
                };
            }
            crate::reader::Action::Quit => return Ok(()),
            _ => {
                status = "Preview does not navigate, submit or fetch media".into();
            }
        }
    }
}
fn acknowledge(
    config: &Config,
    identity: &Identity,
    r: &wire::Reference,
    receipt: &wire::Envelope,
) -> Result<Value> {
    signed::authority(
        config,
        identity,
        json!({"type":"PageMediaReceipt","agreementId":r.agreement_id,"pageId":r.page_id,
        "revision":r.revision,"assetId":r.asset.id,"receipt":receipt}),
    )
}
pub fn fetch(
    config: &Config,
    identity: &Identity,
    r: &wire::Reference,
    selected: Option<&str>,
    review: bool,
) -> Result<Vec<u8>> {
    let host = wire::selected_host(config, identity, r, selected)?;
    let mut bytes = Vec::with_capacity(r.asset.bytes as usize);
    let mut final_receipt = None;
    while (bytes.len() as u64) < r.asset.bytes {
        let offset = bytes.len() as u64;
        let chunk = wire::CHUNK.min(r.asset.bytes - offset);
        let op = wire::operation(config, identity, &host, r, "Fetch", offset, chunk, None)?;
        let result = wire::store(config, &host, &op, None)?;
        let (receipt, state) = wire::receipt(config, identity, &host, r, "Fetch", &result)?;
        ensure!(state.status == "Complete", "media asset is not sealed");
        let data = signed::decode(
            result["payload"].as_str().context("missing media chunk")?,
            wire::CHUNK as usize,
        )?;
        ensure!(data.len() as u64 == chunk, "media chunk length mismatch");
        bytes.extend(data);
        final_receipt = Some(receipt);
    }
    markup::media::validate_asset_bytes(&r.asset, &bytes).map_err(anyhow::Error::msg)?;
    if review {
        acknowledge(
            config,
            identity,
            r,
            &final_receipt.context("missing media review receipt")?,
        )?;
    }
    Ok(bytes)
}
fn upload(
    config: &Config,
    identity: &Identity,
    r: &wire::Reference,
    bytes: &[u8],
    host_key: &str,
) -> Result<Value> {
    markup::media::validate_asset_bytes(&r.asset, bytes).map_err(anyhow::Error::msg)?;
    let host = wire::selected_host(config, identity, r, Some(host_key))?;
    let op = wire::operation(config, identity, &host, r, "Status", 0, 0, None)?;
    let result = wire::store(config, &host, &op, None)?;
    let (_, state) = wire::receipt(config, identity, &host, r, "Status", &result)?;
    ensure!(
        state.stored_bytes == r.asset.bytes || state.stored_bytes % wire::CHUNK == 0,
        "store returned a non-canonical upload boundary"
    );
    let mut offset = state.stored_bytes;
    while offset < r.asset.bytes {
        let end = (offset + wire::CHUNK).min(r.asset.bytes);
        let payload = &bytes[offset as usize..end as usize];
        let op = wire::operation(
            config,
            identity,
            &host,
            r,
            "Put",
            offset,
            end - offset,
            Some(payload),
        )?;
        let result = wire::store(config, &host, &op, Some(payload))?;
        let (_, state) = wire::receipt(config, identity, &host, r, "Put", &result)?;
        ensure!(
            state.stored_bytes == end,
            "store did not confirm the exact immutable chunk"
        );
        offset = end;
    }
    let op = wire::operation(config, identity, &host, r, "Seal", 0, 0, None)?;
    let result = wire::store(config, &host, &op, None)?;
    let (receipt, state) = wire::receipt(config, identity, &host, r, "Seal", &result)?;
    ensure!(state.status == "Complete", "store did not seal media");
    acknowledge(config, identity, r, &receipt)?;
    Ok(json!({"hostKey":host.host_key,"asset":r.asset.id,"status":"Complete","receipt":receipt}))
}
fn source_reference(source: &page_proof::Submission, asset: &str) -> Result<wire::Reference> {
    reference(
        &source.page_id,
        source
            .expected_version
            .checked_add(1)
            .context("page version overflow")?,
        &source.digest,
        &source.namespace,
        &source.body,
        asset,
    )
}
pub fn pending_reference(
    config: &Config,
    identity: &Identity,
    record: &Value,
    asset: &str,
) -> Result<wire::Reference> {
    let (expected, expected_digest, _) = pages::pending(&config.network, record)?;
    let result = signed::authority(
        config,
        identity,
        json!({"type":"PageInspect","pageId":expected.page_id}),
    )?;
    let fresh = json!({"network":config.network,"inspection":result});
    let (source, digest, _) = pages::pending(&config.network, &fresh)?;
    ensure!(
        digest == expected_digest
            && source.body == expected.body
            && fresh["inspection"]["version"] == record["inspection"]["version"],
        "pending page changed; inspect it again before media review"
    );
    source_reference(&source, asset)
}
pub fn read_reference(
    config: &Config,
    identity: &Identity,
    page_id: &str,
    asset: &str,
    expected: Option<&page_proof::Descriptor>,
) -> Result<wire::Reference> {
    let (descriptor, body, _) = pages::read(config, identity, page_id, None)?;
    if let Some(expected) = expected {
        ensure!(
            serde_json::to_value(&descriptor)? == serde_json::to_value(expected)?,
            "page changed; refresh before revealing media"
        );
    }
    reference(
        page_id,
        descriptor.revision,
        &descriptor.digest,
        &descriptor.namespace,
        &body,
        asset,
    )
}
fn foreign_reference(
    treaty: &crate::federation_proof::Treaty,
    descriptor: &page_proof::Descriptor,
    body: &str,
    asset: &str,
) -> Result<wire::Reference> {
    treaty.validate_media(body)?;
    let mut value = reference(
        &descriptor.page_id,
        descriptor.revision,
        &descriptor.digest,
        &descriptor.namespace,
        body,
        asset,
    )?;
    value.agreement_id = Some(treaty.agreement_id.clone());
    value.storage_hosts = treaty.media_destination_hosts.clone();
    value.namespace = treaty.destination_namespace.clone();
    Ok(value)
}
pub fn federated_reference(
    config: &Config,
    identity: &Identity,
    agreement: &str,
    page_id: &str,
    asset: &str,
    expected: Option<&page_proof::Descriptor>,
) -> Result<wire::Reference> {
    let publication = crate::federation::load(config, identity, agreement, page_id)?;
    if let Some(expected) = expected {
        ensure!(
            serde_json::to_value(&publication.descriptor)? == serde_json::to_value(expected)?,
            "federated page changed; refresh before revealing media"
        );
    }
    foreign_reference(
        &publication.treaty,
        &publication.descriptor,
        &publication.body,
        asset,
    )
}
pub fn federated_pending_reference(
    config: &Config,
    identity: &Identity,
    record: &Value,
    asset: &str,
) -> Result<wire::Reference> {
    let (expected_treaty, expected, expected_digest, _) =
        crate::federation::pending(&config.network, record)?;
    let result = signed::authority(
        config,
        identity,
        json!({"type":"FederationInspect",
        "agreementId":expected_treaty.agreement_id,"pageId":expected.page_id}),
    )?;
    let fresh = json!({"network":config.network,"inspection":result});
    let (treaty, descriptor, digest, body) = crate::federation::pending(&config.network, &fresh)?;
    ensure!(
        digest == expected_digest
            && treaty.digest()? == expected_treaty.digest()?
            && fresh["inspection"]["version"] == record["inspection"]["version"],
        "imported pending page changed; inspect it again"
    );
    foreign_reference(&treaty, &descriptor, &body, asset)
}
pub fn run(path: Option<&Path>, command: Command) -> Result<()> {
    match command {
        Command::Import(args) => {
            return crate::print_value(&serde_json::to_value(crate::media_import::import(&args)?)?);
        }
        Command::ExportSvg { input, output } => {
            let bytes = transfer_files::read(&input, markup::media::MAX_VECTOR_BYTES, false)?;
            let vector = markup::media::vector(&bytes).map_err(anyhow::Error::msg)?;
            let svg = markup::media::vector_svg(&vector).map_err(anyhow::Error::msg)?;
            transfer_files::write_new(&output, svg.as_bytes())?;
            return crate::print_value(
                &json!({"profile":markup::media::VECTOR_PROFILE,"svgBytes":svg.len()}),
            );
        }
        _ => {}
    }
    let config: Config = serde_json::from_slice(&files::read_bounded(
        path.context("--config is required")?,
        false,
    )?)?;
    let identity = crate::load_identity(&config.identity)?;
    let result = match command {
        Command::Import(_) | Command::ExportSvg { .. } => unreachable!(),
        Command::Hosts => signed::authority(&config, &identity, json!({"type":"PageMediaHosts"}))?,
        Command::HostConsent { input, output } => {
            let value: wire::HostConsent =
                serde_json::from_slice(&files::read_bounded(&input, false)?)?;
            ensure!(
                !config.application
                    && value.host_key == identity.public_key
                    && value.network == config.network,
                "media host consent must be signed by its own host identity"
            );
            let signed = signed::sign(wire::HOST, &config.network, &identity, &value)?;
            wire::host(&config, &signed, &value.authority_signer)?;
            files::write_new(&output, &serde_json::to_vec_pretty(&signed)?)?;
            json!({"hostKey":value.host_key,"generation":value.generation,"signed":true})
        }
        Command::HostRegister { input } => {
            let consent: wire::Envelope =
                serde_json::from_slice(&files::read_bounded(&input, false)?)?;
            signed::authority(
                &config,
                &identity,
                json!({"type":"PageMediaHostRegister","consent":consent}),
            )?
        }
        Command::HostWithdraw {
            host_key,
            expected_generation,
        } => {
            protocol::hex_bytes::<32>(&host_key)?;
            signed::authority(
                &config,
                &identity,
                json!({"type":"PageMediaHostWithdraw","hostKey":host_key,"expectedGeneration":expected_generation}),
            )?
        }
        Command::PolicySet { minimum_copies } => {
            ensure!(
                (1..=3).contains(&minimum_copies),
                "minimum copies must be 1 through 3"
            );
            signed::authority(
                &config,
                &identity,
                json!({"type":"PageMediaPolicySet","minimumCopies":minimum_copies}),
            )?
        }
        Command::Upload {
            submission,
            asset,
            input,
            host,
        } => {
            let proof: page_proof::Envelope =
                serde_json::from_slice(&files::read_bounded(&submission, true)?)?;
            let (source, _) = page_proof::submission(&config.network, &proof)?;
            ensure!(
                proof.public_key == identity.public_key,
                "upload requires the exact submitting identity"
            );
            let r = source_reference(&source, &asset)?;
            let bytes =
                transfer_files::read(&input, markup::media::MAX_PAGE_BYTES as usize, false)?;
            markup::media::validate_asset_bytes(&r.asset, &bytes).map_err(anyhow::Error::msg)?;
            let selected = host
                .map(|h| vec![h])
                .unwrap_or_else(|| r.asset.hosts.clone());
            let mut results = Vec::new();
            for key in selected {
                results.push(upload(&config, &identity, &r, &bytes, &key)?);
            }
            json!({"asset":asset,"copies":results})
        }
        Command::Inspect {
            review,
            asset,
            output,
            host,
            federated,
        } => {
            let record = serde_json::from_slice(&files::read_bounded(&review, true)?)?;
            let r = if federated {
                federated_pending_reference(&config, &identity, &record, &asset)?
            } else {
                pending_reference(&config, &identity, &record, &asset)?
            };
            let bytes = fetch(&config, &identity, &r, host.as_deref(), true)?;
            transfer_files::write_new(&output, &bytes)?;
            json!({"pageId":r.page_id,"asset":r.asset,"verified":true,"reviewAttested":true})
        }
        Command::Read {
            page_id,
            asset,
            output,
            host,
            agreement,
        } => {
            let r = if let Some(agreement) = agreement {
                federated_reference(&config, &identity, &agreement, &page_id, &asset, None)?
            } else {
                read_reference(&config, &identity, &page_id, &asset, None)?
            };
            let bytes = fetch(&config, &identity, &r, host.as_deref(), false)?;
            transfer_files::write_new(&output, &bytes)?;
            json!({"pageId":page_id,"asset":r.asset,"verified":true})
        }
        Command::Replicate {
            page_id,
            asset,
            source_host,
            destination_host,
        } => {
            ensure!(
                source_host != destination_host,
                "replica destination must differ from the source"
            );
            let r = read_reference(&config, &identity, &page_id, &asset, None)?;
            let bytes = fetch(&config, &identity, &r, Some(&source_host), false)?;
            upload(&config, &identity, &r, &bytes, &destination_host)?
        }
    };
    crate::print_value(&result)
}
