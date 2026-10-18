// SPDX-License-Identifier: MIT
// Explicit local preview and validated media reveal without network access.
use crate::{markup, transfer_files};
use anyhow::{Context, Result, ensure};
use std::path::PathBuf;

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
