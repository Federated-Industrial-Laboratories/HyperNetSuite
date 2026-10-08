// SPDX-License-Identifier: MIT
// One bounded retained-display history for native and explicitly federated pages.
use crate::{
    Config, Identity, federation, federation_proof::Treaty, markup, page_proof::Descriptor, pages,
    protocol, reader,
};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::collections::VecDeque;

const MAXIMUM_HISTORY: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Location {
    Native(String),
    Federated { agreement: String, page_id: String },
}

struct Page {
    location: Location,
    network: String,
    descriptor: Descriptor,
    body: String,
    metadata: Vec<String>,
    treaty: Option<Treaty>,
}

struct Link<'a> {
    network: &'a str,
    author: &'a str,
    namespace: &'a str,
    page_id: &'a str,
}

impl<'a> Link<'a> {
    fn parse(target: &'a str) -> Result<Self> {
        let parts: Vec<_> = target
            .strip_prefix("hypernet://")
            .context("internal page link required")?
            .split('/')
            .collect();
        ensure!(parts.len() == 4, "invalid internal page link");
        protocol::hex_bytes::<32>(parts[0])?;
        protocol::hex_bytes::<32>(parts[1])?;
        ensure!(markup::namespace(parts[2]), "invalid linked namespace");
        protocol::hex_bytes::<16>(parts[3])?;
        Ok(Self {
            network: parts[0],
            author: parts[1],
            namespace: parts[2],
            page_id: parts[3],
        })
    }

    fn matches(&self, page: &Page) -> Result<()> {
        ensure!(
            page.network == self.network
                && page.descriptor.author == self.author
                && page.descriptor.namespace == self.namespace
                && page.descriptor.page_id == self.page_id,
            "link identity does not match publication"
        );
        Ok(())
    }
}

fn agreement(
    local: &str,
    link: &Link<'_>,
    current: Option<&Treaty>,
    records: &[Value],
    now: u64,
) -> Result<String> {
    let mut matched = Vec::new();
    for record in records {
        let treaty: Treaty = serde_json::from_value(record["treaty"].clone())?;
        if record["active"] == true
            && treaty.expires > now
            && treaty.destination_network == local
            && treaty.source_network == link.network
            && treaty.source_namespace == link.namespace
        {
            ensure!(
                record["digest"].as_str() == Some(&treaty.digest()?),
                "agreement digest mismatch"
            );
            matched.push(treaty.agreement_id);
        }
    }
    if let Some(current) = current.filter(|value| {
        value.source_network == link.network && value.source_namespace == link.namespace
    }) {
        ensure!(
            matched.contains(&current.agreement_id),
            "selected agreement is no longer active"
        );
        return Ok(current.agreement_id.clone());
    }
    ensure!(
        matched.len() == 1,
        "link needs exactly one explicit local agreement; choose an agreement with federation read"
    );
    Ok(matched.remove(0))
}

fn route(
    config: &Config,
    identity: &Identity,
    link: &Link<'_>,
    current: Option<&Treaty>,
    replica: Option<&str>,
) -> Result<Location> {
    if link.network == config.network {
        return Ok(Location::Native(link.page_id.into()));
    }
    ensure!(
        replica.is_none(),
        "a foreign link needs an explicit federated read without a native replica selection"
    );
    let response = federation::agreements(config, identity)?;
    let selected = agreement(
        &config.network,
        link,
        current,
        response["result"]["entries"]
            .as_array()
            .context("missing agreement inventory")?,
        crate::now()?,
    )?;
    Ok(Location::Federated {
        agreement: selected,
        page_id: link.page_id.into(),
    })
}

fn load(
    config: &Config,
    identity: &Identity,
    location: Location,
    replica: Option<&str>,
) -> Result<Page> {
    match &location {
        Location::Native(page_id) => {
            let (descriptor, body, revision) = pages::read(config, identity, page_id, replica)?;
            let metadata = vec![
                "Approved at fetch; retained display. Refresh revalidates authority.".into(),
                format!(
                    "Network {} | namespace {} | page {}",
                    config.network, descriptor.namespace, descriptor.page_id
                ),
                format!("Author {}", descriptor.author),
                format!("Reviewer {}", descriptor.reviewer),
                format!(
                    "Publication {} | authority revision {} | SHA256 {}",
                    descriptor.publication_version, revision, descriptor.digest
                ),
                replica
                    .map(|key| format!("Content supplied by replica {key}"))
                    .unwrap_or_else(|| "Content supplied by authority".into()),
            ];
            Ok(Page {
                location,
                network: config.network.clone(),
                descriptor,
                body,
                metadata,
                treaty: None,
            })
        }
        Location::Federated { agreement, page_id } => {
            ensure!(
                replica.is_none(),
                "a native replica cannot supply a federated page"
            );
            let publication = federation::load(config, identity, agreement, page_id)?;
            let metadata = vec![
                "Federated approval at fetch; retained display. Refresh revalidates both domains."
                    .into(),
                format!(
                    "Origin network {} | author {} | namespace {} | page {}",
                    publication.treaty.source_network,
                    publication.descriptor.author,
                    publication.descriptor.namespace,
                    publication.descriptor.page_id
                ),
                format!(
                    "Local network {} | namespace {} | reviewer {}",
                    config.network, publication.treaty.destination_namespace, publication.reviewer
                ),
                format!(
                    "Agreement {} | source publication {} | authority revision {}",
                    publication.treaty.agreement_id,
                    publication.descriptor.publication_version,
                    publication.authority_revision
                ),
            ];
            Ok(Page {
                location,
                network: publication.treaty.source_network.clone(),
                descriptor: publication.descriptor,
                body: publication.body,
                metadata,
                treaty: Some(publication.treaty),
            })
        }
    }
}

pub fn browse(
    config: &Config,
    identity: &Identity,
    first: Location,
    replica: Option<&str>,
    tui: bool,
    ascii: bool,
) -> Result<()> {
    let mut current = load(config, identity, first, replica)?;
    let mut history = VecDeque::new();
    loop {
        let document = markup::parse(&current.body).map_err(anyhow::Error::msg)?;
        match reader::show(&document, &current.metadata, tui, ascii)? {
            reader::Action::Quit => return Ok(()),
            reader::Action::Back => {
                if let Some(previous) = history.pop_back() {
                    current = previous;
                }
            }
            reader::Action::Refresh => {
                let next = load(config, identity, current.location.clone(), replica)?;
                Link {
                    network: &current.network,
                    author: &current.descriptor.author,
                    namespace: &current.descriptor.namespace,
                    page_id: &current.descriptor.page_id,
                }
                .matches(&next)?;
                current = next;
            }
            reader::Action::Open(index) => {
                let target = &document
                    .links
                    .get(index)
                    .context("link selection is invalid")?
                    .target;
                if !target.starts_with("hypernet://") {
                    // External references cannot fetch data, invoke a shell or launch a browser.
                    eprintln!(
                        "External reference (display only): {}",
                        crate::terminal_text(target, false)
                    );
                    return Ok(());
                }
                let link = Link::parse(target)?;
                let location = route(config, identity, &link, current.treaty.as_ref(), replica)?;
                let next = load(config, identity, location, replica)?;
                link.matches(&next)?;
                if history.len() == MAXIMUM_HISTORY {
                    history.pop_front();
                }
                history.push_back(current);
                current = next;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    fn treaty(id: u8) -> Treaty {
        let public = |seed| {
            hex::encode(
                SigningKey::from_bytes(&[seed; 32])
                    .verifying_key()
                    .as_bytes(),
            )
        };
        Treaty {
            version: 1,
            agreement_id: hex::encode([id; 16]),
            source_network: "01".repeat(32),
            destination_network: "02".repeat(32),
            source_authority_key: public(3),
            destination_authority_key: public(4),
            source_bridge_key: public(5),
            destination_bridge_key: public(6),
            source_namespace: "News".into(),
            destination_namespace: "Guests".into(),
            service: "Pages".into(),
            profile: "HyperNetPage/1".into(),
            expires: 200,
        }
    }
    fn record(treaty: &Treaty, active: bool) -> Value {
        json!({"treaty":treaty,"active":active,"digest":treaty.digest().unwrap()})
    }

    #[test]
    fn foreign_navigation_requires_current_explicit_unambiguous_scope() {
        let first = treaty(7);
        let second = treaty(8);
        let address = format!(
            "hypernet://{}/{}/News/{}",
            first.source_network,
            "09".repeat(32),
            "0a".repeat(16)
        );
        let link = Link::parse(&address).unwrap();
        let local = &first.destination_network;
        assert_eq!(
            agreement(local, &link, None, &[record(&first, true)], 100).unwrap(),
            first.agreement_id
        );
        let both = [record(&first, true), record(&second, true)];
        assert!(agreement(local, &link, None, &both, 100).is_err());
        assert_eq!(
            agreement(local, &link, Some(&first), &both, 100).unwrap(),
            first.agreement_id
        );
        assert!(
            agreement(
                local,
                &link,
                Some(&first),
                &[record(&first, false), record(&second, true)],
                100
            )
            .is_err()
        );
        assert!(agreement(local, &link, None, &[record(&first, true)], 200).is_err());
        assert!(agreement(&"0b".repeat(32), &link, None, &[record(&first, true)], 100).is_err());
        let mut changed = record(&first, true);
        changed["digest"] = json!("00".repeat(32));
        assert!(agreement(local, &link, None, &[changed], 100).is_err());
    }

    #[test]
    fn link_validation_preserves_all_origin_identity_components() {
        let target = format!(
            "hypernet://{}/{}/News/{}",
            "01".repeat(32),
            "03".repeat(32),
            "04".repeat(16)
        );
        let link = Link::parse(&target).unwrap();
        let descriptor: Descriptor = serde_json::from_value(json!({"pageId":"04".repeat(16),
            "publicationVersion":2,"revision":1,"author":"03".repeat(32),"reviewer":"05".repeat(32),
            "namespace":"News","audience":"Members","profile":"HyperNetPage/1","digest":"06".repeat(32),
            "submissionDigest":"07".repeat(32),"approvalDigest":"08".repeat(32)})).unwrap();
        let mut page = Page {
            location: Location::Native(link.page_id.into()),
            network: link.network.into(),
            descriptor,
            body: String::new(),
            metadata: Vec::new(),
            treaty: None,
        };
        assert!(link.matches(&page).is_ok());
        for field in ["network", "author", "namespace", "page"] {
            match field {
                "network" => page.network.push('0'),
                "author" => page.descriptor.author.push('0'),
                "namespace" => page.descriptor.namespace.push('X'),
                _ => page.descriptor.page_id.push('0'),
            }
            assert!(link.matches(&page).is_err());
            page.network = link.network.into();
            page.descriptor.author = link.author.into();
            page.descriptor.namespace = link.namespace.into();
            page.descriptor.page_id = link.page_id.into();
        }
        assert!(Link::parse(&format!("{target}/More")).is_err());
        assert!(Link::parse(&target.replace("/News/", "/../")).is_err());
    }
}
