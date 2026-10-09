// SPDX-License-Identifier: MIT
// One bounded retained-display history for native and explicitly federated pages.
use crate::{
    Config, Identity, federation, federation_proof::Treaty, markup, page_proof::Descriptor,
    page_view::View, pages, protocol, reader,
};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{collections::VecDeque, path::Path};

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
            let mut metadata = vec![
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
            metadata.push(format!("Address {}", uri(&config.network, &descriptor)));
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
            let mut metadata = vec![
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
            metadata.push(format!(
                "Address {}",
                uri(&publication.treaty.source_network, &publication.descriptor)
            ));
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

struct Catalogue {
    namespace: Option<String>,
    after: Option<String>,
    next: Option<String>,
    metadata: Vec<String>,
}

enum Content {
    Page(Box<Page>),
    Catalogue(Catalogue),
}
struct Entry {
    content: Content,
    document: markup::Document,
    view: View,
}
impl Entry {
    fn page(page: Page) -> Result<Self> {
        let document = markup::parse(&page.body).map_err(anyhow::Error::msg)?;
        Ok(Self {
            content: Content::Page(Box::new(page)),
            document,
            view: View::new(),
        })
    }
    fn catalogue(
        network: &str,
        namespace: Option<String>,
        after: Option<String>,
        result: pages::Catalogue,
    ) -> Self {
        let mut document = markup::Document {
            title: "Catalogue".into(),
            lines: Vec::new(),
            links: Vec::new(),
            nodes: Vec::new(),
            forms: Vec::new(),
            assets: Vec::new(),
        };
        for (key, descriptor) in result.entries.iter().enumerate() {
            let target = uri(network, descriptor);
            let label = format!(
                "{} | page {} | author {} | publication {}",
                descriptor.namespace,
                descriptor.page_id,
                descriptor.author,
                descriptor.publication_version
            );
            document.lines.push(format!("{} -> {}", label, target));
            document.links.push(markup::Link {
                target,
                label: label.clone(),
            });
            document.nodes.push(markup::Node {
                key,
                id: None,
                style: markup::Style::default(),
                motion: None,
                kind: markup::Kind::Button {
                    label,
                    action: markup::PageAction::Navigate { link: key },
                },
                children: Vec::new(),
            });
        }
        if result.entries.is_empty() {
            document
                .lines
                .push("No publications in this catalogue batch.".into());
            document.nodes.push(markup::Node {
                key: 0,
                id: None,
                style: markup::Style::default(),
                motion: None,
                kind: markup::Kind::Text {
                    text: document.lines[0].clone(),
                    kind: markup::TextKind::Paragraph,
                },
                children: Vec::new(),
            });
        }
        let metadata = vec![
            "Trusted catalogue; publication descriptors at fetch. Titles require a verified page read.".into(),
            format!("Network {network} | namespace {} | authority revision {}", namespace.as_deref().unwrap_or("All"), result.revision),
            format!("Starting cursor {} | entries {} | next {}", after.as_deref().unwrap_or("Beginning"), result.entries.len(), result.next.as_deref().unwrap_or("End")),
        ];
        let metadata = if result.revision == 0 {
            document.lines[0] = "No verified catalogue available.".into();
            if let markup::Kind::Text { text, .. } = &mut document.nodes[0].kind {
                *text = document.lines[0].clone();
            }
            vec![
                "No catalogue has been fetched or verified.".into(),
                format!("Configured network {network}"),
            ]
        } else {
            metadata
        };
        let mut view = View::new();
        if !result.entries.is_empty() {
            view.focused = Some(0);
        }
        Self {
            content: Content::Catalogue(Catalogue {
                namespace,
                after,
                next: result.next,
                metadata,
            }),
            document,
            view,
        }
    }
    fn metadata(&self) -> &[String] {
        match &self.content {
            Content::Page(page) => &page.metadata,
            Content::Catalogue(catalogue) => &catalogue.metadata,
        }
    }
    fn mode(&self) -> reader::Mode {
        match &self.content {
            Content::Page(page) if matches!(page.location, Location::Federated { .. }) => {
                reader::Mode::Foreign
            }
            Content::Page(_) => reader::Mode::Page,
            Content::Catalogue(_) => reader::Mode::Catalogue,
        }
    }
    fn treaty(&self) -> Option<&Treaty> {
        match &self.content {
            Content::Page(page) => page.treaty.as_ref(),
            _ => None,
        }
    }
    fn same_publication(&self, other: &Self) -> bool {
        matches!((&self.content, &other.content), (Content::Page(left), Content::Page(right))
            if left.network == right.network && left.descriptor == right.descriptor && left.body == right.body)
    }
}

fn uri(network: &str, descriptor: &Descriptor) -> String {
    format!(
        "hypernet://{}/{}/{}/{}",
        network, descriptor.author, descriptor.namespace, descriptor.page_id
    )
}

fn address(target: &str) -> Result<bool> {
    ensure!(
        target.len() <= 512
            && !target.is_empty()
            && target.bytes().all(|byte| (33..127).contains(&byte)),
        "address must contain 1 to 512 visible ASCII characters"
    );
    // Use the same canonical target grammar for entered addresses and document links.
    markup::parse(&format!(
        "{}\n# Address\n=> {target} Open\n",
        markup::PROFILE
    ))
    .map_err(|_| anyhow::anyhow!("invalid address; use a canonical hypernet:// or https:// URI"))?;
    Ok(target.starts_with("hypernet://"))
}

fn open(
    config: &Config,
    identity: &Identity,
    target: &str,
    treaty: Option<&Treaty>,
    replica: Option<&str>,
) -> Result<Entry> {
    ensure!(address(target)?, "external references are display only");
    let link = Link::parse(target)?;
    let location = route(config, identity, &link, treaty, replica)?;
    let page = load(config, identity, location, replica)?;
    link.matches(&page)?;
    Entry::page(page)
}

fn catalogue(
    config: &Config,
    identity: &Identity,
    namespace: Option<String>,
    after: Option<String>,
) -> Result<Entry> {
    let result = pages::catalogue(config, identity, namespace.as_deref(), after.as_deref())?;
    Ok(Entry::catalogue(&config.network, namespace, after, result))
}

fn request<F>(
    session: &reader::Session,
    config: &Config,
    identity: &Identity,
    operation: F,
) -> Result<Option<Entry>>
where
    F: FnOnce(&Config, &Identity) -> Result<Entry> + Send + 'static,
{
    let config = config.clone();
    let identity = identity.clone();
    session.request(move || operation(&config, &identity))
}

struct Browser {
    current: Entry,
    history: VecDeque<Entry>,
    status: String,
}
impl Browser {
    fn replace(
        &mut self,
        mut next: Entry,
        refresh: bool,
        preflight: impl FnOnce(&markup::Document, &View) -> Result<()>,
    ) -> Result<()> {
        let retained = refresh && self.current.same_publication(&next);
        preflight(
            &next.document,
            if retained {
                &self.current.view
            } else {
                &next.view
            },
        )?;
        if refresh {
            if retained {
                std::mem::swap(&mut self.current.view, &mut next.view);
            }
            self.current = next;
        } else {
            if self.history.len() == MAXIMUM_HISTORY {
                self.history.pop_front();
            }
            self.history
                .push_back(std::mem::replace(&mut self.current, next));
        }
        Ok(())
    }
    fn back(&mut self) {
        if let Some(previous) = self.history.pop_back() {
            self.current = previous;
            self.status = "Retained view restored; authority was not refreshed".into();
        } else {
            self.status = "No earlier retained view".into();
        }
    }
    fn previous_catalogue(&mut self) {
        let Content::Catalogue(current) = &self.current.content else {
            return;
        };
        let index = self.history.iter().rposition(|entry| {
            matches!(&entry.content,
            Content::Catalogue(previous) if previous.namespace == current.namespace
                && previous.next.is_some() && previous.next == current.after)
        });
        if let Some(index) = index {
            self.current = self.history.remove(index).unwrap();
            self.history.truncate(index);
            self.status = "Retained view restored; authority was not refreshed".into();
        } else {
            self.status = "No previous catalogue batch retained".into();
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    config_path: Option<&Path>,
    target: Option<String>,
    namespace: Option<String>,
    after: Option<String>,
    ascii: bool,
    forms: crate::form_ui::Options,
    graphics: crate::terminal_graphics::Options,
) -> Result<()> {
    let config: Config = serde_json::from_slice(&crate::files::read_bounded(
        config_path.context("--config is required")?,
        false,
    )?)?;
    let identity = crate::load_identity(&config.identity)?;
    if let Some(value) = &namespace {
        ensure!(markup::namespace(value), "invalid namespace");
    }
    if let Some(value) = &after {
        protocol::hex_bytes::<16>(value)?;
    }
    ensure!(
        target.is_none() || after.is_none(),
        "--after cannot be combined with a page address"
    );
    ensure!(
        !config.application || namespace.is_some(),
        "application browser requires --namespace"
    );
    let forms = forms.context(&config)?;
    session(
        &config, &identity, None, target, namespace, after, None, true, ascii, forms, graphics,
    )
}

pub fn browse_graphics(
    config: &Config,
    identity: &Identity,
    first: Location,
    replica: Option<&str>,
    tui: bool,
    ascii: bool,
    graphics: crate::terminal_graphics::Options,
) -> Result<()> {
    session(
        config,
        identity,
        Some(first),
        None,
        None,
        None,
        replica,
        tui,
        ascii,
        None,
        graphics,
    )
}

#[allow(clippy::too_many_arguments)]
fn session(
    config: &Config,
    identity: &Identity,
    first: Option<Location>,
    target: Option<String>,
    namespace: Option<String>,
    after: Option<String>,
    replica: Option<&str>,
    tui: bool,
    ascii: bool,
    forms: Option<crate::form_ui::Context>,
    graphics: crate::terminal_graphics::Options,
) -> Result<()> {
    let session = reader::Session::new(tui, ascii)?;
    session.configure_graphics(&graphics)?;
    let placeholder = Entry::catalogue(
        &config.network,
        namespace.clone(),
        after.clone(),
        pages::Catalogue {
            entries: Vec::new(),
            next: None,
            revision: 0,
        },
    );
    let mut browser = Browser {
        current: placeholder,
        history: VecDeque::new(),
        status: String::new(),
    };
    let replica = replica.map(str::to_owned);
    let initial = if let Some(location) = first {
        let replica = replica.clone();
        request(&session, config, identity, move |config, identity| {
            Entry::page(load(config, identity, location, replica.as_deref())?)
        })
    } else if let Some(target) = target {
        if !address(&target)? {
            browser.status = format!("External reference (display only): {target}");
            Ok(Some(Entry::catalogue(
                &config.network,
                namespace.clone(),
                after.clone(),
                pages::Catalogue {
                    entries: Vec::new(),
                    next: None,
                    revision: 0,
                },
            )))
        } else {
            let replica = replica.clone();
            request(&session, config, identity, move |config, identity| {
                open(config, identity, &target, None, replica.as_deref())
            })
        }
    } else {
        let namespace = namespace.clone();
        request(&session, config, identity, move |config, identity| {
            catalogue(config, identity, namespace, after)
        })
    };
    let initial = initial.and_then(|entry| {
        entry
            .map(|entry| {
                session.preflight(&entry.document, &entry.view)?;
                Ok(entry)
            })
            .transpose()
    });
    match initial {
        Ok(Some(entry)) => browser.current = entry,
        Ok(None) => return Ok(()),
        Err(error) if !session.interactive() => return Err(error),
        Err(error) => {
            // The first failed request has no verified body to retain.
            browser.current = Entry::catalogue(
                &config.network,
                namespace.clone(),
                None,
                pages::Catalogue {
                    entries: Vec::new(),
                    next: None,
                    revision: 0,
                },
            );
            browser.status = reader::bounded_status(&format!("Could not open: {error:#}"));
        }
    }
    if browser.status.is_empty() {
        browser.status = if matches!(browser.current.content, Content::Page(_)) {
            "Page opened"
        } else {
            "Catalogue loaded"
        }
        .into();
    }
    loop {
        let metadata = browser.current.metadata().to_vec();
        let mode = browser.current.mode();
        let action = session.show(
            &browser.current.document,
            &metadata,
            &mut browser.current.view,
            &browser.status,
            mode,
        )?;
        let mut refresh = false;
        let success;
        let failure;
        let response = match action {
            reader::Action::Quit => return Ok(()),
            reader::Action::Reveal(target) => {
                let Content::Page(page) = &browser.current.content else {
                    continue;
                };
                let asset = crate::media::image_asset(&browser.current.document, &target)?;
                let location = page.location.clone();
                let expected = page.descriptor.clone();
                let config = config.clone();
                let identity = identity.clone();
                let selected = asset.clone();
                let fetched = session.request(move || {
                    let reference = match location {
                        Location::Native(id) => crate::media::read_reference(
                            &config,
                            &identity,
                            &id,
                            &selected.id,
                            Some(&expected),
                        )?,
                        Location::Federated { agreement, page_id } => {
                            crate::media::federated_reference(
                                &config,
                                &identity,
                                &agreement,
                                &page_id,
                                &selected.id,
                                Some(&expected),
                            )?
                        }
                    };
                    let bytes = crate::media::fetch(&config, &identity, &reference, None, false)?;
                    crate::media_import::render_asset(&selected, &bytes)
                });
                match fetched {
                    Ok(None) => return Ok(()),
                    Ok(Some(pixels)) => match session.install_image(&asset, pixels) {
                        Ok(()) => {
                            browser.current.view.revealed.insert(asset.id);
                            browser.status = "Verified media revealed; terminal support may require alt fallback".into();
                        }
                        Err(error) => {
                            browser.status = reader::bounded_status(&format!(
                                "Could not display media: {error:#}"
                            ))
                        }
                    },
                    Err(error) => {
                        browser.status =
                            reader::bounded_status(&format!("Could not reveal media: {error:#}"))
                    }
                }
                continue;
            }
            reader::Action::Submit(form) => {
                let Some(context) = &forms else {
                    browser.status = "Form sending needs browse --vault, --key and --mailbox; use --mail-config for separate mail credentials".into();
                    continue;
                };
                let Content::Page(page) = &browser.current.content else {
                    continue;
                };
                if !matches!(page.location, Location::Native(_)) || page.network != config.network {
                    browser.status = "Foreign forms cannot send through this network".into();
                    continue;
                }
                let expected = page.descriptor.clone();
                let values = browser
                    .current
                    .view
                    .form_values
                    .get(&form)
                    .cloned()
                    .unwrap_or_default();
                let mail = context.clone();
                let read_config = config.clone();
                let prepared = session.request(move || {
                    crate::forms::prepare(
                        &mail.config,
                        &read_config,
                        &mail.settings,
                        &expected,
                        &form,
                        values,
                        None,
                    )
                });
                let review = match prepared {
                    Ok(Some(review)) => review,
                    Ok(None) => return Ok(()),
                    Err(error) => {
                        browser.status =
                            reader::bounded_status(&format!("Could not prepare form: {error:#}"));
                        continue;
                    }
                };
                match session.confirm_form(&review)? {
                    None => return Ok(()),
                    Some(false) => {
                        match crate::forms::discard(
                            &context.config,
                            &context.settings,
                            &review.review_id,
                        ) {
                            Ok(()) => {
                                browser.status = "Form review cancelled; no submission sent".into()
                            }
                            Err(error) => {
                                browser.status = reader::bounded_status(&format!(
                                    "No submission sent; review cleanup failed: {error:#}"
                                ))
                            }
                        }
                    }
                    Some(true) => {
                        let mail = context.clone();
                        let read_config = config.clone();
                        let id = review.review_id.clone();
                        match session.request(move || {
                            crate::forms::confirm(&mail.config, &read_config, &mail.settings, &id)
                        }) {
                            Ok(None) => return Ok(()),
                            Ok(Some(result)) => {
                                browser.status = reader::bounded_status(&format!(
                                    "Form submission {}: {}",
                                    review.submission_id, result
                                ))
                            }
                            Err(error) => {
                                browser.status = reader::bounded_status(&format!(
                                    "Form {} delivery not confirmed: {error:#}; inspect the outbox before retry",
                                    review.submission_id
                                ))
                            }
                        }
                    }
                }
                continue;
            }
            reader::Action::Back => {
                browser.back();
                continue;
            }
            reader::Action::Previous => {
                browser.previous_catalogue();
                continue;
            }
            reader::Action::Catalogue | reader::Action::Next => {
                let (scope, cursor) = if matches!(action, reader::Action::Next) {
                    let Content::Catalogue(current) = &browser.current.content else {
                        continue;
                    };
                    let Some(next) = &current.next else {
                        browser.status = "End of catalogue".into();
                        continue;
                    };
                    (current.namespace.clone(), Some(next.clone()))
                } else {
                    (namespace.clone(), None)
                };
                success = "Catalogue loaded";
                failure = "Could not load catalogue";
                request(&session, config, identity, move |config, identity| {
                    catalogue(config, identity, scope, cursor)
                })
            }
            reader::Action::Refresh => {
                refresh = true;
                failure = "Could not refresh";
                match &browser.current.content {
                    Content::Page(page) => {
                        success = "Page refreshed";
                        let location = page.location.clone();
                        let expected = uri(&page.network, &page.descriptor);
                        let replica = replica.clone();
                        request(&session, config, identity, move |config, identity| {
                            let next = load(config, identity, location, replica.as_deref())?;
                            Link::parse(&expected)?.matches(&next)?;
                            Entry::page(next)
                        })
                    }
                    Content::Catalogue(current) => {
                        success = "Catalogue loaded";
                        let scope = current.namespace.clone();
                        let cursor = current.after.clone();
                        request(&session, config, identity, move |config, identity| {
                            catalogue(config, identity, scope, cursor)
                        })
                    }
                }
            }
            reader::Action::Address(target) => {
                match address(&target) {
                    Ok(false) => {
                        browser.status = format!("External reference (display only): {target}");
                        continue;
                    }
                    Err(error) => {
                        browser.status =
                            reader::bounded_status(&format!("Could not open: {error:#}"));
                        continue;
                    }
                    Ok(true) => {}
                }
                success = "Page opened";
                failure = "Could not open";
                let treaty = browser.current.treaty().cloned();
                let replica = replica.clone();
                request(&session, config, identity, move |config, identity| {
                    open(
                        config,
                        identity,
                        &target,
                        treaty.as_ref(),
                        replica.as_deref(),
                    )
                })
            }
            reader::Action::Open(index) => {
                let target = browser
                    .current
                    .document
                    .links
                    .get(index)
                    .context("invalid navigation selection")?
                    .target
                    .clone();
                if !address(&target)? {
                    browser.status = format!("External reference (display only): {target}");
                    continue;
                }
                success = "Page opened";
                failure = "Could not open";
                let treaty = browser.current.treaty().cloned();
                let replica = replica.clone();
                request(&session, config, identity, move |config, identity| {
                    open(
                        config,
                        identity,
                        &target,
                        treaty.as_ref(),
                        replica.as_deref(),
                    )
                })
            }
        };
        match response {
            Ok(None) => return Ok(()),
            Ok(Some(next)) => match browser.replace(next, refresh, |document, view| {
                session.preflight(document, view)
            }) {
                Ok(()) => browser.status = success.into(),
                Err(error) => {
                    browser.status = reader::bounded_status(&format!("{failure}: {error:#}"))
                }
            },
            Err(error) => browser.status = reader::bounded_status(&format!("{failure}: {error:#}")),
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
            version: 2,
            media_profiles: Vec::new(),
            media_source_hosts: Vec::new(),
            media_destination_hosts: Vec::new(),
            media_max_bytes: 0,
            media_required_copies: 0,
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
            profile: "HyperNetPage/2".into(),
            expires: 200,
        }
    }
    fn record(treaty: &Treaty, active: bool) -> Value {
        json!({"treaty":treaty,"active":active,"digest":treaty.digest().unwrap()})
    }

    fn retained_page(version: u64, body: &str) -> Entry {
        Entry::page(Page {
            location: Location::Native("04".repeat(16)), network: "01".repeat(32),
            descriptor: serde_json::from_value(json!({"pageId":"04".repeat(16),
                "publicationVersion":version,"revision":1,"author":"03".repeat(32),"reviewer":"05".repeat(32),
                "namespace":"News","audience":"Members","profile":markup::PROFILE,"digest":"06".repeat(32),
                "submissionDigest":"07".repeat(32),"approvalDigest":"08".repeat(32)})).unwrap(),
            body: body.into(), metadata: Vec::new(), treaty: None,
        }).unwrap()
    }
    fn preflight(document: &markup::Document, view: &View) -> Result<()> {
        reader::preflight_at(document, view, (80, 24), false)
    }
    #[test]
    fn layout_refusal_preserves_current_publication_and_history() {
        let body = "HyperNetPage/2\n# Retained\n: Current verified view\n";
        let large = format!(
            "HyperNetPage/2\n# Budget\n{}",
            "@Spacer {\"rows\":8}\n".repeat(250)
        );
        let mut browser = Browser {
            current: retained_page(2, body),
            history: VecDeque::from([retained_page(2, body)]),
            status: String::new(),
        };
        browser.current.view.offset = 9;
        browser.current.view.focused = Some(4);
        for refresh in [false, true] {
            assert!(
                browser
                    .replace(retained_page(3, &large), refresh, |document, view| {
                        reader::preflight_at(document, view, (300, 24), false)
                    })
                    .is_err()
            );
            assert_eq!(browser.current.document.title, "Retained");
            assert_eq!(browser.current.view.offset, 9);
            assert_eq!(browser.current.view.focused, Some(4));
            assert_eq!(browser.history.len(), 1);
        }
        browser
            .replace(retained_page(3, &large), false, |document, view| {
                reader::preflight_at(document, view, (40, 24), false)
            })
            .unwrap();
        assert_eq!(browser.current.document.title, "Budget");
        assert_eq!(browser.history.len(), 2);
        browser.back();
        assert_eq!(browser.current.document.title, "Retained");
        assert_eq!(browser.current.view.offset, 9);
    }
    #[test]
    fn history_retains_view_and_refresh_cannot_transfer_it_to_changed_content() {
        let body = "HyperNetPage/2\n# Retained\n: Content\n";
        let mut current = retained_page(2, body);
        current.view.offset = 9;
        current.view.focused = Some(4);
        current.view.scrolls.insert(3, 7);
        current.view.details = true;
        current.view.details_offset = 6;
        let mut browser = Browser {
            current,
            history: VecDeque::new(),
            status: String::new(),
        };
        browser
            .replace(retained_page(2, body), true, preflight)
            .unwrap();
        assert_eq!(browser.current.view.offset, 9);
        assert_eq!(browser.current.view.scrolls[&3], 7);
        assert_eq!(browser.current.view.focused, Some(4));
        assert!(browser.current.view.details);
        browser
            .replace(retained_page(2, body), false, preflight)
            .unwrap();
        browser.back();
        assert_eq!(browser.current.view.offset, 9);
        assert_eq!(browser.current.view.details_offset, 6);
        browser
            .replace(retained_page(3, body), true, preflight)
            .unwrap();
        assert_eq!(browser.current.view.offset, 0);
        assert!(browser.current.view.scrolls.is_empty());
        assert!(browser.current.view.focused.is_none());
        browser.current.view.offset = 4;
        browser
            .replace(
                retained_page(3, "HyperNetPage/2\n# Changed\n: Changed bytes\n"),
                true,
                preflight,
            )
            .unwrap();
        assert_eq!(browser.current.view.offset, 0);
        for _ in 0..20 {
            browser
                .replace(retained_page(3, body), false, preflight)
                .unwrap();
        }
        assert_eq!(browser.history.len(), MAXIMUM_HISTORY);
    }
    #[test]
    fn catalogue_back_is_retained_and_cursor_scoped() {
        let make = |after: Option<&str>, next: Option<&str>| {
            Entry::catalogue(
                &"01".repeat(32),
                Some("News".into()),
                after.map(str::to_owned),
                pages::Catalogue {
                    entries: Vec::new(),
                    next: next.map(str::to_owned),
                    revision: 1,
                },
            )
        };
        let mut browser = Browser {
            current: make(None, Some("a")),
            history: VecDeque::new(),
            status: String::new(),
        };
        browser.current.view.offset = 7;
        browser
            .replace(make(Some("a"), None), false, preflight)
            .unwrap();
        browser.previous_catalogue();
        assert_eq!(browser.current.view.offset, 7);
        assert!(browser.history.is_empty());
        browser.previous_catalogue();
        assert_eq!(browser.status, "No previous catalogue batch retained");
    }
    #[test]
    fn entered_addresses_share_canonical_link_policy() {
        let internal = format!(
            "hypernet://{}/{}/News/{}",
            "01".repeat(32),
            "03".repeat(32),
            "04".repeat(16)
        );
        assert!(address(&internal).unwrap());
        assert!(!address("https://example.test/").unwrap());
        for invalid in [
            "",
            "http://example.test/",
            "https://user:pass@example.test/",
            "https://EXAMPLE.test/",
            "https://example.test",
            "https://example.test/ label\n: Injection",
            "file:///tmp/Test",
            "ssh://host/",
            "https://example.test/\x1b",
        ] {
            assert!(address(invalid).is_err(), "{invalid}");
        }
        assert!(address(&format!("{internal}/More")).is_err());
        assert!(address(&format!("https://example.test/{}", "a".repeat(512))).is_err());
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
            "namespace":"News","audience":"Members","profile":"HyperNetPage/2","digest":"06".repeat(32),
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
