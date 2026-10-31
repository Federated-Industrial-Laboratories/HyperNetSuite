// SPDX-License-Identifier: MIT
// Retained views distinguish previously verified content from fresh authorised reads.
use super::*;
use crate::{markup, page_view, reader, viewer};
use std::collections::VecDeque;
#[derive(Clone)]
enum Location {
    Page([u8; 16]),
    Catalogue(String, Option<Digest>),
}
struct Entry {
    location: Location,
    publication: Option<publication::Publication>,
    document: markup::Document,
    metadata: Vec<String>,
    next: Option<Digest>,
    view: page_view::View,
}
impl Entry {
    fn mode(&self) -> reader::Mode {
        if self.publication.is_some() {
            reader::Mode::Page
        } else {
            reader::Mode::Catalogue
        }
    }
}
fn publication(c: &mut Client, grant: &VersionRef, page_id: [u8; 16]) -> Result<Entry> {
    let value = publication::fetch(c, grant, page_id)?;
    let bundle = &value.bundle;
    let document =
        markup::parse(std::str::from_utf8(&bundle.source)?).map_err(anyhow::Error::msg)?;
    let metadata = vec![
        format!(
            "hypernet://{}/{}/{}/{}",
            value.identity.network,
            hex::encode(bundle.author.intent.requester),
            bundle.author.namespace,
            value.identity.page
        ),
        "Approved at fetch; retained display. Refresh checks current authority.".into(),
        format!(
            "Network {} | namespace {} | Page {}",
            value.identity.network, bundle.author.namespace, value.identity.page
        ),
        format!(
            "Author {} | revision {}",
            hex::encode(bundle.author.intent.requester),
            bundle.author.intent.revision
        ),
        format!(
            "Reviewer {} | authority epoch {} height {}",
            hex::encode(bundle.review.intent.requester),
            c.store.descriptor().scope().epoch,
            value.height
        ),
    ];
    Ok(Entry {
        location: Location::Page(page_id),
        publication: Some(value),
        document,
        metadata,
        next: None,
        view: page_view::View::new(),
    })
}

fn catalogue(
    c: &mut Client,
    grant: &VersionRef,
    namespace: String,
    after: Option<Digest>,
) -> Result<Entry> {
    let (result, _) = c.action(
        Action::List {
            namespace: namespace.clone(),
            after,
        },
        Some(grant.clone()),
        Resolved::default(),
    )?;
    let value = result.value.array(5)?;
    let body = value[4].array(4)?;
    let scope = result.prefix.scope();
    let mut source = format!("{}\n# {}\n\nApproved Pages\n", markup::PROFILE, namespace);
    for bytes in body[1].list(page::MAXIMUM_CONTEXT_RECORDS)? {
        let record = domain::Record::parse(bytes.bytes()?, scope.network, scope.incarnation)?;
        if record.reference.kind != 140 {
            continue;
        }
        let head = page::Ledger::parse(&record.payload)?;
        ensure!(
            head.namespace == namespace && head.published.is_some(),
            "catalogue returned another namespace or unpublished Page"
        );
        source.push_str(&format!(
            "=> hypernet://{}/{}/{}/{} Page {}\n",
            hex::encode(scope.network),
            hex::encode(head.author),
            namespace,
            hex::encode(head.raw_page),
            hex::encode(head.raw_page)
        ));
    }
    let document = markup::parse(&source).map_err(anyhow::Error::msg)?;
    let next = if body[3] == V::Null {
        None
    } else {
        Some(body[3].fixed()?)
    };
    let view = page_view::View::new();
    #[cfg(feature = "gui")]
    let view = {
        let mut view = view;
        view.catalogue_next = next.is_some();
        view
    };
    Ok(Entry {
        location: Location::Catalogue(namespace, after),
        publication: None,
        document,
        metadata: catalogue_metadata(result.prefix.height(), next),
        next,
        view,
    })
}
fn catalogue_metadata(height: u64, next: Option<Digest>) -> Vec<String> {
    let mut metadata = vec![format!("Catalogue verified at authority height {height}")];
    if let Some(cursor) = next {
        metadata.push(format!(
            "Continue catalogue with --after {}",
            hex::encode(cursor)
        ));
    }
    metadata
}
fn same_publication(a: &publication::Identity, b: &publication::Identity) -> bool {
    // A new pending revision can change the ledger without changing the approved publication.
    a.network == b.network
        && a.incarnation == b.incarnation
        && a.page == b.page
        && a.revision == b.revision
        && a.approval == b.approval
        && a.bundle == b.bundle
}
fn refreshed_view(
    previous: Option<&publication::Identity>,
    next: Option<&publication::Identity>,
    view: &page_view::View,
) -> page_view::View {
    if previous
        .zip(next)
        .is_some_and(|(a, b)| same_publication(a, b))
    {
        view.clone()
    } else {
        page_view::View::new()
    }
}
fn install_entry(
    current: &mut Entry,
    history: &mut VecDeque<Entry>,
    mut entry: Entry,
    refresh: bool,
    preflight: impl FnOnce(&markup::Document, &page_view::View) -> Result<()>,
) -> Result<()> {
    if refresh {
        entry.view = refreshed_view(
            current.publication.as_ref().map(|p| &p.identity),
            entry.publication.as_ref().map(|p| &p.identity),
            &current.view,
        );
    }
    preflight(&entry.document, &entry.view)?;
    let previous = std::mem::replace(current, entry);
    if !refresh {
        // Sixteen maximum-size sources keep retained Page text below 256 KiB.
        if history.len() == 16 {
            history.pop_front();
        }
        history.push_back(previous);
    }
    Ok(())
}
fn previous_entry(
    current: &mut Entry,
    history: &mut VecDeque<Entry>,
    preflight: impl FnOnce(&markup::Document, &page_view::View) -> Result<()>,
) -> Result<bool> {
    let Some(entry) = history.back() else {
        return Ok(false);
    };
    preflight(&entry.document, &entry.view)?;
    *current = history.pop_back().unwrap();
    Ok(true)
}
fn load(c: &mut Client, grant: &VersionRef, location: Location) -> Result<Entry> {
    match location {
        Location::Page(page) => publication(c, grant, page),
        Location::Catalogue(namespace, after) => catalogue(c, grant, namespace, after),
    }
}
fn open(c: &mut Client, grant: &VersionRef, target: &str) -> Result<Entry> {
    ensure!(
        target.len() <= 512 && target.bytes().all(|b| (33..127).contains(&b)),
        "invalid Page address"
    );
    markup::parse(&format!(
        "{}\n# Address\n=> {target} Open\n",
        markup::PROFILE
    ))
    .map_err(anyhow::Error::msg)?;
    let address = target
        .strip_prefix("hypernet://")
        .context("external references are display only")?;
    let fields = address.split('/').collect::<Vec<_>>();
    ensure!(fields.len() == 4, "invalid Page address");
    ensure!(
        id(fields[0])? == c.bootstrap.descriptor().scope().network,
        "another network requires an explicitly authorised federation route"
    );
    let entry = publication(c, grant, raw(fields[3])?)?;
    let author = &entry.publication.as_ref().unwrap().bundle.author;
    ensure!(
        author.intent.requester == id(fields[1])? && author.namespace == fields[2],
        "Page link identity differs from the approved publication"
    );
    Ok(entry)
}
fn reveal(
    session: &viewer::Session,
    client: &mut Option<Client>,
    grant: &VersionRef,
    entry: &mut Entry,
    target: &str,
    options: &Display,
) -> Result<bool> {
    let asset = crate::media::image_asset(&entry.document, target)?;
    let mut path = None;
    for mapping in &options.media {
        let (id, value) = mapping
            .split_once('=')
            .context("--media requires AssetId=/explicit/path")?;
        if id == asset.id {
            ensure!(path.is_none(), "duplicate media mapping");
            path = Some(PathBuf::from(value));
        }
    }
    let pixels = if let Some(path) = path {
        let bytes = files::read_public_single(&path, markup::media::MAX_PAGE_BYTES as usize)?;
        crate::media_import::render_asset(&asset, &bytes)?
    } else {
        let publication = entry
            .publication
            .as_ref()
            .context("local previews require an explicit local media file")?;
        let expected = publication.identity.clone();
        let references = publication.assets.clone();
        let manifest = asset.clone();
        let g = grant.clone();
        let routes = options.interactions.clone();
        let Some(result) = interactions::request(session, client, move |c| {
            let bytes =
                interactions::media_bytes(c, &g, &expected, &references, &manifest, &routes)?;
            crate::media_import::render_asset(&manifest, &bytes)
        })?
        else {
            return Ok(false);
        };
        result?
    };
    session.install_image(&asset, pixels)?;
    entry.view.revealed.insert(asset.id);
    Ok(true)
}
fn view(
    session: viewer::Session,
    c: Client,
    grant: VersionRef,
    mut current: Entry,
    online: Online,
    options: Display,
) -> Result<()> {
    let mut client = Some(c);
    let mut history = VecDeque::<Entry>::new();
    let mut status = String::new();
    loop {
        let mode = current.mode();
        let action = session.show(
            &current.document,
            &current.metadata,
            &mut current.view,
            &status,
            mode,
        )?;
        let mut exit = false;
        let next = (|| -> Result<Option<Entry>> {
            let g = grant.clone();
            let location = match &action {
                reader::Action::Quit => {
                    exit = true;
                    return Ok(None);
                }
                reader::Action::Refresh => Some(current.location.clone()),
                reader::Action::Catalogue => Some(Location::Catalogue(
                    current
                        .publication
                        .as_ref()
                        .map(|p| p.bundle.author.namespace.clone())
                        .or_else(|| match &current.location {
                            Location::Catalogue(n, _) => Some(n.clone()),
                            _ => None,
                        })
                        .context("catalogue namespace absent")?,
                    None,
                )),
                reader::Action::Next => {
                    let Location::Catalogue(ref namespace, _) = current.location else {
                        anyhow::bail!("no catalogue continuation on this Page")
                    };
                    Some(Location::Catalogue(
                        namespace.clone(),
                        Some(current.next.context("end of catalogue")?),
                    ))
                }
                reader::Action::Open(index) => {
                    let target = current
                        .document
                        .links
                        .get(*index)
                        .context("link is absent")?
                        .target
                        .clone();
                    return match interactions::request(&session, &mut client, move |c| {
                        open(c, &g, &target)
                    })? {
                        Some(result) => result.map(Some),
                        None => {
                            exit = true;
                            Ok(None)
                        }
                    };
                }
                reader::Action::Address(target) => {
                    let target = target.clone();
                    return match interactions::request(&session, &mut client, move |c| {
                        open(c, &g, &target)
                    })? {
                        Some(result) => result.map(Some),
                        None => {
                            exit = true;
                            Ok(None)
                        }
                    };
                }
                reader::Action::Back | reader::Action::Previous => None,
                reader::Action::Reveal(target) => {
                    if !reveal(
                        &session,
                        &mut client,
                        &grant,
                        &mut current,
                        target,
                        &options,
                    )? {
                        exit = true;
                    } else {
                        status = "Verified media revealed".into();
                    }
                    None
                }
                reader::Action::Submit(form) => {
                    let publication = current
                        .publication
                        .as_ref()
                        .context("form has no certified publication")?
                        .identity
                        .clone();
                    let values = current
                        .view
                        .form_values
                        .get(form)
                        .cloned()
                        .unwrap_or_default();
                    match interactions::submit(
                        &session,
                        &mut client,
                        &grant,
                        &online,
                        &options.interactions,
                        publication,
                        form.clone(),
                        values,
                    )? {
                        Some(result) => status = reader::bounded_status(&result),
                        None => exit = true,
                    }
                    None
                }
            };
            if let Some(location) = location {
                return match interactions::request(&session, &mut client, move |c| {
                    load(c, &g, location)
                })? {
                    Some(result) => result.map(Some),
                    None => {
                        exit = true;
                        Ok(None)
                    }
                };
            }
            Ok(None)
        })();
        if exit || client.is_none() {
            return Ok(());
        }
        match next {
            Err(error) => {
                status = reader::bounded_status(&format!("Could not complete action: {error:#}"))
            }
            Ok(Some(entry)) => {
                match install_entry(
                    &mut current,
                    &mut history,
                    entry,
                    matches!(action, reader::Action::Refresh),
                    |document, view| session.preflight(document, view),
                ) {
                    Ok(()) => status.clear(),
                    Err(error) => {
                        status =
                            reader::bounded_status(&format!("Could not display Page: {error:#}"))
                    }
                }
            }
            Ok(None) => {
                if matches!(action, reader::Action::Back | reader::Action::Previous) {
                    status = match previous_entry(&mut current, &mut history, |document, view| {
                        session.preflight(document, view)
                    }) {
                        Ok(true) => "Retained display; refresh to check current authority".into(),
                        Ok(false) => "No retained history".into(),
                        Err(error) => reader::bounded_status(&format!(
                            "Could not display retained Page: {error:#}"
                        )),
                    }
                }
            }
        }
    }
}
pub(super) fn read(
    online: Online,
    capability: Capability,
    page_id: String,
    output: Option<PathBuf>,
    options: Display,
) -> Result<()> {
    viewer::run(options.gui, options.tui, options.ascii, move |session| {
        options.interactions.check()?;
        session.configure_graphics(&options.graphics)?;
        let Some((c, grant, current, online)) = session.request(move || {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let current = publication(&mut c, &grant, raw(&page_id)?)?;
            Ok((c, grant, current, online))
        })?
        else {
            return Ok(());
        };
        if let Some(path) = output {
            files::write_new(&path, &current.publication.as_ref().unwrap().bundle.bytes)?;
        }
        view(session, c, grant, current, online, options)
    })
}
pub fn browse(args: Browse) -> Result<()> {
    let mut options = args.display;
    options.tui = !options.gui;
    viewer::run(options.gui, options.tui, options.ascii, move |session| {
        options.interactions.check()?;
        session.configure_graphics(&options.graphics)?;
        let Some((c, grant, current, online)) = session.request(move || {
            let mut c = Client::new(&args.online)?;
            let grant = c.grant(args.capability)?;
            let current = if let Some(uri) = args.uri {
                open(&mut c, &grant, &uri)?
            } else {
                catalogue(
                    &mut c,
                    &grant,
                    args.namespace
                        .context("--namespace is required without a Page address")?,
                    args.after.as_deref().map(id).transpose()?,
                )?
            };
            Ok((c, grant, current, args.online))
        })?
        else {
            return Ok(());
        };
        view(session, c, grant, current, online, options)
    })
}

#[cfg(test)]
#[path = "../../Tests/Unit/Pages/AuthorityPageNavigationTests.rs"]
mod tests;
