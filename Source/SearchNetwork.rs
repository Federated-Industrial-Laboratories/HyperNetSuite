// SPDX-License-Identifier: MIT
// Search terms travel only to the final selected service; authority operations contain no query material.
use super::*;
use crate::{
    authority_domains::{
        self as domain,
        page::{self, Command as Action, content},
    },
    authority_inspection::page_media_client as media_client,
    authority_objects::Resolved,
    authority_pages::{Client, content_cli},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::fs::FileTypeExt,
};
#[path = "SearchImported.rs"]
pub(super) mod imported;

pub fn endpoint(path: &Path, local: bool, protocol: u64) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_socket() {
        ensure!(
            local,
            "network search requires an explicit relay profile; a local socket needs --local-diagnostics"
        );
        crate::private_route_client::require_local_allowed()?;
    } else {
        let selected = crate::private_route_client::Endpoint::load(path)?;
        ensure!(
            selected.route.protocol == protocol,
            "search route has another protocol"
        );
    }
    Ok(())
}
fn route_binding(
    route: Option<(&crate::route_profile::Profile, Digest)>,
    diagnostics: bool,
    network: Digest,
    incarnation: Digest,
    protocol: u64,
    service: Digest,
) -> Result<()> {
    if let Some((route, subject)) = route {
        ensure!(
            route.network == network
                && route.incarnation == incarnation
                && route.protocol == protocol
                && subject == service,
            "search route differs from the selected network, incarnation, protocol or certified service"
        );
    } else {
        ensure!(
            diagnostics,
            "local search transport requires --local-diagnostics"
        );
    }
    Ok(())
}
fn service_control(
    path: &Path,
    diagnostics: bool,
    network: Digest,
    incarnation: Digest,
    protocol: u64,
    service: Digest,
) -> Result<crate::authority_local_transport::LocalControl> {
    crate::authority_local_transport::LocalControl::open_checked(path, |endpoint| {
        let route = endpoint
            .map(|selected| -> Result<_> {
                Ok((
                    &selected.route,
                    crate::networks::route_subject(&selected.profile, &selected.route)?,
                ))
            })
            .transpose()?;
        route_binding(route, diagnostics, network, incarnation, protocol, service)
    })
}
fn disclosure(path: &Path, local: bool) -> Result<()> {
    if std::fs::symlink_metadata(path)?.file_type().is_socket() {
        ensure!(local, "network search requires a selected reader route");
    } else {
        let selected = crate::private_route_client::Endpoint::load(path)?;
        crate::networks::require_network_search(&selected.profile)?;
    }
    Ok(())
}
pub fn bridge_routes(values: &[String]) -> Result<BTreeMap<Digest, PathBuf>> {
    ensure!(
        values.len() <= 64,
        "too many explicitly selected import agreements"
    );
    let mut out = BTreeMap::new();
    for value in values {
        let (agreement, path) = value
            .split_once('=')
            .context("bridge requires agreement=route")?;
        ensure!(
            !path.is_empty() && out.insert(id(agreement)?, PathBuf::from(path)).is_none(),
            "duplicate or missing import route"
        );
    }
    Ok(out)
}
pub fn native(
    c: &mut Client,
    grant: &VersionRef,
    raw: [u8; 16],
    query: Option<&Request>,
    diagnostics: bool,
) -> Result<library::Entry> {
    let (result, _) = c
        .action(
            Action::Read { page: raw },
            Some(grant.clone()),
            Resolved::default(),
        )
        .context("native search PageRead authority failed")?;
    let n = result.prefix.scope().network;
    let i = result.prefix.scope().incarnation;
    let head = page::Ledger::parse(
        &result
            .cache
            .state
            .record(140, page::page_id(&raw)?)?
            .payload,
    )?;
    let published = head
        .published
        .context("native search publication is absent")?;
    let approval = result.cache.state.record(142, published.id)?;
    ensure!(
        approval.reference == published,
        "native search publication changed"
    );
    let review = page::Review::parse(&approval.payload, n, i)?;
    let revision_record = result
        .cache
        .state
        .record(141, review.statement.revision.id)?;
    ensure!(
        revision_record.reference == review.statement.revision,
        "native search revision changed"
    );
    let revision = page::Revision::parse(&revision_record.payload, n, i)?;
    let placement_ref = content_cli::selected_placement(&result.cache.state, &revision)?;
    let placement =
        content::Placement::parse(&result.cache.state.record(159, placement_ref.id)?.payload)?;
    c.action(
        Action::Content(content::Command::Get {
            placement: placement_ref.clone(),
        }),
        Some(grant.clone()),
        Resolved::default(),
    )
    .context("native search ContentGet authority failed")?;
    let (host, path) = content_cli::search_route(c, &placement, query.is_some())?;
    if let Some(query) = query {
        query.network_scope(n, i, page::namespace_id(&head.namespace)?)?;
    }
    let mut source = Vec::with_capacity(placement.bytes as usize);
    loop {
        let offset = source.len() as u64;
        let count = if query.is_some() {
            placement.bytes
        } else {
            (placement.bytes - offset).min(32768)
        };
        media_client::ensure(
            &c.bootstrap,
            &mut c.store,
            &c.socket,
            &c.key,
            &mut c.session,
            || c.clock.health(),
        )
        .context("native search stream preparation failed")?;
        let reconcile = media_client::pending(&c.store)?.is_some();
        let request = media_client::prepare(
            &c.bootstrap,
            &c.key,
            &mut c.store,
            Action::Content(content::Command::Authorise {
                placement: placement_ref.clone(),
                host: host.clone(),
                effect: if query.is_some() {
                    content::Effect::Search
                } else {
                    content::Effect::Read
                },
                offset,
                bytes: count,
                digest: None,
            }),
            grant.clone(),
            c.clock.health()?,
        )
        .context("native search content request preparation failed")?;
        let control = service_control(&path, diagnostics, n, i, 2, host.id)
            .context("native search content connection failed")?;
        let query_bytes = query.map(Request::encode).transpose()?.unwrap_or_default();
        let packet = media_client::packet(&request, &query_bytes, reconcile)?;
        let reply = control
            .exchange_limit(
                &packet,
                crate::authority_challenge::boot_time_ms()?
                    .checked_add(10000)
                    .context("search deadline overflow")?,
                page::MEDIA_RECEIPT_LIMIT,
            )
            .context("native search content exchange failed")?;
        // The receipt is complete; release the content route before opening authority status.
        drop(control);
        let chunk = media_client::complete(
            &c.bootstrap,
            &reply,
            &c.socket,
            &c.key,
            &mut c.store,
            &mut c.session,
            || c.clock.health(),
            |_, bytes| {
                let response = wire::decode(bytes)?;
                let f = response.array(11)?;
                if let Some(query) = query {
                    Ok(search_text::verify_response(query, f[9].bytes()?)?.0)
                } else {
                    Ok(f[9].bytes()?.to_vec())
                }
            },
        )
        .context("native search completion and stream status failed")?;
        ensure!(
            chunk.len() as u64 == count,
            "retained source extent differs"
        );
        source.extend_from_slice(&chunk);
        if source.len() as u64 == placement.bytes {
            break;
        }
    }
    revision.verify_source(&source)?;
    use sha2::{Digest as _, Sha256};
    ensure!(
        Digest::from(Sha256::digest(&source)) == placement.digest,
        "search source differs from exact placement"
    );
    let bundle =
        page::objects::Bundle::encode(&source, &revision.author.bytes, &review.statement.bytes)?;
    review
        .bundle
        .context("native approval has no bundle")?
        .verify(&bundle)?;
    Ok(library::Entry {
        id: page::page_id(&raw)?,
        namespace: head.namespace,
        grant: grant.clone(),
        publication: published,
        retained_at_ms: result.evaluated_at_ms,
        source: library::Source::Native {
            bundle,
            approval: approval.bytes.clone(),
        },
        lease: None,
    })
}
// Refresh only visible results and one continuation item, never the full candidate corpus.
fn refresh_selection(
    hits: &[local::Hit],
    request: &Request,
    binding: Digest,
) -> Result<BTreeSet<String>> {
    let (selected, next, _) = local::page(hits.to_vec(), request, binding)?;
    let mut ids = selected
        .into_iter()
        .map(|hit| hit.id)
        .collect::<BTreeSet<_>>();
    if let Some(next) = next {
        let mut following = request.clone();
        following.cursor = Some(id(&next)?);
        following.limit = 1;
        let (lookahead, _, _) = local::page(hits.to_vec(), &following, binding)?;
        ensure!(
            lookahead.len() == 1,
            "search continuation has no exact next item"
        );
        ids.extend(lookahead.into_iter().map(|hit| hit.id));
    }
    Ok(ids)
}
pub fn run(
    connection: Connection,
    capability: Capability,
    query: Query,
    bridges: Vec<String>,
) -> Result<()> {
    disclosure(&connection.socket, connection.local_diagnostics)?;
    ensure!(
        !query.namespaces.is_empty() || !bridges.is_empty(),
        "select at least one native namespace or imported agreement"
    );
    let (mut c, vault) = connection
        .open()
        .context("search requester connection failed")?;
    let grant = c.grant(capability)?;
    let request = query.request(&c.store, 1, false)?;
    let bridge_routes = bridge_routes(&bridges)?;
    let mut entries = BTreeMap::new();
    for namespace in &query.namespaces {
        let mut after = None;
        loop {
            let (result, _) = c
                .action(
                    Action::SearchList {
                        namespace: namespace.clone(),
                        after,
                    },
                    Some(grant.clone()),
                    Resolved::default(),
                )
                .context("native search catalogue authority failed")?;
            let response = result.value.array(5)?;
            let body = response[4].array(4)?;
            let mut pages = Vec::new();
            for bytes in body[1].list(page::MAXIMUM_CONTEXT_RECORDS)? {
                let r =
                    domain::Record::parse(bytes.bytes()?, request.network, request.incarnation)?;
                if r.reference.kind == 140 {
                    pages.push(page::Ledger::parse(&r.payload)?.raw_page);
                }
            }
            for raw in pages {
                let entry = native(
                    &mut c,
                    &grant,
                    raw,
                    Some(&request),
                    connection.local_diagnostics,
                )?;
                ensure!(
                    entries.insert(entry.id, entry).is_none(),
                    "native search catalogue repeats a Page"
                );
                ensure!(
                    entries.len() <= library::MAXIMUM_ITEMS,
                    "search corpus admission exceeded"
                );
            }
            let next = if body[3] == V::Null {
                None
            } else {
                Some(body[3].fixed::<32>()?)
            };
            ensure!(
                next.is_none_or(|v| after.is_none_or(|old| v > old)),
                "search catalogue cursor did not progress"
            );
            after = next;
            if after.is_none() {
                break;
            }
        }
    }
    for (agreement, route) in &bridge_routes {
        for entry in imported::search(
            &mut c,
            &grant,
            *agreement,
            route,
            &request,
            connection.local_diagnostics,
        )? {
            ensure!(
                entries.insert(entry.id, entry).is_none(),
                "import search repeats a qualified Page"
            );
            ensure!(
                entries.len() <= library::MAXIMUM_ITEMS,
                "search corpus admission exceeded"
            );
        }
    }
    let mut hits = Vec::new();
    let mut matched_entries = Vec::new();
    for entry in entries.values() {
        let view = source::open(
            entry,
            &c.bootstrap,
            c.store.requester(),
            vault.as_ref(),
            entry.retained_at_ms,
        )?;
        if let Some(matched) = search_text::matching(&request, &view.bytes)? {
            hits.push(local::hit(entry, view, matched));
            matched_entries.push(entry.clone());
        }
    }
    let binding = local::binding(&c.store, &request, 0, c.store.generations())?;
    let selected = refresh_selection(&hits, &request, binding)?;
    matched_entries.retain(|entry| selected.contains(&hex::encode(entry.id)));
    retain::refresh_leases(
        &mut c,
        &grant,
        &mut matched_entries,
        &bridge_routes,
        connection.local_diagnostics,
    )
    .context("cannot authorise the selected search page and continuation; lower --limit if the complete 64-reference proof budget is exceeded")?;
    for entry in &matched_entries {
        entry
            .lease
            .as_ref()
            .context("current search lease absent")?
            .current(&c.store, c.clock.health()?)?;
    }
    let binding = local::binding(&c.store, &request, 0, c.store.generations())?;
    let (results, next, _) = local::page(hits, &request, binding)?;
    let returned = results.len();
    crate::print_value(
        &json!({"status":"SearchResults","scope":"Network","queryLeavesDevice":true,"retainedView":"Current",
        "network":hex::encode(request.network),"height":c.store.prefix().height(),"results":results,"returned":returned,"nextCursor":next,
        "selectedScopes":{"namespaces":query.namespaces,"importAgreements":bridge_routes.keys().map(hex::encode).collect::<Vec<_>>()},
        "coverage":{"returned":returned,"continuationVerified":next.is_some(),"complete":false},
        "freshness":"Returned objects and any continuation item have current permission; whole-corpus counts and search completeness are not certified"}),
    )
}

#[cfg(test)]
#[path = "SearchNetworkTests.rs"]
mod tests;
