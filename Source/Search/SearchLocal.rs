// SPDX-License-Identifier: MIT
// Local search never creates a connector; expired leases expose neither titles nor snippets.
use super::*;
use serde::Serialize;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Hit {
    pub id: String,
    pub namespace: String,
    #[serde(flatten)]
    pub matched: search_text::Match,
    pub uri: Option<String>,
    pub provenance: serde_json::Value,
}
pub fn hit(entry: &library::Entry, view: source::SourceView, matched: search_text::Match) -> Hit {
    Hit {
        id: hex::encode(entry.id),
        namespace: entry.namespace.clone(),
        matched,
        uri: view.uri,
        provenance: view.provenance,
    }
}
pub fn binding(
    store: &Store,
    request: &Request,
    generation: u64,
    extent: &[VersionRef],
) -> Result<Digest> {
    let mut query = request.clone();
    query.operation = [1; 32];
    query.cursor = None;
    // Foreign proof observations advance during each fresh bilateral read. Publication,
    // agreement, trust and capability versions remain part of the cursor binding.
    let references = extent
        .iter()
        .filter(|reference| request.scope != 1 || reference.kind != 157)
        .map(crate::authority_membership::reference)
        .collect();
    let generation_state = wire::digest(&wire::encode(&V::Array(vec![
        V::Uint(generation),
        V::Array(references),
        V::Bytes(store.requester().to_vec()),
        V::Bytes(store.descriptor().scope().configuration.to_vec()),
    ]))?);
    // Stream bookkeeping is not an index generation; exact policy/publication versions are.
    query.snapshot = V::Array(vec![
        V::Array(vec![
            V::Uint(store.prefix().scope().epoch),
            V::Uint(0),
            V::Bytes(generation_state.to_vec()),
        ]),
        V::Array(vec![]),
    ]);
    query.digest()
}
pub fn page(
    mut hits: Vec<Hit>,
    request: &Request,
    binding: Digest,
) -> Result<(Vec<Hit>, Option<String>, usize)> {
    hits.sort_by(|a, b| {
        b.matched
            .score
            .cmp(&a.matched.score)
            .then_with(|| a.id.cmp(&b.id))
    });
    ensure!(
        hits.iter()
            .map(|h| &h.id)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == hits.len(),
        "search result repeats an identity"
    );
    let token = |hit: &Hit| -> Result<Digest> {
        Ok(wire::digest(&wire::encode(&V::Array(vec![
            V::Text("SearchCursor".into()),
            V::Bytes(binding.to_vec()),
            V::Text(hit.id.clone()),
            V::Uint(hit.matched.score),
        ]))?))
    };
    let start = match request.cursor {
        None => 0,
        Some(cursor) => hits
            .iter()
            .enumerate()
            .find_map(|(index, h)| (token(h).ok() == Some(cursor)).then_some(index + 1))
            .context("CursorScope: search authority, corpus, query or visible results changed")?,
    };
    let total = hits.len();
    let end = start.saturating_add(request.limit).min(total);
    let next = if end < total {
        Some(hex::encode(token(&hits[end - 1])?))
    } else {
        None
    };
    let selected = hits.drain(start..end).collect();
    Ok((selected, next, total))
}
pub fn run(
    location: Location,
    corpus: Corpus,
    recipient: Recipient,
    query: Query,
    historical: bool,
) -> Result<()> {
    let bootstrap = control::bootstrap(&location)?;
    let store = Store::open(&location.directory, bootstrap.descriptor().clone())?;
    let request = query.request(&store, 0, historical)?;
    let library = library(&corpus, &bootstrap, &store)?;
    let vault = recipient.open(&bootstrap)?;
    let health = if historical {
        None
    } else {
        control::clock(&location, store.descriptor().voters())
            .and_then(|s| s.health())
            .ok()
    };
    let mut hits = Vec::new();
    let mut available = 0usize;
    let mut locked = 0usize;
    let mut selected = 0usize;
    for entry in library.entries() {
        let namespace = crate::authority_domains::page::namespace_id(&entry.namespace)?;
        if !request.namespaces.is_empty() && !request.namespaces.contains(&namespace) {
            continue;
        }
        selected += 1;
        let current = historical
            || entry.lease.as_ref().zip(health).is_some_and(|(lease, h)| {
                lease.current(&store, h).is_ok() && lease.authorises(entry, &store).is_ok()
            });
        if !current {
            locked += 1;
            continue;
        }
        let at = if historical {
            entry.retained_at_ms
        } else {
            health
                .context("local clock health is absent")?
                .observe()?
                .wall_ms
        };
        let view = match source::open(entry, &bootstrap, store.requester(), vault.as_ref(), at) {
            Ok(view) => view,
            Err(_) => {
                locked += 1;
                continue;
            }
        };
        available += 1;
        if let Some(matched) = search_text::matching(&request, &view.bytes)? {
            hits.push(hit(entry, view, matched));
        }
    }
    // A concurrent local clock loss or lease expiry suppresses the response instead of refreshing it.
    if !historical {
        for entry in library
            .entries()
            .filter(|entry| hits.iter().any(|hit| hit.id == hex::encode(entry.id)))
        {
            entry
                .lease
                .as_ref()
                .context("local search lease absent")?
                .current(&store, health.context("local clock health absent")?)?;
        }
    }
    let binding = binding(&store, &request, library.generation(), store.generations())?;
    let (results, next, count) = page(hits, &request, binding)?;
    crate::print_value(&json!({
        "status":if available == 0 && locked > 0 {"StaleLocked"} else {"SearchResults"},
        "scope":"Local","queryLeavesDevice":false,"network":hex::encode(request.network),
        "retainedView":if historical {"Historical"} else {"Current"},
        "currentRevocationClaim":!historical,
        "coverage":{"selectedRetained":selected,"available":available,"staleOrLocked":locked,"complete":locked == 0},
        "height":store.prefix().height(),"results":results,"matches":count,"nextCursor":next,
        "freshness":if historical {"Retained approvals only; current membership, withdrawal and revocation are not checked"} else {"Only independently refreshed unexpired local authority leases are searched"},
    }))
}

#[cfg(test)]
#[path = "SearchLocalTests.rs"]
mod tests;
