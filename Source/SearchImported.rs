// SPDX-License-Identifier: MIT
// Destination imports use current bilateral evidence; search terms never travel to the source network.
use super::*;
use crate::authority_domains::federation as fed;

fn inventory_pages(proof: &fed::VerifiedForeign) -> Result<Vec<[u8; 16]>> {
    proof
        .state
        .records
        .values()
        .filter(|r| r.reference.kind == 153)
        .map(|r| {
            Ok(fed::Share::parse(&r.payload, proof.state.network, proof.state.incarnation)?.page)
        })
        .collect()
}

fn hydrate_inventory(
    pages: &[[u8; 16]],
    mut page_context: impl FnMut([u8; 16]) -> Result<()>,
) -> Result<()> {
    for raw in pages {
        match page_context(*raw) {
            // PageContext code3 includes an absent, unpublished or inaccessible local import.
            // Only a certified refusal can omit a candidate; stale snapshots and IO fail the search.
            Err(error)
                if error
                    .downcast_ref::<crate::authority_inspection::domain_client::Refusal>()
                    .is_some_and(|r| r.code == 3) => {}
            other => other?,
        }
    }
    Ok(())
}

fn context(
    c: &mut Client,
    grant: &VersionRef,
    agreement: Digest,
    page: Option<[u8; 16]>,
    action: u64,
) -> Result<()> {
    let command = match page {
        Some(page) => fed::Command::PageContext {
            agreement,
            page,
            action,
        },
        None => fed::Command::InventoryContext { agreement, action },
    };
    c.domain_action(command.into(), Some(grant.clone()))
        .context(if page.is_some() {
            "imported search Page context authority failed"
        } else {
            "imported search inventory context authority failed"
        })?;
    Ok(())
}
fn selected(
    c: &Client,
    agreement: Digest,
    raw: [u8; 16],
) -> Result<(Digest, domain::Record, fed::ForeignRevision)> {
    let cache = c.cache()?;
    let treaty = fed::Agreement::parse(
        &cache.state.record(151, agreement)?.payload,
        cache.state.network,
        cache.state.incarnation,
    )?
    .treaty;
    let id = fed::qualified_page(agreement, &treaty.source, raw)?;
    let head = fed::ForeignPage::parse(&cache.state.record(154, id)?.payload)?;
    let published = head
        .published
        .context("imported Page has no local approval")?;
    let approval = cache.state.record(156, published.id)?;
    let review = fed::ForeignReview::parse(
        &approval.payload,
        cache.state.network,
        cache.state.incarnation,
    )?;
    ensure!(
        !head.withdrawn && review.approve && approval.reference == published,
        "imported Page was withdrawn or rejected"
    );
    let revision = cache.state.record(155, review.revision.id)?.clone();
    ensure!(
        revision.reference == review.revision,
        "imported revision changed"
    );
    Ok((
        id,
        revision.clone(),
        fed::ForeignRevision::parse(&revision.payload)?,
    ))
}
#[allow(
    clippy::too_many_arguments,
    reason = "The exact bilateral selection and local query payload have separate bindings."
)]
fn lease(
    c: &Client,
    grant: &VersionRef,
    agreement: Digest,
    route: &Path,
    raw: Option<[u8; 16]>,
    revision: Option<&VersionRef>,
    after: Option<Digest>,
    query: Option<&Request>,
    retained_body: bool,
    diagnostics: bool,
) -> Result<(fed::ForeignProof, Resolved, Vec<[u8; 16]>)> {
    let cache = c.cache()?;
    let (n, i) = (cache.state.network, cache.state.incarnation);
    let accepted = fed::Agreement::parse(&cache.state.record(151, agreement)?.payload, n, i)?;
    ensure!(
        !accepted.treaty.source_side(n, i)?,
        "search selected a source-side Bridge instead of the importing network"
    );
    let trust = cache.state.record(150, accepted.foreign.id)?;
    let floor = cache.state.record(157, accepted.foreign.id)?;
    if let Some(q) = query {
        q.network_scope(
            n,
            i,
            page::namespace_id(&accepted.treaty.destination_namespace)?,
        )?;
    }
    let control = service_control(
        route,
        diagnostics,
        n,
        i,
        6,
        accepted.treaty.destination_bridge,
    )?;
    let packet = wire::encode(&V::Array(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("BridgeLease".into()),
        V::Bytes(agreement.to_vec()),
        raw.map_or(V::Null, |v| V::Bytes(v.to_vec())),
        revision.map_or(V::Null, crate::authority_membership::reference),
        after.map_or(V::Null, |v| V::Bytes(v.to_vec())),
        V::Bytes(trust.bytes.clone()),
        V::Bytes(floor.bytes.clone()),
        V::Bool(query.is_some() || retained_body),
    ]))?;
    let request = if control.route().is_some() {
        let reader = crate::authority_route_reader::sign(
            n,
            i,
            accepted.treaty.destination_bridge,
            grant,
            u64::from(query.is_some()),
            c.clock
                .health()?
                .observe()?
                .wall_ms
                .checked_add(5000)
                .context("Bridge reader expiry overflow")?,
            rand::random(),
            &packet,
            &c.key,
        )?;
        if let Some(q) = query {
            wire::encode(&V::Array(vec![
                V::Uint(200),
                V::Uint(1),
                V::Text("RouteBridgeSearch".into()),
                V::Bytes(reader),
                V::Bytes(q.encode()?),
            ]))?
        } else {
            reader
        }
    } else if let Some(q) = query {
        wire::encode(&V::Array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("BridgeSearch".into()),
            V::Bytes(packet),
            V::Bytes(q.encode()?),
        ]))?
    } else {
        packet
    };
    let bytes = control.exchange_limit(
        &request,
        crate::authority_challenge::boot_time_ms()?
            .checked_add(30000)
            .context("Bridge deadline overflow")?,
        4 * wire::MAXIMUM,
    )?;
    let value = wire::decode_state(&bytes)?;
    let f = value.array(if query.is_some() { 6 } else { 5 })?;
    ensure!(
        f[0].uint()? == 201
            && f[1].uint()? == 1
            && f[2].text()?
                == if query.is_some() {
                    "BridgeSearch"
                } else {
                    "BridgeLease"
                },
        "Bridge search response differs"
    );
    let proof = fed::ForeignProof::parse(f[3].bytes()?)?;
    ensure!(
        proof.trust == trust.reference
            && proof.floor == floor.reference
            && proof.anchor == floor.bytes,
        "Bridge substituted independently accepted foreign authority"
    );
    let fed::Command::Export {
        agreement: source_agreement,
        admission,
        include_bundle,
        ..
    } = proof.command()?
    else {
        anyhow::bail!("search requires a current source Export")
    };
    let fed::Command::Admission {
        agreement: destination,
        page: admitted_page,
        revision: admitted_revision,
        after: admitted_after,
        ..
    } = admission.command()?
    else {
        anyhow::bail!("search lacks exact bilateral Admission")
    };
    ensure!(
        include_bundle == retained_body
            && source_agreement.id == agreement
            && destination.id == agreement
            && admitted_page == raw
            && admitted_revision.as_ref() == revision
            && admitted_after == after,
        "Bridge proof selected another publication or inventory scope"
    );
    let inventory = if !retained_body {
        let verified = proof.verify(
            &cache.state,
            &accepted.treaty,
            c.clock.health()?.observe()?.wall_ms,
            &Resolved::default(),
            false,
        )?;
        if raw.is_none() {
            inventory_pages(&verified)?
        } else {
            vec![]
        }
    } else {
        vec![]
    };
    let objects = if let Some(q) = query {
        let (_, approved) = proof.exported_publication()?;
        let reference = approved
            .bundle
            .context("current source publication has no bundle")?;
        let objects = Resolved::parse(std::slice::from_ref(&reference), &f[4])?;
        let bundle = page::objects::Bundle::parse(
            objects.get(&reference)?,
            accepted.treaty.source.network,
            accepted.treaty.source.incarnation,
        )?;
        ensure!(
            proof.rebuild_bundle(&bundle.source)?.bytes == bundle.bytes,
            "imported search bytes differ from current source approval"
        );
        let (source, _) = search_text::verify_response(q, f[5].bytes()?)?;
        ensure!(
            source == bundle.source,
            "imported search result changed the approved source"
        );
        objects
    } else if retained_body {
        let (_, approved) = proof.exported_publication()?;
        let reference = approved.bundle.context("retained import bundle absent")?;
        let objects = Resolved::parse(std::slice::from_ref(&reference), &f[4])?;
        proof.verify(
            &cache.state,
            &accepted.treaty,
            c.clock.health()?.observe()?.wall_ms,
            &Resolved::default(),
            false,
        )?;
        objects
    } else {
        Resolved::parse(&[], &f[4])?
    };
    Ok((proof, objects, inventory))
}
pub fn fetch(
    c: &mut Client,
    grant: &VersionRef,
    agreement: Digest,
    raw: [u8; 16],
    route: &Path,
    query: Option<&Request>,
    diagnostics: bool,
) -> Result<library::Entry> {
    context(c, grant, agreement, Some(raw), u64::from(query.is_some()))?;
    let (qualified, revision_record, revision) = selected(c, agreement, raw)?;
    let (proof, objects, _) = lease(
        c,
        grant,
        agreement,
        route,
        Some(raw),
        Some(&revision.native),
        None,
        query,
        query.is_none(),
        diagnostics,
    )?;
    let command = if query.is_some() {
        fed::Command::SearchRead {
            page: qualified,
            export: proof,
        }
    } else {
        fed::Command::LocalSearchRead {
            page: qualified,
            export: proof,
        }
    };
    let result = c
        .domain_action(command.into(), Some(grant.clone()))
        .context("imported search publication authority failed")?;
    let head = fed::ForeignPage::parse(&result.cache.state.record(154, qualified)?.payload)?;
    let publication = head
        .published
        .context("imported search approval is absent")?;
    let review = result.cache.state.record(156, publication.id)?;
    let reviewed = fed::ForeignReview::parse(
        &review.payload,
        result.cache.state.network,
        result.cache.state.incarnation,
    )?;
    ensure!(
        review.reference == publication
            && reviewed.revision == revision_record.reference
            && reviewed.approve,
        "imported search publication changed"
    );
    let accepted = fed::Agreement::parse(
        &result.cache.state.record(151, agreement)?.payload,
        result.cache.state.network,
        result.cache.state.incarnation,
    )?;
    Ok(library::Entry {
        id: qualified,
        namespace: accepted.treaty.destination_namespace,
        grant: grant.clone(),
        publication,
        retained_at_ms: result.evaluated_at_ms,
        source: library::Source::Imported {
            bundle: objects.get(&revision.bundle)?.to_vec(),
            revision: revision_record.bytes,
            review: review.bytes.clone(),
        },
        lease: Some(retain::lease(&result, &c.key)?),
    })
}
pub fn refresh(
    c: &mut Client,
    grant: &VersionRef,
    entry: &mut library::Entry,
    route: &Path,
    diagnostics: bool,
) -> Result<()> {
    let library::Source::Imported { revision, .. } = &entry.source else {
        anyhow::bail!("not an imported retained item")
    };
    let s = c.store.prefix().scope();
    let record = domain::Record::parse(revision, s.network, s.incarnation)?;
    let revision = fed::ForeignRevision::parse(&record.payload)?;
    context(
        c,
        grant,
        revision.agreement,
        Some(revision.metadata.author.raw_page),
        0,
    )?;
    let (proof, _, _) = lease(
        c,
        grant,
        revision.agreement,
        route,
        Some(revision.metadata.author.raw_page),
        Some(&revision.native),
        None,
        None,
        false,
        diagnostics,
    )?;
    let result = c
        .domain_action(
            fed::Command::LocalSearchRead {
                page: entry.id,
                export: proof,
            }
            .into(),
            Some(grant.clone()),
        )
        .context("imported search retained authority refresh failed")?;
    let head = fed::ForeignPage::parse(&result.cache.state.record(154, entry.id)?.payload)?;
    ensure!(
        head.published.as_ref() == Some(&entry.publication),
        "retained imported publication was replaced"
    );
    entry.lease = Some(retain::lease(&result, &c.key)?);
    Ok(())
}
pub fn search(
    c: &mut Client,
    grant: &VersionRef,
    agreement: Digest,
    route: &Path,
    query: &Request,
    diagnostics: bool,
) -> Result<Vec<library::Entry>> {
    let mut out = Vec::new();
    let mut after = None;
    loop {
        context(c, grant, agreement, None, 1)?;
        let (_, _, pages) = lease(
            c,
            grant,
            agreement,
            route,
            None,
            None,
            after,
            None,
            false,
            diagnostics,
        )?;
        hydrate_inventory(&pages, |raw| context(c, grant, agreement, Some(raw), 1))?;
        // Exact SearchList preflight needs every admitted local Page dependency. Hydration
        // can consume the original lease lifetime, so obtain new query-free evidence once.
        context(c, grant, agreement, None, 1)?;
        let (proof, _, _) = lease(
            c,
            grant,
            agreement,
            route,
            None,
            None,
            after,
            None,
            false,
            diagnostics,
        )?;
        let result = c
            .domain_action(
                fed::Command::SearchList {
                    agreement,
                    export: proof,
                }
                .into(),
                Some(grant.clone()),
            )
            .context("imported search catalogue authority failed")?;
        let response = result.value.array(5)?;
        let body = response[4].array(4)?;
        let mut pages = Vec::new();
        for bytes in body[1].list(fed::MAXIMUM_CONTEXT_RECORDS)? {
            let r = domain::Record::parse(bytes.bytes()?, query.network, query.incarnation)?;
            if r.reference.kind == 154 {
                pages.push(fed::ForeignPage::parse(&r.payload)?.raw_page);
            }
        }
        for raw in pages {
            out.push(fetch(
                c,
                grant,
                agreement,
                raw,
                route,
                Some(query),
                diagnostics,
            )?);
            ensure!(
                out.len() <= library::MAXIMUM_ITEMS,
                "imported search corpus admission exceeded"
            );
        }
        let next = if body[3] == V::Null {
            None
        } else {
            Some(body[3].fixed::<32>()?)
        };
        ensure!(
            next.is_none_or(|v| after.is_none_or(|old| v > old)),
            "imported search cursor did not progress"
        );
        after = next;
        if after.is_none() {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "SearchImportedTests.rs"]
mod tests;
