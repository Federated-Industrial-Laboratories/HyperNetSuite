// SPDX-License-Identifier: MIT
// Retention and refresh accept identities only; local query entry cannot invoke these transports.
use super::*;
use crate::{
    authority_domains::{
        self as domain, federation as fed,
        page::{self, Command as Action},
    },
    authority_inspection::domain_client::ResultState,
    authority_objects::Resolved,
    authority_pages::Client,
};
use std::collections::{BTreeMap, BTreeSet};

pub fn lease(result: &ResultState, signer: &ed25519_dalek::SigningKey) -> Result<library::Lease> {
    let response = result.value.array(5)?;
    let versions = response[3]
        .list(64)?
        .iter()
        .map(domain::version)
        .collect::<Result<Vec<_>>>()?;
    crate::authority_proof::validate_versions(&versions, 64)?;
    let mut lease = library::Lease {
        configuration: result.prefix.scope().configuration,
        epoch: result.prefix.scope().epoch,
        height: result.prefix.height(),
        policy_state: *result.prefix.policy_state(),
        kernel_boot: library::kernel_boot()?,
        evaluated_at_ms: result.evaluated_at_ms,
        expires_at_ms: result.expires_at_ms,
        deadline_boot_ms: result.deadline_boot_ms,
        versions,
        receipt: result.receipt.clone(),
        attestation: vec![],
    };
    lease.sign(signer)?;
    Ok(lease)
}
fn agreement(entry: &library::Entry, c: &Client) -> Result<Digest> {
    let library::Source::Imported { revision, .. } = &entry.source else {
        anyhow::bail!("not an imported retained item")
    };
    let s = c.store.prefix().scope();
    Ok(fed::ForeignRevision::parse(
        &domain::Record::parse(revision, s.network, s.incarnation)?.payload,
    )?
    .agreement)
}
pub fn refresh_leases(
    c: &mut Client,
    grant: &VersionRef,
    entries: &mut [library::Entry],
    bridges: &BTreeMap<Digest, PathBuf>,
    diagnostics: bool,
) -> Result<()> {
    let mut items = Vec::new();
    let s = c.store.prefix().scope().clone();
    for entry in entries.iter_mut() {
        entry.lease = None;
        entry.grant = grant.clone();
        match &entry.source {
            library::Source::Imported { .. } => {
                let route = bridges
                    .get(&agreement(entry, c)?)
                    .context("retained import requires its explicit destination Bridge route")?;
                network::imported::refresh(c, grant, entry, route, diagnostics)?;
            }
            library::Source::Sealed { binding, .. } => {
                let device = domain::Record::parse(binding, s.network, s.incarnation)?.reference;
                ensure!(device.kind == 108, "retained sealed device binding differs");
                items.push((entry.publication.clone(), Some(device)));
            }
            library::Source::Native { .. } => items.push((entry.publication.clone(), None)),
        }
    }
    if !items.is_empty() {
        items.sort_by_key(|(publication, _)| publication.index());
        ensure!(
            items.len() <= 64 && items.windows(2).all(|w| w[0].0.index() != w[1].0.index()),
            "local lease batch exceeds its exact publication bound"
        );
        let (result, _) = c.action(
            Action::LocalSearchLease { items },
            Some(grant.clone()),
            Resolved::default(),
        )?;
        let current = lease(&result, &c.key)?;
        for entry in entries
            .iter_mut()
            .filter(|entry| !matches!(entry.source, library::Source::Imported { .. }))
        {
            ensure!(
                current.versions.contains(&entry.publication),
                "local lease omitted the exact retained publication"
            );
            entry.lease = Some(current.clone());
        }
    }
    Ok(())
}
pub fn run(command: Retain) -> Result<()> {
    let (connection, capability, corpus, target) = match command {
        Retain::Native {
            connection,
            capability,
            corpus,
            page_id,
        } => (
            connection,
            capability,
            corpus,
            Target::Native(raw(&page_id)?),
        ),
        Retain::Imported {
            connection,
            capability,
            corpus,
            agreement,
            page_id,
            bridge,
        } => (
            connection,
            capability,
            corpus,
            Target::Imported(id(&agreement)?, raw(&page_id)?, bridge),
        ),
        Retain::Sealed {
            connection,
            capability,
            corpus,
            object,
            namespace,
        } => (
            connection,
            capability,
            corpus,
            Target::Sealed(id(&object)?, namespace),
        ),
    };
    let (mut c, vault) = connection.open()?;
    let grant = c.grant(capability)?;
    let mut library = library(&corpus, &c.bootstrap, &c.store)?;
    let mut bridges = BTreeMap::new();
    let entry = match target {
        Target::Native(raw) => {
            network::native(&mut c, &grant, raw, None, connection.local_diagnostics)?
        }
        Target::Imported(agreement, raw, route) => {
            let entry = network::imported::fetch(
                &mut c,
                &grant,
                agreement,
                raw,
                &route,
                None,
                connection.local_diagnostics,
            )?;
            bridges.insert(agreement, route);
            entry
        }
        Target::Sealed(object, namespace) => {
            let device = id(connection
                .device
                .as_deref()
                .context("sealed retention requires the authorised recipient device")?)?;
            let entry = crate::authority_pages::sealed::retain(
                &mut c,
                &grant,
                vault
                    .as_ref()
                    .context("sealed retention requires its recipient vault")?,
                device,
                object,
            )?;
            ensure!(
                entry.namespace == namespace,
                "sealed publication belongs to another namespace"
            );
            entry
        }
    };
    let item = entry.id;
    let mut entries = vec![entry];
    refresh_leases(
        &mut c,
        &grant,
        &mut entries,
        &bridges,
        connection.local_diagnostics,
    )?;
    library.retain_many(entries)?;
    let current = library.entry(item)?.lease.as_ref().is_some_and(|lease| {
        c.clock
            .health()
            .is_ok_and(|h| lease.current(&c.store, h).is_ok())
    });
    crate::print_value(
        &json!({"status":"SearchPublicationRetained","item":hex::encode(item),"scope":"Local","querySubmitted":false,"current":current,"corpusGeneration":library.generation(),"height":c.store.prefix().height()}),
    )
}
enum Target {
    Native([u8; 16]),
    Imported(Digest, [u8; 16], PathBuf),
    Sealed(Digest, String),
}
fn reacquire(
    c: &mut Client,
    grant: &VersionRef,
    entry: &library::Entry,
    vault: Option<&crate::sealed_vault::Vault>,
    bridges: &BTreeMap<Digest, PathBuf>,
    diagnostics: bool,
) -> Result<library::Entry> {
    let s = c.store.prefix().scope();
    match &entry.source {
        library::Source::Native { bundle, .. } => {
            let bundle = page::objects::Bundle::parse(bundle, s.network, s.incarnation)?;
            network::native(c, grant, bundle.author.raw_page, None, diagnostics)
        }
        library::Source::Imported { revision, .. } => {
            let revision = fed::ForeignRevision::parse(
                &domain::Record::parse(revision, s.network, s.incarnation)?.payload,
            )?;
            let route = bridges
                .get(&revision.agreement)
                .context("retained import requires its explicit destination Bridge route")?;
            network::imported::fetch(
                c,
                grant,
                revision.agreement,
                revision.metadata.author.raw_page,
                route,
                None,
                diagnostics,
            )
        }
        library::Source::Sealed { device, .. } => crate::authority_pages::sealed::retain(
            c,
            grant,
            vault.context("sealed sync requires its recipient vault")?,
            *device,
            entry.id,
        ),
    }
}
pub fn sync(
    connection: Connection,
    capability: Capability,
    corpus: Corpus,
    items: Vec<String>,
    bridges: Vec<String>,
) -> Result<()> {
    let (mut c, vault) = connection.open()?;
    let grant = c.grant(capability)?;
    let mut library = library(&corpus, &c.bootstrap, &c.store)?;
    let selected = items
        .iter()
        .map(|v| id(v))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        selected.len() == items.len(),
        "sync repeats a retained item"
    );
    for item in &selected {
        library.entry(*item)?;
    }
    let mut entries = library
        .entries()
        .filter(|entry| selected.is_empty() || selected.contains(&entry.id))
        .cloned()
        .collect::<Vec<_>>();
    ensure!(!entries.is_empty(), "no retained publications selected");
    ensure!(
        entries.len() <= 64,
        "select a bounded local lease batch with repeated --item; authority proof dependencies also apply"
    );
    for entry in &mut entries {
        entry.lease = None;
    }
    library.retain_many(entries.clone())?;
    let bridges = network::bridge_routes(&bridges)?;
    let mut refreshed = Vec::new();
    let mut locked = Vec::new();
    for entry in entries {
        match reacquire(&mut c, &grant, &entry, vault.as_ref(), &bridges, connection.local_diagnostics) {
            Ok(entry) => refreshed.push(entry),
            Err(error) => locked.push(json!({"item":hex::encode(entry.id),"reason":crate::reader::bounded_status(&format!("{error:#}"))})),
        }
    }
    if !refreshed.is_empty() {
        if let Err(error) = refresh_leases(
            &mut c,
            &grant,
            &mut refreshed,
            &bridges,
            connection.local_diagnostics,
        ) {
            for entry in &mut refreshed {
                entry.lease = None;
            }
            locked.push(json!({"scope":"LeaseBatch","reason":crate::reader::bounded_status(&format!("{error:#}"))}));
        }
        library.retain_many(refreshed.clone())?;
    }
    let health = c.clock.health()?;
    let current = refreshed
        .iter()
        .filter(|e| {
            e.lease
                .as_ref()
                .is_some_and(|l| l.current(&c.store, health).is_ok())
        })
        .map(|e| hex::encode(e.id))
        .collect::<Vec<_>>();
    crate::print_value(
        &json!({"status":if current.is_empty() {"StaleLocked"} else {"SearchCorpusSynchronised"},"querySubmitted":false,"currentItems":current,"refreshedItems":refreshed.len(),"locked":locked,"corpusGeneration":library.generation(),"height":c.store.prefix().height(),"freshness":"Current local search uses the original unextended authority deadline; run an explicit sync again after expiry"}),
    )
}
