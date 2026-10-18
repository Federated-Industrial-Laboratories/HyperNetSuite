// SPDX-License-Identifier: MIT
// Scoped deployment caches are usable only while their exact records match retained quorum floors.
use super::*;

pub(super) fn versions(scope: &proof::Scope, entries: &[Vec<u8>]) -> Result<Vec<VersionRef>> {
    Governance::record_versions(scope.network, scope.incarnation, entries)
}
/// Replace obsolete deployment metadata only from an independently certified successor cache.
pub(crate) fn refresh_cached_deployments(
    bootstrap: &Verified,
    store: &Store,
    entries: &mut Vec<Vec<u8>>,
) -> Result<()> {
    let scope = store.descriptor().scope();
    let old = versions(scope, entries)?;
    let mut selected = old
        .iter()
        .cloned()
        .zip(entries.iter().cloned())
        .map(|(reference, bytes)| (reference.index(), (reference, bytes)))
        .collect::<BTreeMap<_, _>>();
    let deployments = old
        .iter()
        .filter(|r| {
            matches!(r.kind, 105 | 117 | 129 | 130)
                && store.generations().iter().any(|current| {
                    current.index() == r.index() && current.generation > r.generation
                })
        })
        .map(|r| r.id)
        .collect::<std::collections::BTreeSet<_>>();
    for deployment in deployments {
        let current = Cache::load(bootstrap, store, deployment, None)?;
        for bytes in current.entries {
            let reference = versions(scope, std::slice::from_ref(&bytes))?.remove(0);
            if let Some((prior, _)) = selected.get(&reference.index()) {
                ensure!(
                    prior.generation < reference.generation || *prior == reference,
                    "cached deployment conflicts with its certified successor"
                );
            }
            selected.insert(reference.index(), (reference, bytes));
        }
    }
    *entries = selected.into_values().map(|(_, bytes)| bytes).collect();
    Ok(())
}
pub(super) fn merged(bootstrap: &Verified, entries: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    let scope = bootstrap.descriptor().scope();
    let mut selected = BTreeMap::new();
    for bytes in bootstrap.governance_records().iter().chain(entries) {
        let r = versions(scope, std::slice::from_ref(bytes))?.remove(0);
        if let Some((old, _)) = selected.get(&r.index()) {
            let old: &VersionRef = old;
            ensure!(
                r.generation >= old.generation
                    && (r.generation != old.generation || r.digest == old.digest),
                "deployment context conflicts with bootstrap"
            );
        }
        selected.insert(r.index(), (r, bytes.clone()));
    }
    Ok(selected.into_values().map(|(_, v)| v).collect())
}
pub(super) fn minimum(
    current: &[VersionRef],
    floor: &[VersionRef],
    capability: bool,
) -> Result<()> {
    for r in current {
        if let Some(old) = floor.iter().find(|old| old.index() == r.index()) {
            ensure!(
                r.generation >= old.generation
                    && (r.generation != old.generation || r.digest == old.digest),
                "deployment result conflicts with retained generation"
            );
        }
    }
    for old in floor
        .iter()
        .filter(|r| r.kind == 130 || capability && r.kind == 126)
    {
        let target = if old.kind == 130 { 129 } else { 102 };
        ensure!(
            !current.iter().any(|r| r.kind == target && r.id == old.id) || current.contains(old),
            "deployment result omitted a retained restriction"
        );
    }
    Ok(())
}
#[derive(Clone)]
pub struct Cache {
    pub(super) scope: proof::Scope,
    pub deployment: [u8; 32],
    pub grant: Option<[u8; 32]>,
    pub(super) entries: Vec<Vec<u8>>,
    pub(super) manifest: Option<Vec<u8>>,
    pub(super) consent: Option<Vec<u8>>,
}
impl Cache {
    fn name(deployment: [u8; 32], grant: Option<[u8; 32]>) -> String {
        match grant {
            Some(g) => format!(
                "DeploymentContext{}{}.cbor",
                hex::encode(deployment),
                hex::encode(g)
            ),
            None => format!("DeploymentState{}.cbor", hex::encode(deployment)),
        }
    }
    pub fn version(&self, kind: u64, id: [u8; 32]) -> Result<VersionRef> {
        versions(&self.scope, &self.entries)?
            .into_iter()
            .find(|v| v.index() == (kind, id))
            .context("deployment cache lacks exact record")
    }
    pub(super) fn current(&self, store: &Store) -> Result<()> {
        ensure!(
            &self.scope == store.prefix().scope(),
            "deployment cache belongs to another network"
        );
        let refs = versions(&self.scope, &self.entries)?;
        minimum(&refs, store.generations(), self.grant.is_some())?;
        ensure!(
            refs.iter().all(|r| store.generations().contains(r)),
            "deployment cache lacks retained quorum authentication"
        );
        Ok(())
    }
    pub fn load(
        bootstrap: &Verified,
        store: &Store,
        deployment: [u8; 32],
        grant: Option<[u8; 32]>,
    ) -> Result<Self> {
        let bytes = files::read_at(
            store.profile_directory(),
            OsStr::new(&Self::name(deployment, grant)),
            CACHE_LIMIT,
            true,
        )?;
        let value = wire::decode(&bytes)?;
        let f = record(&value, 200, 9)?;
        ensure!(
            f[2].text()? == "AuthorityDeploymentCache"
                && bootstrap.descriptor().canonical() == store.initial_descriptor().canonical()
                && proof::Scope::parse(&f[3])? == *store.descriptor().scope()
                && f[4].fixed::<32>()? == deployment
                && f[5] == grant.map_or(V::Null, |g| b(&g)),
            "deployment cache scope differs"
        );
        let mut out = Self {
            scope: store.descriptor().scope().clone(),
            deployment,
            grant,
            entries: f[6]
                .list(64)?
                .iter()
                .map(|v| Ok(v.bytes()?.to_vec()))
                .collect::<Result<_>>()?,
            manifest: if f[7] == V::Null {
                None
            } else {
                Some(f[7].bytes()?.to_vec())
            },
            consent: if f[8] == V::Null {
                None
            } else {
                Some(f[8].bytes()?.to_vec())
            },
        };
        if let Some(pending) = store.resume_ordinary()? {
            let intent = Intent::from_signed(pending.signed())?;
            out.recover_registration(&intent, store.generations())?;
            out.recover_withdrawal(&intent, store.generations())?;
        }
        out.current(store)?;
        if grant.is_none() {
            out.provenance()?;
        }
        Ok(out)
    }
    fn recover_registration(&mut self, intent: &Intent, floor: &[VersionRef]) -> Result<()> {
        if intent.action != "AuthorityDeploymentRegister" || intent.resource != self.deployment {
            return Ok(());
        }
        let operation = Operation::parse(intent)?;
        let Operation::Register { offer, grant, .. } = &operation else {
            bail!("Pending deployment registration has another operation");
        };
        ensure!(
            intent.network == self.scope.network
                && intent.incarnation == self.scope.incarnation
                && self.grant.is_none_or(|id| id == grant.id),
            "Pending registration differs from cached deployment context"
        );
        let created = operation.derive(intent)?;
        let references = created
            .iter()
            .map(|bytes| records::reference(bytes))
            .collect::<Result<Vec<_>>>()?;
        if !references.iter().all(|r| floor.contains(r)) {
            return Ok(());
        }
        // Exact certified floors authenticate reconstruction after cache publication was interrupted.
        // Neither an offline offer nor an uncommitted pending request can advance this cache.
        for bytes in created {
            let reference = records::reference(&bytes)?;
            self.entries.retain(|old| {
                records::reference(old).map_or(true, |r| r.index() != reference.index())
            });
            self.entries.push(bytes);
        }
        membership::sort_records(&mut self.entries)?;
        self.manifest = Some(offer.manifest_bytes.clone());
        self.consent = Some(offer.consent.clone());
        Ok(())
    }
    pub(super) fn recover_withdrawal(
        &mut self,
        intent: &Intent,
        floor: &[VersionRef],
    ) -> Result<()> {
        if self.grant.is_some() || intent.action != "AuthorityDeploymentWithdraw" {
            return Ok(());
        }
        let operation = Operation::parse(intent)?;
        let Operation::Withdraw { admission, .. } = &operation else {
            bail!("pending deployment withdrawal has another operation")
        };
        let (_, registration) = self.provenance()?;
        ensure!(
            intent.network == self.scope.network
                && intent.incarnation == self.scope.incarnation
                && intent.resource == self.deployment
                && intent.requester == registration.operator
                && *admission == registration.reference,
            "pending withdrawal differs from cached deployment ownership"
        );
        let created = operation.derive(intent)?;
        ensure!(created.len() == 1, "withdrawal must derive one restriction");
        let restriction = records::reference(&created[0])?;
        ensure!(
            restriction.kind == 130 && restriction.id == self.deployment,
            "pending withdrawal derives another restriction"
        );
        // Acceptance may persist the certified restriction before cache publication.
        // Its exact retained digest authenticates reconstruction from the unchanged intent.
        if floor.contains(&restriction) && !self.entries.contains(&created[0]) {
            self.entries.push(created[0].clone());
            membership::sort_records(&mut self.entries)?;
        }
        Ok(())
    }
    pub(super) fn save(&self, store: &Store) -> Result<()> {
        self.current(store)?;
        let bytes = wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityDeploymentCache".into()),
            self.scope.value(),
            b(&self.deployment),
            self.grant.map_or(V::Null, |g| b(&g)),
            a(self.entries.iter().map(|v| b(v)).collect()),
            self.manifest.as_ref().map_or(V::Null, |v| b(v)),
            self.consent.as_ref().map_or(V::Null, |v| b(v)),
        ]))?;
        ensure!(bytes.len() <= CACHE_LIMIT, "deployment cache exceeds bound");
        files::atomic_at(
            store.profile_directory(),
            OsStr::new(&Self::name(self.deployment, self.grant)),
            &bytes,
            true,
        )
    }
    pub(super) fn provenance(&self) -> Result<(Manifest, records::Registration)> {
        ensure!(
            versions(&self.scope, &self.entries)?
                .iter()
                .all(|r| matches!(r.kind, 105 | 117 | 129 | 130) && r.id == self.deployment),
            "deployment state contains unrelated records"
        );
        let manifest = Manifest::parse(
            self.manifest
                .as_deref()
                .context("deployment manifest is absent")?,
        )?;
        let (consent, signatures) = wire::envelope(
            self.consent
                .as_deref()
                .context("deployment consent is absent")?,
            1,
        )?;
        let record = self
            .entries
            .iter()
            .find(|v| records::reference(v).is_ok_and(|r| r.kind == 129))
            .context("deployment registration is absent")?;
        let registration =
            records::Registration::parse(record, self.scope.network, self.scope.incarnation)?;
        ensure!(
            manifest.network == self.scope.network
                && manifest.incarnation == self.scope.incarnation
                && manifest.deployment == self.deployment
                && registration.deployment == self.deployment
                && signatures.len() == 1
                && signatures[0].0 == manifest.operator
                && consent == manifest.unsigned_consent(0)?
                && self.entries.contains(&consent)
                && self.entries.contains(&manifest.desired()?)
                && registration.host == manifest.host
                && registration.operator == manifest.operator
                && registration.services == manifest.services()
                && registration.transports == manifest.owned_transports()?
                && registration.monitor == manifest.clock.monitor_key
                && registration.profile == records::reference(&manifest.desired()?)?
                && registration.consent == records::reference(&consent)?,
            "deployment manifest, operator consent and admission differ"
        );
        Ok((manifest, registration))
    }
    /// A signed receipt asserts durable local withdrawal, including while cleanup needs retry.
    pub fn withdrawal(&self, receipt: &[u8]) -> Result<(VersionRef, u64)> {
        let (manifest, registration) = self.provenance()?;
        let (payload, signatures) = wire::envelope(receipt, 1)?;
        let value = wire::decode(&payload)?;
        let f = record(&value, 200, 10)?;
        ensure!(
            f[2].text()? == "HyperNetLocalWithdrawal"
                && f[3].fixed::<32>()? == self.scope.network
                && f[4].fixed::<32>()? == self.scope.incarnation
                && f[5].fixed::<32>()? == self.deployment
                && f[6].fixed::<32>()? == manifest.operator
                && f[7].fixed::<32>()? == manifest.operational_digest()?
                && signatures.len() == 1
                && signatures[0].0 == manifest.operator,
            "local withdrawal receipt does not match registered operator and permanent resources"
        );
        let generation = f[8].uint()?;
        ensure!(
            generation > 0 && matches!(f[9], V::Bool(_)),
            "invalid local withdrawal generation or cleanup state"
        );
        Ok((registration.reference, generation))
    }
}
