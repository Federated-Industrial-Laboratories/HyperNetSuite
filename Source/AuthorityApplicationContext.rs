// SPDX-License-Identifier: MIT
// Selected delegation and lifecycle caches authenticate only their exact retained reference sets.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    pub parent: [u8; 32],
    pub tier: [u8; 32],
    pub child: Option<[u8; 32]>,
}
impl Selection {
    fn value(&self) -> V {
        a(vec![
            b(&self.parent),
            b(&self.tier),
            self.child.map_or(V::Null, |v| b(&v)),
        ])
    }
    fn name(&self) -> Result<String> {
        Ok(format!(
            "Delegation{}.cbor",
            hex::encode(wire::digest(&wire::encode(&self.value())?))
        ))
    }
}
pub(super) fn point(prefix: &Prefix) -> V {
    a(vec![
        V::Uint(prefix.scope().epoch),
        V::Uint(prefix.height()),
        b(prefix.policy_state()),
    ])
}
pub(super) fn versions(entries: &[Vec<u8>]) -> Result<Vec<VersionRef>> {
    let refs = entries
        .iter()
        .map(|bytes| applications::record_reference(bytes))
        .collect::<Result<Vec<_>>>()?;
    proof::validate_versions(&refs, 512)?;
    Ok(refs)
}
fn check_minima(current: &[VersionRef], minimum: &[VersionRef], capability: bool) -> Result<()> {
    for v in current {
        if let Some(prior) = minimum.iter().find(|p| p.index() == v.index()) {
            ensure!(
                v.generation >= prior.generation
                    && (v.generation != prior.generation || v.digest == prior.digest),
                "application result conflicts with retained generation"
            );
        }
    }
    for prior in minimum
        .iter()
        .filter(|p| p.kind == 128 || capability && p.kind == 126)
    {
        let target = if prior.kind == 126 { 102 } else { 127 };
        ensure!(
            !current.iter().any(|v| v.kind == target && v.id == prior.id)
                || current.contains(prior),
            "application result omitted a retained restriction"
        );
    }
    Ok(())
}
pub(super) fn relevant_minima(current: &[VersionRef], minimum: &[VersionRef]) -> Result<()> {
    check_minima(current, minimum, true)
}
pub(super) fn metadata_minima(current: &[VersionRef], minimum: &[VersionRef]) -> Result<()> {
    check_minima(current, minimum, false)
}
pub(super) fn merged(bootstrap: &Verified, entries: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    let mut output = BTreeMap::new();
    for bytes in bootstrap.governance_records().iter().chain(entries) {
        let r = versions(std::slice::from_ref(bytes))?.remove(0);
        if let Some((old, _)) = output.get(&r.index()) {
            let old: &VersionRef = old;
            ensure!(
                r.generation >= old.generation
                    && (r.generation != old.generation || r.digest == old.digest),
                "selected context conflicts with pinned bootstrap"
            );
        }
        output.insert(r.index(), (r, bytes.clone()));
    }
    Ok(output.into_values().map(|(_, v)| v).collect())
}
/// This cache proves only its selected delegation closure and never complete governance.
pub struct DelegationContext {
    pub selection: Selection,
    pub(super) descriptor: TrustDescriptor,
    pub(super) entries: Vec<Vec<u8>>,
}
impl DelegationContext {
    pub fn record(&self, kind: u64, id: [u8; 32]) -> Result<&[u8]> {
        self.entries
            .iter()
            .find(|bytes| {
                versions(std::slice::from_ref(*bytes)).is_ok_and(|v| v[0].index() == (kind, id))
            })
            .map(Vec::as_slice)
            .context("selected context lacks the exact record")
    }
    pub fn version(&self, kind: u64, id: [u8; 32]) -> Result<VersionRef> {
        versions(&self.entries)?
            .into_iter()
            .find(|v| v.index() == (kind, id))
            .context("selected context lacks the exact reference")
    }
    pub fn current(&self, store: &Store) -> Result<()> {
        ensure!(
            *store.prefix().scope() == *self.descriptor.scope(),
            "selected context belongs to another authority"
        );
        let refs = versions(&self.entries)?;
        relevant_minima(&refs, store.generations())?;
        for r in refs {
            ensure!(
                store.generations().contains(&r),
                "selected context is not authenticated by retained floor"
            );
        }
        Ok(())
    }
    pub fn load(bootstrap: &Verified, store: &Store, selection: Selection) -> Result<Self> {
        let name = selection.name()?;
        let bytes = files::read_at(store.profile_directory(), OsStr::new(&name), LIMIT, true)?;
        let value = wire::decode(&bytes)?;
        let f = record(&value, 200, 6)?;
        ensure!(
            bootstrap.fully_accepted()
                && f[2].text()? == "AuthorityDelegationCache"
                && bootstrap.descriptor().canonical() == store.initial_descriptor().canonical()
                && proof::Scope::parse(&f[3])? == *store.descriptor().scope()
                && f[4] == selection.value(),
            "selected context cache belongs to another scope"
        );
        let entries = f[5]
            .list(64)?
            .iter()
            .map(|v| Ok(v.bytes()?.to_vec()))
            .collect::<Result<Vec<_>>>()?;
        let context = Self {
            selection,
            descriptor: store.descriptor().clone(),
            entries,
        };
        Governance::parse(
            context.descriptor.scope().network,
            context.descriptor.scope().incarnation,
            &merged(bootstrap, &context.entries)?,
        )?;
        context.current(store)?;
        Ok(context)
    }
    pub(super) fn save(&self, store: &Store) -> Result<()> {
        self.current(store)?;
        let bytes = wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityDelegationCache".into()),
            self.descriptor.scope().value(),
            self.selection.value(),
            a(self.entries.iter().map(|v| b(v)).collect()),
        ]))?;
        ensure!(bytes.len() <= LIMIT, "selected context cache exceeds bound");
        files::atomic_at(
            store.profile_directory(),
            OsStr::new(&self.selection.name()?),
            &bytes,
            true,
        )
    }
    pub fn refresh_local(
        bootstrap: &Verified,
        selection: Selection,
        path: &Path,
        signer: &SigningKey,
        store: &mut Store,
        session: &mut Session,
        mut clock: impl FnMut() -> Result<ClockHealth>,
    ) -> Result<Self> {
        stream_client::ensure_stream(
            &store.descriptor().clone(),
            path,
            signer,
            store,
            session,
            &mut clock,
        )?;
        let request = Request::Context(selection);
        let pending = Prepared::new(
            bootstrap,
            request,
            None,
            None,
            signer,
            store,
            session,
            clock()?,
        )?;
        let result = pending.local(path, store, session, &mut clock)?;
        result
            .context
            .context("context response did not contain selected records")
    }
}
fn state_name(application: [u8; 32]) -> String {
    format!("Application{}.cbor", hex::encode(application))
}
pub(super) fn save_state(store: &Store, application: [u8; 32], entries: &[Vec<u8>]) -> Result<()> {
    let refs = versions(entries)?;
    metadata_minima(&refs, store.generations())?;
    ensure!(
        refs.iter().all(|v| store.generations().contains(v)),
        "application lifecycle cache lacks floor authentication"
    );
    let bytes = wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("AuthorityApplicationCache".into()),
        store.prefix().scope().value(),
        b(&application),
        a(entries.iter().map(|v| b(v)).collect()),
    ]))?;
    ensure!(
        bytes.len() <= 16384,
        "application lifecycle cache exceeds bound"
    );
    files::atomic_at(
        store.profile_directory(),
        OsStr::new(&state_name(application)),
        &bytes,
        true,
    )
}
pub(super) fn save_get(store: &Store, application: [u8; 32], value: &V) -> Result<()> {
    let f = record(value, 201, 7)?;
    let mut entries = vec![f[4].bytes()?.to_vec(), f[5].bytes()?.to_vec()];
    if f[6] != V::Null {
        entries.push(f[6].bytes()?.to_vec());
    }
    membership::sort_records(&mut entries)?;
    save_state(store, application, &entries)
}
pub(super) fn load_state(store: &Store, application: [u8; 32]) -> Result<Vec<Vec<u8>>> {
    let bytes = files::read_at(
        store.profile_directory(),
        OsStr::new(&state_name(application)),
        16384,
        true,
    )?;
    let value = wire::decode(&bytes)?;
    let f = record(&value, 200, 6)?;
    ensure!(
        f[2].text()? == "AuthorityApplicationCache"
            && proof::Scope::parse(&f[3])? == *store.prefix().scope()
            && f[4].fixed::<32>()? == application,
        "application cache belongs to another lifecycle"
    );
    let entries = f[5]
        .list(3)?
        .iter()
        .map(|v| Ok(v.bytes()?.to_vec()))
        .collect::<Result<Vec<_>>>()?;
    let refs = versions(&entries)?;
    metadata_minima(&refs, store.generations())?;
    ensure!(
        refs.iter().all(|v| store.generations().contains(v)),
        "application cache is not authenticated by floor"
    );
    Ok(entries)
}
pub fn withdrawal_target(store: &Store, application: [u8; 32]) -> Result<VersionRef> {
    if let Some(pending) = store.resume_ordinary()? {
        let intent = Intent::from_signed(pending.signed())?;
        ensure!(
            intent.action == "AuthorityApplicationWithdraw" && intent.resource == application,
            "another exact request is pending"
        );
        let value = wire::decode(&intent.parameters)?;
        return membership::version(&record(&value, 200, 5)?[3]);
    }
    versions(&load_state(store, application)?)?
        .into_iter()
        .find(|v| v.kind == 127)
        .context("application admission is missing")
}
fn read_optional(store: &Store, name: &str, limit: usize) -> Result<Option<Vec<u8>>> {
    let name = OsStr::new(name);
    match files::read_at(store.profile_directory(), name, limit, true) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) => {
            let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
            let name_c = CString::new(name.as_bytes())?;
            let code = unsafe {
                libc::fstatat(
                    store.profile_directory().as_raw_fd(),
                    name_c.as_ptr(),
                    st.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            ensure!(
                code != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT),
                "existing application cache cannot be safely read: {error}"
            );
            Ok(None)
        }
    }
}
pub(super) fn check_list_cache(store: &Store, value: &V) -> Result<()> {
    let Some(bytes) = read_optional(store, "ApplicationList.cbor", 65536)? else {
        return Ok(());
    };
    let prior = wire::decode(&bytes)?;
    let f = record(&prior, 200, 6)?;
    ensure!(
        f[2].text()? == "AuthorityApplicationListCache"
            && proof::Scope::parse(&f[3])? == *store.prefix().scope()
            && f[4].fixed::<32>()? == store.requester(),
        "application list cache belongs to another owner"
    );
    let current = record(value, 201, 5)?[4].list(63)?;
    for old in f[5].list(63)? {
        let old = old.array(4)?;
        let row = current
            .iter()
            .find(|r| r.array(4).is_ok_and(|r| r[0] == old[0]))
            .context("application list omitted a retained owner admission")?
            .array(4)?;
        ensure!(
            row[..3] == old[..3] && (old[3] == V::Null || old[3] == row[3]),
            "application list rewrote permanent owner lifecycle"
        );
        for item in &old[1..] {
            if *item != V::Null {
                ensure!(
                    store.generations().contains(&membership::version(item)?),
                    "application list cache lacks floor authentication"
                );
            }
        }
    }
    Ok(())
}
pub(super) fn save_list(store: &Store, value: &V) -> Result<()> {
    let rows = record(value, 201, 5)?[4].clone();
    let bytes = wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("AuthorityApplicationListCache".into()),
        store.prefix().scope().value(),
        b(&store.requester()),
        rows,
    ]))?;
    ensure!(bytes.len() <= 65536, "application list cache exceeds bound");
    files::atomic_at(
        store.profile_directory(),
        OsStr::new("ApplicationList.cbor"),
        &bytes,
        true,
    )
}
