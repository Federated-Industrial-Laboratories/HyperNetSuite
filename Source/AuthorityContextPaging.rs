// SPDX-License-Identifier: MIT
// Certified pages remain private and incomplete until their complete records root is checked.
use super::*;

pub(super) const PAGE_BYTES: usize = 32768;
const STAGING: &str = "GovernancePages.cbor";

fn exists(store: &Store) -> Result<bool> {
    let name = CString::new(STAGING)?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            store.profile_directory().as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    ensure!(
        error.raw_os_error() == Some(libc::ENOENT),
        "cannot inspect context staging: {error}"
    );
    Ok(false)
}
pub(super) fn clear(store: &Store) -> Result<()> {
    ensure!(
        store.resume_ordinary()?.is_none(),
        "resolve or explicitly fence the pending request before restarting discovery"
    );
    if exists(store)? {
        files::remove_private_at(store.profile_directory(), OsStr::new(STAGING))?;
    }
    Ok(())
}
pub(super) fn root(scope: &proof::Scope, refs: &[VersionRef]) -> Result<[u8; 32]> {
    Ok(wire::digest(&wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("AuthorityRecordsView".into()),
        a(vec![
            b(&scope.network),
            b(&scope.incarnation),
            V::Uint(scope.epoch),
        ]),
        a(refs.iter().map(version_value).collect()),
    ]))?))
}
#[derive(Clone, Debug)]
pub(super) struct Pages {
    pub root: [u8; 32],
    pub count: usize,
    pub entries: Vec<Vec<u8>>,
}
impl Pages {
    pub fn load(
        descriptor: &TrustDescriptor,
        grant: [u8; 32],
        store: &Store,
    ) -> Result<Option<Self>> {
        if !exists(store)? {
            return Ok(None);
        }
        let bytes = files::read_at(
            store.profile_directory(),
            OsStr::new(STAGING),
            CONTEXT_LIMIT,
            true,
        )?;
        let decoded = wire::decode_state(&bytes)?;
        let f = record(&decoded, 200, 8)?;
        ensure!(
            f[2].text()? == "AuthorityContextPages"
                && proof::Scope::parse(&f[3])? == *descriptor.scope()
                && f[4].fixed::<32>()? == grant,
            "context staging belongs to another discovery; restart it explicitly"
        );
        let pages = Self {
            root: f[5].fixed()?,
            count: usize::try_from(f[6].uint()?)?,
            entries: f[7]
                .list(MAX_RECORDS)?
                .iter()
                .map(|v| Ok(v.bytes()?.to_vec()))
                .collect::<Result<_>>()?,
        };
        ensure!(
            pages.root != [0; 32]
                && pages.count > 0
                && pages.count <= MAX_RECORDS
                && !pages.entries.is_empty()
                && pages.entries.len() <= pages.count,
            "invalid context staging dimensions"
        );
        let scope = descriptor.scope();
        let refs = Governance::record_versions(scope.network, scope.incarnation, &pages.entries)?;
        ensure!(
            refs.iter().all(|r| store.generations().contains(r)),
            "context staging lacks retained certified hashes; restart discovery explicitly"
        );
        Ok(Some(pages))
    }
    pub fn cursor(&self) -> V {
        a(vec![
            b(&self.root),
            V::Uint(self.count as u64),
            V::Uint(self.entries.len() as u64),
        ])
    }
    pub fn complete(&self) -> bool {
        self.entries.len() == self.count
    }
    pub fn save(&self, descriptor: &TrustDescriptor, grant: [u8; 32], store: &Store) -> Result<()> {
        let bytes = wire::encode_state(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityContextPages".into()),
            descriptor.scope().value(),
            b(&grant),
            b(&self.root),
            V::Uint(self.count as u64),
            a(self.entries.iter().map(|v| b(v)).collect()),
        ]))?;
        ensure!(
            bytes.len() <= CONTEXT_LIMIT,
            "context staging exceeds its bound"
        );
        files::atomic_at(store.profile_directory(), OsStr::new(STAGING), &bytes, true)
    }
}
pub(super) fn resume(
    descriptor: &TrustDescriptor,
    grant: [u8; 32],
    store: &Store,
    cursor: &V,
) -> Result<Option<Pages>> {
    if *cursor == V::Null {
        return Ok(None);
    }
    let f = cursor.array(3)?;
    let root = f[0].fixed::<32>()?;
    let count = usize::try_from(f[1].uint()?)?;
    let start = usize::try_from(f[2].uint()?)?;
    ensure!(
        start > 0 && start < count && count <= MAX_RECORDS,
        "invalid pending page cursor"
    );
    let mut pages = Pages::load(descriptor, grant, store)?
        .context("pending page requires its retained preceding pages")?;
    ensure!(
        pages.root == root && pages.count == count && pages.entries.len() >= start,
        "pending page differs from retained discovery"
    );
    // The cache callback can finish before the request's local completion is durable.
    pages.entries.truncate(start);
    Ok(Some(pages))
}
pub(super) fn append(
    descriptor: &TrustDescriptor,
    before: Option<&Pages>,
    body: &V,
    refs: &[VersionRef],
) -> Result<Pages> {
    let f = body.array(5)?;
    let root = f[0].fixed::<32>()?;
    let count = usize::try_from(f[1].uint()?)?;
    let start = usize::try_from(f[2].uint()?)?;
    let entries = f[4]
        .list(64)?
        .iter()
        .map(|v| Ok(v.bytes()?.to_vec()))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        root != [0; 32]
            && count > 0
            && count <= MAX_RECORDS
            && !entries.is_empty()
            && start == before.map_or(0, |p| p.entries.len())
            && start
                .checked_add(entries.len())
                .is_some_and(|end| end <= count)
            && before.is_none_or(|p| p.root == root && p.count == count),
        "context page changed or skipped its records view"
    );
    let end = start + entries.len();
    ensure!(
        f[3] == if end == count {
            V::Null
        } else {
            V::Uint(end as u64)
        },
        "context page cursor is not contiguous or terminal"
    );
    let scope = descriptor.scope();
    ensure!(
        Governance::record_versions(scope.network, scope.incarnation, &entries)? == refs,
        "context page records differ from their certified references"
    );
    let mut accumulated = before.map_or_else(Vec::new, |p| p.entries.clone());
    accumulated.extend(entries);
    let all = Governance::record_versions(scope.network, scope.incarnation, &accumulated)?;
    if end == count {
        ensure!(
            self::root(scope, &all)? == root,
            "complete context differs from its certified records root"
        );
    }
    Ok(Pages {
        root,
        count,
        entries: accumulated,
    })
}
