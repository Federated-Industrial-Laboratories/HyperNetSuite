// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl AncestryEvidence {
    #[cfg(test)]
    pub(super) fn direct(nodes: Vec<Vec<u8>>) -> Self {
        Self(HistoryEvidence::direct(nodes))
    }

    #[cfg(test)]
    pub(super) fn checkpoint_reply(store: &Store, target: &[u8], bytes: &[u8]) -> Result<Self> {
        Ok(Self(HistoryEvidence::checkpoint_reply(
            store.prefix(),
            target,
            bytes,
        )?))
    }
}
