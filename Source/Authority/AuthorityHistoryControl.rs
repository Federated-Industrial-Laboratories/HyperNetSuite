// SPDX-License-Identifier: MIT
// Requester adaptation of the shared bounded private-control evidence exchange.
use super::*;
use crate::authority_local_transport::HistoryEvidence;
pub(super) struct AncestryEvidence(HistoryEvidence);
impl std::ops::Deref for AncestryEvidence {
    type Target = HistoryEvidence;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl AncestryEvidence {
    pub(super) fn from_shared(evidence: HistoryEvidence) -> Self {
        Self(evidence)
    }
    pub(super) fn attach(
        &self,
        store: &Store,
        result: proof::VerifiedResult,
    ) -> Result<proof::VerifiedResult> {
        self.0.attach(store, result)
    }
    pub(super) fn fetch(
        control: &LocalControl,
        store: &Store,
        target: &[u8],
        deadline: u64,
    ) -> Result<Self> {
        Ok(Self(HistoryEvidence::fetch(
            control,
            store.prefix(),
            store.tree_head(),
            target,
            deadline,
        )?))
    }
}

#[cfg(test)]
include!("../../Tests/Support/Authority/AuthorityHistoryControl.rs");
