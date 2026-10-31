// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl<'a> GovernancePrepared<'a> {
    #[cfg(test)]
    fn finish(
        self,
        reply: CertifiedReply,
        ancestry: Vec<Vec<u8>>,
        store: &mut Store,
        session: &mut Session,
        clock: &mut impl FnMut() -> Result<ClockHealth>,
    ) -> Result<Outcome> {
        self.finish_evidence(
            reply,
            AncestryEvidence::direct(ancestry),
            store,
            session,
            clock,
        )
    }
}
