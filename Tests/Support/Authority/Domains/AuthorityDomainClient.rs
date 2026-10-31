// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl<'a> Prepared<'a> {
    #[cfg(test)]
    fn new(
        bootstrap: &'a Verified,
        request: Request,
        cache: Cache,
        signer: &SigningKey,
        store: &mut Store,
        session: &mut Session,
        health: ClockHealth,
    ) -> Result<Self> {
        Self::new_with_objects(
            bootstrap,
            request,
            cache,
            signer,
            store,
            session,
            vec![],
            &mut || Ok(health),
        )
    }

    #[cfg(test)]
    fn finish(
        self,
        reply: CertifiedReply,
        evidence: AncestryEvidence,
        store: &mut Store,
        session: &mut Session,
        clock: &mut impl FnMut() -> Result<ClockHealth>,
    ) -> Result<ResultState> {
        Ok(self
            .finish_with_objects(
                reply,
                evidence,
                crate::authority_objects::Resolved::default(),
                store,
                session,
                clock,
            )?
            .0)
    }
}
