// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
use crate::authority_challenge::boot_time_ms;

impl Prepared<'_> {
    #[cfg(test)]
    pub fn ordered_request(&self) -> &[u8] {
        &self.ordered
    }

    #[cfg(test)]
    pub fn cancel(self, session: &mut Session) -> Result<()> {
        session.discard(&self.challenge)
    }

    #[cfg(test)]
    fn ancestry_reply(&self, bytes: &[u8], tip: &[u8]) -> Result<Vec<Vec<u8>>> {
        let value = wire::decode(bytes)?;
        let f = record(&value, 43, 4)?;
        ensure!(
            proof::Scope::parse(&f[2])? == *self.context.descriptor.scope(),
            "ancestry response scope differs"
        );
        let nodes = f[3]
            .list(128)?
            .iter()
            .map(|v| Ok(v.bytes()?.to_vec()))
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            nodes.last().is_some_and(|node| node == tip),
            "ancestry does not end at requested certified node"
        );
        Ok(nodes)
    }

    /// External transport may supply bytes, but all acceptance and effect checks remain fixed here.
    #[cfg(test)]
    pub fn accept(
        self,
        local_reply: &[u8],
        ancestry: Vec<Vec<u8>>,
        store: &mut Store,
        session: &mut Session,
        mut clock: impl FnMut() -> Result<ClockHealth>,
    ) -> Result<Inspection> {
        let challenge = self.challenge.clone();
        let result = (|| {
            let certified = self
                .local_reply(local_reply)?
                .context("inspection is not certified")?;
            self.finish(certified, ancestry, store, session, &mut clock)
        })();
        if result.is_err() {
            session.discard(&challenge)?;
        }
        result
    }

    #[cfg(test)]
    fn finish(
        self,
        reply: CertifiedReply,
        ancestry: Vec<Vec<u8>>,
        store: &mut Store,
        session: &mut Session,
        clock: &mut impl FnMut() -> Result<ClockHealth>,
    ) -> Result<Inspection> {
        self.finish_evidence(
            reply,
            AncestryEvidence::direct(ancestry),
            store,
            session,
            clock,
        )
    }
}
