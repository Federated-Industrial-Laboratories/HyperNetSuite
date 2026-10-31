// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
pub(crate) use evaluation::evaluate_domain;

impl Statement {
    #[cfg(test)]
    pub fn encode(&self) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(61),
            V::Uint(1),
            self.scope.value(),
            b(&self.request),
            b(&self.challenge),
            b(&self.requester),
            b(&self.recipient),
            V::Uint(self.height),
            b(&self.node),
            b(&self.state),
            V::Uint(self.evaluated_at_ms),
            V::Uint(self.expires_at_ms),
            b(&self.result),
        ]))
    }
}
