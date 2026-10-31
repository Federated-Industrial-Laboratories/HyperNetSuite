// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Copy {
    #[cfg(test)]
    pub fn payload(&self, network: Digest, incarnation: Digest) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("PageContentCopy".into()),
            b(&network),
            b(&incarnation),
            reference(&self.placement),
            reference(&self.host),
            b(&self.digest),
            V::Uint(self.bytes),
            b(&self.request),
            V::Uint(self.recorded_ms),
            V::Uint(self.expires_ms),
        ]))
    }
}
