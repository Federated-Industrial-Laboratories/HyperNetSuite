// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Container {
    #[cfg(test)]
    pub fn content_digests(&self) -> (Digest, Vec<(Digest, Digest)>) {
        (
            ciphertext_digest(&self.source),
            self.assets
                .iter()
                .map(|a| (a.id, ciphertext_digest(&a.bytes)))
                .collect(),
        )
    }
}
