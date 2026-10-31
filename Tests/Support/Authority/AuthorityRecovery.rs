// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Predecessor {
    #[cfg(test)]
    pub fn new(bootstrap: &Verified, prefix: &Prefix) -> Result<Self> {
        let scope = bootstrap.descriptor().scope();
        let reference = VersionRef {
            kind: 114,
            id: scope.network,
            generation: 1,
            digest: wire::digest(&bootstrap.recovery_payload),
        };
        Self::retained(bootstrap, prefix, &bootstrap.recovery_payload, &reference)
    }

    #[cfg(test)]
    pub fn point(&self) -> &V {
        &self.point
    }
}
