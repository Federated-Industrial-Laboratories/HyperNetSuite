// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Socket<'_> {
    #[cfg(test)]
    fn reusable(&self) -> bool {
        self.reusable_for(crate::authority_challenge::MAXIMUM_DURATION_MS)
    }

    #[cfg(test)]
    fn reusable_at(&self, now: u64) -> bool {
        self.reusable_for_at(now, crate::authority_challenge::MAXIMUM_DURATION_MS)
    }
}
