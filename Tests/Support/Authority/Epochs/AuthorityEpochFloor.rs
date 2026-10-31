// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Store {
    #[cfg(test)]
    pub fn epoch_sealed(&self) -> bool {
        self.stored.sealed.is_some()
    }
}
