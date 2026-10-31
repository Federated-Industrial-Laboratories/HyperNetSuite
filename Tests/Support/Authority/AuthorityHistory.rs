// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl ValidatedCheckpoint {
    #[cfg(test)]
    pub fn statement(&self) -> &[u8] {
        &self.statement
    }
}
