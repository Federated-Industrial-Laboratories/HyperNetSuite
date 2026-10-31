// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Request {
    #[cfg(test)]
    pub fn signed(&self) -> &[u8] {
        &self.signed
    }
}
