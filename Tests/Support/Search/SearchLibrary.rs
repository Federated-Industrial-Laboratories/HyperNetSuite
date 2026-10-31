// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Library {
    #[cfg(test)]
    pub fn retain(&mut self, entry: Entry) -> Result<()> {
        self.retain_many(vec![entry])
    }
}
