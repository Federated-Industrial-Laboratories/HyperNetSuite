// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Index {
    #[cfg(test)]
    pub fn open_count(&self) -> usize {
        self.deployments
            .keys()
            .filter(|d| !self.withdrawals.contains_key(*d))
            .count()
    }

    #[cfg(test)]
    pub fn extend_reservations(&self, base: &Reservations) -> Reservations {
        let mut output = base.clone();
        for key in &self.reserved {
            if !output.contains(key) {
                output.0.push((7, *key));
            }
        }
        output
    }
}
