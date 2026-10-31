// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
pub fn retained_inputs(_state: &State) -> Result<Vec<Reference>> {
    Ok(vec![])
}
