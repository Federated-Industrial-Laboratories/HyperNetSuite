// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
pub(crate) fn current_view_for_test(
    store: &Store,
    result: &ResultState,
    now: crate::authority_challenge::Observation,
) -> Result<bool> {
    current_view_at(store, result, now)
}
