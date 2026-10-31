// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
pub(super) fn take_signature_statistics() -> SignatureStatistics {
    STATISTICS.with(|cell| cell.replace(SignatureStatistics::default()))
}
