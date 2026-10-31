// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl LocalControl {
    #[cfg(test)]
    pub(crate) fn prepared_for_test(
        route: crate::private_route_client::Prepared,
        store: &crate::authority_floor::Store,
    ) -> Result<Self> {
        Self {
            endpoint: Endpoint::Relay(Box::new(route)),
            history: None,
        }
        .prefetch_authority(store)
    }

    #[cfg(test)]
    pub(crate) fn validate_prefetch_for_test(
        store: &crate::authority_floor::Store,
        bytes: &[u8],
    ) -> Result<bool> {
        Ok(PrefetchedHistory::parse(store, bytes)?.is_some())
    }

    #[cfg(test)]
    pub(crate) fn with_prefetch_for_test(
        mut self,
        store: &crate::authority_floor::Store,
        bytes: &[u8],
    ) -> Result<Self> {
        self.history = PrefetchedHistory::parse(store, bytes)?;
        Ok(self)
    }
}
