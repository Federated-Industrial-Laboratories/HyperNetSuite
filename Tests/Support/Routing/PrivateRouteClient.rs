// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl ContentPool {
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.route.is_none()
    }
}

impl Prepared {
    #[cfg(test)]
    pub(crate) fn from_channel(
        endpoint: Endpoint,
        session: crate::route_connector::Session<'static>,
        deadline: u64,
    ) -> Self {
        Self {
            endpoint,
            deadline,
            session: std::cell::RefCell::new(session),
            observed: std::cell::Cell::new(false),
            authority: Weak::new(),
            reused: false,
            completed_floor: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn in_pool(mut self, pool: &Arc<Mutex<AuthorityPool>>) -> Self {
        self.authority = Arc::downgrade(pool);
        self
    }
}
