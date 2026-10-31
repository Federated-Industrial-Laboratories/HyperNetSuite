// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Store {
    /// The lower bound is an independent credential start, or zero when none applies.
    /// The original live challenge already establishes causal issuance through BOOTTIME.
    #[cfg(test)]
    pub fn accept(
        &mut self,
        result: VerifiedResult,
        session: &mut Session,
        health: ClockHealth,
        not_before_ms: u64,
    ) -> Result<DurablePermit> {
        self.accept_with_clock(result, session, &mut || Ok(health), not_before_ms)
    }
}

impl DurablePermit {
    #[cfg(test)]
    pub fn perform<T>(
        self,
        store: &mut Store,
        session: &mut Session,
        health: ClockHealth,
        requested_effect: u64,
        check_current_restrictions: impl FnMut(&proof::Restrictions) -> Result<()>,
        effect: impl FnOnce(&OperationResult, &Store) -> Result<T>,
    ) -> Result<T> {
        self.perform_with_clock(
            store,
            session,
            &mut || Ok(health),
            requested_effect,
            check_current_restrictions,
            effect,
        )
    }

    #[cfg(test)]
    pub fn perform_once<T>(
        self,
        store: &mut Store,
        session: &mut Session,
        health: ClockHealth,
        requested_effect: u64,
        check_current_restrictions: impl FnMut(&proof::Restrictions) -> Result<()>,
        effect: impl FnOnce(&OperationResult, &Store) -> Result<T>,
    ) -> Result<T> {
        ensure!(
            matches!(self.result.request(), proof::SignedRequest::Intent(_)),
            "stream controls cannot invoke irreversible handlers"
        );
        self.run(
            store,
            session,
            &mut || Ok(health),
            requested_effect,
            check_current_restrictions,
            effect,
            true,
        )
    }
}
