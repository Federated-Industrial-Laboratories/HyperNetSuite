// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
pub fn evaluate(
    state: &State,
    records: &[Vec<u8>],
    reserved: &Reservations,
    intent: &Intent,
    at: u64,
    replay: bool,
) -> Result<Decision> {
    Operation::parse(intent)?.prepare(state, records, reserved, intent, at, replay, true)
}

impl State {
    #[cfg(test)]
    pub fn parse(value: &V, network: Digest, incarnation: Digest) -> Result<Self> {
        Self::parse_inner(value, network, incarnation, false)
    }

    #[cfg(test)]
    pub fn requesters(&self) -> Vec<Key> {
        let mut requesters: Vec<_> = self
            .keys
            .iter()
            .filter_map(|(key, (class, _))| {
                matches!(
                    *class,
                    3 | sealed_identity::ROOT_KEY | sealed_identity::SIGNING_KEY
                )
                .then_some(*key)
            })
            .collect();
        requesters.extend(routes::requesters(self).expect("validated invitation records"));
        requesters.sort();
        requesters.dedup();
        requesters
    }
}
