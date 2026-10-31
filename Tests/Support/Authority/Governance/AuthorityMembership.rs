// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Reservations {
    #[cfg(test)]
    pub fn parse(value: &V) -> Result<Self> {
        let mut keys = BTreeSet::new();
        let entries = value
            .list(64)?
            .iter()
            .map(|v| {
                let f = v.array(2)?;
                let pair = (f[0].uint()?, f[1].fixed()?);
                wire::valid_key(&pair.1)?;
                ensure!(
                    pair.0 <= 6 && keys.insert(pair.1),
                    "unknown role or reused reserved key"
                );
                Ok(pair)
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            entries.windows(2).all(|v| v[0] < v[1]),
            "role reservations are not sorted and unique"
        );
        Ok(Self(entries))
    }
}
