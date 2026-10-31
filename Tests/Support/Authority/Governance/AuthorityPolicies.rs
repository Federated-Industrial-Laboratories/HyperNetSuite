// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Operation {
    #[cfg(test)]
    pub fn handles(action: &str) -> bool {
        action == "AuthorityPolicyApply"
    }

    #[cfg(test)]
    pub fn parse(intent: &Intent) -> Result<Self> {
        let v = wire::decode(&intent.parameters)?;
        let f = v.array(11)?;
        ensure!(
            Self::handles(&intent.action)
                && f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == intent.action
                && intent.profile_generation == 0,
            "policy action context differs"
        );
        let optional = |v: &V| {
            if *v == V::Null {
                Ok(None)
            } else {
                Ok::<_, anyhow::Error>(Some(v.bytes()?.to_vec()))
            }
        };
        let out = Self {
            grant: id(&f[3])?,
            previous_policy: f[4].bytes()?.to_vec(),
            previous_recovery: f[5].bytes()?.to_vec(),
            policy: f[6].bytes()?.to_vec(),
            recovery: f[7].bytes()?.to_vec(),
            old_authorisation: optional(&f[8])?,
            new_acceptance: optional(&f[9])?,
            snapshot: Snapshot::parse(&f[10])?,
        };
        let old = record_reference(
            &out.previous_policy,
            intent.network,
            intent.incarnation,
            100,
        )?;
        let new = record_reference(&out.policy, intent.network, intent.incarnation, 100)?;
        ensure!(
            intent.resource == intent.network
                && intent.revision == new.generation
                && old.generation.checked_add(1) == Some(new.generation)
                && intent.expected == out.snapshot.references
                && intent.minimum_policy_epoch == out.snapshot.epoch
                && intent.minimum_policy_height == out.snapshot.height,
            "policy proposal differs from signed predecessor snapshot"
        );
        out.validate(intent.network, intent.incarnation)?;
        Ok(out)
    }
}
