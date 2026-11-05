// SPDX-License-Identifier: MIT
// Optional cleanup binds one consumed result and cannot supply authority.
use super::*;

pub(crate) struct Acknowledgement {
    scope: Scope,
    id: Digest,
    statement: Digest,
    result: Digest,
    not_after_ms: u64,
}
impl Acknowledgement {
    pub(crate) fn sign(
        statement: &Statement,
        key: &SigningKey,
        not_after_ms: u64,
    ) -> Result<Vec<u8>> {
        ensure!(
            key.verifying_key().to_bytes() == statement.requester
                && statement.requester == statement.recipient
                && not_after_ms > 0
                && not_after_ms <= statement.expires_at_ms,
            "fresh acknowledgement signer or deadline differs from consumed result"
        );
        wire::sign_envelope(
            &wire::encode(&a(vec![
                V::Uint(63),
                V::Uint(1),
                statement.scope.value(),
                b(&bound_id(&statement.request, &statement.challenge)?),
                b(&wire::digest(&statement.encode()?)),
                b(&statement.result),
                V::Uint(not_after_ms),
            ]))?,
            key,
        )
    }
    pub(crate) fn packet(&self, signed: &[u8]) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(41),
            V::Uint(1),
            self.scope.value(),
            V::Uint(8),
            b(signed),
        ]))
    }

    pub(crate) const MAXIMUM: usize = 1024;

    pub(crate) fn parse(bytes: &[u8], scope: &Scope) -> Result<Self> {
        ensure!(
            bytes.len() <= Self::MAXIMUM,
            "fresh acknowledgement exceeds bound"
        );
        let (payload, signatures) = wire::envelope(bytes, 1)?;
        let value = wire::decode(&payload)?;
        let fields = value.array(7)?;
        ensure!(
            fields[0].uint()? == 63
                && fields[1].uint()? == 1
                && signatures.len() == 1
                && Scope::parse(&fields[2])? == *scope,
            "fresh acknowledgement context differs"
        );
        let result = Self {
            scope: scope.clone(),
            id: fields[3].fixed()?,
            statement: fields[4].fixed()?,
            result: fields[5].fixed()?,
            not_after_ms: fields[6].uint()?,
        };
        ensure!(
            result.id != [0; 32]
                && result.statement != [0; 32]
                && result.result != [0; 32]
                && result.not_after_ms > 0,
            "fresh acknowledgement binding is empty"
        );
        Ok(result)
    }
    pub(crate) fn deadline(
        &self,
        observed: crate::authority_challenge::Observation,
        original: u64,
    ) -> Result<u64> {
        use crate::authority_challenge::{DELTA_MS, MAXIMUM_DURATION_MS};
        let latest_wall = observed.wall_ms.saturating_add(DELTA_MS);
        ensure!(
            self.not_after_ms > latest_wall
                && self.not_after_ms <= observed.wall_ms.saturating_add(MAXIMUM_DURATION_MS),
            "fresh acknowledgement deadline expired or exceeds its original read bound"
        );
        Ok(original.min(
            observed
                .boot_ms
                .saturating_add(self.not_after_ms - latest_wall),
        ))
    }
    pub(crate) fn receipt(&self, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() <= Self::MAXIMUM,
            "fresh acknowledgement receipt exceeds bound"
        );
        let value = wire::decode(bytes)?;
        let fields = value.array(7)?;
        ensure!(
            fields[0].uint()? == 64
                && fields[1].uint()? == 1
                && Scope::parse(&fields[2])? == self.scope
                && fields[3].fixed::<32>()? == self.id
                && fields[4].fixed::<32>()? == self.statement
                && fields[5].fixed::<32>()? == self.result
                && matches!(fields[6], V::Bool(_)),
            "fresh acknowledgement receipt differs"
        );
        Ok(())
    }
    pub(crate) fn not_released(&self) -> Result<Vec<u8>> {
        wire::encode(&V::Array(vec![
            V::Uint(64),
            V::Uint(1),
            self.scope.value(),
            V::Bytes(self.id.to_vec()),
            V::Bytes(self.statement.to_vec()),
            V::Bytes(self.result.to_vec()),
            V::Bool(false),
        ]))
    }
}
