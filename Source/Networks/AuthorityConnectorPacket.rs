// SPDX-License-Identifier: MIT
// Remote authority connectors expose only bounded same-network protocol1 control packets.
use crate::{
    authority_proof::{Digest, Scope, SignedRequest},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Result, ensure};

pub(crate) struct Cleanup {
    scope: Scope,
    id: Digest,
    statement: Digest,
    result: Digest,
    not_after_ms: u64,
}
impl Cleanup {
    pub(crate) const MAXIMUM: usize = 1024;

    fn parse(bytes: &[u8], scope: &Scope) -> Result<Self> {
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

pub(crate) fn validate(
    network: Digest,
    incarnation: Digest,
    packet: &[u8],
) -> Result<Option<Cleanup>> {
    let value = wire::decode(packet)?;
    let fields = value.array(5)?;
    let scope = Scope::parse(&fields[2])?;
    ensure!(
        fields[0].uint()? == 41
            && fields[1].uint()? == 1
            && scope.network == network
            && scope.incarnation == incarnation
            && matches!(fields[3].uint()?, 0..=4 | 6 | 7 | 8),
        "authority endpoint refuses management or foreign control frames"
    );
    let body = if matches!(fields[3].uint()?, 1 | 7) {
        V::Null
    } else {
        wire::decode(fields[4].bytes()?)?
    };
    match fields[3].uint()? {
        0 => {
            let submission = body.array(2)?;
            let ordered = wire::decode(submission[0].bytes()?)?;
            let ordered = ordered.array(6)?;
            ensure!(
                ordered[0].uint()? == 22
                    && ordered[1].uint()? == 1
                    && Scope::parse(&ordered[2])? == scope,
                "authority submission context differs"
            );
            let signed = SignedRequest::from_signed(ordered[3].bytes()?)?;
            ensure!(
                signed.network() == network && signed.incarnation() == incarnation,
                "authority submission has another network identity"
            );
        }
        1 | 7 => {
            fields[4].fixed::<32>()?;
        }
        2 => {
            body.array(0)?;
        }
        3 => {
            let body = body.array(3)?;
            body[0].uint()?;
            body[1].fixed::<32>()?;
            body[2].fixed::<32>()?;
        }
        4 => {
            let body = body.array(5)?;
            body[0].uint()?;
            body[1].fixed::<32>()?;
            if body[2] != V::Null {
                body[2].fixed::<32>()?;
            }
            body[3].uint()?;
            if body[4] != V::Null {
                body[4].fixed::<32>()?;
            }
        }
        6 => {
            let body = body.array(2)?;
            let request = crate::authority_read::Request::from_signed(body[0].bytes()?)?;
            ensure!(
                request.scope == scope,
                "fresh read submission context differs"
            );
            crate::authority_read::read_id(body[0].bytes()?, body[1].bytes()?)?;
        }
        8 => return Cleanup::parse(fields[4].bytes()?, &scope).map(Some),
        _ => unreachable!(),
    }
    Ok(None)
}
