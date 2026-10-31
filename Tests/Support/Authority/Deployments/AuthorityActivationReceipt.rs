// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
use ed25519_dalek::SigningKey;

impl Receipt {
    #[cfg(test)]
    pub fn create(
        request: &Request,
        challenge: &[u8],
        ordered: &[u8],
        result: &proof::VerifiedResult,
        signer: &SigningKey,
        completed_at: u64,
    ) -> Result<Self> {
        ensure!(
            signer.verifying_key().to_bytes() == request.operation().recipient
                && result.disposition() == proof::Disposition::Permit,
            "activation completion requires its exact serving recipient"
        );
        let signed = wire::sign_envelope(
            &wire::encode(&a(vec![
                V::Uint(200),
                V::Uint(1),
                V::Text("RuntimeActivationComplete".into()),
                result.point().prefix().scope().value(),
                b(&request.intent().digest),
                b(&result.executed.result),
                V::Uint(request.operation().role),
                V::Uint(request.operation().local_generation),
                V::Uint(completed_at),
            ]))?,
            signer,
        )?;
        let continuity = result.continuity();
        let history = result.history();
        let bytes = wire::encode_state(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("RuntimeActivationReceipt".into()),
            b(&request.encode()?),
            b(challenge),
            b(ordered),
            b(result.operation_result_bytes()),
            b(result.point().certificate()),
            a(continuity.ancestry.iter().map(|n| b(n)).collect()),
            history.map_or(V::Null, |h| b(h.checkpoint().canonical_proof())),
            history.map_or(V::Null, |h| b(h.canonical())),
            b(&signed),
        ]))?;
        Self::parse(&bytes)
    }
}
