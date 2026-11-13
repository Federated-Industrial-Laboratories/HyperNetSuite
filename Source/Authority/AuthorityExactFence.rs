// SPDX-License-Identifier: MIT
// Bound fences close one retained ordinary request generation and recognize its certified successor.
use super::*;
use crate::authority_proof::{CompletionMetadata, Digest, FenceOutcome, Intent};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FenceTarget {
    pub generation: u64,
    pub generation_id: Digest,
    pub sequence: u64,
    pub intent: Digest,
}
impl FenceTarget {
    pub fn matches(&self, intent: &Intent) -> Result<()> {
        ensure!(
            self.generation > 0
                && self.generation.checked_add(1).is_some()
                && self.generation == intent.generation
                && self.generation_id == intent.generation_id
                && self.sequence == intent.sequence
                && self.intent == intent.digest,
            "fence target differs from the exact retained request"
        );
        Ok(())
    }
    fn predecessor(&self, retired: u64, completion: Option<&CompletionMetadata>) -> Result<()> {
        ensure!(
            retired < self.sequence
                && completion.is_none_or(|c| {
                    c.sequence < self.sequence
                        || c.sequence == self.sequence && c.intent == self.intent
                }),
            "fence comparison advances beyond or conflicts with its exact target"
        );
        Ok(())
    }
    fn before(&self, metadata: &OwnStreamMetadata) -> Result<()> {
        let state = metadata.state().context("fence target stream absent")?;
        ensure!(
            state.generation == self.generation && state.generation_id == self.generation_id,
            "fence target generation differs"
        );
        self.predecessor(state.retired_through, state.completion.as_ref())
    }
    fn after(&self, metadata: &OwnStreamMetadata, fence: Option<Digest>) -> Result<()> {
        let state = metadata.state().context("fence successor stream absent")?;
        let last = state
            .last_fence
            .as_ref()
            .context("certified fence predecessor absent")?;
        ensure!(
            self.generation.checked_add(1) == Some(state.generation)
                && last.previous_generation == self.generation
                && last.previous_generation_id == self.generation_id
                && state.generation_id == last.digest
                && fence.is_none_or(|digest| last.digest == digest),
            "certified fence successor differs from the exact target"
        );
        self.predecessor(
            last.previous_retired_through,
            last.previous_completion.as_ref(),
        )
    }
}

/// The caller holds Store's requester lock throughout validation, status, preparation and retry.
#[allow(clippy::too_many_arguments)]
pub(crate) fn fence_exact_local(
    descriptor: &TrustDescriptor,
    path: &Path,
    signer: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    mut clock: impl FnMut() -> Result<ClockHealth>,
    target: FenceTarget,
) -> Result<StreamResponse> {
    store.require_requester(signer.verifying_key().to_bytes())?;
    let original = store.retained_fence_target(target.intent)?;
    let intent = Intent::from_signed(original.signed())?;
    target.matches(&intent)?;
    ensure!(
        intent.requester == store.requester(),
        "fence target requester differs"
    );
    let prepared = if let Some(pending) = store.resume_fence()? {
        let SignedRequest::StreamFence(fence) = SignedRequest::from_signed(pending.signed())?
        else {
            bail!("pending fence request differs");
        };
        ensure!(
            fence.expected_generation == target.generation
                && fence.expected_generation_id == target.generation_id
                && store
                    .fence_subject()?
                    .is_some_and(|subject| subject.digest() == target.intent),
            "another exact fence is already pending"
        );
        let metadata = OwnStreamMetadata::parse(
            pending
                .expected_metadata()
                .context("fence comparison absent")?,
        )?;
        target.before(&metadata)?;
        pending
    } else {
        let metadata = status_local(descriptor, path, signer, store, session, &mut clock)?;
        if metadata
            .state()
            .is_some_and(|s| s.generation != target.generation)
        {
            target.after(&metadata, None)?;
            return Ok(StreamResponse::Fence {
                outcome: FenceOutcome::AlreadyApplied,
                metadata,
            });
        }
        target.before(&metadata)?;
        ensure!(
            store
                .resume_ordinary()?
                .is_some_and(|pending| pending.digest() == target.intent),
            "only the exact pending ordinary request can prepare this fence"
        );
        prepare_fence(descriptor, signer, store, &metadata)?
    };
    let digest = prepared.digest();
    let response = submit_fence(
        descriptor, path, signer, store, session, &mut clock, prepared,
    )?;
    let metadata = match &response {
        StreamResponse::Fence {
            outcome: FenceOutcome::Applied | FenceOutcome::AlreadyApplied,
            metadata,
        } => metadata,
        _ => bail!("exact fence was not applied"),
    };
    target.after(metadata, Some(digest))?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn metadata(
        target: FenceTarget,
        generation: u64,
        id: Digest,
        retired: u64,
        completion: V,
    ) -> OwnStreamMetadata {
        let scope = proof::Scope {
            network: [1; 32],
            incarnation: [2; 32],
            configuration: [3; 32],
            epoch: 0,
        };
        let key = SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes();
        let bytes = wire::encode(&a(vec![
            V::Uint(56),
            V::Uint(1),
            scope.value(),
            b(&key),
            V::Bool(true),
            V::Uint(generation + 1),
            b(&[88; 32]),
            V::Uint(0),
            V::Null,
            a(vec![
                b(&[88; 32]),
                b(&target.intent),
                V::Uint(generation),
                b(&id),
                V::Uint(retired),
                completion,
            ]),
        ]))
        .unwrap();
        OwnStreamMetadata::parse(&bytes).unwrap()
    }
    #[test]
    fn exact_fence_successor_rejects_unrelated_generation_and_conflicting_history() {
        let target = FenceTarget {
            generation: 2,
            generation_id: [22; 32],
            sequence: 2,
            intent: [77; 32],
        };
        let completion = |sequence: u64, intent: Digest| {
            a(vec![
                V::Uint(sequence),
                b(&intent),
                V::Uint(0),
                V::Uint(0),
                b(&[99; 32]),
            ])
        };
        for (retired, original) in [
            (0, V::Null),
            (0, completion(1, [76; 32])),
            (1, completion(2, target.intent)),
        ] {
            let value = metadata(target, 2, target.generation_id, retired, original);
            target.after(&value, Some([88; 32])).unwrap();
            target.after(&value, None).unwrap();
            assert!(target.after(&value, Some([89; 32])).is_err());
        }
        for value in [
            metadata(target, 3, target.generation_id, 0, V::Null),
            metadata(target, 2, [23; 32], 0, V::Null),
            metadata(target, 2, target.generation_id, 1, completion(2, [78; 32])),
            metadata(target, 2, target.generation_id, 2, V::Null),
            metadata(target, 2, target.generation_id, 2, completion(3, [79; 32])),
        ] {
            assert!(target.after(&value, None).is_err());
        }
    }
}
