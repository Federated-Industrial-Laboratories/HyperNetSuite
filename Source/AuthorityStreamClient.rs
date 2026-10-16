// SPDX-License-Identifier: MIT
// Own-stream controls preserve exact fences and do not grant domain access.
use super::*;
use crate::authority_proof::{OwnStreamMetadata, SignedRequest, StreamResponse};

struct ControlPrepared {
    descriptor: TrustDescriptor,
    request: Vec<u8>,
    expected: Option<Vec<u8>>,
    challenge: Vec<u8>,
    ordered: Vec<u8>,
    deadline: u64,
}
impl ControlPrepared {
    fn new(
        descriptor: &TrustDescriptor,
        request: Vec<u8>,
        expected: Option<Vec<u8>>,
        signer: &SigningKey,
        store: &Store,
        session: &mut Session,
        health: ClockHealth,
    ) -> Result<Self> {
        store.require_requester(signer.verifying_key().to_bytes())?;
        let parsed = SignedRequest::from_signed(&request)?;
        ensure!(
            !matches!(parsed, SignedRequest::Intent(_))
                && parsed.requester() == signer.verifying_key().to_bytes()
                && descriptor.scope() == store.prefix().scope(),
            "stream control differs from the bound requester or configuration"
        );
        let now = health.observe()?;
        let challenge = session.issue(&request, signer, random_id()?, DURATION, health)?;
        let parsed = Challenge::from_signed(&challenge)?;
        let ordered = wire::encode(&a(vec![
            V::Uint(22),
            V::Uint(1),
            descriptor.scope().value(),
            b(&request),
            b(&challenge),
            V::Uint(parsed.expires_at_ms),
        ]))?;
        Ok(Self {
            descriptor: descriptor.clone(),
            request,
            expected,
            challenge,
            ordered,
            deadline: now
                .boot_ms
                .checked_add(DURATION)
                .context("stream control deadline overflow")?,
        })
    }
    fn packet(&self, operation: u64, payload: &[u8]) -> Result<Vec<u8>> {
        let payload = if operation == 0 {
            wire::encode(&a(vec![b(payload), a(vec![])]))?
        } else {
            payload.to_vec()
        };
        wire::encode(&a(vec![
            V::Uint(41),
            V::Uint(1),
            self.descriptor.scope().value(),
            V::Uint(operation),
            b(&payload),
        ]))
    }
    fn exchange(
        &self,
        control: &LocalControl,
        store: &Store,
        clock: &mut impl FnMut() -> Result<ClockHealth>,
    ) -> Result<(CertifiedReply, AncestryEvidence)> {
        let digest = wire::digest(&self.ordered);
        let mut bytes = control.exchange(&self.packet(0, &self.ordered)?, self.deadline)?;
        let reply = loop {
            let value = wire::decode(&bytes)?;
            let f = record(&value, 42, 10)?;
            f[9].array(0)?;
            ensure!(
                proof::Scope::parse(&f[2])? == *self.descriptor.scope()
                    && f[4].uint()? == 0
                    && f[5].fixed::<32>()? == digest,
                "local control refused or returned another stream request"
            );
            match f[3].uint()? {
                0 => {
                    f[6].null()?;
                    f[7].null()?;
                    f[8].null()?;
                }
                1 => {
                    break CertifiedReply {
                        node: f[6].bytes()?.to_vec(),
                        certificate: f[7].bytes()?.to_vec(),
                        result: f[8].bytes()?.to_vec(),
                    };
                }
                _ => bail!("invalid stream control response"),
            }
            clock()?.observe()?;
            std::thread::sleep(Duration::from_millis(remaining(self.deadline)?.min(25)));
            bytes = control.exchange(&self.packet(1, &digest)?, self.deadline)?;
        };
        let evidence = AncestryEvidence::fetch(control, store, &reply.node, self.deadline)?;
        Ok((reply, evidence))
    }
    fn local(
        self,
        control: &LocalControl,
        store: &mut Store,
        session: &mut Session,
        clock: &mut impl FnMut() -> Result<ClockHealth>,
    ) -> Result<StreamResponse> {
        let challenge = self.challenge.clone();
        let result = (|| {
            let (reply, evidence) = self.exchange(control, store, clock)?;
            let verified = proof::verify_response(
                &self.descriptor,
                proof::ProofContext {
                    intent: &self.request,
                    challenge: &self.challenge,
                    restrictions: Restrictions::default(),
                    minimum_height: store.prefix().height(),
                    maximum_effect: 1,
                    expected_stream: self.expected.as_deref(),
                },
                proof::Response {
                    ordered_request: &self.ordered,
                    operation_result: &reply.result,
                    certificate: &reply.certificate,
                    ancestry: &evidence.nodes,
                },
                |_, _, _| bail!("ordinary action cannot use the stream control path"),
            )?;
            let verified = evidence.attach(store, verified)?;
            let response = verified
                .stream_response()
                .context("missing typed stream response")?
                .clone();
            if verified.disposition() != Disposition::Permit {
                let code = verified.code();
                store.observe(verified)?;
                bail!("stream control refused with code {code}");
            }
            let permit = store.accept(verified, session, clock()?, 0)?;
            remaining(self.deadline)?;
            permit.perform(
                store,
                session,
                clock()?,
                1,
                |r| {
                    ensure!(
                        *r == Restrictions::default(),
                        "stream control restrictions changed"
                    );
                    Ok(())
                },
                |_, _| Ok(response),
            )
        })();
        if result.is_err() {
            session.discard(&challenge)?;
        }
        result
    }
}

pub fn status_local(
    descriptor: &TrustDescriptor,
    path: &Path,
    signer: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    mut clock: impl FnMut() -> Result<ClockHealth>,
) -> Result<OwnStreamMetadata> {
    store.require_requester(signer.verifying_key().to_bytes())?;
    let request = wire::sign_envelope(
        &wire::encode(&a(vec![
            V::Uint(55),
            V::Uint(1),
            b(&descriptor.scope().network),
            b(&descriptor.scope().incarnation),
            b(&store.requester()),
            b(&random_id()?),
            V::Uint(store.prefix().scope().epoch),
            V::Uint(store.prefix().height()),
        ]))?,
        signer,
    )?;
    let control = LocalControl::prepare_authority(path, store)?;
    let prepared =
        ControlPrepared::new(descriptor, request, None, signer, store, session, clock()?)?;
    match prepared.local(&control, store, session, &mut clock)? {
        StreamResponse::Status(metadata) => {
            control.retain();
            Ok(metadata)
        }
        _ => bail!("status returned another control result"),
    }
}

/// Invocation explicitly authorizes fencing. A retry retains the exact previously signed request.
pub fn fence_local(
    descriptor: &TrustDescriptor,
    path: &Path,
    signer: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    mut clock: impl FnMut() -> Result<ClockHealth>,
) -> Result<StreamResponse> {
    store.require_requester(signer.verifying_key().to_bytes())?;
    let prepared = if let Some(pending) = store.resume_fence()? {
        pending
    } else {
        let metadata = status_local(descriptor, path, signer, store, session, &mut clock)?;
        let state = metadata
            .state()
            .context("requester has no admitted stream")?;
        let request = wire::sign_envelope(
            &wire::encode(&a(vec![
                V::Uint(57),
                V::Uint(1),
                b(&descriptor.scope().network),
                b(&descriptor.scope().incarnation),
                b(&store.requester()),
                b(&random_id()?),
                V::Uint(store.prefix().scope().epoch),
                V::Uint(store.prefix().height()),
                V::Uint(state.generation),
                b(&state.generation_id),
                b(&wire::digest(metadata.canonical())),
            ]))?,
            signer,
        )?;
        store.prepare_fence(&request, metadata.canonical())?
    };
    let control = LocalControl::prepare_authority(path, store)?;
    ControlPrepared::new(
        descriptor,
        prepared.signed().to_vec(),
        prepared.expected_metadata().map(<[u8]>::to_vec),
        signer,
        store,
        session,
        clock()?,
    )?
    .local(&control, store, session, &mut clock)
}

/// Only authenticated own-stream metadata can distinguish original refusal from denied disclosure.
pub(crate) fn resolve_refusal_local(
    descriptor: &TrustDescriptor,
    path: &Path,
    signer: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    mut clock: impl FnMut() -> Result<ClockHealth>,
) -> Result<()> {
    store.require_requester(signer.verifying_key().to_bytes())?;
    ensure!(
        store.resume_fence()?.is_none(),
        "an unresolved explicit fence must be resumed first"
    );
    if store.refusal_needs_status()? {
        status_local(descriptor, path, signer, store, session, &mut clock)?;
    }
    Ok(())
}

pub(super) fn ensure_stream(
    descriptor: &TrustDescriptor,
    path: &Path,
    signer: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    clock: &mut impl FnMut() -> Result<ClockHealth>,
) -> Result<()> {
    store.require_requester(signer.verifying_key().to_bytes())?;
    ensure!(
        store.resume_fence()?.is_none(),
        "an unresolved explicit fence must be resumed first"
    );
    ensure!(
        descriptor.scope() == store.descriptor().scope(),
        "stream descriptor differs from the current requester configuration"
    );
    if store.needs_stream_status()? {
        status_local(descriptor, path, signer, store, session, clock)?;
    }
    Ok(())
}
