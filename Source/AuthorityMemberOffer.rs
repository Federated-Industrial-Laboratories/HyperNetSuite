// SPDX-License-Identifier: MIT
// Offline offers disclose one exact grant and require both identities over immutable semantics.
use super::*;
use ed25519_dalek::Signer;

pub const OFFER_LIMIT: usize = 8192;
pub const RECEIPT_LIMIT: usize = 65536;
const ACCEPTANCE: &str = "AuthorityMemberAcceptance";

#[derive(Clone)]
pub struct Offer {
    pub envelope: Vec<u8>,
    pub reader_grant: Vec<u8>,
    pub member: [u8; 32],
    pub candidate: [u8; 32],
    pub inviter: [u8; 32],
    pub reader: VersionRef,
    pub validity: (u64, u64),
    pub acceptance_validity: (u64, u64),
    pub payload: Vec<u8>,
}
fn reference(value: &V) -> Result<VersionRef> {
    let f = value.array(4)?;
    let reference = VersionRef {
        kind: f[0].uint()?,
        id: f[1].fixed()?,
        generation: f[2].uint()?,
        digest: f[3].fixed()?,
    };
    proof::validate_versions(std::slice::from_ref(&reference), 1)?;
    Ok(reference)
}
fn span(value: &V) -> Result<(u64, u64)> {
    let f = value.array(2)?;
    let span = (f[0].uint()?, f[1].uint()?);
    ensure!(span.0 < span.1, "invalid membership validity");
    Ok(span)
}
impl Offer {
    pub fn parse(bootstrap: &Verified, bytes: &[u8], accepted: bool) -> Result<Self> {
        ensure!(
            bootstrap.fully_accepted() && bytes.len() <= OFFER_LIMIT,
            "member offer requires accepted bootstrap and bounded bytes"
        );
        let value = wire::decode(bytes)?;
        let f = record(&value, 200, 5)?;
        ensure!(
            f[2].text()? == "AuthorityMemberOffer",
            "unexpected member artifact"
        );
        let envelope = f[3].bytes()?.to_vec();
        ensure!(
            envelope.len() <= 1024,
            "member acceptance exceeds its bound"
        );
        let (payload, signatures) = wire::envelope(&envelope, 2)?;
        let value = wire::decode(&payload)?;
        let p = record(&value, 200, 12)?;
        let scope = bootstrap.descriptor().scope();
        ensure!(
            p[2].text()? == ACCEPTANCE
                && p[3].fixed::<32>()? == scope.network
                && p[4].fixed::<32>()? == scope.incarnation,
            "member offer belongs to another network or incarnation"
        );
        let member = p[5].fixed::<32>()?;
        let candidate = p[6].fixed::<32>()?;
        let validity = span(&p[7])?;
        let reader = reference(&p[8])?;
        let inviter = p[9].fixed::<32>()?;
        let acceptance_validity = span(&p[11])?;
        wire::valid_key(&candidate)?;
        wire::valid_key(&inviter)?;
        ensure!(
            member != [0; 32]
                && p[10].fixed::<32>()? != [0; 32]
                && candidate != inviter
                && reader.kind == 102
                && reader.generation == 1
                && validity.0 <= acceptance_validity.0
                && acceptance_validity.1 <= validity.1
                && acceptance_validity.1 - acceptance_validity.0 <= 86_400_000
                && !bootstrap
                    .reservations()
                    .iter()
                    .any(|(_, key)| *key == candidate),
            "invalid member identities, grant or acceptance interval"
        );
        ensure!(
            signatures.len() == if accepted { 2 } else { 1 }
                && signatures
                    .iter()
                    .all(|(key, _)| *key == inviter || accepted && *key == candidate)
                && signatures.iter().any(|(key, _)| *key == inviter),
            "member offer lacks the exact required signatures"
        );
        let reader_grant = f[4].bytes()?.to_vec();
        let decoded = wire::decode(&reader_grant)?;
        let grant = record(&decoded, 102, 17)?;
        ensure!(
            reader.digest == wire::digest(&reader_grant)
                && grant[2].fixed::<32>()? == scope.network
                && grant[3].fixed::<32>()? == scope.incarnation
                && grant[4].uint()? == reader.generation
                && grant[6].fixed::<32>()? == reader.id
                && grant[8].fixed::<32>()? == candidate
                && grant[10].list(32)?.contains(&V::Uint(0)),
            "member offer differs from the exact candidate reader grant"
        );
        grant[5].null()?;
        span(&grant[12])?;
        Ok(Self {
            envelope,
            reader_grant,
            member,
            candidate,
            inviter,
            reader,
            validity,
            acceptance_validity,
            payload,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityMemberOffer".into()),
            b(&self.envelope),
            b(&self.reader_grant),
        ]))
    }
    pub fn authenticate_inviter(
        &self,
        bootstrap: &Verified,
        inviter_pin: Option<[u8; 32]>,
    ) -> Result<()> {
        let genesis_inviter = bootstrap.reservations().contains(&(4, self.inviter));
        ensure!(
            inviter_pin.map_or(genesis_inviter, |key| key == self.inviter),
            "inviter requires an independently authenticated key pin"
        );
        Ok(())
    }
    pub fn accept(
        &self,
        bootstrap: &Verified,
        signer: &SigningKey,
        inviter_pin: Option<[u8; 32]>,
    ) -> Result<Vec<u8>> {
        ensure!(
            signer.verifying_key().to_bytes() == self.candidate,
            "acceptance key differs from the offered candidate"
        );
        self.authenticate_inviter(bootstrap, inviter_pin)?;
        let (_, mut signatures) = wire::envelope(&self.envelope, 1)?;
        let signature = signer
            .sign(&wire::signature_message(&self.payload, &self.candidate))
            .to_bytes();
        signatures.push((self.candidate, signature));
        signatures.sort_by_key(|(key, _)| *key);
        let envelope = wire::encode(&a(vec![
            V::Uint(0),
            V::Uint(1),
            b(&self.payload),
            a(signatures
                .iter()
                .map(|(key, signature)| a(vec![b(key), b(signature)]))
                .collect()),
        ]))?;
        let mut accepted = self.clone();
        accepted.envelope = envelope;
        let bytes = accepted.encode()?;
        Self::parse(bootstrap, &bytes, true)?;
        Ok(bytes)
    }
}
pub struct Invitation {
    pub member: [u8; 32],
    pub reader_grant: [u8; 32],
    pub validity: (u64, u64),
    pub acceptance_ms: u64,
}
pub fn invite(
    bootstrap: &Verified,
    context: &ContextState,
    store: &Store,
    request: Invitation,
    signer: &SigningKey,
    health: ClockHealth,
) -> Result<Vec<u8>> {
    context.current(store)?;
    store.require_requester(signer.verifying_key().to_bytes())?;
    ensure!(
        (1..=86_400_000).contains(&request.acceptance_ms),
        "acceptance interval exceeds 24 hours"
    );
    let now = health.observe()?;
    let reader_grant = context
        .governance
        .record_bytes(102, request.reader_grant)?
        .to_vec();
    let value = wire::decode(&reader_grant)?;
    let grant = record(&value, 102, 17)?;
    let scope = bootstrap.descriptor().scope();
    let reference = VersionRef {
        kind: 102,
        id: request.reader_grant,
        generation: grant[4].uint()?,
        digest: wire::digest(&reader_grant),
    };
    let start = now
        .wall_ms
        .saturating_sub(crate::authority_governance::UNCERTAINTY_MS)
        .max(request.validity.0);
    let end = start
        .checked_add(request.acceptance_ms)
        .context("acceptance interval overflow")?
        .min(request.validity.1);
    let payload = wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text(ACCEPTANCE.into()),
        b(&scope.network),
        b(&scope.incarnation),
        b(&request.member),
        grant[8].clone(),
        a(vec![
            V::Uint(request.validity.0),
            V::Uint(request.validity.1),
        ]),
        version_value(&reference),
        b(&signer.verifying_key().to_bytes()),
        b(&random_id()?),
        a(vec![V::Uint(start), V::Uint(end)]),
    ]))?;
    let bytes = wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("AuthorityMemberOffer".into()),
        b(&wire::sign_envelope(&payload, signer)?),
        b(&reader_grant),
    ]))?;
    Offer::parse(bootstrap, &bytes, false)?;
    Ok(bytes)
}

pub(super) fn preflight_receipt(
    intent: &Intent,
    created: &[u8],
    reference: &VersionRef,
) -> Result<()> {
    let references = wire::encode(&a(intent.expected.iter().map(version_value).collect()))?;
    let mut versions = intent.expected.clone();
    versions.push(reference.clone());
    versions.sort_by_key(VersionRef::index);
    proof::validate_versions(&versions, 64)?;
    let value = wire::encode(&a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text(intent.action.clone()),
        a(versions.iter().map(version_value).collect()),
        b(created),
    ]))?;
    let result = wire::encode(&a(vec![
        V::Uint(24),
        V::Uint(1),
        V::Text(intent.action.clone()),
        V::Uint(0),
        V::Uint(0),
        b(&value),
    ]))?;
    // Intent and challenge each occur twice. Fixed allowances cover maximal U64 fields,
    // four signatures, exact kind23/kind14 records and every enclosing CBOR header.
    let signed_intent = intent.parameters.len() + references.len() + 512;
    let maximum = 2 * signed_intent + 2 * 512 + 512 + result.len() + 4096 + 512 + 128;
    ensure!(
        maximum <= RECEIPT_LIMIT,
        "member receipt cannot fit its bounded output"
    );
    Ok(())
}
pub(super) fn receipt(
    intent: &[u8],
    challenge: &[u8],
    ordered: &[u8],
    reply: &CertifiedReply,
) -> Result<Vec<u8>> {
    let bytes = wire::encode(&a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityMemberConfirmation".into()),
        b(intent),
        b(challenge),
        b(ordered),
        b(&reply.result),
        b(&reply.certificate),
        b(&reply.node),
    ]))?;
    ensure!(
        bytes.len() <= RECEIPT_LIMIT,
        "member receipt exceeds its bound"
    );
    Ok(bytes)
}
pub(super) fn save_receipt(path: &Path, bytes: &[u8], intent: &[u8]) -> Result<()> {
    let directory =
        files::private_directory(path.parent().context("receipt directory is required")?)?;
    let name = path.file_name().context("receipt filename is required")?;
    // A failed Complete can leave a published receipt; only this exact signed mutation may replace it.
    match files::read_at(&directory, name, RECEIPT_LIMIT, true) {
        Ok(prior) => {
            let value = wire::decode(&prior)?;
            let f = record(&value, 201, 9)?;
            ensure!(
                f[2].text()? == "AuthorityMemberConfirmation" && f[3].bytes()? == intent,
                "receipt destination belongs to another admission"
            );
            let old_intent = Intent::from_signed(f[3].bytes()?)?;
            let old_challenge = Challenge::from_signed(f[4].bytes()?)?;
            ensure!(
                old_challenge.intent == old_intent.digest,
                "existing receipt challenge differs from admission"
            );
            // Equal intended mutation is required; the fresh proof replaces only this private receipt.
            files::atomic_at(&directory, name, bytes, true)
        }
        Err(error) => {
            let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
            let name_c = CString::new(name.as_bytes())?;
            let code = unsafe {
                libc::fstatat(
                    directory.as_raw_fd(),
                    name_c.as_ptr(),
                    st.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            ensure!(
                code != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT),
                "existing receipt cannot be safely read: {error}"
            );
            files::atomic_at(&directory, name, bytes, false)
        }
    }
}
/// Historical evidence is intentionally unable to enter an authority session or floor.
pub struct HistoricalAdmission {
    certified_height: u64,
}
impl HistoricalAdmission {
    pub fn certified_height(&self) -> u64 {
        self.certified_height
    }
}
pub fn confirm(
    bootstrap: &Verified,
    offer: &Offer,
    bytes: &[u8],
    epochs: &[crate::authority_epoch::archive::Activated],
) -> Result<HistoricalAdmission> {
    ensure!(
        bootstrap.fully_accepted() && bytes.len() <= RECEIPT_LIMIT,
        "invalid historical evidence bound"
    );
    let decoded = wire::decode(bytes)?;
    let f = record(&decoded, 201, 9)?;
    ensure!(
        f[2].text()? == "AuthorityMemberConfirmation",
        "unexpected confirmation artifact"
    );
    let intent_bytes = f[3].bytes()?;
    let challenge_bytes = f[4].bytes()?;
    let intent = Intent::from_signed(intent_bytes)?;
    let challenge = Challenge::from_signed(challenge_bytes)?;
    let parameters = wire::decode(&intent.parameters)?;
    let p = record(&parameters, 200, 6)?;
    let ordered = wire::decode(f[5].bytes()?)?;
    let claimed = proof::Scope::parse(&ordered.array(6)?[2])?;
    let descriptor = crate::authority_epoch::archive::descriptor_for_scope(
        bootstrap.descriptor(),
        epochs,
        &claimed,
    )?;
    let scope = descriptor.scope();
    ensure!(
        intent.action == "AuthorityAdmitMember"
            && p[2].text()? == intent.action
            && intent.network == scope.network
            && intent.incarnation == scope.incarnation
            && intent.requester == offer.inviter
            && intent.resource == offer.member
            && intent.revision == 1
            && intent.profile_generation == 0
            && challenge.recipient == offer.inviter
            && p[4].bytes()? == offer.envelope,
        "historical admission differs from the exact accepted offer"
    );
    let snapshot = p[5].array(2)?;
    let point = snapshot[0].array(3)?;
    ensure!(
        point[0].uint()? == scope.epoch
            && point[1].uint()? == intent.minimum_policy_height
            && parse_versions(&snapshot[1])? == intent.expected,
        "historical admission snapshot differs from signed dependencies"
    );
    let created = wire::encode(&a(vec![
        V::Uint(125),
        V::Uint(1),
        b(&scope.network),
        b(&scope.incarnation),
        V::Uint(1),
        V::Null,
        b(&offer.member),
        b(&offer.candidate),
        a(vec![V::Uint(offer.validity.0), V::Uint(offer.validity.1)]),
        V::Bool(false),
        version_value(&offer.reader),
        p[5].clone(),
    ]))?;
    let mut versions = intent.expected.clone();
    versions.push(VersionRef {
        kind: 125,
        id: offer.member,
        generation: 1,
        digest: wire::digest(&created),
    });
    versions.sort_by_key(VersionRef::index);
    proof::validate_versions(&versions, 64)?;
    let ancestry = vec![f[8].bytes()?.to_vec()];
    let verified = proof::verify_response(
        &descriptor,
        proof::ProofContext {
            intent: intent_bytes,
            challenge: challenge_bytes,
            restrictions: Restrictions::default(),
            minimum_height: 0,
            maximum_effect: 1,
            expected_stream: None,
        },
        proof::Response {
            ordered_request: f[5].bytes()?,
            operation_result: f[6].bytes()?,
            certificate: f[7].bytes()?,
            ancestry: &ancestry,
        },
        |_, result, executed| {
            let decoded = wire::decode(&result.value)?;
            let value = record(&decoded, 201, 5)?;
            ensure!(
                result.disposition == Disposition::Permit
                    && executed.maximum_effect == 1
                    && value[2].text()? == "AuthorityAdmitMember"
                    && parse_versions(&value[3])? == versions
                    && value[4].bytes()? == created
                    && executed.expires_at_ms
                        <= challenge
                            .evaluation_expiry(executed.evaluated_at_ms, executed.expires_at_ms)?,
                "certificate does not prove the exact historical admission"
            );
            ActionValidation::new(versions.clone())
        },
    )?;
    Ok(HistoricalAdmission {
        certified_height: verified.point().prefix().height(),
    })
}
