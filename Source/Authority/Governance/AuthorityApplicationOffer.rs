// SPDX-License-Identifier: MIT
// Application consent binds independent identities to one exact immutable grant.
use super::*;
use crate::authority_applications::Acceptance;
use ed25519_dalek::Signer;

pub const OFFER_LIMIT: usize = 8192;
pub const RECEIPT_LIMIT: usize = 65536;
const LABEL: &str = "AuthorityApplicationOffer";
const CONFIRMATION: &str = "AuthorityApplicationConfirmation";

pub struct Offer {
    pub acceptance: Acceptance,
    pub grant: Vec<u8>,
}
impl Offer {
    pub fn parse(bootstrap: &Verified, bytes: &[u8], accepted: bool) -> Result<Self> {
        ensure!(
            bootstrap.fully_accepted() && bytes.len() <= OFFER_LIMIT,
            "application offer requires accepted bootstrap and bounded bytes"
        );
        let decoded = wire::decode(bytes)?;
        let f = record(&decoded, 200, 5)?;
        ensure!(f[2].text()? == LABEL, "unexpected application artifact");
        let scope = bootstrap.descriptor().scope();
        let acceptance =
            Acceptance::parse(f[3].bytes()?, scope.network, scope.incarnation, accepted)?;
        ensure!(
            !bootstrap
                .reservations()
                .iter()
                .any(|(_, key)| *key == acceptance.application),
            "reserved identity cannot be an application"
        );
        let grant = f[4].bytes()?.to_vec();
        let value = wire::decode(&grant)?;
        let g = record(&value, 102, 17)?;
        let child = crate::authority_membership::ChildSpec::parse(
            &a(vec![
                g[6].clone(),
                g[8].clone(),
                g[9].clone(),
                g[10].clone(),
                g[11].clone(),
                g[12].clone(),
                g[14].clone(),
                g[15].clone(),
            ]),
            scope.network,
        )?;
        let parent = crate::authority_membership::version(&g[13])?;
        crate::authority_membership::Snapshot::parse(&g[16])?;
        ensure!(
            g[2].fixed::<32>()? == scope.network
                && g[3].fixed::<32>()? == scope.incarnation
                && g[4].uint()? == 1
                && g[4].uint()? == acceptance.grant.generation
                && g[6].fixed::<32>()? == acceptance.grant.id
                && g[7].fixed::<32>()? == acceptance.owner
                && g[8].fixed::<32>()? == acceptance.application
                && wire::digest(&grant) == acceptance.grant.digest
                && parent.kind == 102
                && !child.actions.contains(&11)
                && child.depth == 0
                && child.validity.0 <= acceptance.validity.0
                && child.validity.1 >= acceptance.validity.1,
            "application offer differs from its exact non-delegating grant"
        );
        g[5].null()?;
        Ok(Self { acceptance, grant })
    }
    pub fn authenticate_owner(&self, bootstrap: &Verified, pin: Option<[u8; 32]>) -> Result<()> {
        ensure!(
            pin.map_or(
                bootstrap
                    .reservations()
                    .contains(&(4, self.acceptance.owner)),
                |v| v == self.acceptance.owner
            ),
            "owner requires an independently authenticated key pin"
        );
        Ok(())
    }
    pub fn accept(
        &self,
        bootstrap: &Verified,
        signer: &SigningKey,
        pin: Option<[u8; 32]>,
    ) -> Result<Vec<u8>> {
        self.authenticate_owner(bootstrap, pin)?;
        let application = signer.verifying_key().to_bytes();
        ensure!(
            application == self.acceptance.application,
            "acceptance key differs from the offered application"
        );
        let (payload, mut signatures) = wire::envelope(&self.acceptance.envelope, 1)?;
        signatures.push((
            application,
            signer
                .sign(&wire::signature_message(&payload, &application))
                .to_bytes(),
        ));
        signatures.sort_by_key(|(key, _)| *key);
        let envelope = wire::encode(&a(vec![
            V::Uint(0),
            V::Uint(1),
            b(&payload),
            a(signatures
                .iter()
                .map(|(key, signature)| a(vec![b(key), b(signature)]))
                .collect()),
        ]))?;
        let bytes = wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text(LABEL.into()),
            b(&envelope),
            b(&self.grant),
        ]))?;
        Self::parse(bootstrap, &bytes, true)?;
        Ok(bytes)
    }
}
pub struct Invitation {
    pub grant: [u8; 32],
    pub validity: (u64, u64),
    pub acceptance_ms: u64,
}
pub fn invite(
    bootstrap: &Verified,
    context: &application_client::DelegationContext,
    store: &Store,
    request: Invitation,
    signer: &SigningKey,
    health: ClockHealth,
) -> Result<Vec<u8>> {
    context.current(store)?;
    store.require_requester(signer.verifying_key().to_bytes())?;
    ensure!(
        context.selection.child == Some(request.grant),
        "offer requires the exact selected child context"
    );
    ensure!(
        (1..=86_400_000).contains(&request.acceptance_ms),
        "acceptance interval exceeds 24 hours"
    );
    let grant = context.record(102, request.grant)?.to_vec();
    let value = wire::decode(&grant)?;
    let g = record(&value, 102, 17)?;
    let now = health.observe()?.wall_ms;
    let start = now
        .saturating_sub(crate::authority_governance::UNCERTAINTY_MS)
        .max(request.validity.0);
    let end = start
        .checked_add(request.acceptance_ms)
        .context("acceptance interval overflow")?
        .min(request.validity.1);
    let scope = bootstrap.descriptor().scope();
    let payload = wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("AuthorityApplicationAcceptance".into()),
        b(&scope.network),
        b(&scope.incarnation),
        g[8].clone(),
        b(&signer.verifying_key().to_bytes()),
        version_value(&context.version(102, request.grant)?),
        a(vec![
            V::Uint(request.validity.0),
            V::Uint(request.validity.1),
        ]),
        b(&random_id()?),
        a(vec![V::Uint(start), V::Uint(end)]),
    ]))?;
    let bytes = wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text(LABEL.into()),
        b(&wire::sign_envelope(&payload, signer)?),
        b(&grant),
    ]))?;
    Offer::parse(bootstrap, &bytes, false)?;
    Ok(bytes)
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
        V::Text(CONFIRMATION.into()),
        b(intent),
        b(challenge),
        b(ordered),
        b(&reply.result),
        b(&reply.certificate),
        b(&reply.node),
    ]))?;
    ensure!(
        bytes.len() <= RECEIPT_LIMIT,
        "application receipt exceeds its bound"
    );
    Ok(bytes)
}
pub(super) fn save_receipt(path: &Path, bytes: &[u8], intent: &[u8]) -> Result<()> {
    let directory =
        files::private_directory(path.parent().context("receipt directory is required")?)?;
    let name = path.file_name().context("receipt filename is required")?;
    match files::read_at(&directory, name, RECEIPT_LIMIT, true) {
        Ok(prior) => {
            let decoded = wire::decode(&prior)?;
            let f = record(&decoded, 201, 9)?;
            ensure!(
                f[2].text()? == CONFIRMATION && f[3].bytes()? == intent,
                "receipt destination belongs to another registration"
            );
            let old = Intent::from_signed(f[3].bytes()?)?;
            ensure!(
                Challenge::from_signed(f[4].bytes()?)?.intent == old.digest,
                "existing receipt challenge differs from registration"
            );
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
/// Historical registration evidence cannot establish current application authority.
pub fn confirm(
    bootstrap: &Verified,
    offer: &Offer,
    bytes: &[u8],
    epochs: &[crate::authority_epoch::archive::Activated],
) -> Result<u64> {
    ensure!(
        bootstrap.fully_accepted() && bytes.len() <= RECEIPT_LIMIT,
        "invalid application confirmation bounds"
    );
    let decoded = wire::decode(bytes)?;
    let f = record(&decoded, 201, 9)?;
    ensure!(
        f[2].text()? == CONFIRMATION,
        "unexpected confirmation artifact"
    );
    let intent = Intent::from_signed(f[3].bytes()?)?;
    let challenge = Challenge::from_signed(f[4].bytes()?)?;
    let value = wire::decode(&intent.parameters)?;
    let p = record(&value, 200, 6)?;
    let ordered = wire::decode(f[5].bytes()?)?;
    let scope = proof::Scope::parse(&ordered.array(6)?[2])?;
    let descriptor = crate::authority_epoch::archive::descriptor_for_scope(
        bootstrap.descriptor(),
        epochs,
        &scope,
    )?;
    let scope = descriptor.scope();
    ensure!(
        intent.action == "AuthorityApplicationRegister"
            && p[2].text()? == intent.action
            && intent.network == scope.network
            && intent.incarnation == scope.incarnation
            && intent.requester == offer.acceptance.owner
            && intent.resource == offer.acceptance.application
            && intent.revision == 1
            && intent.profile_generation == 0
            && challenge.recipient == intent.requester
            && p[4].bytes()? == offer.acceptance.envelope,
        "historical registration differs from exact consent"
    );
    let snapshot = p[5].array(2)?;
    let point = snapshot[0].array(3)?;
    ensure!(
        point[0].uint()? == scope.epoch
            && point[1].uint()? == intent.minimum_policy_height
            && parse_versions(&snapshot[1])? == intent.expected,
        "historical snapshot differs from signed dependencies"
    );
    let created = crate::authority_applications::Operation::parse(&intent)?
        .derive(&intent)?
        .context("registration did not derive an admission")?;
    let mut versions = intent.expected.clone();
    versions.push(VersionRef {
        kind: 127,
        id: intent.resource,
        generation: 1,
        digest: wire::digest(&created),
    });
    versions.sort_by_key(VersionRef::index);
    proof::validate_versions(&versions, 64)?;
    let ancestry = vec![f[8].bytes()?.to_vec()];
    let verified = proof::verify_response(
        &descriptor,
        proof::ProofContext {
            intent: f[3].bytes()?,
            challenge: f[4].bytes()?,
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
            let value = wire::decode(&result.value)?;
            let r = record(&value, 201, 6)?;
            ensure!(
                result.disposition == Disposition::Permit
                    && executed.maximum_effect == 1
                    && r[2].text()? == intent.action
                    && parse_versions(&r[3])? == versions
                    && r[4].bytes()? == created
                    && r[5].uint()? > intent.minimum_policy_height
                    && r[5].uint()? <= executed.height
                    && executed.expires_at_ms
                        <= challenge
                            .evaluation_expiry(executed.evaluated_at_ms, executed.expires_at_ms)?,
                "certificate does not prove the exact historical registration"
            );
            ActionValidation::new(versions.clone())
        },
    )?;
    Ok(verified.point().prefix().height())
}

/// Renewal artifacts retain the exact predecessor and require independent possession again.
pub struct RenewalOffer {
    pub previous: Vec<u8>,
    pub envelope: Vec<u8>,
    pub consent: crate::authority_applications::Renewal,
}
impl RenewalOffer {
    pub fn parse(bootstrap: &Verified, bytes: &[u8], accepted: bool) -> Result<Self> {
        ensure!(
            bootstrap.fully_accepted() && bytes.len() <= OFFER_LIMIT,
            "renewal offer exceeds bound or lacks accepted bootstrap"
        );
        let value = wire::decode(bytes)?;
        let f = value.array(5)?;
        ensure!(
            f[0].uint()? == 200
                && f[1].uint()? == 2
                && f[2].text()? == "AuthorityApplicationRenewalOffer",
            "renewal artifact context differs"
        );
        let scope = bootstrap.descriptor().scope();
        let previous = f[3].bytes()?.to_vec();
        let old = crate::authority_applications::Registration::parse(
            &previous,
            scope.network,
            scope.incarnation,
        )?;
        let envelope = f[4].bytes()?.to_vec();
        let consent = crate::authority_applications::Renewal::parse(
            &envelope,
            scope.network,
            scope.incarnation,
            accepted,
        )?;
        ensure!(
            old.reference == consent.admission
                && old.owner == consent.owner
                && old.grant == consent.grant
                && consent.validity.1 > old.validity.1,
            "renewal differs from exact existing rights"
        );
        Ok(Self {
            previous,
            envelope,
            consent,
        })
    }
    pub fn authenticate_owner(&self, bootstrap: &Verified, pin: Option<[u8; 32]>) -> Result<()> {
        ensure!(
            pin.map_or(
                bootstrap.reservations().contains(&(4, self.consent.owner)),
                |v| v == self.consent.owner
            ),
            "renewal owner requires an independently authenticated key pin"
        );
        Ok(())
    }
    pub fn accept(
        &self,
        bootstrap: &Verified,
        signer: &SigningKey,
        pin: Option<[u8; 32]>,
    ) -> Result<Vec<u8>> {
        self.authenticate_owner(bootstrap, pin)?;
        let key = signer.verifying_key().to_bytes();
        ensure!(
            key == self.consent.admission.id,
            "renewal acceptance key differs from application"
        );
        let (payload, mut signatures) = wire::envelope(&self.envelope, 1)?;
        signatures.push((
            key,
            signer
                .sign(&wire::signature_message(&payload, &key))
                .to_bytes(),
        ));
        signatures.sort_by_key(|(key, _)| *key);
        let envelope = wire::encode(&a(vec![
            V::Uint(0),
            V::Uint(1),
            b(&payload),
            a(signatures
                .iter()
                .map(|(key, signature)| a(vec![b(key), b(signature)]))
                .collect()),
        ]))?;
        let bytes = renewal_artifact(&self.previous, &envelope)?;
        Self::parse(bootstrap, &bytes, true)?;
        Ok(bytes)
    }
}
fn renewal_artifact(previous: &[u8], envelope: &[u8]) -> Result<Vec<u8>> {
    wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(2),
        V::Text("AuthorityApplicationRenewalOffer".into()),
        b(previous),
        b(envelope),
    ]))
}
pub fn invite_renewal(
    bootstrap: &Verified,
    store: &Store,
    application: [u8; 32],
    validity: (u64, u64),
    acceptance_ms: u64,
    signer: &SigningKey,
    health: ClockHealth,
) -> Result<Vec<u8>> {
    store.require_requester(signer.verifying_key().to_bytes())?;
    ensure!(
        (1..=86_400_000).contains(&acceptance_ms),
        "acceptance interval exceeds 24 hours"
    );
    let previous = application_client::renewal_target(store, application)?;
    let scope = bootstrap.descriptor().scope();
    let old = crate::authority_applications::Registration::parse(
        &previous,
        scope.network,
        scope.incarnation,
    )?;
    ensure!(
        old.owner == signer.verifying_key().to_bytes(),
        "renewal signer differs from owner"
    );
    let now = health.observe()?.wall_ms;
    let start = now
        .saturating_sub(crate::authority_governance::UNCERTAINTY_MS)
        .max(validity.0);
    let end = start
        .checked_add(acceptance_ms)
        .context("renewal acceptance interval overflow")?
        .min(validity.1);
    let payload = wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(2),
        V::Text("AuthorityApplicationRenewal".into()),
        b(&scope.network),
        b(&scope.incarnation),
        version_value(&old.reference),
        b(&old.owner),
        version_value(&old.grant),
        a(vec![V::Uint(validity.0), V::Uint(validity.1)]),
        b(&random_id()?),
        a(vec![V::Uint(start), V::Uint(end)]),
    ]))?;
    let bytes = renewal_artifact(&previous, &wire::sign_envelope(&payload, signer)?)?;
    RenewalOffer::parse(bootstrap, &bytes, false)?;
    Ok(bytes)
}
