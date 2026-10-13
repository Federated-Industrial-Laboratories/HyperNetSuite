// SPDX-License-Identifier: MIT
// Member mutations retain exact dependencies and publish local evidence before completion.
use super::*;
use crate::authority_membership::{self as membership, Mutation, Reservations};

#[derive(Clone)]
pub enum MemberMutation {
    Delegate { parent: VersionRef, child: V },
    Admit { grant: [u8; 32], accepted: Vec<u8> },
    Redeem { grant: [u8; 32], accepted: Vec<u8> },
}
impl MemberMutation {
    fn action(&self) -> &'static str {
        match self {
            Self::Delegate { .. } => "AuthorityDelegateGrant",
            Self::Admit { .. } => "AuthorityAdmitMember",
            Self::Redeem { .. } => "AuthorityRedeemMember",
        }
    }
    fn fields(&self) -> (V, V) {
        match self {
            Self::Delegate { parent, child } => (version_value(parent), child.clone()),
            Self::Admit { grant, accepted } | Self::Redeem { grant, accepted } => {
                (b(grant), b(accepted))
            }
        }
    }
    fn resource(&self, descriptor: &TrustDescriptor) -> Result<[u8; 32]> {
        Ok(match self {
            Self::Delegate { child, .. } => {
                membership::ChildSpec::parse(child, descriptor.scope().network)?.id
            }
            Self::Admit { accepted, .. } | Self::Redeem { accepted, .. } => {
                membership::Acceptance::parse(
                    accepted,
                    descriptor.scope().network,
                    descriptor.scope().incarnation,
                    true,
                )?
                .member_id
            }
        })
    }
}
pub struct MemberRequest<'a> {
    pub bootstrap: &'a Verified,
    pub mutation: MemberMutation,
    pub receipt: Option<&'a Path>,
}
pub(super) struct MemberPrepared<'a> {
    pub(super) context: &'a ContextState,
    pub(super) action: &'static str,
    pub(super) mutation: Mutation,
    pub(super) reservations: Reservations,
    pub(super) reference: VersionRef,
    pub(super) created: Vec<u8>,
    pub(super) receipt: Option<&'a Path>,
}
impl ContextState {
    pub fn version(&self, kind: u64, id: [u8; 32]) -> Result<VersionRef> {
        self.governance
            .versions()
            .into_iter()
            .find(|v| v.kind == kind && v.id == id)
            .context("required exact context record is absent")
    }
    pub fn grant_tier(&self, grant: [u8; 32]) -> Result<VersionRef> {
        let value = wire::decode(self.governance.record_bytes(102, grant)?)?;
        membership::version(&value.array(17)?[9])
    }
    pub fn member_local(
        &self,
        path: &Path,
        request: MemberRequest<'_>,
        signer: &SigningKey,
        store: &mut Store,
        session: &mut Session,
        mut clock: impl FnMut() -> Result<ClockHealth>,
    ) -> Result<CreatedRecord> {
        // Discovery prepares the stream before capturing the mutation's causal floor.
        self.current(store)?;
        let control = LocalControl::prepare_authority(path, store)?;
        let pending = GovernancePrepared::member(self, request, signer, store, session, clock()?)?;
        match pending.local(&control, store, session, &mut clock)? {
            Outcome::Created(record) => Ok(*record),
            _ => bail!("unexpected member mutation result"),
        }
    }
}
impl<'a> GovernancePrepared<'a> {
    pub(super) fn member(
        context: &'a ContextState,
        request: MemberRequest<'a>,
        signer: &SigningKey,
        store: &mut Store,
        session: &mut Session,
        health: ClockHealth,
    ) -> Result<Self> {
        let MemberRequest {
            bootstrap,
            mutation: request,
            receipt,
        } = request;
        context.current(store)?;
        store.require_requester(signer.verifying_key().to_bytes())?;
        ensure!(
            bootstrap.fully_accepted()
                && bootstrap.descriptor().canonical() == store.initial_descriptor().canonical(),
            "membership bootstrap differs from independently accepted trust"
        );
        let action = request.action();
        let resource = request.resource(&context.descriptor)?;
        let reservations = Reservations(bootstrap.reservations().to_vec());
        let (authority, contents) = request.fields();
        let intent = if let Some(pending) = store.resume_ordinary()? {
            let intent = Intent::from_signed(pending.signed())?;
            let value = wire::decode(&intent.parameters)?;
            let f = record(&value, 200, 6)?;
            ensure!(
                intent.action == action
                    && intent.resource == resource
                    && intent.revision == 1
                    && intent.profile_generation == 0
                    && f[2].text()? == action
                    && f[3] == authority
                    && f[4] == contents,
                "another exact request is pending; resume it or explicitly fence its generation"
            );
            intent
        } else {
            let scope = context.descriptor.scope();
            let mut intent = Intent {
                network: scope.network,
                incarnation: scope.incarnation,
                generation: 1,
                generation_id: [1; 32],
                sequence: 1,
                acknowledged_through: 0,
                requester: signer.verifying_key().to_bytes(),
                action: action.into(),
                resource,
                revision: 1,
                profile_generation: 0,
                minimum_policy_epoch: scope.epoch,
                minimum_policy_height: store.prefix().height(),
                expected: Vec::new(),
                parameters: Vec::new(),
                digest: [1; 32],
            };
            let parameters = |references: &[VersionRef]| {
                wire::encode(&a(vec![
                    V::Uint(200),
                    V::Uint(1),
                    V::Text(action.into()),
                    authority.clone(),
                    contents.clone(),
                    a(vec![
                        point(store.prefix()),
                        a(references.iter().map(version_value).collect()),
                    ]),
                ]))
            };
            intent.parameters = parameters(&[])?;
            let mutation = Mutation::parse(&intent)?;
            let decision = mutation.prepare(
                &records(&context.governance)?,
                &reservations,
                &intent,
                health.observe()?.wall_ms,
                false,
            )?;
            ensure!(
                decision.code == 0,
                "member mutation preflight refused with code {}",
                decision.code
            );
            intent.expected = decision.dependencies;
            intent.parameters = parameters(&intent.expected)?;
            intent
        };
        let mutation = Mutation::parse(&intent)?;
        let created = mutation.derive(&intent)?;
        let reference = VersionRef {
            kind: if action == "AuthorityDelegateGrant" {
                102
            } else {
                125
            },
            id: resource,
            generation: 1,
            digest: wire::digest(&created),
        };
        member_offer::preflight_receipt(&intent, &created, &reference)?;
        let grant = mutation.grant();
        Self::new(
            Parameters {
                descriptor: context.descriptor.clone(),
                grant,
                mode: Mode::Member(MemberPrepared {
                    context,
                    action,
                    mutation,
                    reservations,
                    reference,
                    created,
                    receipt,
                }),
                expected: intent.expected,
                canonical: intent.parameters,
            },
            signer,
            store,
            session,
            health,
        )
    }
}
impl MemberPrepared<'_> {
    pub(super) fn candidate(
        &self,
        intent: &Intent,
        result: &OperationResult,
        executed: &ExecutedResult,
        versions: &[VersionRef],
    ) -> Result<(Governance, crate::authority_governance::CapabilityDecision)> {
        let value = wire::decode(&result.value)?;
        let f = record(&value, 201, 6)?;
        ensure!(
            intent.action == self.action && f[4].bytes()? == self.created,
            "member result differs from its exact derived record"
        );
        let mut entries = records(&self.context.governance)?;
        let cached = self.context.governance.versions().contains(&self.reference);
        let creation_height = f[5].uint()?;
        ensure!(
            creation_height > self.mutation.snapshot().height && creation_height <= executed.height,
            "member creation height differs from its causal floor or execution"
        );
        // The immutable result names the original commit, independently of intervening orders.
        let replay = executed.height > creation_height;
        if replay && !cached {
            entries.push(self.created.clone());
            membership::sort_records(&mut entries)?;
        }
        let decision = self.mutation.authorise(
            &entries,
            &self.reservations,
            intent,
            executed.evaluated_at_ms,
            replay,
        )?;
        ensure!(
            decision.code == 0
                && decision.record == self.created
                && decision.created == self.reference
                && decision.dependencies == intent.expected,
            "member result lacks exact current authority or dependencies"
        );
        let mut expected = decision.dependencies.clone();
        expected.push(self.reference.clone());
        expected.sort_by_key(VersionRef::index);
        proof::validate_versions(&expected, 64)?;
        ensure!(
            expected == versions,
            "member result omits or replaces an exact dependency"
        );
        if !cached && !replay {
            entries.push(self.created.clone());
        }
        membership::sort_records(&mut entries)?;
        ensure!(
            entries.len() <= MAX_RECORDS,
            "governance context capacity exceeded"
        );
        let governance = Governance::parse(intent.network, intent.incarnation, &entries)?;
        Ok((
            governance,
            crate::authority_governance::CapabilityDecision {
                dependencies: decision.dependencies,
                not_before_ms: decision.not_before_ms,
                expires_ms: decision.expires_ms,
            },
        ))
    }
}
