// SPDX-License-Identifier: MIT
// Explicit member workflows keep offline consent separate from current quorum authority.
use super::*;
use crate::authority_inspection::{
    MemberMutation, MemberRequest,
    member_offer::{self, Invitation, Offer},
};
use anyhow::Context;
use std::path::Path;

#[derive(Args)]
pub struct Offline {
    #[arg(long)]
    bootstrap: PathBuf,
    /// SHA256 independently verified for the complete accepted bootstrap.
    #[arg(long)]
    bootstrap_digest: String,
}
#[derive(Args)]
pub struct Delegate {
    #[command(flatten)]
    location: Location,
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    socket: PathBuf,
    /// Grant with InspectAudit; it need not be the delegation parent.
    #[arg(long)]
    context_grant: String,
    #[arg(long)]
    parent: String,
    #[arg(long)]
    id: String,
    #[arg(long)]
    subject: String,
    #[arg(long)]
    tier: Option<String>,
    #[arg(long, value_delimiter = ',', default_value = "0")]
    actions: Vec<u64>,
    /// Sorted scope pairs kind:identifier; the default is this network.
    #[arg(long, value_delimiter = ',')]
    scopes: Vec<String>,
    #[arg(long)]
    not_before_ms: u64,
    #[arg(long)]
    expires_ms: u64,
    #[arg(long, default_value_t = 0)]
    delegation_depth: u64,
    #[arg(long, value_delimiter = ',', num_args = 4, default_value = "0,1,0,1")]
    limits: Vec<u64>,
}
#[derive(Args)]
pub struct Invite {
    #[command(flatten)]
    location: Location,
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    reader_grant: String,
    #[arg(long)]
    member: String,
    #[arg(long)]
    not_before_ms: u64,
    #[arg(long)]
    expires_ms: u64,
    #[arg(long, default_value_t = 3_600_000)]
    acceptance_ms: u64,
    #[arg(long)]
    output: PathBuf,
}
#[derive(Args)]
pub struct InspectOffer {
    #[command(flatten)]
    trust: Offline,
    #[arg(long)]
    offer: PathBuf,
    #[arg(long)]
    inviter_key: Option<String>,
}
#[derive(Args)]
pub struct Accept {
    #[command(flatten)]
    trust: Offline,
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    offer: PathBuf,
    /// Independently authenticated inviter pin, required outside genesis administrators.
    #[arg(long)]
    inviter_key: Option<String>,
    #[arg(long)]
    output: PathBuf,
}
#[derive(Args)]
pub struct Admit {
    #[command(flatten)]
    location: Location,
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    socket: PathBuf,
    /// Separate grant authorising discovery of the complete current context.
    #[arg(long)]
    context_grant: String,
    #[arg(long)]
    grant: String,
    #[arg(long)]
    accepted: PathBuf,
    #[arg(long)]
    receipt: PathBuf,
}
#[derive(Args)]
pub struct Confirm {
    #[command(flatten)]
    trust: Offline,
    #[arg(long)]
    accepted: PathBuf,
    #[arg(long)]
    receipt: PathBuf,
    /// Complete verified epoch archive when the admission was certified after replacement.
    #[arg(long)]
    prior_epochs: Option<PathBuf>,
}
fn offline(trust: &Offline) -> Result<trust_bootstrap::Verified> {
    let bytes = files::read_single(&trust.bootstrap, trust_wire::MAXIMUM, true)?;
    ensure!(
        Sha256::digest(&bytes).as_slice() == trust_bootstrap::hex32(&trust.bootstrap_digest)?,
        "bootstrap differs from independently verified digest"
    );
    trust_bootstrap::inspect(&bytes, true)
}
fn id(value: &str) -> Result<[u8; 32]> {
    trust_bootstrap::hex32(value)
}
fn output_offer(status: &str, offer: &Offer) -> Result<()> {
    crate::print_value(&json!({"status":status,"member":hex::encode(offer.member),
        "candidate":hex::encode(offer.candidate),"inviter":hex::encode(offer.inviter),
        "readerGrant":hex::encode(offer.reader.id),"memberValidity":offer.validity,
        "acceptanceValidity":offer.acceptance_validity,"record":diagnostic(trust_wire::decode(&offer.reader_grant)?)}))
}
#[allow(
    clippy::too_many_arguments,
    reason = "Keep protocol inputs, state and validation callbacks explicit."
)]
fn refresh(
    location: &Location,
    bootstrap: &trust_bootstrap::Verified,
    socket: &Path,
    grant: [u8; 32],
    signer: &SigningKey,
    store: &mut Store,
    session: &mut Session,
    source: &authority_clock::Source,
) -> Result<ContextState> {
    if let Some(pending) = store.resume_ordinary()? {
        let intent = crate::authority_proof::Intent::from_signed(pending.signed())?;
        if intent.action != "AuthorityContext" {
            return ContextState::load(bootstrap, store, &location.directory);
        }
    }
    ContextState::refresh_local(bootstrap, socket, grant, signer, store, session, || {
        source.health()
    })
}
pub fn delegate(command: Delegate) -> Result<()> {
    let verified = bootstrap(&command.location)?;
    let mut store = Store::open(&command.location.directory, verified.descriptor().clone())?;
    let source = clock(&command.location, store.descriptor().voters())?;
    let signer = signer(&command.key)?;
    let mut session = Session::new()?;
    let context = refresh(
        &command.location,
        &verified,
        &command.socket,
        id(&command.context_grant)?,
        &signer,
        &mut store,
        &mut session,
        &source,
    )?;
    let parent = context.version(102, id(&command.parent)?)?;
    let tier = match command.tier {
        Some(tier) => context.version(101, id(&tier)?)?,
        None => context.grant_tier(parent.id)?,
    };
    let scopes = if command.scopes.is_empty() {
        vec![Value::Array(vec![
            Value::Uint(0),
            Value::Bytes(verified.descriptor().scope().network.to_vec()),
        ])]
    } else {
        command
            .scopes
            .iter()
            .map(|value| {
                let (kind, identifier) = value
                    .split_once(':')
                    .context("scope must be kind:identifier")?;
                Ok(Value::Array(vec![
                    Value::Uint(kind.parse()?),
                    Value::Bytes(id(identifier)?.to_vec()),
                ]))
            })
            .collect::<Result<Vec<_>>>()?
    };
    let version = |v: &crate::authority_proof::VersionRef| {
        Value::Array(vec![
            Value::Uint(v.kind),
            Value::Bytes(v.id.to_vec()),
            Value::Uint(v.generation),
            Value::Bytes(v.digest.to_vec()),
        ])
    };
    let child = Value::Array(vec![
        Value::Bytes(id(&command.id)?.to_vec()),
        Value::Bytes(id(&command.subject)?.to_vec()),
        version(&tier),
        Value::Array(command.actions.into_iter().map(Value::Uint).collect()),
        Value::Array(scopes),
        Value::Array(vec![
            Value::Uint(command.not_before_ms),
            Value::Uint(command.expires_ms),
        ]),
        Value::Uint(command.delegation_depth),
        Value::Array(command.limits.into_iter().map(Value::Uint).collect()),
    ]);
    let result = context.member_local(
        &command.socket,
        MemberRequest {
            bootstrap: &verified,
            mutation: MemberMutation::Delegate { parent, child },
            receipt: None,
        },
        &signer,
        &mut store,
        &mut session,
        || source.health(),
    )?;
    crate::print_value(
        &json!({"status":"GrantDelegated","grant":hex::encode(result.reference().id),
        "recordDigest":hex::encode(result.reference().digest),"committedHeight":result.prefix().height(),
        "record":diagnostic(trust_wire::decode(result.canonical())?)}),
    )
}
pub fn invite(command: Invite) -> Result<()> {
    let verified = bootstrap(&command.location)?;
    let store = Store::open(&command.location.directory, verified.descriptor().clone())?;
    let source = clock(&command.location, store.descriptor().voters())?;
    let context = ContextState::load(&verified, &store, &command.location.directory)?;
    let bytes = member_offer::invite(
        &verified,
        &context,
        &store,
        Invitation {
            member: id(&command.member)?,
            reader_grant: id(&command.reader_grant)?,
            validity: (command.not_before_ms, command.expires_ms),
            acceptance_ms: command.acceptance_ms,
        },
        &signer(&command.key)?,
        source.health()?,
    )?;
    files::write_new(&command.output, &bytes)?;
    output_offer("MemberOffered", &Offer::parse(&verified, &bytes, false)?)
}
pub fn inspect_offer(command: InspectOffer) -> Result<()> {
    let verified = offline(&command.trust)?;
    let bytes = files::read_single(&command.offer, member_offer::OFFER_LIMIT, true)?;
    let offer = Offer::parse(&verified, &bytes, false)
        .or_else(|_| Offer::parse(&verified, &bytes, true))?;
    offer.authenticate_inviter(
        &verified,
        command.inviter_key.as_deref().map(id).transpose()?,
    )?;
    output_offer("MemberOfferInspected", &offer)
}
pub fn accept(command: Accept) -> Result<()> {
    let verified = offline(&command.trust)?;
    let bytes = files::read_single(&command.offer, member_offer::OFFER_LIMIT, true)?;
    let offer = Offer::parse(&verified, &bytes, false)?;
    let bytes = offer.accept(
        &verified,
        &signer(&command.key)?,
        command.inviter_key.as_deref().map(id).transpose()?,
    )?;
    files::write_new(&command.output, &bytes)?;
    output_offer("MemberAccepted", &Offer::parse(&verified, &bytes, true)?)
}
pub fn admit(command: Admit) -> Result<()> {
    let verified = bootstrap(&command.location)?;
    let bytes = files::read_single(&command.accepted, member_offer::OFFER_LIMIT, true)?;
    let offer = Offer::parse(&verified, &bytes, true)?;
    let mut store = Store::open(&command.location.directory, verified.descriptor().clone())?;
    let source = clock(&command.location, store.descriptor().voters())?;
    let signer = signer(&command.key)?;
    let mut session = Session::new()?;
    let context = refresh(
        &command.location,
        &verified,
        &command.socket,
        id(&command.context_grant)?,
        &signer,
        &mut store,
        &mut session,
        &source,
    )?;
    let result = context.member_local(
        &command.socket,
        MemberRequest {
            bootstrap: &verified,
            mutation: MemberMutation::Admit {
                grant: id(&command.grant)?,
                accepted: offer.envelope,
            },
            receipt: Some(&command.receipt),
        },
        &signer,
        &mut store,
        &mut session,
        || source.health(),
    )?;
    crate::print_value(
        &json!({"status":"MemberAdmitted","member":hex::encode(result.reference().id),
        "recordDigest":hex::encode(result.reference().digest),"committedHeight":result.prefix().height()}),
    )
}
pub fn confirm(command: Confirm) -> Result<()> {
    let verified = offline(&command.trust)?;
    let offer = Offer::parse(
        &verified,
        &files::read_single(&command.accepted, member_offer::OFFER_LIMIT, true)?,
        true,
    )?;
    let bytes = files::read_single(&command.receipt, member_offer::RECEIPT_LIMIT, true)?;
    let epochs = command
        .prior_epochs
        .as_ref()
        .map(
            |path| -> Result<Vec<crate::authority_epoch::archive::Activated>> {
                Ok(serde_json::from_slice(&files::read_single(
                    path,
                    crate::authority_epoch::archive::MAX_ARCHIVE_BYTES,
                    true,
                )?)?)
            },
        )
        .transpose()?
        .unwrap_or_default();
    let confirmation = member_offer::confirm(&verified, &offer, &bytes, &epochs)?;
    crate::print_value(
        &json!({"status":"HistoricalMemberAdmission","member":hex::encode(offer.member),
        "candidate":hex::encode(offer.candidate),"readerGrant":hex::encode(offer.reader.id),
        "certifiedHeight":confirmation.certified_height(),"currentPermission":false}),
    )
}
