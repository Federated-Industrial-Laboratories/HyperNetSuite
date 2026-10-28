// SPDX-License-Identifier: MIT
// Independent application keys use explicit grants and quorum-certified lifecycle operations.
use crate::{
    authority_challenge::Session,
    authority_floor::Store,
    authority_inspection::{
        application_client::{self as client, DelegationContext, Request, Selection},
        application_offer::{self as offers, Offer},
    },
    authority_inspection_cli::{Location, bootstrap, clock, diagnostic, signer},
    transfer_files as files, trust_bootstrap,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[derive(Args)]
pub struct Online {
    #[command(flatten)]
    location: Location,
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    socket: PathBuf,
}
#[derive(Args)]
pub struct Scope {
    #[arg(long)]
    parent: String,
    #[arg(long)]
    tier: String,
}
impl Scope {
    fn selection(&self, child: Option<[u8; 32]>) -> Result<Selection> {
        Ok(Selection {
            parent: id(&self.parent)?,
            tier: id(&self.tier)?,
            child,
        })
    }
}
#[derive(Args)]
pub struct Offline {
    #[arg(long)]
    bootstrap: PathBuf,
    /// SHA256 independently verified for the complete accepted bootstrap.
    #[arg(long)]
    bootstrap_digest: String,
}
#[derive(Subcommand)]
pub enum Command {
    /// Discover only the exact owner delegation closure; InspectAudit is not required.
    Context {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        scope: Scope,
        #[arg(long)]
        child: Option<String>,
    },
    /// Create a non-delegating child grant without admitting its application key.
    Delegate {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        scope: Scope,
        #[arg(long)]
        id: String,
        #[arg(long)]
        subject: String,
        #[arg(long, value_delimiter = ',', default_value = "0")]
        actions: Vec<u64>,
        /// Sorted kind:identifier pairs; defaults to this network.
        #[arg(long, value_delimiter = ',')]
        scopes: Vec<String>,
        #[arg(long)]
        not_before_ms: u64,
        #[arg(long)]
        expires_ms: u64,
        #[arg(long, value_delimiter = ',', num_args = 4, default_value = "0,1,0,1")]
        limits: Vec<u64>,
    },
    /// Write an owner-signed immutable offer containing only its exact child grant.
    Offer {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        key: PathBuf,
        #[command(flatten)]
        scope: Scope,
        #[arg(long)]
        grant: String,
        #[arg(long)]
        not_before_ms: u64,
        #[arg(long)]
        expires_ms: u64,
        #[arg(long, default_value_t = 3_600_000)]
        acceptance_ms: u64,
        #[arg(long)]
        output: PathBuf,
    },
    InspectOffer {
        #[command(flatten)]
        trust: Offline,
        #[arg(long)]
        offer: PathBuf,
        #[arg(long)]
        owner_key: Option<String>,
    },
    /// Sign after independently authenticating bootstrap and owner identity.
    Accept {
        #[command(flatten)]
        trust: Offline,
        #[arg(long)]
        offer: PathBuf,
        #[arg(long)]
        owner_key: Option<String>,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Register exact dual consent and save historical confirmation before completing locally.
    Register {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        scope: Scope,
        #[arg(long)]
        accepted: PathBuf,
        #[arg(long)]
        receipt: PathBuf,
    },
    Confirm {
        #[command(flatten)]
        trust: Offline,
        #[arg(long)]
        accepted: PathBuf,
        #[arg(long)]
        receipt: PathBuf,
        /// Verified epoch activations from the independently accepted initial network.
        #[arg(long)]
        prior_epochs: Option<PathBuf>,
    },
    /// Offer a finite same-rights renewal from a previously fetched application admission.
    RenewalOffer {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        application_key: String,
        #[arg(long)]
        not_before_ms: u64,
        #[arg(long)]
        expires_ms: u64,
        #[arg(long, default_value_t = 3_600_000)]
        acceptance_ms: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Independently approve a renewal of this application's unchanged rights.
    AcceptRenewal {
        #[command(flatten)]
        trust: Offline,
        #[arg(long)]
        offer: PathBuf,
        #[arg(long)]
        owner_key: Option<String>,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Extend an existing admission using fresh owner and application consent.
    Renew {
        #[command(flatten)]
        online: Online,
        #[command(flatten)]
        scope: Scope,
        #[arg(long)]
        accepted: PathBuf,
    },
    /// Read lifecycle metadata as its recorded owner or application, without domain authority.
    Get {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        application_key: String,
    },
    /// Return this owner's complete bounded application metadata set.
    List {
        #[command(flatten)]
        online: Online,
    },
    /// Permanently withdraw as owner or application, including after grant expiry or revocation.
    Withdraw {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        application_key: String,
    },
}
fn id(value: &str) -> Result<[u8; 32]> {
    trust_bootstrap::hex32(value)
}
fn b(bytes: &[u8]) -> V {
    V::Bytes(bytes.to_vec())
}
fn a(values: Vec<V>) -> V {
    V::Array(values)
}
fn reference(r: &crate::authority_proof::VersionRef) -> V {
    a(vec![
        V::Uint(r.kind),
        b(&r.id),
        V::Uint(r.generation),
        b(&r.digest),
    ])
}
fn offline(trust: &Offline) -> Result<trust_bootstrap::Verified> {
    let bytes = files::read_single(&trust.bootstrap, wire::MAXIMUM, true)?;
    ensure!(
        Sha256::digest(&bytes).as_slice() == id(&trust.bootstrap_digest)?,
        "bootstrap differs from independently verified digest"
    );
    trust_bootstrap::inspect(&bytes, true)
}
fn offer_output(status: &str, offer: &Offer) -> Result<()> {
    let consent = &offer.acceptance;
    crate::print_value(
        &json!({"status":status,"application":hex::encode(consent.application),"owner":hex::encode(consent.owner),"grant":hex::encode(consent.grant.id),"applicationValidity":consent.validity,"acceptanceValidity":consent.acceptance_validity,"record":diagnostic(wire::decode(&offer.grant)?)}),
    )
}
#[allow(
    clippy::too_many_arguments,
    reason = "Keep protocol inputs, state and validation callbacks explicit."
)]
fn context(
    verified: &trust_bootstrap::Verified,
    online: &Online,
    selection: Selection,
    pending_action: Option<&str>,
    signer: &ed25519_dalek::SigningKey,
    store: &mut Store,
    session: &mut Session,
    source: &crate::authority_clock::Source,
) -> Result<DelegationContext> {
    crate::authority_inspection::stream_client::resolve_refusal_local(
        &store.descriptor().clone(),
        &online.socket,
        signer,
        store,
        session,
        || source.health(),
    )?;
    if let Some(pending) = store.resume_ordinary()? {
        let intent = crate::authority_proof::Intent::from_signed(pending.signed())?;
        if intent.action != "AuthorityDelegationContext" {
            ensure!(
                pending_action == Some(intent.action.as_str()),
                "another exact request remains unresolved; resume it or explicitly fence its generation"
            );
            return DelegationContext::load(verified, store, selection);
        }
    }
    DelegationContext::refresh_local(
        verified,
        selection,
        &online.socket,
        signer,
        store,
        session,
        || source.health(),
    )
}
fn mutation_output(status: &str, result: &client::ResultState) -> Result<()> {
    let f = result.value.array(5)?;
    let bytes = f[4].bytes()?;
    let value = wire::decode(bytes)?;
    let fields = value.list(17)?;
    let kind = fields[0].uint()?;
    let application = match kind {
        102 => fields[8].fixed::<32>()?,
        127 => fields[6].fixed()?,
        128 => crate::authority_membership::version(&fields[6])?.id,
        _ => bail!("unexpected application mutation record"),
    };
    let grant = if kind == 102 {
        Some(hex::encode(fields[6].fixed::<32>()?))
    } else if kind == 127 {
        Some(hex::encode(
            crate::authority_membership::version(&fields[8])?.id,
        ))
    } else {
        None
    };
    crate::print_value(
        &json!({"status":status,"application":hex::encode(application),"grant":grant,"recordDigest":hex::encode(wire::digest(bytes)),"committedHeight":result.prefix.height(),"record":diagnostic(value)}),
    )
}
fn state_output(result: &client::ResultState) -> Result<()> {
    let f = result.value.array(7)?;
    let admission = wire::decode(f[4].bytes()?)?;
    let p = admission.array(11)?;
    crate::print_value(
        &json!({"status":"ApplicationState","application":hex::encode(p[6].fixed::<32>()?),"owner":hex::encode(p[7].fixed::<32>()?),"withdrawn":f[6] != V::Null,"admissionDigest":hex::encode(wire::digest(f[4].bytes()?)),"grantDigest":hex::encode(wire::digest(f[5].bytes()?)),"withdrawalDigest":if f[6] == V::Null { None } else { Some(hex::encode(wire::digest(f[6].bytes()?))) },"committedHeight":result.prefix.height(),"currentPermission":false,"record":diagnostic(result.value.clone())}),
    )
}
fn list_output(result: &client::ResultState) -> Result<()> {
    let rows = result.value.array(5)?[4].list(63)?.iter().map(|row| {
        let f = row.array(4)?;
        let version = |v: &V| -> Result<Value> { let r = crate::authority_membership::version(v)?; Ok(json!({"kind":r.kind,"id":hex::encode(r.id),"generation":r.generation,"digest":hex::encode(r.digest)})) };
        Ok(json!({"application":hex::encode(f[0].fixed::<32>()?),"admission":version(&f[1])?,"grant":version(&f[2])?,"withdrawal":if f[3] == V::Null { Value::Null } else { version(&f[3])? }}))
    }).collect::<Result<Vec<_>>>()?;
    crate::print_value(
        &json!({"status":"ApplicationList","applications":rows,"complete":true,"currentPermission":false,"committedHeight":result.prefix.height()}),
    )
}
pub fn run(command: Command) -> Result<()> {
    match command {
        Command::InspectOffer {
            trust,
            offer,
            owner_key,
        } => {
            let verified = offline(&trust)?;
            let bytes = files::read_single(&offer, offers::OFFER_LIMIT, true)?;
            let offer = Offer::parse(&verified, &bytes, false)
                .or_else(|_| Offer::parse(&verified, &bytes, true))?;
            offer.authenticate_owner(&verified, owner_key.as_deref().map(id).transpose()?)?;
            offer_output("ApplicationOfferInspected", &offer)
        }
        Command::Accept {
            trust,
            offer,
            owner_key,
            key,
            output,
        } => {
            let verified = offline(&trust)?;
            let bytes = files::read_single(&offer, offers::OFFER_LIMIT, true)?;
            let offer = Offer::parse(&verified, &bytes, false)?;
            let bytes = offer.accept(
                &verified,
                &signer(&key)?,
                owner_key.as_deref().map(id).transpose()?,
            )?;
            files::write_new(&output, &bytes)?;
            offer_output(
                "ApplicationAccepted",
                &Offer::parse(&verified, &bytes, true)?,
            )
        }
        Command::Confirm {
            trust,
            accepted,
            receipt,
            prior_epochs,
        } => {
            let verified = offline(&trust)?;
            let accepted = files::read_single(&accepted, offers::OFFER_LIMIT, true)?;
            let offer = Offer::parse(&verified, &accepted, true)?;
            let receipt = files::read_single(&receipt, offers::RECEIPT_LIMIT, true)?;
            let epochs = prior_epochs
                .map(
                    |path| -> Result<Vec<crate::authority_epoch::archive::Activated>> {
                        Ok(serde_json::from_slice(&files::read_single(
                            &path,
                            crate::authority_epoch::archive::MAX_ARCHIVE_BYTES,
                            true,
                        )?)?)
                    },
                )
                .transpose()?
                .unwrap_or_default();
            let height = offers::confirm(&verified, &offer, &receipt, &epochs)?;
            crate::print_value(
                &json!({"status":"HistoricalApplicationRegistration","application":hex::encode(offer.acceptance.application),"certifiedHeight":height,"currentPermission":false}),
            )
        }
        Command::Offer {
            location,
            key,
            scope,
            grant,
            not_before_ms,
            expires_ms,
            acceptance_ms,
            output,
        } => {
            let verified = bootstrap(&location)?;
            let store = Store::open(&location.directory, verified.descriptor().clone())?;
            let source = clock(&location, store.descriptor().voters())?;
            let grant = id(&grant)?;
            let context =
                DelegationContext::load(&verified, &store, scope.selection(Some(grant))?)?;
            let bytes = offers::invite(
                &verified,
                &context,
                &store,
                offers::Invitation {
                    grant,
                    validity: (not_before_ms, expires_ms),
                    acceptance_ms,
                },
                &signer(&key)?,
                source.health()?,
            )?;
            files::write_new(&output, &bytes)?;
            offer_output(
                "ApplicationOffered",
                &Offer::parse(&verified, &bytes, false)?,
            )
        }
        Command::Context {
            online,
            scope,
            child,
        } => {
            let verified = bootstrap(&online.location)?;
            let signer = signer(&online.key)?;
            let mut store = Store::open(&online.location.directory, verified.descriptor().clone())?;
            let source = clock(&online.location, store.descriptor().voters())?;
            let mut session = Session::new()?;
            context(
                &verified,
                &online,
                scope.selection(child.as_deref().map(id).transpose()?)?,
                None,
                &signer,
                &mut store,
                &mut session,
                &source,
            )?;
            crate::print_value(
                &json!({"status":"DelegationContextRefreshed","committedHeight":store.prefix().height()}),
            )
        }
        Command::Delegate {
            online,
            scope,
            id: grant,
            subject,
            actions,
            scopes,
            not_before_ms,
            expires_ms,
            limits,
        } => {
            let verified = bootstrap(&online.location)?;
            let signer = signer(&online.key)?;
            let mut store = Store::open(&online.location.directory, verified.descriptor().clone())?;
            let source = clock(&online.location, store.descriptor().voters())?;
            let mut session = Session::new()?;
            let grant = id(&grant)?;
            let selected = scope.selection(None)?;
            let context = context(
                &verified,
                &online,
                selected.clone(),
                Some("AuthorityDelegateGrant"),
                &signer,
                &mut store,
                &mut session,
                &source,
            )?;
            let scopes = if scopes.is_empty() {
                vec![a(vec![
                    V::Uint(0),
                    b(&verified.descriptor().scope().network),
                ])]
            } else {
                scopes
                    .iter()
                    .map(|v| {
                        let (kind, identifier) =
                            v.split_once(':').context("scope must be kind:identifier")?;
                        Ok(a(vec![V::Uint(kind.parse()?), b(&id(identifier)?)]))
                    })
                    .collect::<Result<Vec<_>>>()?
            };
            ensure!(!actions.contains(&11), "application grant cannot delegate");
            let request = Request::Delegate {
                parent: context.version(102, selected.parent)?,
                child: a(vec![
                    b(&grant),
                    b(&id(&subject)?),
                    reference(&context.version(101, selected.tier)?),
                    a(actions.into_iter().map(V::Uint).collect()),
                    a(scopes),
                    a(vec![V::Uint(not_before_ms), V::Uint(expires_ms)]),
                    V::Uint(0),
                    a(limits.into_iter().map(V::Uint).collect()),
                ]),
            };
            let result = client::local(
                &verified,
                request,
                Some(&context),
                None,
                &online.socket,
                &signer,
                &mut store,
                &mut session,
                || source.health(),
            )?;
            // The offer opens a distinct cache that includes the exact created child.
            DelegationContext::refresh_local(
                &verified,
                scope.selection(Some(grant))?,
                &online.socket,
                &signer,
                &mut store,
                &mut session,
                || source.health(),
            )?;
            mutation_output("ApplicationGrantDelegated", &result)
        }
        Command::Register {
            online,
            scope,
            accepted,
            receipt,
        } => {
            let verified = bootstrap(&online.location)?;
            let bytes = files::read_single(&accepted, offers::OFFER_LIMIT, true)?;
            let offer = Offer::parse(&verified, &bytes, true)?;
            let signer = signer(&online.key)?;
            ensure!(
                signer.verifying_key().to_bytes() == offer.acceptance.owner,
                "registration signer differs from consenting owner"
            );
            let mut store = Store::open(&online.location.directory, verified.descriptor().clone())?;
            let source = clock(&online.location, store.descriptor().voters())?;
            let mut session = Session::new()?;
            let selected = scope.selection(Some(offer.acceptance.grant.id))?;
            let context = context(
                &verified,
                &online,
                selected.clone(),
                Some("AuthorityApplicationRegister"),
                &signer,
                &mut store,
                &mut session,
                &source,
            )?;
            let result = client::local(
                &verified,
                Request::Register {
                    parent: context.version(102, selected.parent)?,
                    accepted: offer.acceptance.envelope,
                },
                Some(&context),
                Some(&receipt),
                &online.socket,
                &signer,
                &mut store,
                &mut session,
                || source.health(),
            )?;
            mutation_output("ApplicationRegistered", &result)
        }
        Command::RenewalOffer {
            location,
            key,
            application_key,
            not_before_ms,
            expires_ms,
            acceptance_ms,
            output,
        } => {
            let verified = bootstrap(&location)?;
            let store = Store::open(&location.directory, verified.descriptor().clone())?;
            let source = clock(&location, store.descriptor().voters())?;
            let bytes = offers::invite_renewal(
                &verified,
                &store,
                id(&application_key)?,
                (not_before_ms, expires_ms),
                acceptance_ms,
                &signer(&key)?,
                source.health()?,
            )?;
            files::write_new(&output, &bytes)?;
            renewal_output(
                "ApplicationRenewalOffered",
                &offers::RenewalOffer::parse(&verified, &bytes, false)?,
            )
        }
        Command::AcceptRenewal {
            trust,
            offer,
            owner_key,
            key,
            output,
        } => {
            let verified = offline(&trust)?;
            let bytes = files::read_single(&offer, offers::OFFER_LIMIT, true)?;
            let offer = offers::RenewalOffer::parse(&verified, &bytes, false)?;
            let bytes = offer.accept(
                &verified,
                &signer(&key)?,
                owner_key.as_deref().map(id).transpose()?,
            )?;
            files::write_new(&output, &bytes)?;
            renewal_output(
                "ApplicationRenewalAccepted",
                &offers::RenewalOffer::parse(&verified, &bytes, true)?,
            )
        }
        Command::Renew {
            online,
            scope,
            accepted,
        } => {
            let verified = bootstrap(&online.location)?;
            let bytes = files::read_single(&accepted, offers::OFFER_LIMIT, true)?;
            let offer = offers::RenewalOffer::parse(&verified, &bytes, true)?;
            let signer = signer(&online.key)?;
            ensure!(
                signer.verifying_key().to_bytes() == offer.consent.owner,
                "renewal signer differs from owner"
            );
            let mut store = Store::open(&online.location.directory, verified.descriptor().clone())?;
            let source = clock(&online.location, store.descriptor().voters())?;
            let mut session = Session::new()?;
            let context = context(
                &verified,
                &online,
                scope.selection(Some(offer.consent.grant.id))?,
                Some("AuthorityApplicationRenew"),
                &signer,
                &mut store,
                &mut session,
                &source,
            )?;
            let result = client::local(
                &verified,
                Request::Renew {
                    previous: offer.previous,
                    accepted: offer.envelope,
                },
                Some(&context),
                None,
                &online.socket,
                &signer,
                &mut store,
                &mut session,
                || source.health(),
            )?;
            mutation_output("ApplicationRenewed", &result)
        }
        Command::Get {
            online,
            application_key,
        } => lifecycle(online, Some(id(&application_key)?), false),
        Command::List { online } => lifecycle(online, None, false),
        Command::Withdraw {
            online,
            application_key,
        } => lifecycle(online, Some(id(&application_key)?), true),
    }
}
fn lifecycle(online: Online, application: Option<[u8; 32]>, withdraw: bool) -> Result<()> {
    let verified = bootstrap(&online.location)?;
    let signer = signer(&online.key)?;
    let mut store = Store::open(&online.location.directory, verified.descriptor().clone())?;
    let source = clock(&online.location, store.descriptor().voters())?;
    let mut session = Session::new()?;
    let request = if withdraw {
        crate::authority_inspection::stream_client::resolve_refusal_local(
            &store.descriptor().clone(),
            &online.socket,
            &signer,
            &mut store,
            &mut session,
            || source.health(),
        )?;
        let application = application.context("withdrawal requires application key")?;
        let needs_get = store.resume_ordinary()?.is_none_or(|p| {
            crate::authority_proof::Intent::from_signed(p.signed())
                .is_ok_and(|i| i.action == "AuthorityApplicationGet")
        });
        if needs_get {
            client::local(
                &verified,
                Request::Get(application),
                None,
                None,
                &online.socket,
                &signer,
                &mut store,
                &mut session,
                || source.health(),
            )?;
        }
        Request::Withdraw(client::withdrawal_target(&store, application)?)
    } else {
        application.map_or(Request::List, Request::Get)
    };
    let result = client::local(
        &verified,
        request,
        None,
        None,
        &online.socket,
        &signer,
        &mut store,
        &mut session,
        || source.health(),
    )?;
    if withdraw {
        mutation_output("ApplicationWithdrawn", &result)
    } else if application.is_some() {
        state_output(&result)
    } else {
        list_output(&result)
    }
}

#[cfg(test)]
#[path = "../Authority/Governance/AuthorityApplicationCliTests.rs"]
mod tests;

fn renewal_output(status: &str, offer: &offers::RenewalOffer) -> Result<()> {
    crate::print_value(
        &json!({"status":status,"application":hex::encode(offer.consent.admission.id),
        "owner":hex::encode(offer.consent.owner),"previousGeneration":offer.consent.admission.generation,
        "validity":offer.consent.validity,"acceptanceValidity":offer.consent.acceptance_validity,
        "grant":hex::encode(offer.consent.grant.id),"rightsChanged":false}),
    )
}
