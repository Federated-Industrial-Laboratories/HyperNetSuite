// SPDX-License-Identifier: MIT
// Policy proposals are inspected before independent custody signatures and ordered submission.
use super::*;
use crate::{
    authority_governance::{Governance, Requirement},
    authority_inspection::policy,
    authority_membership::{Snapshot, reference},
    authority_policies::{self as policies, Custody, Operation},
    trust_wire::{self as wire, Value as V},
};
use anyhow::Context;
use serde::Deserialize;
use std::{collections::BTreeMap, path::Path};
#[derive(Args)]
pub struct Online {
    #[command(flatten)]
    location: Location,
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    socket: PathBuf,
    #[arg(long)]
    grant: String,
}
#[derive(Subcommand)]
pub enum Command {
    /// Fetch only the current network trust contract without administrative inspection authority.
    Discover {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        socket: PathBuf,
    },
    /// Fetch the certified current policy and print its exact trust contract digest.
    Get {
        #[command(flatten)]
        online: Online,
    },
    /// Produce an exact successor proposal from the current certified policy and typed settings.
    Prepare {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        spec: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Inspect a bounded proposal offline before signing or submitting it.
    Inspect {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        proposal: PathBuf,
    },
    /// Sign exact proposed custody using one independently held old or new custody identity.
    Sign {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        proposal: PathBuf,
        #[arg(long)]
        proposal_digest: String,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        new_custody: bool,
        #[arg(long)]
        output: PathBuf,
    },
    /// Assemble old authorisation and new acceptance separately; signatures never cross cohorts.
    Assemble {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        proposal: PathBuf,
        #[arg(long,num_args=1..=3)]
        old_share: Vec<PathBuf>,
        #[arg(long,num_args=1..=3)]
        new_share: Vec<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Submit the exact inspected successor through current administration authority.
    Apply {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        proposal: PathBuf,
        #[arg(long)]
        proposal_digest: String,
    },
    /// Accept an inspected current trust contract locally; route and publication minima remain separate.
    Accept {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        trust_digest: String,
    },
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Recovery {
    custody: u64,
    principals: Vec<String>,
    keys: Vec<(String, String)>,
    immutable_shared: bool,
    accepted_by: Vec<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Spec {
    enrolment: u64,
    public_reading: bool,
    minimum_route: u64,
    allowed_relay_domains: Vec<String>,
    allowed_publication_modes: Vec<u64>,
    default_publication_mode: u64,
    limits: [u64; 4],
    manual_review_default: bool,
    policy_authority: Vec<String>,
    recovery: Option<Recovery>,
}
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
fn id(v: &str) -> Result<[u8; 32]> {
    trust_bootstrap::hex32(v)
}
fn read(path: &Path) -> Result<Vec<u8>> {
    files::read_public_single(path, wire::MAXIMUM)
}
fn identifiers(v: &[String]) -> Result<V> {
    Ok(a(v
        .iter()
        .map(|s| Ok(b(&id(s)?)))
        .collect::<Result<_>>()?))
}
fn policy_spec(bytes: &[u8]) -> Result<Json> {
    let value = wire::decode(bytes)?;
    let p = value.array(17)?;
    let ids = |v: &V| max_ids(v);
    Ok(
        json!({"enrolment":p[6].uint()?,"publicReading":p[7].boolean()?,"minimumRoute":p[8].uint()?,"allowedRelayDomains":ids(&p[9])?,"allowedPublicationModes":p[10].list(2)?.iter().map(V::uint).collect::<Result<Vec<_>>>()?,"defaultPublicationMode":p[11].uint()?,"limits":p[13].array(4)?.iter().map(V::uint).collect::<Result<Vec<_>>>()?,"manualReviewDefault":p[14].boolean()?,"policyAuthority":ids(&p[15])?,"recovery":null}),
    )
}
fn max_ids(value: &V) -> Result<Vec<String>> {
    value
        .list(16)?
        .iter()
        .map(|v| Ok(hex::encode(v.fixed::<32>()?)))
        .collect()
}
fn recovery_spec(bytes: &[u8]) -> Result<Json> {
    let value = wire::decode(bytes)?;
    let r = value.array(13)?;
    Ok(
        json!({"custody":r[6].uint()?,"principals":max_ids(&r[8])?,"keys":r[9].list(3)?.iter().map(|v|{let p=v.array(2)?;Ok(vec![hex::encode(p[0].fixed::<32>()?),hex::encode(p[1].fixed::<32>()?)])}).collect::<Result<Vec<_>>>()?,"immutableShared":r[10].boolean()?,"acceptedBy":max_ids(&r[11])?}),
    )
}
fn describe(op: &Operation) -> Result<Json> {
    let p = wire::decode(&op.policy)?;
    let p = p.array(17)?;
    let n = p[2].fixed()?;
    let i = p[3].fixed()?;
    let r = Custody::parse(&op.recovery, n, i)?;
    let old = Custody::parse(&op.previous_recovery, n, i)?;
    Ok(
        json!({"proposalDigest":hex::encode(wire::digest(&op.parameters()?)),"network":hex::encode(n),"policyGeneration":p[4].uint()?,"enrolment":p[6].uint()?,"publicReading":p[7].boolean()?,"minimumRoute":p[8].uint()?,"allowedRelayDomains":p[9].list(16)?.iter().map(|v|Ok(hex::encode(v.fixed::<32>()?))).collect::<Result<Vec<_>>>()?,"allowedPublicationModes":p[10].list(2)?.iter().map(V::uint).collect::<Result<Vec<_>>>()?,"recoveryGeneration":r.reference.generation,"custody":r.mode,"threshold":r.threshold,"immutableShared":r.immutable,"weakerRecovery":r.weaker_than(&old),"oldAuthorisation":op.old_authorisation.is_some(),"newAcceptance":op.new_acceptance.is_some(),"networkUsed":false,"previousPolicy":policy_spec(&op.previous_policy)?,"proposedPolicy":policy_spec(&op.policy)?,"previousRecovery":recovery_spec(&op.previous_recovery)?,"proposedRecovery":recovery_spec(&op.recovery)?}),
    )
}
struct Client {
    online: Online,
    bootstrap: trust_bootstrap::Verified,
    store: Store,
    key: SigningKey,
    session: Session,
    clock: authority_clock::Source,
    grant: [u8; 32],
}
impl Client {
    fn open(online: Online) -> Result<Self> {
        let bootstrap = bootstrap(&online.location)?;
        let store = Store::open(&online.location.directory, bootstrap.descriptor().clone())?;
        let key = signer(&online.key)?;
        store.require_requester(key.verifying_key().to_bytes())?;
        let clock = clock(&online.location, store.descriptor().voters())?;
        let grant = id(&online.grant)?;
        Ok(Self {
            online,
            bootstrap,
            store,
            key,
            clock,
            grant,
            session: Session::new()?,
        })
    }
    fn context(&mut self) -> Result<ContextState> {
        ContextState::refresh_local(
            &self.bootstrap,
            &self.online.socket,
            self.grant,
            &self.key,
            &mut self.store,
            &mut self.session,
            || self.clock.health(),
        )
    }
}
fn combine(payload: &[u8], paths: &[PathBuf]) -> Result<Vec<u8>> {
    ensure!(
        (1..=3).contains(&paths.len()),
        "one to three independent custody shares required"
    );
    let mut signatures = BTreeMap::new();
    for path in paths {
        let (bytes, pairs) = wire::envelope(&read(path)?, 1)?;
        ensure!(bytes == payload, "custody share names another proposal");
        for (k, s) in pairs {
            ensure!(signatures.insert(k, s).is_none(), "duplicate custody share");
        }
    }
    wire::encode(&a(vec![
        V::Uint(0),
        V::Uint(1),
        b(payload),
        a(signatures
            .into_iter()
            .map(|(k, s)| a(vec![b(&k), b(&s)]))
            .collect()),
    ]))
}
pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Discover {
            location,
            key,
            socket,
        } => {
            let bootstrap = super::bootstrap(&location)?;
            let signer = super::signer(&key)?;
            let mut store = Store::open(&location.directory, bootstrap.descriptor().clone())?;
            let clock = super::clock(&location, store.descriptor().voters())?;
            let mut session = Session::new()?;
            ensure!(
                store.resume_ordinary()?.is_none()
                    || store
                        .resume_ordinary()?
                        .is_some_and(|p| crate::authority_proof::Intent::from_signed(p.signed())
                            .is_ok_and(|i| i.action == "AuthorityPolicyContext")),
                "resolve the pending ordinary operation before explicit policy discovery"
            );
            policy::discover(
                &bootstrap,
                &socket,
                &signer,
                &mut store,
                &mut session,
                || clock.health(),
            )?;
            let (p, r) = policy::current(&bootstrap, &store)?;
            crate::print_value(
                &json!({"trustDigest":hex::encode(policy::acceptance_digest(&bootstrap,&store)?),"accepted":policy::require_accepted(&bootstrap,&store).is_ok(),"spec":policy_spec(&p)?,"currentRecovery":recovery_spec(&r)?}),
            )
        }
        Command::Get { online } => {
            let mut c = Client::open(online)?;
            c.context()?;
            let (p, r) = policy::current(&c.bootstrap, &c.store)?;
            let s = c.bootstrap.descriptor().scope();
            let custody = Custody::parse(&r, s.network, s.incarnation)?;
            crate::print_value(
                &json!({"trustDigest":hex::encode(policy::acceptance_digest(&c.bootstrap,&c.store)?),"policyDigest":hex::encode(wire::digest(&p)),"recoveryDigest":hex::encode(wire::digest(&r)),"policyGeneration":policies::record_reference(&p,s.network,s.incarnation,100)?.generation,"custody":custody.mode,"threshold":custody.threshold,"accepted":policy::require_accepted(&c.bootstrap,&c.store).is_ok(),"spec":policy_spec(&p)?,"currentRecovery":recovery_spec(&r)?}),
            )
        }
        Command::Prepare {
            online,
            spec,
            output,
        } => {
            let mut c = Client::open(online)?;
            let context = c.context()?;
            policy::require_accepted(&c.bootstrap, &c.store)?;
            let source = context.current_records(&c.store)?;
            let s = c.bootstrap.descriptor().scope();
            let governance = Governance::parse(s.network, s.incarnation, &source)?;
            let previous_policy = governance.record_bytes(100, s.network)?.to_vec();
            let previous_recovery = governance.record_bytes(114, s.network)?.to_vec();
            let old = policies::record_reference(&previous_policy, s.network, s.incarnation, 100)?;
            let old_r = Custody::parse(&previous_recovery, s.network, s.incarnation)?;
            let input: Spec = serde_json::from_slice(&read(&spec)?)?;
            let cap = governance.current_capability(
                c.grant,
                &Requirement {
                    subject: c.key.verifying_key().to_bytes(),
                    actions: &[9],
                    scope: (0, s.network),
                    namespace: None,
                    usage: [0, 1, 0, 1],
                    evaluated_at_ms: c.clock.health()?.observe()?.wall_ms,
                    expected: &[],
                },
            )?;
            let mut expected = cap.dependencies;
            expected.push(old_r.reference.clone());
            if let Some(recovery) = &input.recovery {
                let principals = recovery
                    .principals
                    .iter()
                    .map(|v| id(v))
                    .collect::<Result<Vec<_>>>()?;
                expected.extend(policies::custody_dependencies(
                    &governance,
                    &old_r,
                    &principals,
                    c.clock.health()?.observe()?.wall_ms,
                )?);
            }
            expected.sort_by_key(crate::authority_proof::VersionRef::index);
            expected.dedup();
            let snapshot = Snapshot::parse(&a(vec![
                a(vec![
                    V::Uint(c.store.prefix().scope().epoch),
                    V::Uint(c.store.prefix().height()),
                    b(c.store.prefix().policy_state()),
                ]),
                a(expected.iter().map(reference).collect()),
            ]))?;
            let recovery = if let Some(r) = input.recovery {
                wire::encode(&a(vec![
                    V::Uint(114),
                    V::Uint(1),
                    b(&s.network),
                    b(&s.incarnation),
                    V::Uint(
                        old_r
                            .reference
                            .generation
                            .checked_add(1)
                            .context("recovery generation exhausted")?,
                    ),
                    b(&old_r.reference.digest),
                    V::Uint(r.custody),
                    V::Uint(if r.custody == 0 { 1 } else { 2 }),
                    identifiers(&r.principals)?,
                    a(r.keys
                        .iter()
                        .map(|(p, k)| Ok(a(vec![b(&id(p)?), b(&id(k)?)])))
                        .collect::<Result<_>>()?),
                    V::Bool(r.immutable_shared),
                    identifiers(&r.accepted_by)?,
                    snapshot.value.clone(),
                ]))?
            } else {
                previous_recovery.clone()
            };
            let r = Custody::parse(&recovery, s.network, s.incarnation)?;
            let policy_bytes = wire::encode(&a(vec![
                V::Uint(100),
                V::Uint(1),
                b(&s.network),
                b(&s.incarnation),
                V::Uint(
                    old.generation
                        .checked_add(1)
                        .context("policy generation exhausted")?,
                ),
                b(&old.digest),
                V::Uint(input.enrolment),
                V::Bool(input.public_reading),
                V::Uint(input.minimum_route),
                identifiers(&input.allowed_relay_domains)?,
                a(input
                    .allowed_publication_modes
                    .into_iter()
                    .map(V::Uint)
                    .collect()),
                V::Uint(input.default_publication_mode),
                reference(&r.reference),
                a(input.limits.into_iter().map(V::Uint).collect()),
                V::Bool(input.manual_review_default),
                identifiers(&input.policy_authority)?,
                snapshot.value.clone(),
            ]))?;
            let op = Operation {
                grant: c.grant,
                previous_policy,
                previous_recovery,
                policy: policy_bytes,
                recovery,
                old_authorisation: None,
                new_acceptance: None,
                snapshot,
            };
            op.validate_unsigned(s.network, s.incarnation)?;
            op.apply_records(&source, s.network, s.incarnation)?;
            files::write_new(&output, &op.parameters()?)?;
            crate::print_value(&describe(&op)?)
        }
        Command::Inspect { location, proposal } => {
            let boot = bootstrap(&location)?;
            let s = boot.descriptor().scope();
            let op = Operation::decode(&read(&proposal)?, s.network, s.incarnation, false)?;
            crate::print_value(&describe(&op)?)
        }
        Command::Sign {
            location,
            proposal,
            proposal_digest,
            identity,
            new_custody,
            output,
        } => {
            let boot = bootstrap(&location)?;
            let s = boot.descriptor().scope();
            let bytes = read(&proposal)?;
            ensure!(
                wire::digest(&bytes) == id(&proposal_digest)?,
                "inspected policy proposal digest differs"
            );
            let op = Operation::decode(&bytes, s.network, s.incarnation, false)?;
            ensure!(
                op.previous_recovery != op.recovery,
                "policy has no custody change"
            );
            let custody = Custody::parse(
                if new_custody {
                    &op.recovery
                } else {
                    &op.previous_recovery
                },
                s.network,
                s.incarnation,
            )?;
            let key = signer(&identity)?;
            let k = key.verifying_key().to_bytes();
            ensure!(
                custody.keys.iter().any(|(_, key)| *key == k)
                    && (!new_custody || custody.accepted.contains(&policies::key_fingerprint(&k))),
                "identity is outside selected custody cohort"
            );
            files::write_new(&output, &wire::sign_envelope(&op.recovery, &key)?)?;
            crate::print_value(
                &json!({"state":"PolicyCustodyShare","newCustody":new_custody,"proposalDigest":proposal_digest}),
            )
        }
        Command::Assemble {
            location,
            proposal,
            old_share,
            new_share,
            output,
        } => {
            let boot = bootstrap(&location)?;
            let s = boot.descriptor().scope();
            let mut op = Operation::decode(&read(&proposal)?, s.network, s.incarnation, false)?;
            op.old_authorisation = Some(combine(&op.recovery, &old_share)?);
            op.new_acceptance = Some(combine(&op.recovery, &new_share)?);
            op.validate(s.network, s.incarnation)?;
            files::write_new(&output, &op.parameters()?)?;
            crate::print_value(&describe(&op)?)
        }
        Command::Apply {
            online,
            proposal,
            proposal_digest,
        } => {
            let mut c = Client::open(online)?;
            let s = c.bootstrap.descriptor().scope();
            let bytes = read(&proposal)?;
            ensure!(
                wire::digest(&bytes) == id(&proposal_digest)?,
                "inspected policy submission digest differs"
            );
            let op = Operation::decode(&bytes, s.network, s.incarnation, true)?;
            ensure!(
                op.grant == c.grant,
                "proposal uses another administration grant"
            );
            let context = ContextState::load(&c.bootstrap, &c.store, &c.online.location.directory)?;
            let result = policy::execute_context(
                &c.bootstrap,
                &context,
                &c.online.socket,
                op,
                &c.key,
                &mut c.store,
                &mut c.session,
                || c.clock.health(),
            )?;
            crate::print_value(
                &json!({"state":"PolicyCommitted","height":result.prefix.height(),"trustDigest":hex::encode(policy::acceptance_digest(&c.bootstrap,&c.store)?),"accepted":policy::require_accepted(&c.bootstrap,&c.store).is_ok()}),
            )
        }
        Command::Accept {
            location,
            trust_digest,
        } => {
            let boot = bootstrap(&location)?;
            let store = Store::open(&location.directory, boot.descriptor().clone())?;
            policy::accept(&boot, &store, id(&trust_digest)?)?;
            crate::print_value(
                &json!({"state":"TrustContractAccepted","trustDigest":trust_digest,"networkUsed":false}),
            )
        }
    }
}
