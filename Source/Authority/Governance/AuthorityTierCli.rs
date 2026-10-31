// SPDX-License-Identifier: MIT
// Administrative edits apply only the complete proposal and impact view selected by the operator.
use super::*;
use crate::{authority_inspection::tier, authority_proof::VersionRef, authority_tiers::Spec};
use anyhow::Context;
use serde::Deserialize;
use std::path::Path;

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
    /// List current tiers; rank is a presentation field and grants no authority.
    List {
        #[command(flatten)]
        online: Online,
    },
    /// Inspect one exact tier and its current administration dependencies.
    Get {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        tier: String,
    },
    /// Review every affected record and save the complete exact proposal.
    Preview {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        spec: PathBuf,
        /// Require this tier to be absent; without this flag the exact current tier is edited.
        #[arg(long)]
        create: bool,
        #[arg(long)]
        output: PathBuf,
    },
    /// Apply an exact previously reviewed proposal; changed policy state refuses the operation.
    Apply {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        preview: PathBuf,
        /// Digest printed by the complete preview command.
        #[arg(long)]
        preview_digest: String,
    },
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Scope {
    kind: u64,
    id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Input {
    id: String,
    rank: u64,
    label: String,
    actions: Vec<u64>,
    scopes: Vec<Scope>,
    delegation_depth: u64,
    limits: [u64; 4],
}
impl Input {
    fn spec(self, network: [u8; 32]) -> Result<Spec> {
        let spec = Spec {
            id: trust_bootstrap::hex32(&self.id)?,
            rank: self.rank,
            label: self.label,
            actions: self.actions,
            scopes: self
                .scopes
                .into_iter()
                .map(|s| Ok((s.kind, trust_bootstrap::hex32(&s.id)?)))
                .collect::<Result<_>>()?,
            depth: self.delegation_depth,
            limits: self.limits,
        };
        Spec::parse(&spec.value(), network)
    }
}
fn b(v: &[u8]) -> Value {
    Value::Bytes(v.to_vec())
}
fn a(v: Vec<Value>) -> Value {
    Value::Array(v)
}
fn reference(r: &VersionRef) -> Value {
    crate::authority_membership::reference(r)
}
fn refs(value: &Value) -> Result<Vec<VersionRef>> {
    let refs = value
        .list(64)?
        .iter()
        .map(|v| {
            let f = v.array(4)?;
            Ok(VersionRef {
                kind: f[0].uint()?,
                id: f[1].fixed()?,
                generation: f[2].uint()?,
                digest: f[3].fixed()?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    crate::authority_proof::validate_versions(&refs, 64)?;
    Ok(refs)
}
fn row(bytes: &[u8], network: [u8; 32], incarnation: [u8; 32]) -> Result<Json> {
    let (spec, r) = Spec::from_record(bytes, network, incarnation)?;
    Ok(
        json!({"id":hex::encode(r.id),"generation":r.generation,"digest":hex::encode(r.digest),
        "rank":spec.rank,"label":spec.label,"actions":spec.actions,
        "scopes":spec.scopes.iter().map(|(kind,id)|json!({"kind":kind,"id":hex::encode(id)})).collect::<Vec<_>>(),
        "delegationDepth":spec.depth,"limits":spec.limits}),
    )
}
struct Client {
    online: Online,
    bootstrap: trust_bootstrap::Verified,
    store: Store,
    signer: SigningKey,
    session: Session,
    clock: authority_clock::Source,
    grant: [u8; 32],
}
impl Client {
    fn open(online: Online) -> Result<Self> {
        let bootstrap = bootstrap(&online.location)?;
        let store = Store::open(&online.location.directory, bootstrap.descriptor().clone())?;
        let signer = signer(&online.key)?;
        store.require_requester(signer.verifying_key().to_bytes())?;
        let clock = clock(&online.location, store.descriptor().voters())?;
        let grant = trust_bootstrap::hex32(&online.grant)?;
        Ok(Self {
            online,
            bootstrap,
            store,
            signer,
            clock,
            grant,
            session: Session::new()?,
        })
    }
    fn call(&mut self, request: tier::Request) -> Result<tier::ResultState> {
        tier::execute(
            &self.bootstrap,
            &self.online.socket,
            self.grant,
            request,
            &self.signer,
            &mut self.store,
            &mut self.session,
            || self.clock.health(),
        )
    }
    fn context(&mut self, selected: Option<[u8; 32]>) -> Result<()> {
        self.call(tier::Request::Context(selected))?;
        Ok(())
    }
}
type CompletePreview = ([u8; 32], [u8; 32], [u8; 32], Vec<Value>);
pub(super) fn collect_preview(
    mut fetch: impl FnMut(Option<[u8; 32]>) -> Result<Value>,
) -> Result<CompletePreview> {
    let mut cursor = None;
    let mut binding = None;
    let mut impacts = Vec::new();
    let mut subjects = std::collections::BTreeSet::new();
    for page in 0..crate::authority_tiers::MAX_IMPACTS.div_ceil(crate::authority_tiers::IMPACT_PAGE)
    {
        let value = fetch(cursor)?;
        let fields = value.array(5)?[4].array(7)?;
        let current = (
            fields[0].fixed::<32>()?,
            fields[1].fixed::<32>()?,
            fields[2].fixed::<32>()?,
            fields[3].uint()?,
        );
        ensure!(
            current.3 <= crate::authority_tiers::MAX_IMPACTS as u64
                && fields[4].uint()? == page as u64,
            "preview pages are incomplete or out of order"
        );
        if let Some(first) = binding {
            ensure!(
                first == current,
                "preview policy or impact view changed between pages"
            );
        }
        binding = Some(current);
        let rows = fields[5].list(crate::authority_tiers::IMPACT_PAGE)?;
        let remaining = (current.3 as usize)
            .checked_sub(impacts.len())
            .context("preview repeats impact rows")?;
        ensure!(
            rows.len() == remaining.min(crate::authority_tiers::IMPACT_PAGE),
            "preview impact page is truncated"
        );
        for row in rows {
            let row = row.array(5)?;
            ensure!(
                subjects.insert((row[0].uint()?, row[1].fixed::<32>()?)),
                "preview repeats an affected subject"
            );
        }
        impacts.extend_from_slice(rows);
        cursor = if fields[6] == Value::Null {
            None
        } else {
            Some(fields[6].fixed()?)
        };
        if cursor.is_none() {
            ensure!(
                impacts.len() as u64 == current.3
                    && trust_wire::digest(&trust_wire::encode_state(&a(impacts.clone()))?)
                        == current.2,
                "complete preview impact digest differs"
            );
            return Ok((current.0, current.1, current.2, impacts));
        }
        ensure!(
            impacts.len() < current.3 as usize,
            "preview continuation exceeds its complete impact count"
        );
    }
    anyhow::bail!("preview impact bound exceeded")
}
fn reviewed(path: &Path, pin: &str) -> Result<Value> {
    let bytes = files::read_single(path, crate::authority_capacity::MAX_STATE_BYTES, true)?;
    ensure!(
        trust_wire::digest(&bytes) == trust_bootstrap::hex32(pin)?,
        "reviewed preview digest differs"
    );
    trust_wire::decode_state(&bytes)
}
pub fn run(command: Command) -> Result<()> {
    match command {
        Command::List { online } => {
            let mut client = Client::open(online)?;
            client.context(None)?;
            let s = client.bootstrap.descriptor().scope().clone();
            let mut after = None;
            let mut rows = Vec::new();
            loop {
                let result = client.call(tier::Request::List(after))?;
                let f = result.value.array(6)?;
                for bytes in f[4].list(32)? {
                    rows.push(row(bytes.bytes()?, s.network, s.incarnation)?);
                }
                ensure!(rows.len() <= 256, "tier inventory capacity exceeded");
                after = if f[5] == Value::Null {
                    None
                } else {
                    Some(f[5].fixed()?)
                };
                if after.is_none() {
                    break;
                }
            }
            crate::print_value(
                &json!({"status":"TiersVerified","tiers":rows,"height":client.store.prefix().height(),"rankConfersAuthority":false}),
            )
        }
        Command::Get { online, tier: id } => {
            let mut client = Client::open(online)?;
            let id = trust_bootstrap::hex32(&id)?;
            client.context(Some(id))?;
            let s = client.bootstrap.descriptor().scope();
            let source = tier::load(&client.bootstrap, &client.store)?;
            let governance =
                crate::authority_governance::Governance::parse(s.network, s.incarnation, &source)?;
            crate::print_value(
                &json!({"status":"TierVerified","tier":row(governance.record_bytes(101,id)?,s.network,s.incarnation)?,"height":client.store.prefix().height()}),
            )
        }
        Command::Preview {
            online,
            spec,
            create,
            output,
        } => {
            let mut client = Client::open(online)?;
            let scope = client.bootstrap.descriptor().scope().clone();
            let raw = files::read_single(&spec, 16384, true)?;
            let input: Input = serde_json::from_slice(&raw)?;
            let spec = input.spec(scope.network)?;
            client.context(if create { None } else { Some(spec.id) })?;
            let source = tier::load(&client.bootstrap, &client.store)?;
            let governance = crate::authority_governance::Governance::parse(
                scope.network,
                scope.incarnation,
                &source,
            )?;
            let previous = if create {
                None
            } else {
                Some(governance.record_bytes(101, spec.id)?.to_vec())
            };
            let expected = tier::dependencies(
                &client.bootstrap,
                &client.store,
                client.grant,
                previous.clone(),
                spec.clone(),
                client.clock.health()?.observe()?.wall_ms,
            )?;
            let (proposal, view, impact, impacts) = collect_preview(|token| {
                Ok(client
                    .call(tier::Request::Change {
                        previous: previous.clone(),
                        spec: Box::new(spec.clone()),
                        expected: expected.clone(),
                        token,
                        apply: false,
                    })?
                    .value)
            })?;
            let artifact = a(vec![
                Value::Uint(200),
                Value::Uint(1),
                Value::Text("ReviewedTierChange".into()),
                b(&client.bootstrap.file_digest()),
                b(&scope.network),
                b(&scope.incarnation),
                b(&client.store.requester()),
                b(&client.grant),
                previous.as_ref().map_or(Value::Null, |v| b(v)),
                spec.value(),
                a(expected.iter().map(reference).collect()),
                b(&proposal),
                b(&view),
                b(&impact),
                a(impacts.clone()),
            ]);
            let bytes = trust_wire::encode_state(&artifact)?;
            files::write_new(&output, &bytes)?;
            crate::print_value(
                &json!({"status":"TierPreviewComplete","id":hex::encode(spec.id),"create":create,
                "previewDigest":hex::encode(trust_wire::digest(&bytes)),"requestDigest":hex::encode(proposal),
                "impactDigest":hex::encode(impact),"impactCount":impacts.len(),"impacts":diagnostic(a(impacts)),
                "applied":false,"height":client.store.prefix().height()}),
            )
        }
        Command::Apply {
            online,
            preview,
            preview_digest,
        } => {
            let mut client = Client::open(online)?;
            let value = reviewed(&preview, &preview_digest)?;
            let f = value.array(15)?;
            let scope = client.bootstrap.descriptor().scope();
            ensure!(
                f[0].uint()? == 200
                    && f[1].uint()? == 1
                    && f[2].text()? == "ReviewedTierChange"
                    && f[3].fixed::<32>()? == client.bootstrap.file_digest()
                    && f[4].fixed::<32>()? == scope.network
                    && f[5].fixed::<32>()? == scope.incarnation
                    && f[6].fixed::<32>()? == client.store.requester()
                    && f[7].fixed::<32>()? == client.grant,
                "reviewed tier proposal belongs to another authority or requester"
            );
            let impacts = f[14].list(crate::authority_tiers::MAX_IMPACTS)?;
            ensure!(
                trust_wire::digest(&trust_wire::encode_state(&a(impacts.to_vec()))?)
                    == f[13].fixed::<32>()?,
                "reviewed impact digest differs"
            );
            let previous = if f[8] == Value::Null {
                None
            } else {
                Some(f[8].bytes()?.to_vec())
            };
            let spec = Spec::parse(&f[9], scope.network)?;
            let expected = refs(&f[10])?;
            let result = client.call(tier::Request::Change {
                previous,
                spec: Box::new(spec),
                expected,
                token: Some(f[12].fixed()?),
                apply: true,
            })?;
            let s = client.bootstrap.descriptor().scope();
            crate::print_value(
                &json!({"status":"TierApplied","tier":row(result.value.array(6)?[4].bytes()?,s.network,s.incarnation)?,
                "reviewedPreviewDigest":preview_digest,"height":result.prefix.height()}),
            )
        }
    }
}

#[cfg(test)]
#[path = "../../../Tests/Unit/Authority/Governance/AuthorityTierCliTests.rs"]
mod tests;
