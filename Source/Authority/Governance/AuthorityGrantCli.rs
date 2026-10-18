// SPDX-License-Identifier: MIT
// Complete certified impact review precedes an exact, separately selected grant mutation.
use super::*;
use crate::{
    authority_inspection::grant, authority_membership::reference, authority_proof::VersionRef,
};
use serde::Deserialize;

#[derive(Args)]
pub struct Online {
    #[command(flatten)]
    location: Location,
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    socket: PathBuf,
    /// Separate InspectAudit grant for complete current context discovery.
    #[arg(long)]
    context_grant: String,
}
#[derive(Subcommand)]
pub enum Command {
    /// Review the exact child grant and all affected authority dependencies.
    DelegatePreview {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        parent: String,
        #[arg(long)]
        spec: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Review withdrawal of an exact current grant and its dependent capabilities.
    RevokePreview {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        grant: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Apply exactly the saved reviewed proposal; changed policy state refuses it.
    Apply {
        #[command(flatten)]
        online: Online,
        #[arg(long)]
        preview: PathBuf,
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
struct Child {
    id: String,
    subject: String,
    tier: Option<String>,
    actions: Vec<u64>,
    scopes: Vec<Scope>,
    not_before_ms: u64,
    expires_ms: u64,
    delegation_depth: u64,
    limits: [u64; 4],
}
fn b(v: &[u8]) -> Value {
    Value::Bytes(v.to_vec())
}
fn a(v: Vec<Value>) -> Value {
    Value::Array(v)
}
impl Child {
    fn value(self, context: &ContextState, parent: &VersionRef) -> Result<Value> {
        let selected = self
            .tier
            .as_deref()
            .map(trust_bootstrap::hex32)
            .transpose()?;
        let tier = match selected {
            Some(id) => context.version(101, id)?,
            None => {
                let pin = context.grant_tier(parent.id)?;
                context.version(101, pin.id)?
            }
        };
        Ok(a(vec![
            b(&trust_bootstrap::hex32(&self.id)?),
            b(&trust_bootstrap::hex32(&self.subject)?),
            reference(&tier),
            a(self.actions.into_iter().map(Value::Uint).collect()),
            a(self
                .scopes
                .into_iter()
                .map(|s| {
                    Ok(a(vec![
                        Value::Uint(s.kind),
                        b(&trust_bootstrap::hex32(&s.id)?),
                    ]))
                })
                .collect::<Result<_>>()?),
            a(vec![
                Value::Uint(self.not_before_ms),
                Value::Uint(self.expires_ms),
            ]),
            Value::Uint(self.delegation_depth),
            a(self.limits.into_iter().map(Value::Uint).collect()),
        ]))
    }
}
struct Client {
    online: Online,
    bootstrap: trust_bootstrap::Verified,
    store: Store,
    signer: SigningKey,
    session: Session,
    clock: authority_clock::Source,
    context: ContextState,
}
impl Client {
    fn open(online: Online) -> Result<Self> {
        let bootstrap = bootstrap(&online.location)?;
        let mut store = Store::open(&online.location.directory, bootstrap.descriptor().clone())?;
        let signer = signer(&online.key)?;
        store.require_requester(signer.verifying_key().to_bytes())?;
        let clock = clock(&online.location, store.descriptor().voters())?;
        let mut session = Session::new()?;
        let context = if store.resume_ordinary()?.is_some_and(|p| {
            crate::authority_proof::Intent::from_signed(p.signed())
                .is_ok_and(|i| i.action != "AuthorityContext")
        }) {
            ContextState::load(&bootstrap, &store, &online.location.directory)?
        } else {
            ContextState::refresh_local(
                &bootstrap,
                &online.socket,
                trust_bootstrap::hex32(&online.context_grant)?,
                &signer,
                &mut store,
                &mut session,
                || clock.health(),
            )?
        };
        Ok(Self {
            online,
            bootstrap,
            store,
            signer,
            session,
            clock,
            context,
        })
    }
    fn call(
        &mut self,
        proposal: grant::Proposal,
        token: Option<[u8; 32]>,
        apply: bool,
    ) -> Result<grant::ResultState> {
        grant::execute(
            &self.context,
            &self.bootstrap,
            &self.online.socket,
            proposal,
            token,
            apply,
            &self.signer,
            &mut self.store,
            &mut self.session,
            || self.clock.health(),
        )
    }
    fn preview(&mut self, proposal: grant::Proposal, output: PathBuf) -> Result<()> {
        let (request, view, impact, impacts) = super::tier_cli::collect_preview(|token| {
            Ok(self.call(proposal.clone(), token, false)?.value)
        })?;
        let s = self.bootstrap.descriptor().scope();
        let artifact = a(vec![
            Value::Uint(200),
            Value::Uint(1),
            Value::Text("ReviewedGrantChange".into()),
            b(&self.bootstrap.file_digest()),
            b(&s.network),
            b(&s.incarnation),
            b(&self.store.requester()),
            b(&proposal.parameters),
            b(&request),
            b(&view),
            b(&impact),
            a(impacts.clone()),
        ]);
        let bytes = trust_wire::encode_state(&artifact)?;
        files::write_new(&output, &bytes)?;
        crate::print_value(
            &json!({"status":"GrantPreviewComplete","proposal":diagnostic(trust_wire::decode(&proposal.parameters)?),"previewDigest":hex::encode(trust_wire::digest(&bytes)),"requestDigest":hex::encode(request),"impactDigest":hex::encode(impact),"impactCount":impacts.len(),"impacts":diagnostic(a(impacts)),"applied":false,"height":self.store.prefix().height()}),
        )
    }
}
pub fn run(command: Command) -> Result<()> {
    match command {
        Command::DelegatePreview {
            online,
            parent,
            spec,
            output,
        } => {
            let mut client = Client::open(online)?;
            let parent = client
                .context
                .version(102, trust_bootstrap::hex32(&parent)?)?;
            let raw = files::read_single(&spec, 16384, true)?;
            let input: Child = serde_json::from_slice(&raw)?;
            let child = input.value(&client.context, &parent)?;
            let proposal = grant::delegate(
                &client.context,
                &client.bootstrap,
                &client.store,
                parent,
                child,
                client.clock.health()?.observe()?.wall_ms,
            )?;
            client.preview(proposal, output)
        }
        Command::RevokePreview {
            online,
            grant: authority,
            target,
            output,
        } => {
            let mut client = Client::open(online)?;
            let target = client
                .context
                .version(102, trust_bootstrap::hex32(&target)?)?;
            let proposal = grant::revoke(
                &client.context,
                &client.store,
                trust_bootstrap::hex32(&authority)?,
                target,
                client.clock.health()?.observe()?.wall_ms,
            )?;
            client.preview(proposal, output)
        }
        Command::Apply {
            online,
            preview,
            preview_digest,
        } => {
            let mut client = Client::open(online)?;
            let bytes =
                files::read_single(&preview, crate::authority_capacity::MAX_STATE_BYTES, true)?;
            ensure!(
                trust_wire::digest(&bytes) == trust_bootstrap::hex32(&preview_digest)?,
                "reviewed grant preview digest differs"
            );
            let value = trust_wire::decode_state(&bytes)?;
            let f = value.array(12)?;
            let scope = client.bootstrap.descriptor().scope();
            ensure!(
                f[0].uint()? == 200
                    && f[1].uint()? == 1
                    && f[2].text()? == "ReviewedGrantChange"
                    && f[3].fixed::<32>()? == client.bootstrap.file_digest()
                    && f[4].fixed::<32>()? == scope.network
                    && f[5].fixed::<32>()? == scope.incarnation
                    && f[6].fixed::<32>()? == client.store.requester(),
                "reviewed grant belongs to another authority or requester"
            );
            ensure!(
                trust_wire::digest(&trust_wire::encode_state(&a(f[11]
                    .list(crate::authority_tiers::MAX_IMPACTS)?
                    .to_vec()))?)
                    == f[10].fixed::<32>()?,
                "reviewed grant impact digest differs"
            );
            let proposal = grant::Proposal::parse(f[7].bytes()?, scope.network)?;
            let result = client.call(proposal, Some(f[9].fixed()?), true)?;
            let f = result.value.array(6)?;
            crate::print_value(
                &json!({"status":"GrantApplied","reviewedPreviewDigest":preview_digest,"record":diagnostic(trust_wire::decode(f[4].bytes()?)?),"committedHeight":f[5].uint()?,"height":result.prefix.height()}),
            )
        }
    }
}
