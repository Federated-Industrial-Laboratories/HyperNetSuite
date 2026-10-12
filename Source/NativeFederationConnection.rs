// SPDX-License-Identifier: MIT
// Every local federation result passes the existing durable requester and typed domain verifier.
use super::*;
pub(super) struct Client {
    pub bootstrap: Verified,
    pub key: SigningKey,
    pub store: Store,
    pub session: Session,
    pub clock: authority_clock::Source,
    pub socket: PathBuf,
    pub directory: PathBuf,
}
impl Client {
    pub fn new(online: &Online) -> Result<Self> {
        let bootstrap = control::bootstrap(&online.location)?;
        let key = domain_cli::signer(&online.key)?;
        let mut store = Store::open(&online.location.directory, bootstrap.descriptor().clone())?;
        store.require_requester(key.verifying_key().to_bytes())?;
        let clock = control::clock(&online.location, store.descriptor().voters())?;
        let mut session = Session::new()?;
        stream_client::resolve_refusal_local(
            &store.descriptor().clone(),
            &online.socket,
            &key,
            &mut store,
            &mut session,
            || clock.health(),
        )?;
        Ok(Self {
            bootstrap,
            key,
            store,
            session,
            clock,
            socket: online.socket.clone(),
            directory: online.location.directory.clone(),
        })
    }
    pub fn scope(&self) -> (Digest, Digest) {
        let s = self.store.descriptor().scope();
        (s.network, s.incarnation)
    }
    pub fn cache(&self) -> Result<Cache> {
        Cache::load(&self.bootstrap, &self.store)
    }
    pub fn grant(&self, capability: Capability) -> Result<VersionRef> {
        domain_cli::capability(Some(capability), &self.bootstrap, &self.cache()?)?
            .context("federation capability absent")
    }
    pub fn maintenance(
        &self,
        grant: Option<String>,
        path: Option<PathBuf>,
    ) -> Result<Option<VersionRef>> {
        let Some(grant) = grant else {
            ensure!(path.is_none(), "grant record requires its identity");
            return Ok(None);
        };
        let lookup = id(&grant)?;
        if let Some(path) = path {
            let (n, i) = self.scope();
            let refs = crate::authority_governance::Governance::record_versions(
                n,
                i,
                &[files::read_public_single(&path, 16384)?],
            )?;
            ensure!(
                refs.len() == 1 && refs[0].kind == 102 && refs[0].id == lookup,
                "maintenance grant record differs"
            );
            Ok(Some(refs[0].clone()))
        } else {
            Ok(Some(self.cache()?.grant(&self.bootstrap, lookup)?))
        }
    }
    pub fn action(
        &mut self,
        command: Action,
        grant: Option<VersionRef>,
        objects: Resolved,
    ) -> Result<(ResultState, Resolved)> {
        domain_client::local_with_objects(
            &self.bootstrap,
            Request {
                command: command.into(),
                grant,
            },
            &self.socket,
            &self.key,
            &mut self.store,
            &mut self.session,
            objects,
            || self.clock.health(),
        )
    }
    pub fn pending(&self) -> Result<Option<(Action, Option<VersionRef>)>> {
        let Some(pending) = self.store.resume_ordinary()? else {
            return Ok(None);
        };
        let op = domain::Operation::parse(&Intent::from_signed(pending.signed())?)?;
        let domain::Command::Federation(command) = op.command else {
            anyhow::bail!("another domain request is pending; resume its exact command")
        };
        Ok(Some((command, op.grant)))
    }
    pub fn resume(
        &mut self,
        matches: impl FnOnce(&Action) -> bool,
    ) -> Result<Option<(ResultState, Resolved)>> {
        let Some((command, grant)) = self.pending()? else {
            return Ok(None);
        };
        if !matches(&command) {
            ensure!(
                !command.mutation() && !command.returns_bundle(),
                "another federation request is pending; resume its exact command"
            );
            self.action(command, grant, Resolved::default())?;
            return Ok(None);
        }
        Ok(Some(self.action(command, grant, Resolved::default())?))
    }
    pub fn page_context(
        &mut self,
        agreement: Digest,
        raw_page: [u8; 16],
        action: u64,
        grant: &VersionRef,
    ) -> Result<ResultState> {
        Ok(self
            .action(
                Action::PageContext {
                    agreement,
                    page: raw_page,
                    action,
                },
                Some(grant.clone()),
                Resolved::default(),
            )?
            .0)
    }
    pub fn inventory_context(
        &mut self,
        agreement: Digest,
        action: u64,
        grant: &VersionRef,
    ) -> Result<ResultState> {
        Ok(self
            .action(
                Action::InventoryContext { agreement, action },
                Some(grant.clone()),
                Resolved::default(),
            )?
            .0)
    }
    pub fn context(
        &mut self,
        action: u64,
        resource: Digest,
        namespace: Option<String>,
        grant: &VersionRef,
    ) -> Result<()> {
        self.action(
            Action::Context {
                action,
                resource,
                namespace,
            },
            Some(grant.clone()),
            Resolved::default(),
        )?;
        Ok(())
    }
    pub fn statement(
        &self,
        action: &str,
        resource: Digest,
        revision: u64,
        parameters: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let s = self.store.descriptor().scope();
        let b = |v: &[u8]| V::Bytes(v.to_vec());
        wire::sign_envelope(
            &wire::encode(&V::Array(vec![
                V::Uint(20),
                V::Uint(1),
                b(&s.network),
                b(&s.incarnation),
                V::Uint(1),
                b(&rand::random::<Digest>()),
                V::Uint(1),
                V::Uint(0),
                b(&self.key.verifying_key().to_bytes()),
                V::Text(action.into()),
                b(&resource),
                V::Uint(revision),
                V::Uint(0),
                V::Uint(s.epoch),
                V::Uint(self.store.prefix().height()),
                V::Array(vec![]),
                b(&parameters),
            ]))?,
            &self.key,
        )
    }
}
pub(super) fn access(access: cli::Access) -> Result<(Client, VersionRef)> {
    let c = Client::new(&access.online)?;
    let grant = c.grant(access.capability)?;
    Ok((c, grant))
}
pub(super) fn maintenance(access: cli::Maintenance) -> Result<(Client, Option<VersionRef>)> {
    let c = Client::new(&access.online)?;
    let grant = c.maintenance(access.grant, access.grant_record)?;
    Ok((c, grant))
}
