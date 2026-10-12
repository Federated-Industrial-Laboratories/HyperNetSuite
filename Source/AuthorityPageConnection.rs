// SPDX-License-Identifier: MIT
// Page metadata and immutable bytes are exposed only after current quorum verification.
use super::*;
pub(crate) struct Client {
    pub bootstrap: Verified,
    pub key: SigningKey,
    pub store: Store,
    pub(super) session: Session,
    pub(super) clock: authority_clock::Source,
    pub(super) socket: PathBuf,
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
        })
    }
    pub fn cache(&self) -> Result<Cache> {
        Cache::load(&self.bootstrap, &self.store)
    }
    pub fn grant(&self, capability: Capability) -> Result<VersionRef> {
        domain_cli::capability(Some(capability), &self.bootstrap, &self.cache()?)?
            .context("Page capability is absent")
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
    pub fn context(
        &mut self,
        action: u64,
        page: [u8; 16],
        namespace: Option<String>,
        grant: &VersionRef,
    ) -> Result<ResultState> {
        Ok(self
            .action(
                Action::Context {
                    action,
                    scope_kind: 2,
                    resource: page::page_id(&page)?,
                    namespace,
                },
                Some(grant.clone()),
                Resolved::default(),
            )?
            .0)
    }
    pub fn statement(
        &self,
        action: &str,
        resource: Digest,
        revision: u64,
        parameters: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let scope = self.store.descriptor().scope();
        let b = |bytes: &[u8]| V::Bytes(bytes.to_vec());
        wire::sign_envelope(
            &wire::encode(&V::Array(vec![
                V::Uint(20),
                V::Uint(1),
                b(&scope.network),
                b(&scope.incarnation),
                V::Uint(1),
                b(&rand::random::<Digest>()),
                V::Uint(1),
                V::Uint(0),
                b(&self.key.verifying_key().to_bytes()),
                V::Text(action.into()),
                b(&resource),
                V::Uint(revision),
                V::Uint(0),
                V::Uint(scope.epoch),
                V::Uint(self.store.prefix().height()),
                V::Array(vec![]),
                b(&parameters),
            ]))?,
            &self.key,
        )
    }
}
