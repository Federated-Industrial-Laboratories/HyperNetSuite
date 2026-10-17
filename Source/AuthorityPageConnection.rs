// SPDX-License-Identifier: MIT
// Page metadata and immutable bytes are exposed only after current quorum verification.
use super::*;
pub(crate) struct Client {
    pub bootstrap: Verified,
    pub directory: PathBuf,
    pub key: SigningKey,
    pub store: Store,
    pub(crate) session: Session,
    pub(crate) clock: authority_clock::Source,
    pub(crate) socket: PathBuf,
    pub(crate) content: crate::private_route_client::ContentPool,
}
impl Client {
    pub(crate) fn content_operation<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        let result = operation(self);
        if result.is_err() {
            self.content.clear();
        }
        result
    }
    pub fn new(online: &Online) -> Result<Self> {
        Self::owned(
            &online.location,
            &online.socket,
            domain_cli::signer(&online.key)?,
        )
    }
    pub fn owned(location: &control::Location, socket: &Path, key: SigningKey) -> Result<Self> {
        let bootstrap = control::bootstrap(location)?;
        let mut store = Store::open(&location.directory, bootstrap.descriptor().clone())?;
        store.require_requester(key.verifying_key().to_bytes())?;
        let clock = control::clock(location, store.descriptor().voters())?;
        let mut session = Session::new()?;
        stream_client::resolve_refusal_local(
            &store.descriptor().clone(),
            socket,
            &key,
            &mut store,
            &mut session,
            || clock.health(),
        )?;
        Ok(Self {
            directory: location.directory.clone(),
            bootstrap,
            key,
            store,
            session,
            clock,
            socket: socket.into(),
            content: Default::default(),
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
        let result = domain_client::local_with_objects(
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
        );
        if result.is_err() {
            self.content.clear();
        }
        result
    }
    pub fn domain_action(
        &mut self,
        command: domain::Command,
        grant: Option<VersionRef>,
    ) -> Result<ResultState> {
        let result = domain_client::local(
            &self.bootstrap,
            Request { command, grant },
            &self.socket,
            &self.key,
            &mut self.store,
            &mut self.session,
            || self.clock.health(),
        );
        if result.is_err() {
            self.content.clear();
        }
        result
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
