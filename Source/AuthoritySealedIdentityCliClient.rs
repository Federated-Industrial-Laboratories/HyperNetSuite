// SPDX-License-Identifier: MIT
// Recipient commands use the installed quorum route and retain exact ordinary-request retries.
use super::*;
pub(super) struct Client {
    pub bootstrap: Verified,
    pub key: SigningKey,
    pub store: Store,
    pub clock: authority_clock::Source,
    session: Session,
    socket: PathBuf,
}
impl Client {
    pub fn new(online: &Online) -> Result<Self> {
        Self::owned(
            &online.location,
            &online.socket,
            super::super::domain_cli::signer(&online.key)?,
        )
    }
    pub fn owned(location: &Location, socket: &Path, key: SigningKey) -> Result<Self> {
        let bootstrap = super::super::bootstrap(location)?;
        let mut store = Store::open(&location.directory, bootstrap.descriptor().clone())?;
        store.require_requester(key.verifying_key().to_bytes())?;
        let clock = super::super::clock(location, store.descriptor().voters())?;
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
            bootstrap,
            key,
            store,
            clock,
            session,
            socket: socket.into(),
        })
    }
    pub fn cache(&self) -> Result<Cache> {
        Cache::load(&self.bootstrap, &self.store)
    }
    pub fn grant(&self, capability: Capability) -> Result<VersionRef> {
        super::super::domain_cli::capability(Some(capability), &self.bootstrap, &self.cache()?)?
            .context("recipient capability missing")
    }
    pub fn snapshot(&self, references: &[VersionRef]) -> Result<V> {
        Ok(a(vec![
            a(vec![
                V::Uint(self.store.prefix().scope().epoch),
                V::Uint(self.store.prefix().height()),
                b(self.store.prefix().policy_state()),
            ]),
            a(references.iter().map(reference).collect()),
        ]))
    }
    pub fn action(
        &mut self,
        command: identity::Command,
        grant: Option<VersionRef>,
    ) -> Result<ResultState> {
        domain_client::local(
            &self.bootstrap,
            Request {
                command: command.into(),
                grant,
            },
            &self.socket,
            &self.key,
            &mut self.store,
            &mut self.session,
            || self.clock.health(),
        )
    }
    pub fn prepare(
        &self,
        name: &str,
        resource: Digest,
        grant: Option<VersionRef>,
        build: impl Fn(&Self, &V) -> Result<identity::Command>,
    ) -> Result<identity::Command> {
        if let Some(pending) = self.store.resume_ordinary()? {
            let intent = Intent::from_signed(pending.signed())?;
            let operation = domain::Operation::parse(&intent)?;
            let domain::Command::SealedIdentity(command) = operation.command else {
                anyhow::bail!("another domain operation is pending")
            };
            ensure!(
                command.name() == name
                    && command.resource() == resource
                    && operation.grant == grant,
                "another recipient operation is pending"
            );
            return Ok(command);
        }
        let snapshot = self.snapshot(&[])?;
        let command = build(self, &snapshot)?;
        let operation = domain::Operation {
            grant,
            command: command.into(),
            snapshot: domain::snapshot(&snapshot)?,
        };
        let scope = self.bootstrap.descriptor().scope();
        let intent = Intent {
            network: scope.network,
            incarnation: scope.incarnation,
            generation: 1,
            generation_id: [1; 32],
            sequence: 1,
            acknowledged_through: 0,
            requester: self.key.verifying_key().to_bytes(),
            action: "AuthorityDomain".into(),
            resource,
            revision: 1,
            profile_generation: 0,
            minimum_policy_epoch: scope.epoch,
            minimum_policy_height: self.store.prefix().height(),
            expected: vec![],
            parameters: operation.parameters()?,
            digest: [1; 32],
        };
        let cache = self.cache()?;
        let governance = domain::result::merge(&self.bootstrap, &cache.records)?;
        let preview = operation.prepare(
            &cache.state,
            &governance,
            &Reservations(self.bootstrap.reservations().to_vec()),
            &intent,
            self.clock.health()?.observe()?.wall_ms,
            false,
            false,
        )?;
        ensure!(
            preview.code == 0,
            "recipient preflight refused with code {}; refresh its current context",
            preview.code
        );
        build(self, &self.snapshot(&preview.dependencies)?)
    }
    pub fn context(
        &mut self,
        kind: u64,
        lookup: Digest,
        grant: Option<VersionRef>,
    ) -> Result<domain::Record> {
        let result = self.action(identity::Command::Context { kind, lookup }, grant)?;
        Ok(result.cache.state.record(kind, lookup)?.clone())
    }
    pub fn directory(&mut self, member: Digest, grant: &VersionRef) -> Result<()> {
        let pending = self
            .store
            .resume_ordinary()?
            .map(|pending| domain::Operation::parse(&Intent::from_signed(pending.signed())?))
            .transpose()?;
        let (mut view, mut after) = directory_cursor(pending.as_ref(), member, grant)?;
        for _ in 0..128 {
            let result = self.action(
                identity::Command::Directory {
                    member,
                    view,
                    after,
                },
                Some(grant.clone()),
            )?;
            let f = result.value.array(5)?;
            let marker = f[4].array(4)?[3].array(2)?;
            view = Some(marker[0].fixed()?);
            if marker[1] == V::Null {
                return Ok(());
            }
            let cursor = marker[1].array(2)?;
            after = Some((cursor[0].uint()?, cursor[1].fixed()?));
        }
        anyhow::bail!("recipient directory exceeds bounded continuation")
    }
}

type DirectoryCursor = (Option<Digest>, Option<(u64, Digest)>);

fn directory_cursor(
    pending: Option<&domain::Operation>,
    member: Digest,
    grant: &VersionRef,
) -> Result<DirectoryCursor> {
    let Some(operation) = pending else {
        return Ok((None, None));
    };
    let domain::Command::SealedIdentity(identity::Command::Directory {
        member: expected,
        view,
        after,
    }) = &operation.command
    else {
        anyhow::bail!("another exact operation is pending before recipient directory retrieval");
    };
    ensure!(
        *expected == member && operation.grant.as_ref() == Some(grant),
        "pending recipient directory has another member or grant"
    );
    Ok((*view, *after))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recipient_directory_retry_preserves_cursor_member_and_exact_grant() {
        let member = [1; 32];
        let grant = VersionRef {
            kind: 102,
            id: [2; 32],
            generation: 1,
            digest: [3; 32],
        };
        let view = Some([4; 32]);
        let after = Some((108, [5; 32]));
        let mut operation = domain::Operation {
            command: identity::Command::Directory {
                member,
                view,
                after,
            }
            .into(),
            grant: Some(grant.clone()),
            snapshot: domain::snapshot(&a(vec![
                a(vec![V::Uint(1), V::Uint(0), b(&[6; 32])]),
                a(vec![]),
            ]))
            .unwrap(),
        };
        assert_eq!(
            directory_cursor(None, member, &grant).unwrap(),
            (None, None)
        );
        assert_eq!(
            directory_cursor(Some(&operation), member, &grant).unwrap(),
            (view, after)
        );
        assert!(directory_cursor(Some(&operation), [7; 32], &grant).is_err());
        let mut changed = grant.clone();
        changed.generation = 2;
        assert!(directory_cursor(Some(&operation), member, &changed).is_err());
        operation.command = identity::Command::Context {
            kind: 107,
            lookup: member,
        }
        .into();
        assert!(directory_cursor(Some(&operation), member, &grant).is_err());
    }
}
