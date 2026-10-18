// SPDX-License-Identifier: MIT
// Local authority and store exchanges retain exact requester-stream state.
use super::*;
pub(crate) struct Client {
    pub(crate) bootstrap: Verified,
    pub(crate) key: SigningKey,
    pub(crate) store: Store,
    pub(crate) session: Session,
    pub(crate) clock: authority_clock::Source,
    pub(crate) authority: PathBuf,
    work_directory: PathBuf,
}
impl Client {
    pub(crate) fn new(location: &Location, socket: &Path, key: SigningKey) -> Result<Self> {
        let bootstrap = control::bootstrap(location)?;
        let mut store = Store::open(&location.directory, bootstrap.descriptor().clone())?;
        store.require_requester(key.verifying_key().to_bytes())?;
        let clock = control::clock(location, store.descriptor().voters())?;
        let mut session = Session::new()?;
        let descriptor = store.descriptor().clone();
        stream_client::resolve_refusal_local(
            &descriptor,
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
            session,
            clock,
            authority: socket.into(),
            work_directory: location.directory.clone(),
        })
    }
    pub(crate) fn manager(online: &Online) -> Result<Self> {
        Self::new(
            &online.location,
            &online.socket,
            domain_cli::signer(&online.key)?,
        )
    }
    pub(crate) fn action(
        &mut self,
        command: Action,
        grant: Option<VersionRef>,
    ) -> Result<domain_client::ResultState> {
        domain_client::local(
            &self.bootstrap,
            DomainRequest {
                command: command.into(),
                grant,
            },
            &self.authority,
            &self.key,
            &mut self.store,
            &mut self.session,
            || self.clock.health(),
        )
    }
    pub(crate) fn cache(&self) -> Result<Cache> {
        Cache::load(&self.bootstrap, &self.store)
    }
    pub(crate) fn capability(&self, c: Capability) -> Result<Option<VersionRef>> {
        domain_cli::capability(Some(c), &self.bootstrap, &self.cache()?)
    }
    pub(crate) fn pending(&self) -> Result<Option<domain::Operation>> {
        self.store
            .resume_ordinary()?
            .map(|p| {
                let intent = crate::authority_proof::Intent::from_signed(p.signed())?;
                domain::Operation::parse(&intent)
            })
            .transpose()
    }
    pub(crate) fn resume_metadata(&mut self, allowed: impl FnOnce(&Action) -> bool) -> Result<()> {
        if let Some(op) = self.pending()? {
            let domain::Command::Mail(command) = op.command else {
                anyhow::bail!("another domain request is pending");
            };
            if matches!(command, Action::Execute { .. }) {
                return Ok(());
            }
            ensure!(
                allowed(&command),
                "another mail metadata request is pending; resume its exact command"
            );
            self.action(command, op.grant)?;
        }
        Ok(())
    }
    pub(crate) fn mailbox(&self, address: Digest) -> Result<mail::Mailbox> {
        mail::Mailbox::parse(
            &self.cache()?.state.record(137, address)?.payload,
            self.bootstrap.descriptor().scope().network,
        )
    }
    pub(crate) fn refresh(
        &mut self,
        address: Digest,
        source: Option<Digest>,
    ) -> Result<mail::Mailbox> {
        self.action(Action::Get { address, source }, None)?;
        self.mailbox(address)
    }
    pub(crate) fn effect<T>(
        &mut self,
        transport: &Transport,
        command: Action,
        payload: &[u8],
        apply: impl FnOnce(&mail::Request, &[u8], &[u8]) -> Result<T>,
    ) -> Result<T> {
        mail_client::ensure(
            &self.bootstrap,
            &mut self.store,
            &self.authority,
            &self.key,
            &mut self.session,
            || self.clock.health(),
        )?;
        let reconcile = self.store.resume_ordinary()?.is_some();
        let request = mail_client::prepare(
            &self.bootstrap,
            &self.key,
            &mut self.store,
            command,
            self.clock.health()?,
        )?;
        let packet = mail_client::packet(&request, payload, reconcile)?;
        let receipt = transport.exchange(&packet, &self.work_directory)?;
        mail_client::complete(
            &self.bootstrap,
            &receipt,
            &self.authority,
            &self.key,
            &mut self.store,
            &mut self.session,
            || self.clock.health(),
            |request, response| apply(request, response, &receipt),
        )
    }
}
impl Transport {
    fn exchange(&self, packet: &[u8], work_directory: &Path) -> Result<Vec<u8>> {
        if let Some(socket) = &self.service_socket {
            return crate::authority_local_transport::LocalControl::open(socket)?.exchange_limit(
                packet,
                crate::authority_challenge::boot_time_ms()?
                    .checked_add(10000)
                    .context("mail exchange deadline overflow")?,
                mail::RECEIPT_LIMIT,
            );
        }
        crate::private_route_client::require_local_allowed()?;
        let root = self
            .service_directory
            .as_ref()
            .context("mail service directory absent")?;
        let _parent = files::private_directory(work_directory)?;
        let temporary = work_directory.join(format!("MailExchange{}", crate::random_hex::<16>()));
        let _directory = files::create_directory(&temporary)?;
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(self.0.join("Packet.cbor"));
                let _ = std::fs::remove_file(self.0.join("Receipt.cbor"));
                let _ = std::fs::remove_dir(&self.0);
            }
        }
        let _cleanup = Cleanup(temporary.clone());
        let input = temporary.join("Packet.cbor");
        let output = temporary.join("Receipt.cbor");
        files::write_new(&input, packet)?;
        let result = Process::new(&self.core)
            .args(["runtime", "services", "exchange", "--directory"])
            .arg(root)
            .arg("--packet")
            .arg(input)
            .arg("--receipt")
            .arg(&output)
            .output()?;
        ensure!(
            result.status.success(),
            "installed mail exchange failed: {}",
            String::from_utf8_lossy(&result.stderr[..result.stderr.len().min(2048)])
        );
        files::read_single(&output, mail::RECEIPT_LIMIT, true)
    }
}
