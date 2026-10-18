// SPDX-License-Identifier: MIT
// Candidate possession is demonstrated only after decrypting a pinned endpoint's single-use challenge.
use super::*;
#[path = "AuthoritySealedIdentityCliPending.rs"]
mod pending;
use pending::{Data, Pending};

pub(super) fn run(command: Command) -> Result<()> {
    match command {
        Command::Challenge {
            online,
            capability,
            binding,
            delegate_binding,
            challenge_directory,
            output,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let binding_bytes = read(&binding)?;
            let binding_record = record(&binding_bytes, &c.bootstrap)?;
            let s = c.bootstrap.descriptor().scope();
            let (n, i) = (s.network, s.incarnation);
            let device = identity::Binding::parse(&identity::payload(&binding_record)?, n, i)?;
            crypto::validate_recipient_key(device.encryption_key)?;
            let endpoint = c.key.verifying_key().to_bytes();
            let pin = id(&online.location.bootstrap_digest)?;
            let delegate = delegate_binding.as_ref().map(|p| read(p)).transpose()?;
            if challenge_directory.try_exists()? {
                let pending = Pending::open(&challenge_directory, &c.bootstrap, pin, endpoint)?;
                ensure!(
                    pending.data.binding == binding_bytes
                        && pending.data.delegate == delegate
                        && pending.data.status == 0
                        && pending.data.expires_ms
                            > c.clock.health()?.observe()?.wall_ms.saturating_add(1250),
                    "challenge directory is expired, consumed or bound to another candidate"
                );
                files::write_new(&output, &pending.data.ciphertext)?;
                return status("RecipientChallengeRetained", &pending.data);
            }
            let root_record = c.context(107, device.member, Some(grant.clone()))?;
            let root = identity::Root::parse(&identity::payload(&root_record)?, n, i)?;
            ensure!(
                device.root == root.reference
                    && !identity::revoked(&c.cache()?.state, &root.reference),
                "candidate root is stale or revoked"
            );
            if let Some(delegate) = &delegate {
                verify_delegate(&mut c, &grant, &binding_record, delegate)?;
            } else {
                identity::signer(&binding_record, root.key)?;
            }
            let issued_ms = c.clock.health()?.observe()?.wall_ms;
            ensure!(
                device.validity.0 <= issued_ms
                    && device.validity.1 > issued_ms.saturating_add(1250),
                "candidate binding is not current"
            );
            let expires_ms = issued_ms
                .checked_add(30_000)
                .context("challenge clock exhausted")?
                .min(device.validity.1);
            let operation: Digest = rand::random();
            let nonce: Digest = rand::random();
            let challenge = signed(
                123,
                0,
                None,
                vec![
                    b(&operation),
                    b(&device.reference.digest),
                    b(&endpoint),
                    b(&nonce),
                    V::Uint(expires_ms),
                ],
                &c.bootstrap,
                &c.key,
            )?;
            let ciphertext = crypto::encrypt_challenge(&device.encryption_key, &challenge)?;
            let pending = Pending::create(
                &challenge_directory,
                Data {
                    version: 1,
                    network: n,
                    incarnation: i,
                    bootstrap: pin,
                    endpoint,
                    binding: binding_bytes,
                    delegate,
                    challenge,
                    ciphertext,
                    issued_ms,
                    expires_ms,
                    clock_floor_ms: issued_ms,
                    status: 0,
                    response: None,
                    command: None,
                    grant: None,
                    committed: None,
                },
            )?;
            files::write_new(&output, &pending.data.ciphertext)?;
            status("RecipientChallengeIssued", &pending.data)
        }
        Command::Respond {
            local,
            binding,
            challenge,
            endpoint_key,
            output,
        } => {
            let verified = super::super::bootstrap(&local.location)?;
            let s = verified.descriptor().scope();
            let binding = record(&read(&binding)?, &verified)?;
            let device =
                identity::Binding::parse(&identity::payload(&binding)?, s.network, s.incarnation)?;
            let vault = vault(&local.vault, &local.location)?;
            let key = vault.device_signer(device.device)?;
            let encryption = vault.device_identity(device.device)?;
            ensure!(
                key.verifying_key().to_bytes() == device.signing_key
                    && crypto::recipient_key(&encryption.to_public())? == device.encryption_key,
                "candidate keys differ from exact binding"
            );
            let plain = crypto::decrypt_challenge(
                &encryption,
                &files::read_public_single(&challenge, wire::MAXIMUM + 4096)?,
            )?;
            let (payload, signatures) = wire::envelope(&plain, 1)?;
            let challenge = identity::Challenge::parse(&payload, s.network, s.incarnation)?;
            let endpoint = id(&endpoint_key)?;
            let at = now()?;
            ensure!(
                signatures[0].0 == endpoint
                    && challenge.endpoint == endpoint
                    && challenge.binding == device.reference.digest
                    && challenge.expires_ms > at.saturating_add(1250)
                    && challenge.expires_ms <= at.saturating_add(31_000),
                "candidate challenge endpoint, binding or expiry differs"
            );
            let proof = signed(
                122,
                0,
                None,
                vec![
                    b(&challenge.operation),
                    b(&challenge.binding),
                    b(&endpoint),
                    b(&wire::digest(&payload)),
                    V::Uint(challenge.expires_ms),
                ],
                &verified,
                &key,
            )?;
            files::write_new(&output, &proof)?;
            crate::print_value(
                &json!({"status":"RecipientPossessionProved","device":hex::encode(device.device),"bindingDigest":hex::encode(device.reference.digest),"expiresMs":challenge.expires_ms}),
            )
        }
        Command::Admit {
            online,
            capability,
            challenge_directory,
            response,
            scopes,
            not_before_ms,
            expires_ms,
            output,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let mut pending = Pending::open(
                &challenge_directory,
                &c.bootstrap,
                id(&online.location.bootstrap_digest)?,
                c.key.verifying_key().to_bytes(),
            )?;
            let response = read(&response)?;
            pending.consume(&response, c.clock.health()?.observe()?.wall_ms)?;
            let s = c.bootstrap.descriptor().scope();
            let (n, i) = (s.network, s.incarnation);
            let binding = record(&pending.data.binding, &c.bootstrap)?;
            let device = identity::Binding::parse(&identity::payload(&binding)?, n, i)?;
            let mut scopes = scopes
                .iter()
                .map(|v| scope(v, n))
                .collect::<Result<Vec<_>>>()?;
            scopes.sort();
            ensure!(
                scopes.windows(2).all(|w| w[0] < w[1]),
                "admission scopes repeat"
            );
            let command = if let Some(bytes) = &pending.data.command {
                ensure!(
                    pending.data.grant.as_ref() == Some(&wire::encode(&reference(&grant))?),
                    "exact challenge retry changes admission capability"
                );
                let command = identity::Command::parse(&wire::decode(bytes)?, n, i)?;
                let identity::Command::Device { admission, .. } = &command else {
                    anyhow::bail!("private challenge command is not device admission")
                };
                let admitted = identity::Admission::parse(&identity::payload(admission)?, n, i)?;
                ensure!(
                    admitted.scopes == scopes && admitted.validity == (not_before_ms, expires_ms),
                    "exact challenge retry changes admission options"
                );
                command
            } else {
                ensure!(
                    pending.data.expires_ms
                        > c.clock.health()?.observe()?.wall_ms.saturating_add(1250),
                    "private challenge expired before admission preparation"
                );
                c.context(107, device.member, Some(grant.clone()))?;
                let delegate = if let Some(bytes) = &pending.data.delegate {
                    Some(verify_delegate(&mut c, &grant, &binding, bytes)?)
                } else {
                    None
                };
                let possession_digest = wire::digest(&wire::envelope(&response, 1)?.0);
                let command = c.prepare(
                    "SealedIdentityDevice",
                    device.device,
                    Some(grant.clone()),
                    |c, snapshot| {
                        let bytes = signed(
                            109,
                            1,
                            None,
                            vec![
                                b(&device.member),
                                reference(&device.reference),
                                a(scopes
                                    .iter()
                                    .map(|(k, id)| a(vec![V::Uint(*k), b(id)]))
                                    .collect()),
                                a(vec![V::Uint(not_before_ms), V::Uint(expires_ms)]),
                                b(&possession_digest),
                                snapshot.clone(),
                            ],
                            &c.bootstrap,
                            &c.key,
                        )?;
                        Ok(identity::Command::Device {
                            binding: binding.clone(),
                            admission: Box::new(record(&bytes, &c.bootstrap)?),
                            challenge: pending.data.challenge.clone(),
                            possession: response.clone(),
                            delegate: delegate.clone(),
                        })
                    },
                )?;
                pending.data.command = Some(wire::encode(&command.value())?);
                pending.data.grant = Some(wire::encode(&reference(&grant))?);
                pending.persist()?;
                command
            };
            let identity::Command::Device { admission, .. } = &command else {
                anyhow::bail!("private challenge command is not device admission")
            };
            let expected = admission.clone();
            let committed = if let Some(bytes) = &pending.data.committed {
                let stored = record(bytes, &c.bootstrap)?;
                ensure!(
                    stored.bytes == expected.bytes,
                    "retained admission differs from consumed challenge"
                );
                stored
            } else if let Some(stored) = c
                .cache()?
                .state
                .records
                .get(&expected.reference.index())
                .filter(|stored| stored.bytes == expected.bytes)
            {
                stored.clone()
            } else {
                ensure!(
                    c.store.resume_ordinary()?.is_some()
                        || pending.data.expires_ms
                            > c.clock.health()?.observe()?.wall_ms.saturating_add(1250),
                    "expired challenge may resume only its retained exact request"
                );
                let result = c.action(command, Some(grant))?;
                let stored = result
                    .cache
                    .state
                    .record(109, device.reference.digest)?
                    .clone();
                ensure!(
                    stored.bytes == expected.bytes,
                    "committed admission differs from exact challenge"
                );
                stored
            };
            pending.data.committed = Some(committed.bytes.clone());
            pending.data.status = 2;
            pending.persist()?;
            emit("RecipientDeviceAdmitted", &committed, &output)
        }
        _ => anyhow::bail!("not a recipient challenge command"),
    }
}
fn status(status: &str, data: &Data) -> Result<()> {
    crate::print_value(
        &json!({"status":status,"endpointKey":hex::encode(data.endpoint),"expiresMs":data.expires_ms}),
    )
}

fn verify_delegate(
    c: &mut Client,
    grant: &VersionRef,
    binding: &domain::Record,
    supplied: &[u8],
) -> Result<VersionRef> {
    let record = record(supplied, &c.bootstrap)?;
    let s = c.bootstrap.descriptor().scope();
    let (n, i) = (s.network, s.incarnation);
    let delegate = identity::Binding::parse(&identity::payload(&record)?, n, i)?;
    let candidate = identity::Binding::parse(&identity::payload(binding)?, n, i)?;
    let current = c.context(108, delegate.device, Some(grant.clone()))?;
    ensure!(
        current.reference == delegate.reference,
        "enrolment delegate binding changed"
    );
    let admission = c.context(109, delegate.reference.digest, Some(grant.clone()))?;
    let admission = identity::Admission::parse(&identity::payload(&admission)?, n, i)?;
    let at = c.clock.health()?.observe()?.wall_ms;
    let cache = c.cache()?;
    ensure!(
        delegate.root == candidate.root
            && delegate.member == candidate.member
            && delegate.purposes.contains(&1)
            && delegate.validity.0 <= at
            && at < delegate.validity.1
            && admission.binding == delegate.reference
            && admission.validity.0 <= at
            && at < admission.validity.1
            && !identity::revoked(&cache.state, &delegate.reference)
            && !identity::revoked(&cache.state, &admission.reference),
        "enrolment delegate is expired, revoked or outside candidate root"
    );
    identity::signer(binding, delegate.signing_key)?;
    Ok(delegate.reference)
}
