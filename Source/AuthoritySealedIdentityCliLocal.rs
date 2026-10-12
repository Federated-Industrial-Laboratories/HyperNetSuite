// SPDX-License-Identifier: MIT
// Local recipient preparation never obtains authority or changes contact trust implicitly.
use super::*;
pub(super) fn run(command: Command) -> Result<()> {
    match command {
        Command::Init { local } => {
            let verified = super::super::bootstrap(&local.location)?;
            let s = verified.descriptor().scope();
            let vault = Vault::initialise(
                &local.vault.vault,
                &local.vault.age_key,
                s.network,
                s.incarnation,
                id(&local.location.bootstrap_digest)?,
            )?;
            crate::print_value(
                &json!({"status":"SealedVaultCreated","trustKey":hex::encode(vault.trust_key()?)}),
            )
        }
        Command::RootCreate {
            local,
            member,
            threshold,
            recovery_keys,
            output,
        } => {
            let verified = super::super::bootstrap(&local.location)?;
            let s = verified.descriptor().scope();
            let member = id(&member)?;
            let mut keys = recovery_keys
                .iter()
                .map(|text| {
                    let (p, k) = text
                        .split_once(':')
                        .context("recovery key requires PrincipalId:SigningKey")?;
                    let p = id(p)?;
                    let k = id(k)?;
                    wire::valid_key(&k)?;
                    Ok((p, k))
                })
                .collect::<Result<Vec<_>>>()?;
            keys.sort();
            let custody = wire::encode(&a(vec![
                V::Uint(200),
                V::Uint(1),
                V::Text("RecipientCustody".into()),
                b(&s.network),
                b(&s.incarnation),
                b(&member),
                V::Uint(threshold),
                a(keys.iter().map(|(p, k)| a(vec![b(p), b(k)])).collect()),
            ]))?;
            identity::Custody::parse(&custody, s.network, s.incarnation)?;
            let mut vault = vault(&local.vault, &local.location)?;
            let public = vault.generate_root(member)?;
            files::write_new(&output, &custody)?;
            crate::print_value(
                &json!({"status":"RecipientRootCreated","member":hex::encode(member),"rootKey":hex::encode(public),"custodyDigest":hex::encode(wire::digest(&custody))}),
            )
        }
        Command::DeviceCreate {
            local,
            member,
            device,
            output,
        } => {
            let verified = super::super::bootstrap(&local.location)?;
            let s = verified.descriptor().scope();
            let member = id(&member)?;
            let device = device
                .as_deref()
                .map(id)
                .transpose()?
                .unwrap_or_else(rand::random);
            let mut vault = vault(&local.vault, &local.location)?;
            let keys = vault.generate_device(member, device)?;
            let payload = wire::encode(&a(vec![
                V::Uint(200),
                V::Uint(1),
                V::Text("SealedDeviceKeys".into()),
                b(&s.network),
                b(&s.incarnation),
                b(&member),
                b(&device),
                b(&keys.signing_key),
                b(&keys.encryption_key),
            ]))?;
            let envelope = wire::sign_envelope(&payload, &vault.device_signer(device)?)?;
            files::write_new(&output, &envelope)?;
            crate::print_value(
                &json!({"status":"RecipientDeviceCreated","member":hex::encode(member),"device":hex::encode(device),"signingKey":hex::encode(keys.signing_key),"encryptionKey":hex::encode(keys.encryption_key)}),
            )
        }
        Command::DeviceBind {
            local,
            root,
            device_keys,
            not_before_ms,
            expires_ms,
            enrol_devices,
            previous,
            delegate_binding,
            delegate_admission,
            output,
        } => {
            let verified = super::super::bootstrap(&local.location)?;
            let s = verified.descriptor().scope();
            let root_record = record(&read(&root)?, &verified)?;
            let root =
                identity::Root::parse(&identity::payload(&root_record)?, s.network, s.incarnation)?;
            let vault = vault(&local.vault, &local.location)?;
            let signer = if let Some(delegate) = delegate_binding {
                let delegate = record(&read(&delegate)?, &verified)?;
                let delegate = identity::Binding::parse(
                    &identity::payload(&delegate)?,
                    s.network,
                    s.incarnation,
                )?;
                let admitted = record(
                    &read(&delegate_admission.context("delegate admission is required")?)?,
                    &verified,
                )?;
                let admitted = identity::Admission::parse(
                    &identity::payload(&admitted)?,
                    s.network,
                    s.incarnation,
                )?;
                let at = now()?;
                ensure!(
                    delegate.root == root.reference
                        && delegate.member == root.member
                        && delegate.purposes.contains(&1)
                        && delegate.validity.0 <= at
                        && at < delegate.validity.1
                        && admitted.binding == delegate.reference
                        && admitted.validity.0 <= at
                        && at < admitted.validity.1,
                    "local enrolment delegate lacks exact current root, purpose or admission"
                );
                let signer = vault.device_signer(delegate.device)?;
                ensure!(
                    signer.verifying_key().to_bytes() == delegate.signing_key,
                    "delegate binding differs from locally held device key"
                );
                signer
            } else {
                ensure!(delegate_admission.is_none(), "delegate binding is required");
                let signer = vault.root_signer(root.member)?;
                ensure!(
                    signer.verifying_key().to_bytes() == root.key,
                    "root record differs from locally held user root"
                );
                signer
            };
            let (bytes, signatures) = wire::envelope(&read(&device_keys)?, 1)?;
            let values = wire::decode(&bytes)?;
            let f = values.array(9)?;
            ensure!(
                f[0].uint()? == 200
                    && f[1].uint()? == 1
                    && f[2].text()? == "SealedDeviceKeys"
                    && f[3].fixed::<32>()? == s.network
                    && f[4].fixed::<32>()? == s.incarnation
                    && f[5].fixed::<32>()? == root.member
                    && f[7].fixed::<32>()? == signatures[0].0,
                "candidate device request context or signature differs"
            );
            let device = f[6].fixed::<32>()?;
            crypto::validate_recipient_key(f[8].fixed()?)?;
            let previous = previous
                .as_ref()
                .map(|p| record(&read(p)?, &verified))
                .transpose()?;
            let generation = if let Some(old) = &previous {
                ensure!(
                    old.reference.kind == 108 && old.reference.id == device,
                    "replacement device identity differs"
                );
                old.reference
                    .generation
                    .checked_add(1)
                    .context("device generation exhausted")?
            } else {
                1
            };
            let bytes = signed(
                108,
                generation,
                previous.as_ref().map(|r| r.reference.digest),
                vec![
                    b(&root.member),
                    reference(&root.reference),
                    b(&device),
                    f[7].clone(),
                    f[8].clone(),
                    a(if enrol_devices {
                        vec![V::Uint(0), V::Uint(1)]
                    } else {
                        vec![V::Uint(0)]
                    }),
                    a(vec![V::Uint(not_before_ms), V::Uint(expires_ms)]),
                ],
                &verified,
                &signer,
            )?;
            emit("RecipientDeviceBound", &record(&bytes, &verified)?, &output)
        }
        Command::FloorInitialise {
            local,
            role,
            identity: identity_id,
        } => {
            let verified = super::super::bootstrap(&local.location)?;
            let vault = vault(&local.vault, &local.location)?;
            let identity_id = id(&identity_id)?;
            let key = match role {
                Role::Root => vault.root_signer(identity_id)?,
                Role::Device => vault.device_signer(identity_id)?,
            };
            let clock = super::super::clock(&local.location, verified.descriptor().voters())?;
            files::create_directory(&local.location.directory)?;
            let store = Store::initialise(
                &local.location.directory,
                verified.descriptor().clone(),
                key.verifying_key().to_bytes(),
                clock.health()?,
            )?;
            crate::authority_inspection::ContextState::bootstrap(&verified, &store)?
                .save(&store)?;
            crate::print_value(
                &json!({"status":"RecipientFloorInitialised","requester":hex::encode(store.requester())}),
            )
        }
        Command::ContactAccept {
            local,
            root,
            root_digest,
            trust_context,
            previous_digest,
            recovery,
            custody,
            output,
        } => {
            let verified = super::super::bootstrap(&local.location)?;
            let bytes = read(&root)?;
            let r = record(&bytes, &verified)?;
            let s = verified.descriptor().scope();
            let root = identity::Root::parse(&identity::payload(&r)?, s.network, s.incarnation)?;
            let mut vault = vault(&local.vault, &local.location)?;
            let accepted = if let Some(previous_digest) = previous_digest {
                let old = vault.contact_root(root.member)?;
                ensure!(
                    old.reference.digest == id(&previous_digest)?,
                    "explicit prior contact fingerprint differs"
                );
                let recovery = recovery.as_ref().map(|p| read(p)).transpose()?;
                let custody = custody.as_ref().map(|p| read(p)).transpose()?;
                vault.accept_successor(
                    &bytes,
                    &old.reference,
                    id(&root_digest)?,
                    id(&trust_context)?,
                    recovery.as_deref(),
                    custody.as_deref(),
                )?
            } else {
                ensure!(
                    recovery.is_none() && custody.is_none(),
                    "initial contact cannot claim recipient recovery"
                );
                vault.accept_contact(&bytes, id(&root_digest)?, id(&trust_context)?)?
            };
            files::write_new(&output, &accepted)?;
            crate::print_value(
                &json!({"status":"RecipientContactAccepted","member":hex::encode(root.member),"rootDigest":hex::encode(root.reference.digest)}),
            )
        }
        _ => anyhow::bail!("not a local recipient command"),
    }
}
