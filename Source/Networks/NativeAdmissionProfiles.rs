// SPDX-License-Identifier: MIT
// Scoped joining uses the normal private network profiles, routes and witnessed requester floors.
use super::*;
use crate::{
    authority_admission as native,
    authority_challenge::Session,
    authority_floor::Store,
    authority_inspection::{admission as client, admission::types::RoleRequest},
};
use std::ffi::OsStr;

pub(crate) fn prepare(
    path: &Path,
    bootstrap: &[u8],
    proof: &[u8],
    minimum: u64,
    role: u64,
) -> Result<RoleRequest> {
    let _lock = profile_lock(path)?;
    let now = time()?;
    let checked = match trust::check(bootstrap, true, now) {
        Ok(checked) => checked,
        Err(_) => {
            let checked = trust::inspect(bootstrap, true)?;
            crate::authority_inspection::policy::certificate::verify(&checked, proof, now)?;
            checked
        }
    };
    let minimum = match minimum {
        0 => trust::Assurance::Organisational,
        1 => trust::Assurance::Independent,
        _ => anyhow::bail!("unsupported route minimum"),
    };
    let profile = if path.exists() {
        let (profile, existing) = load(path)?;
        ensure!(
            existing.file_digest() == checked.file_digest() && profile.minimum_route >= minimum,
            "saved role profile has another network or privacy minimum"
        );
        profile
    } else {
        let profile = Profile {
            format: "HyperNetOfflineClient/1".into(),
            bootstrap: hex::encode(bootstrap),
            fingerprint: hex::encode(trust_wire::digest(bootstrap)),
            descriptor_digest: checked.summary.descriptor_digest.clone(),
            client_id: hex::encode(random()),
            device: identity(),
            relay_identity: identity(),
            minimum_route: minimum,
            accepted_relay_domains: vec![checked.summary.route.relay_domain.clone()],
            required_publication_modes: checked.summary.publication_modes.clone(),
            permit_network_search: false,
            recovery: None,
            joined: None,
        };
        verify_profile(&profile, bootstrap, false)?;
        output(path, &Zeroizing::new(serde_json::to_vec(&profile)?))?;
        profile
    };
    let signed = request(&profile, &checked)?;
    Ok(RoleRequest {
        role,
        member: profile.device.public_key.clone(),
        relay: profile.relay_identity.public_key.clone(),
        request: hex::encode(signed),
    })
}
fn signing_key(profile: &Profile) -> Result<SigningKey> {
    let secret = Zeroizing::new(trust::hex32(&profile.device.secret_key)?);
    let key = SigningKey::from_bytes(&secret);
    ensure!(
        hex::encode(key.verifying_key().to_bytes()) == profile.device.public_key,
        "candidate key pair differs"
    );
    Ok(key)
}
fn request(profile: &Profile, checked: &trust::Verified) -> Result<Vec<u8>> {
    let value = trust_wire::Value::Array(vec![
        trust_wire::Value::Uint(200),
        trust_wire::Value::Uint(1),
        trust_wire::Value::Text("HyperNetJoinRequest".into()),
        trust_wire::Value::Bytes(trust::hex32(&checked.summary.network)?.to_vec()),
        trust_wire::Value::Bytes(trust::hex32(&checked.summary.incarnation)?.to_vec()),
        trust_wire::Value::Bytes(trust::hex32(&profile.descriptor_digest)?.to_vec()),
        trust_wire::Value::Bytes(trust::hex32(&profile.client_id)?.to_vec()),
        trust_wire::Value::Bytes(trust::hex32(&profile.device.public_key)?.to_vec()),
        trust_wire::Value::Bytes(trust::hex32(&profile.relay_identity.public_key)?.to_vec()),
        trust_wire::Value::Uint(
            profile
                .minimum_route
                .max(checked.summary.minimum_route)
                .number(),
        ),
    ]);
    trust_wire::sign_envelope(&trust_wire::encode(&value)?, &signing_key(profile)?)
}
pub(crate) fn acceptance(
    path: &Path,
    slot: &native::Slot,
    n: [u8; 32],
    i: [u8; 32],
) -> Result<Vec<u8>> {
    let (profile, bootstrap) = load(path)?;
    ensure!(
        bootstrap.descriptor().scope().network == n
            && bootstrap.descriptor().scope().incarnation == i,
        "candidate profile has another context"
    );
    let member = trust::hex32(&profile.device.public_key)?;
    let relay = trust::hex32(&profile.relay_identity.public_key)?;
    let role = slot
        .roles
        .iter()
        .find(|r| r.member == member && r.relay == relay)
        .context("candidate role does not match local keys")?;
    ensure!(
        role.request == request(&profile, &bootstrap)?,
        "candidate role request differs from retained local preparation"
    );
    trust_wire::sign_envelope(&slot.acceptance_payload(n, i)?, &signing_key(&profile)?)
}
fn exact(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        ensure!(
            files::read_single(path, crate::trust_wire::MAXIMUM, true)? == bytes,
            "retained admission artifact differs"
        );
        Ok(())
    } else {
        output(path, bytes)
    }
}
fn route(
    profile: &Profile,
    d: &native::Disclosure,
    slot: &native::Slot,
    role: &native::Role,
    purpose: u64,
) -> Result<(crate::route_profile::Profile, [u8; 32])> {
    use crate::{
        authority_domains::{
            Record,
            routes::{Service, Voucher},
        },
        route_profile::{Assurance, Limits, Profile as Route},
    };
    let bootstrap = trust::inspect(&hex::decode(&profile.bootstrap)?, true)?;
    let scope = bootstrap.descriptor().scope();
    let records = d
        .domains
        .iter()
        .map(|b| Record::parse(b, scope.network, scope.incarnation))
        .collect::<Result<Vec<_>>>()?;
    let id = native::identifier(slot.policy, slot.slot, role.role, purpose)?;
    let record = records
        .iter()
        .find(|r| r.reference.kind == 166 && r.reference.id == id)
        .context("admission voucher absent")?;
    let voucher = Voucher::parse(&record.payload)?;
    let relay = Service::parse(
        &records
            .iter()
            .find(|r| r.reference == voucher.relay)
            .context("admission relay absent")?
            .payload,
        scope.network,
        scope.incarnation,
    )?
    .profile;
    let destination = Service::parse(
        &records
            .iter()
            .find(|r| r.reference == voucher.destination)
            .context("admission destination absent")?
            .payload,
        scope.network,
        scope.incarnation,
    )?
    .profile;
    let minimum = if profile.minimum_route.max(bootstrap.summary.minimum_route)
        == trust::Assurance::Independent
    {
        Assurance::Independent
    } else {
        Assurance::Organisation
    };
    let subject = if purpose == 5 {
        let template = d.policy.template(role.role)?;
        template
            .application
            .or(template.page)
            .unwrap_or(destination.service)
    } else {
        role.member
    };
    let route = Route {
        version: 1,
        network: scope.network,
        incarnation: scope.incarnation,
        relay_address: relay.address.context("admission relay lacks address")?,
        relay: relay.identity,
        destination: destination.identity,
        domain: destination.domain,
        relay_domain: relay.domain,
        protocol: destination.protocol,
        assurance: relay.assurance,
        minimum_assurance: minimum,
        limits: Limits {
            bytes: relay.limits.bytes.min(destination.limits.bytes),
            duration_ms: relay.limits.duration_ms.min(destination.limits.duration_ms),
            idle_ms: relay.limits.idle_ms.min(destination.limits.idle_ms),
        },
        voucher: record.bytes.clone(),
    };
    route.validate()?;
    Ok((route, subject))
}
pub(crate) fn install(
    path: &Path,
    clock_path: &Path,
    d: &native::Disclosure,
    role_id: u64,
    expected: &client::types::Claim,
) -> Result<client::types::RoleProfile> {
    let _lock = profile_lock(path)?;
    let (mut profile, bootstrap) = load(path)?;
    let slot = d
        .selected
        .as_ref()
        .context("admission result lacks member slot")?;
    let role = slot
        .roles
        .iter()
        .find(|r| r.role == role_id)
        .context("admission result lacks selected role")?;
    ensure!(
        slot.active()
            && profile.device.public_key == hex::encode(role.member)
            && profile.relay_identity.public_key == hex::encode(role.relay),
        "admission result differs from local candidate keys"
    );
    let new = profile.joined.is_none();
    let joined = profile
        .joined
        .as_ref()
        .map(|j| j.directory.clone())
        .unwrap_or_else(|| path.parent().expect("profile parent").join("Joined"));
    if !joined.exists() {
        ensure!(
            new,
            "retained joined state disappeared; preserve the requester floor"
        );
        files::create_directory(&joined)?;
    }
    let directory = files::private_directory(&joined)?;
    exact(
        &joined.join("Bootstrap.cbor"),
        &hex::decode(&profile.bootstrap)?,
    )?;
    exact(
        &joined.join("Device.json"),
        &Zeroizing::new(serde_json::to_vec(&profile.device)?),
    )?;
    let requester = joined.join("Requester");
    let clock = crate::authority_clock::Source::select(clock_path, None, None)?;
    let mut store = if requester.exists() {
        Store::open(&requester, bootstrap.descriptor().clone())?
    } else {
        ensure!(new, "retained requester floor disappeared");
        files::create_directory(&requester)?;
        let store = Store::initialise(
            &requester,
            bootstrap.descriptor().clone(),
            role.member,
            clock.health()?,
        )?;
        crate::authority_inspection::ContextState::bootstrap(&bootstrap, &store)?.save(&store)?;
        store
    };
    let member = native::identifier(slot.policy, slot.slot, role.role, 0)?;
    let reader = native::identifier(slot.policy, slot.slot, role.role, 1)?;
    profile.joined = Some(onboarding::Joined {
        directory: joined.clone(),
        clock_witness: clock_path.to_path_buf(),
        invitation_digest: hex::encode(slot.claim),
        member: hex::encode(member),
        reader_grant: hex::encode(reader),
        admitted: false,
    });
    onboarding::save_profile(path, &profile)?;
    for purpose in [4, 5] {
        let (route, subject) = route(&profile, d, slot, role, purpose)?;
        workflow::retain_route(path, &joined, route, subject)?;
    }
    let media = joined.join("Media");
    if !media.exists() {
        files::create_directory(&media)?;
    }
    let signer = signing_key(&profile)?;
    let mut session = Session::new()?;
    let _selection = crate::private_route_client::Selection::new(path)?;
    crate::authority_inspection::stream_client::status_local(
        &store.descriptor().clone(),
        &joined.join("AuthorityRoute.json"),
        &signer,
        &mut store,
        &mut session,
        || clock.health(),
    )?;
    let (current, _) = client::query(
        &bootstrap,
        &joined.join("AuthorityRoute.json"),
        &signer,
        &mut store,
        &mut session,
        &mut || clock.health(),
        slot.policy,
        Some(slot.claim),
    )?;
    let active = current
        .selected
        .context("current admission slot disappeared")?;
    ensure!(
        active.active()
            && active.claim == slot.claim
            && active.assignment == slot.assignment
            && active.request == slot.request
            && active.application == slot.application,
        "current native admission changed during installation"
    );
    // The explicit local acceptance covers this exact certified network contract.
    let digest = crate::authority_inspection::policy::acceptance_digest(&bootstrap, &store)?;
    crate::authority_inspection::policy::accept(&bootstrap, &store, digest)?;
    profile
        .joined
        .as_mut()
        .context("joined binding absent")?
        .admitted = true;
    onboarding::save_profile(path, &profile)?;
    files::atomic_at(
        &directory,
        OsStr::new("NativeAdmission.json"),
        &serde_json::to_vec(expected)?,
        true,
    )?;
    let destination = d.policy.template(role.role)?.destination;
    Ok(client::types::RoleProfile {
        role: role.role,
        profile: path.to_string_lossy().into_owned(),
        directory: joined.to_string_lossy().into_owned(),
        member: hex::encode(role.member),
        reader_grant: hex::encode(reader),
        connect_grant: (role.role == 1)
            .then(|| native::identifier(slot.policy, slot.slot, role.role, 3).map(hex::encode))
            .transpose()?,
        clock_witness: clock_path.to_string_lossy().into_owned(),
        authority_route: joined
            .join("AuthorityRoute.json")
            .to_string_lossy()
            .into_owned(),
        destination_route: workflow::route_path(&joined, &hex::encode(destination))
            .to_string_lossy()
            .into_owned(),
    })
}
