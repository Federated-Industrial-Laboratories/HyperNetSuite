// SPDX-License-Identifier: MIT
// Public join artifacts bind separate device and relay keys to independently accepted network trust.
use super::*;
use crate::trust_wire::Value as V;
use clap::Args;
use sha2::Digest as _;

#[derive(Args)]
pub struct Join {
    #[arg(long)]
    pub profile: PathBuf,
    #[arg(long)]
    pub invitation: PathBuf,
    /// SHA256 of the complete invitation, verified through an independent channel.
    #[arg(long)]
    pub invitation_digest: String,
    /// New private client state directory, or the exact directory from an interrupted join.
    #[arg(long)]
    pub directory: PathBuf,
    /// Current health from this client's local clock monitor.
    #[arg(long)]
    pub clock_witness: PathBuf,
}
fn key(identity: &Identity) -> Result<SigningKey> {
    let secret = Zeroizing::new(trust::hex32(&identity.secret_key)?);
    let key = SigningKey::from_bytes(&secret);
    ensure!(
        hex::encode(key.verifying_key().to_bytes()) == identity.public_key,
        "profile key differs"
    );
    Ok(key)
}
pub fn request(profile: &Path, destination: &Path) -> Result<()> {
    let (profile, checked) = load(profile)?;
    let bytes = trust_wire::encode(&V::Array(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("HyperNetJoinRequest".into()),
        V::Bytes(trust::hex32(&checked.summary.network)?.to_vec()),
        V::Bytes(trust::hex32(&checked.summary.incarnation)?.to_vec()),
        V::Bytes(trust::hex32(&profile.descriptor_digest)?.to_vec()),
        V::Bytes(trust::hex32(&profile.client_id)?.to_vec()),
        V::Bytes(trust::hex32(&profile.device.public_key)?.to_vec()),
        V::Bytes(trust::hex32(&profile.relay_identity.public_key)?.to_vec()),
        V::Uint(
            profile
                .minimum_route
                .max(checked.summary.minimum_route)
                .number(),
        ),
    ]))?;
    let bytes = trust_wire::sign_envelope(&bytes, &key(&profile.device)?)?;
    output(destination, &bytes)?;
    crate::print_value(&json!({"state":"PublicJoinRequest","request":destination,
        "requestDigest":hex::encode(trust_wire::digest(&bytes)),"devicePublicKey":profile.device.public_key,
        "relayPublicKey":profile.relay_identity.public_key,"networkUsed":false,"hostingRoles":[]}))
}
pub fn inspect_request(path: &Path) -> Result<()> {
    let bytes = files::read_single(path, 4096, false)?;
    let (payload, signatures) = trust_wire::envelope(&bytes, 1)?;
    let v = trust_wire::decode(&payload)?;
    let f = v.array(10)?;
    ensure!(
        f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "HyperNetJoinRequest",
        "invalid join request"
    );
    let network = f[3].fixed::<32>()?;
    let incarnation = f[4].fixed::<32>()?;
    let descriptor = f[5].fixed::<32>()?;
    let client = f[6].fixed::<32>()?;
    let device = f[7].fixed::<32>()?;
    let relay = f[8].fixed::<32>()?;
    trust_wire::valid_key(&device)?;
    trust_wire::valid_key(&relay)?;
    ensure!(
        signatures.len() == 1
            && signatures[0].0 == device
            && device != relay
            && [network, incarnation, descriptor, client]
                .iter()
                .all(|v| *v != [0; 32])
            && f[9].uint()? <= 1,
        "join request identity or minimum is invalid"
    );
    crate::print_value(
        &json!({"state":"PublicJoinRequest","requestDigest":hex::encode(trust_wire::digest(&bytes)),
        "network":hex::encode(network),"incarnation":hex::encode(incarnation),"descriptorDigest":hex::encode(descriptor),
        "client":hex::encode(client),"devicePublicKey":hex::encode(device),"relayPublicKey":hex::encode(relay),
        "minimumRoute":if f[9].uint()? == 1 {"Independent"} else {"Organisational"},"networkUsed":false,"membership":false}),
    )
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Joined {
    pub directory: PathBuf,
    pub clock_witness: PathBuf,
    pub invitation_digest: String,
    pub member: String,
    pub reader_grant: String,
    pub admitted: bool,
}
pub(super) fn save_profile(path: &Path, profile: &Profile) -> Result<()> {
    let directory = files::private_directory(path.parent().context("profile parent absent")?)?;
    let bytes = Zeroizing::new(serde_json::to_vec(profile)?);
    ensure!(bytes.len() <= PROFILE_LIMIT, "profile exceeds capacity");
    files::atomic_at(
        &directory,
        path.file_name().context("profile filename absent")?,
        &bytes,
        true,
    )
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Invitation {
    format: String,
    bootstrap_digest: String,
    offer: String,
    admission_grant: String,
    authority_route: crate::route_profile::Profile,
}
#[derive(Args)]
pub struct AssembleInvitation {
    #[arg(long)]
    bootstrap: PathBuf,
    #[arg(long)]
    bootstrap_digest: String,
    #[arg(long)]
    offer: PathBuf,
    #[arg(long)]
    admission_grant: String,
    /// Route profile containing the exact pending candidate's separate possession-key voucher.
    #[arg(long)]
    authority_route: PathBuf,
    #[arg(long)]
    output: PathBuf,
}
pub fn assemble(arguments: AssembleInvitation) -> Result<()> {
    let bytes = files::read_single(&arguments.bootstrap, trust_wire::MAXIMUM, false)?;
    ensure!(
        sha2::Sha256::digest(&bytes).as_slice() == trust::hex32(&arguments.bootstrap_digest)?,
        "bootstrap differs from independently accepted file digest"
    );
    let bootstrap = trust::inspect(&bytes, true)?;
    let offer = files::read_single(
        &arguments.offer,
        crate::authority_inspection::member_offer::OFFER_LIMIT,
        false,
    )?;
    let _ = crate::authority_inspection::member_offer::Offer::parse(&bootstrap, &offer, false)?;
    trust::hex32(&arguments.admission_grant)?;
    let route: crate::route_profile::Profile = serde_json::from_slice(&files::read_single(
        &arguments.authority_route,
        600000,
        false,
    )?)?;
    ensure!(
        route.network == bootstrap.descriptor().scope().network
            && route.incarnation == bootstrap.descriptor().scope().incarnation
            && route.protocol == 1,
        "invitation route differs from accepted network authority"
    );
    route.validate()?;
    let invitation = Invitation {
        format: "HyperNetInvitation/1".into(),
        bootstrap_digest: arguments.bootstrap_digest,
        offer: hex::encode(offer),
        admission_grant: arguments.admission_grant,
        authority_route: route,
    };
    let bytes = serde_json::to_vec(&invitation)?;
    output(&arguments.output, &bytes)?;
    crate::print_value(
        &json!({"state":"InvitationAssembled","invitation":arguments.output,
        "invitationDigest":hex::encode(sha2::Sha256::digest(&bytes)),"networkUsed":false,
        "note":"Candidate admission still requires current pending invitation and inviter authority"}),
    )
}

fn exact_file(path: &Path, bytes: &[u8]) -> Result<()> {
    match files::read_single(path, 600000, true) {
        Ok(saved) => ensure!(
            saved == bytes,
            "interrupted join artifact differs: {}",
            path.display()
        ),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            files::write_new(path, bytes)?
        }
        Err(error) => return Err(error),
    }
    Ok(())
}
pub fn join(arguments: Join) -> Result<()> {
    use crate::{
        authority_challenge::Session,
        authority_domains::{self as domain, routes},
        authority_floor::Store,
        authority_inspection::{
            ContextState, MemberMutation, MemberRequest,
            domain_client::{self, Cache, Request},
            member_offer::Offer,
        },
    };
    let _guard = profile_lock(&arguments.profile)?;
    let (mut profile, bootstrap) = load(&arguments.profile)?;
    let raw = files::read_single(&arguments.invitation, 800000, false)?;
    ensure!(
        sha2::Sha256::digest(&raw).as_slice() == trust::hex32(&arguments.invitation_digest)?,
        "invitation differs from independently accepted fingerprint"
    );
    let invitation: Invitation = serde_json::from_slice(&raw)?;
    ensure!(
        invitation.format == "HyperNetInvitation/1"
            && invitation.bootstrap_digest == hex::encode(bootstrap.file_digest()),
        "invitation belongs to another independently accepted bootstrap"
    );
    let offer = Offer::parse(&bootstrap, &hex::decode(&invitation.offer)?, false)?;
    ensure!(
        offer.candidate == trust::hex32(&profile.device.public_key)?,
        "invitation names another candidate device"
    );
    let signer = key(&profile.device)?;
    // The complete invitation digest independently authenticates this inviter; current authority is still required online.
    let accepted = offer.accept(&bootstrap, &signer, Some(offer.inviter))?;
    let accepted = Offer::parse(&bootstrap, &accepted, true)?;
    route_key(&arguments.profile, &invitation.authority_route)?;
    ensure!(
        invitation.authority_route.protocol == 1,
        "join requires the pinned authority route"
    );
    let voucher_record = domain::Record::parse(
        &invitation.authority_route.voucher,
        bootstrap.descriptor().scope().network,
        bootstrap.descriptor().scope().incarnation,
    )?;
    ensure!(
        voucher_record.reference.kind == 166,
        "invitation lacks a typed route voucher"
    );
    let voucher = routes::Voucher::parse(&voucher_record.payload)?;
    ensure!(
        voucher.possession == trust::hex32(&profile.relay_identity.public_key)?
            && voucher.sponsor == accepted.inviter
            && voucher.action == 10
            && voucher.grant.id == trust::hex32(&invitation.admission_grant)?
            && voucher.relay.id == invitation.authority_route.relay.service
            && voucher.destination.id == invitation.authority_route.destination.service,
        "bootstrap voucher differs from the candidate's separate relay key or inviter authority"
    );
    ensure!(
        arguments.directory.is_absolute() && arguments.clock_witness.is_absolute(),
        "join paths must be absolute"
    );
    let clock = crate::authority_clock::Source::select(&arguments.clock_witness, None, None)?;
    let health = clock.health()?;
    if let Some(joined) = &profile.joined {
        ensure!(
            joined.directory == arguments.directory
                && joined.clock_witness == arguments.clock_witness
                && joined.invitation_digest == arguments.invitation_digest
                && joined.member == hex::encode(accepted.member),
            "client already binds another join; preserve its retained state"
        );
        if joined.admitted {
            return workflow::status(&arguments.profile);
        }
    }
    let binding = serde_json::to_vec(
        &json!({"format":"HyperNetJoinBinding/1","client":profile.client_id,
        "bootstrapDigest":hex::encode(bootstrap.file_digest()),"invitationDigest":arguments.invitation_digest,
        "device":profile.device.public_key,"relay":profile.relay_identity.public_key}),
    )?;
    if !arguments.directory.exists() {
        files::create_directory(&arguments.directory)?;
    }
    files::private_directory(&arguments.directory)?;
    ensure!(
        arguments.directory.canonicalize()? == arguments.directory,
        "join directory must be canonical"
    );
    exact_file(&arguments.directory.join("JoinBinding.json"), &binding)?;
    exact_file(
        &arguments.directory.join("Bootstrap.cbor"),
        &hex::decode(&profile.bootstrap)?,
    )?;
    let device = Zeroizing::new(serde_json::to_vec(&profile.device)?);
    exact_file(&arguments.directory.join("Device.json"), &device)?;
    exact_file(
        &arguments.directory.join("AcceptedMember.cbor"),
        &accepted.encode()?,
    )?;
    exact_file(
        &arguments.directory.join("AuthorityTemplate.json"),
        &serde_json::to_vec(&invitation.authority_route)?,
    )?;
    let directory = arguments.directory.join("Requester");
    let initial = !directory.exists();
    if initial {
        files::create_directory(&directory)?;
    }
    let mut store = if initial {
        Store::initialise(
            &directory,
            bootstrap.descriptor().clone(),
            signer.verifying_key().to_bytes(),
            health,
        )?
    } else {
        Store::open(&directory, bootstrap.descriptor().clone())?
    };
    store.require_requester(signer.verifying_key().to_bytes())?;
    if initial {
        ContextState::bootstrap(&bootstrap, &store)?.save(&store)?;
    }
    let media = arguments.directory.join("Media");
    if !media.exists() {
        files::create_directory(&media)?;
    }
    workflow::retain_route(
        &arguments.profile,
        &arguments.directory,
        invitation.authority_route,
        accepted.candidate,
    )?;
    profile.joined = Some(Joined {
        directory: arguments.directory.clone(),
        clock_witness: arguments.clock_witness,
        invitation_digest: arguments.invitation_digest,
        member: hex::encode(accepted.member),
        reader_grant: hex::encode(accepted.reader.id),
        admitted: false,
    });
    save_profile(&arguments.profile, &profile)?;
    let _selection = crate::private_route_client::Selection::new(&arguments.profile)?;
    let socket = arguments.directory.join("AuthorityRoute.json");
    let mut session = Session::new()?;
    let pending = store
        .resume_ordinary()?
        .map(|p| crate::authority_proof::Intent::from_signed(p.signed()))
        .transpose()?;
    let context = if pending
        .as_ref()
        .is_some_and(|p| p.action == "AuthorityRedeemMember")
    {
        ContextState::load(&bootstrap, &store, &directory)?
    } else {
        let result = domain_client::local(
            &bootstrap,
            Request {
                command: domain::Command::Route(routes::Command::CandidateContext {
                    accepted: accepted.envelope.clone(),
                }),
                grant: None,
            },
            &socket,
            &signer,
            &mut store,
            &mut session,
            || clock.health(),
        )?;
        let records = domain::result::merge(&bootstrap, &result.cache.records)?;
        let context = ContextState::retained(&bootstrap, &store, &records)?;
        context.save(&store)?;
        context
    };
    let existing = context.current_records(&store)?.iter().find_map(|bytes| {
        let value = trust_wire::decode(bytes).ok()?;
        let f = value.list(32).ok()?;
        (f[0].uint().ok()? == 125 && f[6].fixed::<32>().ok()? == accepted.member).then_some(value)
    });
    if let Some(existing) = existing {
        let f = existing.array(12)?;
        ensure!(
            f[7].fixed::<32>()? == accepted.candidate
                && !f[9].boolean()?
                && crate::authority_membership::version(&f[10])? == accepted.reader,
            "retained member differs from exact accepted candidate or is inactive"
        );
        let validity = f[8].array(2)?;
        ensure!(
            (validity[0].uint()?, validity[1].uint()?) == accepted.validity,
            "retained membership validity differs from accepted invitation"
        );
        Cache::retain_context(&bootstrap, &store, &context)?;
        profile
            .joined
            .as_mut()
            .context("join binding absent")?
            .admitted = true;
        save_profile(&arguments.profile, &profile)?;
        return crate::print_value(
            &json!({"state":"Joined","member":hex::encode(accepted.member),
            "certifiedHeight":store.prefix().height(),"directory":arguments.directory,"hostingRoles":[],"directFallback":false}),
        );
    }
    let result = context.member_local(
        &socket,
        MemberRequest {
            bootstrap: &bootstrap,
            mutation: MemberMutation::Redeem {
                grant: trust::hex32(&invitation.admission_grant)?,
                accepted: accepted.envelope,
            },
            receipt: Some(&arguments.directory.join("MembershipReceipt.cbor")),
        },
        &signer,
        &mut store,
        &mut session,
        || clock.health(),
    )?;
    ensure!(
        result.reference().kind == 125 && result.reference().id == accepted.member,
        "join returned another member"
    );
    let current = ContextState::load(&bootstrap, &store, &directory)?;
    Cache::retain_context(&bootstrap, &store, &current)?;
    profile
        .joined
        .as_mut()
        .context("join binding absent")?
        .admitted = true;
    save_profile(&arguments.profile, &profile)?;
    crate::print_value(
        &json!({"state":"Joined","member":hex::encode(accepted.member),"certifiedHeight":result.prefix().height(),
        "directory":arguments.directory,"hostingRoles":[],"inboundListeners":false,"directFallback":false,
        "next":"Issue a normal route voucher and retain its profile before the bootstrap voucher expires"}),
    )
}
