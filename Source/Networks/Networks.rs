// SPDX-License-Identifier: MIT
// Independently pinned network profiles separate offline preparation from explicit relay access.
use crate::{Identity, transfer_files as files, trust_bootstrap as trust, trust_wire};
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use ed25519_dalek::SigningKey;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

#[cfg(feature = "gui")]
#[path = "NetworkApplication.rs"]
pub(crate) mod application;
#[path = "NetworkDiagnostics.rs"]
mod diagnostics;
#[path = "../Routing/PrivateRouteOnboarding.rs"]
mod onboarding;
#[path = "../Authority/AuthorityRecoveryCli.rs"]
mod recovery;
#[path = "../Routing/PrivateRouteWorkflow.rs"]
mod workflow;

const PROFILE_LIMIT: usize = 600000;

#[derive(Subcommand)]
pub enum Command {
    /// Preview or explicitly export bounded, redacted local diagnostics without a connection.
    Diagnose(diagnostics::Options),
    /// Observe local clock health without changing time or trusting a remote host boot.
    Clock {
        #[command(subcommand)]
        command: crate::private_route_clock::Command,
    },
    /// Propose, observe and independently accept a new network after authority loss.
    Recovery {
        #[command(subcommand)]
        command: recovery::Command,
    },
    /// Create an offline governance draft from public keys and explicit policy.
    Draft {
        #[arg(long)]
        spec: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Inspect an offline draft or accepted bootstrap before independent verification.
    InspectBootstrap {
        #[arg(long)]
        bootstrap: PathBuf,
    },
    /// Accept one exact recovery policy with an explicitly selected offline key.
    RecoveryAccept {
        #[arg(long)]
        draft: PathBuf,
        /// Independently checked digest printed by inspect-bootstrap.
        #[arg(long)]
        fingerprint: String,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Combine separately produced custody acceptances into an offline bootstrap.
    Assemble {
        #[arg(long)]
        draft: PathBuf,
        #[arg(long, required=true, num_args=1..=3)]
        acceptance: Vec<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Prepare private client-only keys and independently authenticated trust, offline.
    Prepare {
        #[arg(long)]
        bootstrap: PathBuf,
        /// Digest of the entire bootstrap, verified through an independent channel.
        #[arg(long)]
        fingerprint: String,
        #[arg(long, default_value="Independent", value_parser=["Independent", "Organisational"])]
        minimum_route: String,
        /// Restrict accepted publication modes; repeat to allow both.
        #[arg(long, value_parser=["HostReadable", "Sealed"])]
        publication_mode: Vec<String>,
        /// Explicit local permission for a later, separately requested network search.
        #[arg(long)]
        permit_network_search: bool,
        #[arg(long)]
        output: PathBuf,
    },
    /// Inspect nonsecret trust and route assumptions in a prepared client profile.
    Inspect {
        #[arg(long)]
        profile: PathBuf,
    },
    /// Publish only device and separate relay public keys for a candidate-specific invitation.
    Request {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Inspect a public request without granting membership or hosting rights.
    InspectRequest {
        #[arg(long)]
        request: PathBuf,
    },
    /// Assemble already authorised candidate and relay material for independent delivery.
    Invitation(onboarding::AssembleInvitation),
    /// Accept an independently pinned invitation and join only through its approved relay.
    Join(onboarding::Join),
    /// Run a normal client command with this network's retained trust, identity and relay routes.
    Connect(workflow::Connect),
    /// Retain an authenticated relay route for an explicitly selected domain service.
    RetainRoute(workflow::Retain),
    /// Inspect retained route identities and the latest local connection observation.
    Status {
        #[arg(long)]
        profile: PathBuf,
    },
    /// Remove only this local profile; this does not revoke network rights.
    Remove {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        fingerprint: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Profile {
    format: String,
    bootstrap: String,
    fingerprint: String,
    descriptor_digest: String,
    client_id: String,
    device: Identity,
    relay_identity: Identity,
    minimum_route: trust::Assurance,
    accepted_relay_domains: Vec<String>,
    required_publication_modes: Vec<String>,
    permit_network_search: bool,
    #[serde(default)]
    recovery: Option<recovery::Binding>,
    #[serde(default)]
    joined: Option<onboarding::Joined>,
}

fn time() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn random() -> [u8; 32] {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
fn identity() -> Identity {
    let key = SigningKey::generate(&mut OsRng);
    Identity {
        secret_key: hex::encode(key.to_bytes()),
        public_key: hex::encode(key.verifying_key().to_bytes()),
    }
}
fn output(path: &Path, bytes: &[u8]) -> Result<()> {
    files::Destination::open(path)?.publish(bytes)
}
fn profile_lock(path: &Path) -> Result<std::fs::File> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let directory = files::private_directory(parent)?;
    files::profile_lock(
        &directory,
        path.file_name().context("profile filename required")?,
    )
}
fn fingerprint(bytes: &[u8], pin: &str) -> Result<()> {
    ensure!(
        trust::hex32(pin)? == trust_wire::digest(bytes),
        "bootstrap fingerprint mismatch"
    );
    Ok(())
}
fn report(checked: &trust::Verified) -> Result<()> {
    crate::print_value(&json!({
        "state":if checked.summary.draft {"DraftAwaitingRecoveryAcceptance"} else {"OfflineBootstrap"},
        "trust":checked.summary,
        "currentAuthority":false,"networkUsed":false,"routeObserved":false,"membership":false,
        "custodyAssumption":"Key signatures establish acceptance; independent human custody and key protection require separate verification",
        "privacyAssumption":if checked.summary.route.assurance == trust::Assurance::Independent {
            "Declared separate operators; actual independence and noncollusion are not proven"
        } else { "The organisation can correlate reader and destination activity" },
        "join":"Requires an independently pinned invitation and explicit relay-only join",
    }))
}
fn verify_profile(profile: &Profile, bytes: &[u8], current: bool) -> Result<trust::Verified> {
    ensure!(
        profile.format == "HyperNetOfflineClient/1",
        "unsupported offline client profile"
    );
    fingerprint(bytes, &profile.fingerprint)?;
    let checked = if current {
        trust::check(bytes, true, time()?)?
    } else {
        trust::inspect(bytes, true)?
    };
    ensure!(
        profile.descriptor_digest == checked.summary.descriptor_digest,
        "profile descriptor digest mismatch"
    );
    ensure!(
        trust::hex32(&profile.client_id)? != [0; 32],
        "zero client identifier"
    );
    for identity in [&profile.device, &profile.relay_identity] {
        let secret = Zeroizing::new(trust::hex32(&identity.secret_key)?);
        let key = SigningKey::from_bytes(&secret);
        ensure!(
            hex::encode(key.verifying_key().to_bytes()) == identity.public_key,
            "profile key pair mismatch"
        );
        ensure!(
            !checked.summary.voters.contains(&identity.public_key)
                && !checked
                    .summary
                    .administrators
                    .contains(&identity.public_key)
                && !checked
                    .summary
                    .recovery
                    .keys
                    .iter()
                    .any(|v| v.public_key == identity.public_key)
                && checked.summary.route.relay_transport_key != identity.public_key
                && checked.summary.route.admission_transport_key != identity.public_key,
            "client key reuses a bootstrap role identity"
        );
    }
    ensure!(
        profile.device.public_key != profile.relay_identity.public_key,
        "client and relay credentials must differ"
    );
    ensure!(
        checked.summary.route.assurance >= profile.minimum_route.max(checked.summary.minimum_route),
        "route is below client privacy minimum"
    );
    ensure!(
        !profile.accepted_relay_domains.is_empty()
            && profile
                .accepted_relay_domains
                .windows(2)
                .all(|v| v[0] < v[1])
            && profile.accepted_relay_domains.len() <= 16
            && profile
                .accepted_relay_domains
                .iter()
                .all(|v| trust::hex32(v).is_ok())
            && profile
                .accepted_relay_domains
                .contains(&checked.summary.route.relay_domain),
        "route is outside client accepted domains"
    );
    ensure!(
        !profile.required_publication_modes.is_empty()
            && profile.required_publication_modes.len() <= 2
            && profile
                .required_publication_modes
                .windows(2)
                .all(|v| v[0] < v[1])
            && profile
                .required_publication_modes
                .iter()
                .all(|v| checked.summary.publication_modes.contains(v)),
        "client publication intersection is empty or invalid"
    );
    recovery::verify_profile_binding(profile)?;
    Ok(checked)
}
fn load(path: &Path) -> Result<(Profile, trust::Verified)> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    files::private_directory(parent)?;
    let raw = Zeroizing::new(files::read_single(path, PROFILE_LIMIT, true)?);
    let profile: Profile = serde_json::from_slice(&raw)?;
    ensure!(
        profile.bootstrap.len() <= trust_wire::MAXIMUM * 2,
        "oversized stored bootstrap"
    );
    let bytes = hex::decode(&profile.bootstrap)?;
    let checked = verify_profile(&profile, &bytes, false)?;
    Ok((profile, checked))
}
fn profile_report(profile: &Profile, checked: &trust::Verified) -> Result<()> {
    let current = trust::check(&hex::decode(&profile.bootstrap)?, true, time()?).is_ok();
    crate::print_value(
        &json!({"state":if profile.joined.as_ref().is_some_and(|j| j.admitted) { "Joined" } else { "OfflinePrepared" },"fingerprint":profile.fingerprint,
            "bootstrapTimeValid":current,
            "descriptorDigest":profile.descriptor_digest,"client":profile.client_id,
            "devicePublicKey":profile.device.public_key,"relayPublicKey":profile.relay_identity.public_key,
            "minimumRoute":profile.minimum_route,"effectiveMinimumRoute":profile.minimum_route.max(checked.summary.minimum_route),
            "acceptedRelayDomains":profile.accepted_relay_domains,"publicationModes":profile.required_publication_modes,
            "permitNetworkSearch":profile.permit_network_search,"trust":checked.summary,
            "membership":profile.joined.as_ref().is_some_and(|j| j.admitted),"currentAuthority":false,"hostingRoles":[],"inboundListeners":false,
            "networkUsed":false,"routeObserved":false,"join":"Requires an independently pinned invitation and explicit relay-only join",
            "privacyAssumption":if checked.summary.route.assurance == trust::Assurance::Independent {
                "Declared separate operators; actual independence and noncollusion are not proven"
            } else { "The organisation can correlate reader and destination activity" },
        }),
    )
}

pub(crate) fn require_network_search(path: &Path) -> Result<()> {
    let (profile, _) = load(path)?;
    ensure!(
        profile.permit_network_search,
        "this network profile does not permit disclosure of search terms"
    );
    Ok(())
}
pub(crate) fn route_subject(
    path: &Path,
    route: &crate::route_profile::Profile,
) -> Result<[u8; 32]> {
    workflow::route_subject(path, route)
}
pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Diagnose(options) => diagnostics::run(options),
        Command::Recovery { command } => recovery::run(command),
        Command::Clock { command } => crate::private_route_clock::run(command),
        Command::Draft {
            spec,
            output: destination,
        } => {
            let spec: trust::DraftSpec =
                serde_json::from_slice(&files::read_single(&spec, 65536, false)?)?;
            let bytes = trust::draft(spec, [random(), random(), random(), random()], time()?)?;
            let checked = trust::check(&bytes, false, time()?)?;
            output(&destination, &bytes)?;
            report(&checked)
        }
        Command::InspectBootstrap { bootstrap } => {
            let bytes = files::read_single(&bootstrap, trust_wire::MAXIMUM, false)?;
            report(&trust::inspect(&bytes, false)?)
        }
        Command::RecoveryAccept {
            draft,
            fingerprint: pin,
            identity,
            output: destination,
        } => {
            let bytes = files::read_single(&draft, trust_wire::MAXIMUM, false)?;
            fingerprint(&bytes, &pin)?;
            let raw = Zeroizing::new(files::read_single(&identity, 4096, true)?);
            let identity: Identity = serde_json::from_slice(&raw)?;
            let secret = Zeroizing::new(trust::hex32(&identity.secret_key)?);
            ensure!(
                hex::encode(SigningKey::from_bytes(&secret).verifying_key().to_bytes())
                    == identity.public_key,
                "recovery key pair mismatch"
            );
            let accepted = trust::accept(&bytes, &SigningKey::from_bytes(&secret), time()?)?;
            output(&destination, &accepted)?;
            crate::print_value(
                &json!({"state":"RecoveryPolicyAccepted","draftFingerprint":pin,"publicKey":identity.public_key,"networkUsed":false}),
            )
        }
        Command::Assemble {
            draft,
            acceptance,
            output: destination,
        } => {
            let bytes = files::read_single(&draft, trust_wire::MAXIMUM, false)?;
            let acceptances = acceptance
                .iter()
                .map(|path| files::read_single(path, trust_wire::MAXIMUM, false))
                .collect::<Result<Vec<_>>>()?;
            let assembled = trust::assemble(&bytes, &acceptances, time()?)?;
            let checked = trust::check(&assembled, true, time()?)?;
            output(&destination, &assembled)?;
            report(&checked)
        }
        Command::Prepare {
            bootstrap,
            fingerprint: pin,
            minimum_route,
            publication_mode,
            permit_network_search,
            output: destination,
        } => {
            let _guard = profile_lock(&destination)?;
            let bytes = files::read_single(&bootstrap, trust_wire::MAXIMUM, false)?;
            fingerprint(&bytes, &pin)?;
            let checked = trust::check(&bytes, true, time()?)?;
            let minimum_route = if minimum_route == "Independent" {
                trust::Assurance::Independent
            } else {
                trust::Assurance::Organisational
            };
            let mut modes = if publication_mode.is_empty() {
                checked.summary.publication_modes.clone()
            } else {
                publication_mode
            };
            modes.sort();
            let profile = Profile {
                format: "HyperNetOfflineClient/1".into(),
                bootstrap: hex::encode(&bytes),
                fingerprint: pin,
                descriptor_digest: checked.summary.descriptor_digest.clone(),
                client_id: hex::encode(random()),
                device: identity(),
                relay_identity: identity(),
                minimum_route,
                accepted_relay_domains: vec![checked.summary.route.relay_domain.clone()],
                required_publication_modes: modes,
                permit_network_search,
                recovery: None,
                joined: None,
            };
            let checked = verify_profile(&profile, &bytes, true)?;
            let encoded = Zeroizing::new(serde_json::to_vec(&profile)?);
            ensure!(encoded.len() <= PROFILE_LIMIT, "profile exceeds size bound");
            output(&destination, &encoded)?;
            profile_report(&profile, &checked)
        }
        Command::Inspect { profile } => {
            let (profile, checked) = load(&profile)?;
            profile_report(&profile, &checked)
        }
        Command::Request { profile, output } => onboarding::request(&profile, &output),
        Command::InspectRequest { request } => onboarding::inspect_request(&request),
        Command::Invitation(arguments) => onboarding::assemble(arguments),
        Command::Join(arguments) => onboarding::join(arguments),
        Command::Connect(arguments) => workflow::connect(arguments),
        Command::RetainRoute(arguments) => workflow::retain(arguments),
        Command::Status { profile } => workflow::status(&profile),
        Command::Remove {
            profile,
            fingerprint: pin,
        } => {
            let _guard = profile_lock(&profile)?;
            let (saved, _) = load(&profile)?;
            ensure!(
                saved.fingerprint == pin && trust::hex32(&pin).is_ok(),
                "profile fingerprint mismatch"
            );
            let parent = profile
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let directory = files::private_directory(parent)?;
            let filename = profile.file_name().context("profile filename required")?;
            files::remove_private_at(&directory, filename)?;
            crate::print_value(
                &json!({"removed":profile,"networkUsed":false,"networkRightsRevoked":false}),
            )
        }
    }
}

pub(crate) fn route_key(path: &Path, route: &crate::route_profile::Profile) -> Result<SigningKey> {
    let (profile, checked) = load(path)?;
    route.validate()?;
    let required = profile.minimum_route.max(checked.summary.minimum_route);
    let required = if required == trust::Assurance::Independent {
        crate::route_profile::Assurance::Independent
    } else {
        crate::route_profile::Assurance::Organisation
    };
    ensure!(
        route.network == trust::hex32(&checked.summary.network)?
            && route.incarnation == trust::hex32(&checked.summary.incarnation)?
            && route.relay.service == trust::hex32(&checked.summary.route.relay_service)?
            && route.relay.transport_key
                == trust::hex32(&checked.summary.route.relay_transport_key)?
            && profile.accepted_relay_domains.contains(&route.relay_domain)
            && checked
                .summary
                .allowed_relay_domains
                .contains(&route.relay_domain)
            && route.minimum_assurance >= required
            && route.assurance >= required,
        "selected relay conflicts with independently pinned network or client privacy minimum"
    );
    if route.protocol == 1 {
        ensure!(
            route.destination.service == trust::hex32(&checked.summary.route.admission_service)?
                && route.destination.transport_key
                    == trust::hex32(&checked.summary.route.admission_transport_key)?
                && route.domain == checked.summary.route.admission_domain,
            "authority route differs from independently pinned admission identity"
        );
    }
    let record =
        crate::authority_domains::Record::parse(&route.voucher, route.network, route.incarnation)?;
    ensure!(
        record.reference.kind == 166,
        "selected route lacks a typed possession voucher"
    );
    let voucher = crate::authority_domains::routes::Voucher::parse(&record.payload)?;
    ensure!(
        voucher.possession == trust::hex32(&profile.relay_identity.public_key)?
            && voucher.relay.id == route.relay.service
            && voucher.destination.id == route.destination.service,
        "selected route voucher differs from the client possession key or registered endpoints"
    );
    let secret = Zeroizing::new(trust::hex32(&profile.relay_identity.secret_key)?);
    Ok(SigningKey::from_bytes(&secret))
}
