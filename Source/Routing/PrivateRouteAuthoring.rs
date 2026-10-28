// SPDX-License-Identifier: MIT
// Operators sign finite route profiles derived from independently reviewed deployment consent.
use crate::{
    authority_deployment_records,
    authority_domains::routes,
    authority_inspection_cli::domain_cli,
    route_profile::{self, Assurance, Identity, Limits},
    runtime_manifest::{self, Manifest},
    transfer_files as files, trust_bootstrap, trust_wire as wire,
};
use anyhow::{Context, Result, ensure};
use clap::{Args, ValueEnum};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::{
    ffi::OsStr,
    fs::File,
    net::SocketAddr,
    path::{Path, PathBuf},
};
#[derive(Args)]
struct Trust {
    #[arg(long)]
    bootstrap: PathBuf,
    /// Independently authenticated digest of the complete accepted bootstrap.
    #[arg(long)]
    bootstrap_digest: String,
}
impl Trust {
    fn load(&self) -> Result<trust_bootstrap::Verified> {
        let bytes = files::read_single(&self.bootstrap, wire::MAXIMUM, false)?;
        ensure!(
            Sha256::digest(&bytes).as_slice() == trust_bootstrap::hex32(&self.bootstrap_digest)?,
            "bootstrap differs from independently accepted digest"
        );
        trust_bootstrap::inspect(&bytes, true)
    }
}
#[derive(Clone, Copy, ValueEnum)]
pub enum Mode {
    Relay,
    Public,
    Attached,
}
#[derive(Clone, Copy, ValueEnum)]
pub enum Protocol {
    Relay,
    Authority,
    Content,
    Media,
    Mail,
    Transfer,
    BridgeReader,
    Application,
}
impl Protocol {
    fn number(self) -> u64 {
        match self {
            Self::Relay => 0,
            Self::Authority => 1,
            Self::Content => 2,
            Self::Media => 3,
            Self::Mail => 4,
            Self::Transfer => 5,
            Self::BridgeReader => 6,
            Self::Application => 7,
        }
    }
}
#[derive(Args)]
pub struct Profile {
    #[command(flatten)]
    trust: Trust,
    #[arg(long)]
    manifest: PathBuf,
    /// Reviewed kind117 deployment profile digest printed by deployment inspection.
    #[arg(long)]
    profile_digest: String,
    /// Private operator identity; its public key must exactly match the manifest.
    #[arg(long)]
    key: PathBuf,
    /// Opaque nonzero route identifier, separate from the service signing key.
    #[arg(long)]
    service: String,
    /// Manifest endpoint identifier owned and bound by role5.
    #[arg(long)]
    endpoint: String,
    /// Independently declared operator control domain, as 64 lowercase hexadecimal digits.
    #[arg(long)]
    domain: String,
    #[arg(long, value_enum)]
    mode: Mode,
    #[arg(long, value_enum)]
    protocol: Protocol,
    #[arg(long)]
    server_name: String,
    #[arg(long)]
    certificate_authority: PathBuf,
    /// Required only for an outbound attachment to this exact opaque relay identifier.
    #[arg(long)]
    relay: Option<String>,
    #[arg(long,default_value="Independent",value_parser=["Independent","Organisational"])]
    assurance: String,
    #[arg(long)]
    maximum_bytes: u64,
    #[arg(long)]
    maximum_duration_ms: u64,
    #[arg(long)]
    maximum_idle_ms: u64,
    #[arg(long)]
    maximum_connections: u64,
    #[arg(long)]
    output: PathBuf,
}
fn id(value: &str) -> Result<[u8; 32]> {
    trust_bootstrap::hex32(value)
}
fn assurance(value: &str) -> Assurance {
    if value == "Independent" {
        Assurance::Independent
    } else {
        Assurance::Organisation
    }
}
fn output_directory(path: &Path) -> Result<(File, &OsStr)> {
    let name = path
        .file_name()
        .context("route artifact file name required")?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok((files::private_directory(parent)?, name))
}
pub fn profile(arguments: Profile) -> Result<()> {
    let (output, name) = output_directory(&arguments.output)?;
    let bootstrap = arguments.trust.load()?;
    let scope = bootstrap.descriptor().scope();
    let manifest = Manifest::parse(&files::read_public_single(
        &arguments.manifest,
        runtime_manifest::MAXIMUM,
    )?)?;
    ensure!(
        manifest.network == scope.network
            && manifest.incarnation == scope.incarnation
            && manifest.bootstrap_digest == bootstrap.file_digest()
            && wire::digest(&manifest.desired()?) == id(&arguments.profile_digest)?,
        "route manifest differs from independently reviewed deployment"
    );
    let signer = domain_cli::signer(&arguments.key)?;
    ensure!(
        signer.verifying_key().to_bytes() == manifest.operator,
        "route profile signer is not the manifest operator"
    );
    let role = manifest
        .roles
        .iter()
        .find(|role| role.role == 5)
        .context("deployment has no route role5")?;
    let endpoint = id(&arguments.endpoint)?;
    ensure!(
        role.bind_endpoint_ids.contains(&endpoint),
        "route endpoint is not an owned role5 binding"
    );
    let endpoint = manifest
        .endpoints
        .iter()
        .find(|v| v.endpoint_id == endpoint)
        .context("route endpoint missing from manifest")?;
    ensure!(
        endpoint.service_key == role.service_key,
        "route endpoint belongs to another service key"
    );
    let service = id(&arguments.service)?;
    let domain = id(&arguments.domain)?;
    ensure!(
        service != [0; 32] && domain != [0; 32] && hex::encode(domain) == arguments.domain,
        "route service or canonical operator domain is invalid"
    );
    let mode = match arguments.mode {
        Mode::Relay => 1,
        Mode::Public => 2,
        Mode::Attached => 3,
    };
    let protocol = arguments.protocol.number();
    ensure!(
        (mode == 1) == (protocol == 0) && (mode == 3) == arguments.relay.is_some(),
        "relay protocol or attachment identity differs from selected mode"
    );
    ensure!(
        arguments.maximum_connections > 0 && arguments.maximum_connections <= manifest.limits[2],
        "route connection admission exceeds the reviewed manifest"
    );
    let identity = Identity {
        service,
        server_name: arguments.server_name,
        transport_key: endpoint.transport_key,
        leaf_der: endpoint.leaf_der.clone(),
        certificate_authority_pem: String::from_utf8(files::read_public_single(
            &arguments.certificate_authority,
            65536,
        )?)?,
    };
    identity.validate()?;
    // Validate the certificate authority encoding without DNS or a network connection.
    let _ = crate::route_tls::client(&identity)?;
    let mut profile = routes::RegisteredProfile {
        deployment: manifest.deployment,
        service: role.service_key,
        operator: manifest.operator,
        deployment_profile: authority_deployment_records::reference(&manifest.desired()?)?,
        consent: authority_deployment_records::reference(&manifest.unsigned_consent(0)?)?,
        endpoint: endpoint.endpoint_id,
        identity,
        address: (mode != 3).then_some(SocketAddr::new(endpoint.address, endpoint.port)),
        domain: arguments.domain,
        protocol,
        mode,
        relay: arguments.relay.as_deref().map(id).transpose()?,
        limits: Limits {
            bytes: arguments.maximum_bytes,
            duration_ms: arguments.maximum_duration_ms,
            idle_ms: arguments.maximum_idle_ms,
        },
        maximum_connections: arguments.maximum_connections,
        assurance: assurance(&arguments.assurance),
        validity: manifest.validity,
        manifest: manifest.clone(),
        envelope: vec![],
    };
    profile.envelope =
        wire::sign_envelope(&profile.payload(scope.network, scope.incarnation)?, &signer)?;
    let checked =
        routes::RegisteredProfile::parse(&profile.envelope, scope.network, scope.incarnation)?;
    files::atomic_at(&output, name, &checked.envelope, false)?;
    crate::print_value(
        &json!({"state":"RouteProfileSigned","route":hex::encode(service),"serviceKey":hex::encode(role.service_key),
        "deployment":hex::encode(manifest.deployment),"profileDigest":hex::encode(wire::digest(&checked.envelope)),
        "mode":mode,"protocol":protocol,"currentPermission":false,"networkUsed":false}),
    )
}
#[derive(Args)]
pub struct Template {
    #[command(flatten)]
    trust: Trust,
    #[arg(long)]
    relay_profile: PathBuf,
    #[arg(long)]
    destination_profile: PathBuf,
    #[arg(long,default_value="Independent",value_parser=["Independent","Organisational"])]
    minimum_route: String,
    #[arg(long)]
    output: PathBuf,
}
pub fn template(arguments: Template) -> Result<()> {
    let (output, name) = output_directory(&arguments.output)?;
    let bootstrap = arguments.trust.load()?;
    let scope = bootstrap.descriptor().scope();
    let load = |path: &PathBuf| -> Result<routes::RegisteredProfile> {
        routes::RegisteredProfile::parse(
            &files::read_single(path, 32768, false)?,
            scope.network,
            scope.incarnation,
        )
    };
    let relay = load(&arguments.relay_profile)?;
    let destination = load(&arguments.destination_profile)?;
    let minimum = assurance(&arguments.minimum_route).max(
        if bootstrap.summary.minimum_route == trust_bootstrap::Assurance::Independent {
            Assurance::Independent
        } else {
            Assurance::Organisation
        },
    );
    ensure!(
        relay.mode == 1
            && destination.mode != 1
            && destination
                .relay
                .is_none_or(|id| id == relay.identity.service)
            && relay.assurance >= minimum
            && relay.identity.service != destination.identity.service
            && relay.identity.transport_key != destination.identity.transport_key
            && (relay.assurance != Assurance::Independent || relay.domain != destination.domain),
        "route pair cannot meet the selected network minimum"
    );
    let route = route_profile::Profile {
        version: 1,
        network: scope.network,
        incarnation: scope.incarnation,
        relay_address: relay.address.context("relay has no public endpoint")?,
        relay: relay.identity,
        destination: destination.identity,
        relay_domain: relay.domain,
        domain: destination.domain,
        protocol: destination.protocol,
        assurance: relay.assurance,
        minimum_assurance: minimum,
        limits: Limits {
            bytes: relay.limits.bytes.min(destination.limits.bytes),
            duration_ms: relay.limits.duration_ms.min(destination.limits.duration_ms),
            idle_ms: relay.limits.idle_ms.min(destination.limits.idle_ms),
        },
        voucher: vec![],
    };
    files::atomic_at(&output, name, &serde_json::to_vec(&route)?, false)?;
    crate::print_value(
        &json!({"state":"UnissuedRouteTemplate","output":arguments.output,"currentPermission":false,"networkUsed":false,
        "next":"Issue a voucher against current registered profiles; the template alone cannot connect"}),
    )
}

#[cfg(test)]
#[path = "PrivateRouteAuthoringTests.rs"]
mod tests;
