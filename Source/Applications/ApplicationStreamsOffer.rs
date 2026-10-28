// SPDX-License-Identifier: MIT
// Inert service artifacts bind the exact local endpoint before either party submits authority state.
use super::*;
use ed25519_dalek::Signer;
use sha2::{Digest as _, Sha256};
#[derive(Args)]
pub struct Trust {
    #[arg(long)]
    bootstrap: PathBuf,
    #[arg(long)]
    bootstrap_digest: String,
}
impl Trust {
    fn load(&self) -> Result<trust_bootstrap::Verified> {
        let bytes = files::read_single(&self.bootstrap, wire::MAXIMUM, true)?;
        ensure!(
            Sha256::digest(&bytes).as_slice() == id(&self.bootstrap_digest)?,
            "bootstrap differs from independently verified digest"
        );
        trust_bootstrap::inspect(&bytes, true)
    }
}
#[derive(Args)]
pub struct Arguments {
    #[command(flatten)]
    trust: Trust,
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    service: String,
    /// Exact registered route ID:generation:digest.
    #[arg(long)]
    route: String,
    #[arg(long)]
    operator: String,
    #[arg(long)]
    endpoint: String,
    #[arg(long)]
    protocol: String,
    #[arg(long)]
    not_before_ms: u64,
    #[arg(long)]
    expires_ms: u64,
    #[arg(long, default_value_t = 1073741824)]
    maximum_bytes: u64,
    #[arg(long, default_value_t = 60000)]
    duration_ms: u64,
    #[arg(long, default_value_t = 15000)]
    idle_ms: u64,
    #[arg(long)]
    output: PathBuf,
}
#[derive(Args)]
pub struct Inspection {
    #[command(flatten)]
    trust: Trust,
    #[arg(long)]
    offer: PathBuf,
    #[arg(long)]
    owner_key: Option<String>,
}
#[derive(Args)]
pub struct Acceptance {
    #[command(flatten)]
    inspection: Inspection,
    #[arg(long)]
    key: PathBuf,
    /// Operator-signed route profile containing the exact local endpoint identity.
    #[arg(long)]
    route_profile: PathBuf,
    #[arg(long)]
    output: PathBuf,
}
pub(super) struct Artifact {
    pub registration: streams::Registration,
    pub binding: streams::local::Binding,
}
impl Artifact {
    pub fn parse(
        bootstrap: &trust_bootstrap::Verified,
        bytes: &[u8],
        accepted: bool,
    ) -> Result<Self> {
        ensure!(
            bootstrap.fully_accepted() && bytes.len() <= 16384,
            "service offer requires accepted bootstrap and bounded bytes"
        );
        let value = wire::decode(bytes)?;
        let f = value.array(5)?;
        ensure!(
            f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == "ApplicationStreamServiceOffer",
            "service artifact context differs"
        );
        let scope = bootstrap.descriptor().scope();
        let binding: streams::local::Binding = serde_json::from_slice(f[3].bytes()?)?;
        binding.validate()?;
        let registration = if accepted {
            streams::Registration::parse(f[4].bytes()?, scope.network, scope.incarnation)?
        } else {
            streams::Registration::parse_offer(f[4].bytes()?, scope.network, scope.incarnation)?
        };
        ensure!(
            binding.network == scope.network
                && binding.incarnation == scope.incarnation
                && binding.service == registration.id
                && binding.owner == registration.owner
                && binding.protocol == registration.protocol
                && binding.digest()? == registration.binding,
            "local binding differs from exact service consent"
        );
        Ok(Self {
            registration,
            binding,
        })
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        wire::encode(&V::Array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("ApplicationStreamServiceOffer".into()),
            V::Bytes(self.binding.encode()?),
            V::Bytes(self.registration.envelope.clone()),
        ]))
    }
    fn authenticate(&self, bootstrap: &trust_bootstrap::Verified, pin: Option<&str>) -> Result<()> {
        let pinned = pin.map(id).transpose()?;
        ensure!(
            pinned.map_or(
                bootstrap
                    .reservations()
                    .contains(&(4, self.registration.owner)),
                |key| key == self.registration.owner
            ),
            "service owner requires an independently authenticated key pin"
        );
        Ok(())
    }
    fn report(&self, status: &str) -> Result<()> {
        crate::print_value(
            &json!({"status":status,"service":hex::encode(self.registration.id),"owner":hex::encode(self.registration.owner),"operator":hex::encode(self.registration.operator),"endpoint":hex::encode(self.binding.endpoint),"protocol":self.registration.protocol,"route":{"id":hex::encode(self.registration.route.id),"generation":self.registration.route.generation,"digest":hex::encode(self.registration.route.digest)},"binding":hex::encode(self.registration.binding),"validity":self.registration.validity,"maximumBytes":self.registration.limits.bytes,"durationMs":self.registration.limits.duration_ms,"idleMs":self.registration.limits.idle_ms}),
        )
    }
}
pub fn create(a: Arguments) -> Result<()> {
    let bootstrap = a.trust.load()?;
    let scope = bootstrap.descriptor().scope();
    let signer = control::signer(&a.key)?;
    let owner = signer.verifying_key().to_bytes();
    let service = id(&a.service)?;
    let binding = streams::local::Binding {
        version: 1,
        id: crate::route_protocol::random()?,
        network: scope.network,
        incarnation: scope.incarnation,
        service,
        owner,
        endpoint: id(&a.endpoint)?,
        protocol: a.protocol.clone(),
    };
    let mut registration = streams::Registration {
        id: service,
        route: reference(&a.route, 165)?,
        owner,
        operator: id(&a.operator)?,
        protocol: a.protocol,
        binding: binding.digest()?,
        limits: crate::route_profile::Limits {
            bytes: a.maximum_bytes,
            duration_ms: a.duration_ms,
            idle_ms: a.idle_ms,
        },
        validity: (a.not_before_ms, a.expires_ms),
        envelope: vec![],
    };
    registration.envelope = wire::sign_envelope(
        &registration.payload(scope.network, scope.incarnation)?,
        &signer,
    )?;
    let bytes = Artifact {
        registration,
        binding,
    }
    .bytes()?;
    let artifact = Artifact::parse(&bootstrap, &bytes, false)?;
    files::write_new(&a.output, &bytes)?;
    artifact.report("ApplicationServiceOffered")
}
pub fn inspect(a: Inspection) -> Result<()> {
    let bootstrap = a.trust.load()?;
    let bytes = files::read_single(&a.offer, 16384, true)?;
    let artifact = Artifact::parse(&bootstrap, &bytes, false)
        .or_else(|_| Artifact::parse(&bootstrap, &bytes, true))?;
    artifact.authenticate(&bootstrap, a.owner_key.as_deref())?;
    artifact.report("ApplicationServiceInspected")
}
pub fn accept(a: Acceptance) -> Result<()> {
    let bootstrap = a.inspection.trust.load()?;
    let mut artifact = Artifact::parse(
        &bootstrap,
        &files::read_single(&a.inspection.offer, 16384, true)?,
        false,
    )?;
    artifact.authenticate(&bootstrap, a.inspection.owner_key.as_deref())?;
    let signer = control::signer(&a.key)?;
    let key = signer.verifying_key().to_bytes();
    ensure!(
        key == artifact.registration.operator,
        "service acceptance key differs from operator"
    );
    let scope = bootstrap.descriptor().scope();
    let route = domain::routes::RegisteredProfile::parse(
        &files::read_single(&a.route_profile, 65536, true)?,
        scope.network,
        scope.incarnation,
    )?;
    artifact
        .binding
        .registration(&artifact.registration, &route)?;
    let (payload, mut signatures) = wire::envelope(&artifact.registration.envelope, 1)?;
    if key != artifact.registration.owner {
        signatures.push((
            key,
            signer
                .sign(&wire::signature_message(&payload, &key))
                .to_bytes(),
        ));
    }
    signatures.sort_by_key(|(key, _)| *key);
    artifact.registration.envelope = wire::encode(&V::Array(vec![
        V::Uint(0),
        V::Uint(1),
        V::Bytes(payload),
        V::Array(
            signatures
                .iter()
                .map(|(key, signature)| {
                    V::Array(vec![V::Bytes(key.to_vec()), V::Bytes(signature.to_vec())])
                })
                .collect(),
        ),
    ]))?;
    let bytes = artifact.bytes()?;
    let artifact = Artifact::parse(&bootstrap, &bytes, true)?;
    files::write_new(&a.output, &bytes)?;
    artifact.report("ApplicationServiceAccepted")
}

#[derive(Args)]
pub struct EndpointConfiguration {
    #[command(flatten)]
    trust: Trust,
    #[arg(long)]
    accepted: PathBuf,
    /// Existing version1 relay configuration, including the consented attachment identity.
    #[arg(long)]
    configuration: PathBuf,
    #[arg(long)]
    output: PathBuf,
}
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RelayConfiguration {
    version: u64,
    relay_identity: Option<crate::route_profile::Identity>,
    relay_address: Option<std::net::SocketAddr>,
}
pub fn endpoint_config(a: EndpointConfiguration) -> Result<()> {
    let bootstrap = a.trust.load()?;
    let artifact = Artifact::parse(
        &bootstrap,
        &files::read_single(&a.accepted, 16384, true)?,
        true,
    )?;
    let config: RelayConfiguration =
        serde_json::from_slice(&files::read_single(&a.configuration, 65536, true)?)?;
    ensure!(
        config.version == 1 && config.relay_identity.is_some() == config.relay_address.is_some(),
        "endpoint input must be exact version1 relay configuration"
    );
    if let Some(relay) = &config.relay_identity {
        relay.validate()?;
    }
    let output = json!({"version":2,"relayIdentity":config.relay_identity,"relayAddress":config.relay_address,
        "application":{"registration":artifact.registration.envelope,"binding":artifact.binding}});
    files::write_new(&a.output, &serde_json::to_vec(&output)?)?;
    artifact.report("ApplicationEndpointConfigured")
}
