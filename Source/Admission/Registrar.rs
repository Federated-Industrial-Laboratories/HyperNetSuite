// SPDX-License-Identifier: MIT
// The private registrar serializes exact native admission and its optional HRC extension.
use super::{
    helper,
    protocol::{
        self, Challenge, ChallengeRequest, Descriptor, Metadata, Permissions, Request, Response,
        Signed,
    },
    store::{self, Claim, Locked, Phase},
};
use anyhow::{Result, ensure};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub version: u8,
    pub directory: PathBuf,
    pub origin: String,
    pub name: String,
    pub native: helper::Native,
    pub descriptor_key_file: PathBuf,
    pub socket: PathBuf,
    pub edge_uid: u32,
    #[serde(default)]
    pub owner_uid: Option<u32>,
    pub welcome: Option<String>,
    pub hrc: Option<helper::Hrc>,
    pub hrc_descriptor: Option<Value>,
    pub reader: bool,
}
impl Configuration {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.edge_uid != unsafe { libc::geteuid() }
                && self.edge_uid != self.owner_uid.unwrap_or_else(|| unsafe { libc::geteuid() }),
            "public edge must use a separate mapped host identity"
        );
        ensure!(
            self.version == 1
                && self.socket.is_absolute()
                && self.descriptor_key_file.is_absolute(),
            "invalid registrar paths"
        );
        super::private::directory(&self.directory)?;
        let origin = super::location::Location::parse(&self.origin)?;
        ensure!(
            origin.origin.as_str() == self.origin && origin.identity_pin.is_none(),
            "registrar requires an exact HTTPS origin"
        );
        ensure!(
            !self.name.trim().is_empty()
                && self.name.len() <= 128
                && !self.name.chars().any(char::is_control),
            "invalid server name"
        );
        ensure!(
            self.reader || self.hrc.is_some(),
            "server must offer Pages or chat"
        );
        ensure!(
            self.hrc.is_some() == self.hrc_descriptor.is_some(),
            "HRC extension descriptor missing"
        );
        ensure!(
            self.welcome.as_ref().is_none_or(|s| s.len() <= 2048
                && s.starts_with("hypernet:")
                && !s.chars().any(char::is_control)),
            "welcome must be a native HyperNet location"
        );
        Ok(())
    }
}
pub struct Registrar {
    pub config: Configuration,
    pub store: Locked,
    key: SigningKey,
    boot: String,
    budget: Budget,
}
struct Budget {
    start: Instant,
    total: u16,
    sources: BTreeMap<String, u16>,
}
impl Budget {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            total: 0,
            sources: BTreeMap::new(),
        }
    }
    fn admit(&mut self, source: &str) -> Result<()> {
        if self.start.elapsed() >= Duration::from_secs(60) {
            *self = Self::new();
        }
        let source: std::net::IpAddr = source.parse()?;
        let source = match source {
            std::net::IpAddr::V6(v) => {
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(u128::from(v) & (!0u128 << 64)))
            }
            other => other,
        }
        .to_string();
        ensure!(
            self.total < 120 && (self.sources.contains_key(&source) || self.sources.len() < 128),
            "AdmissionRateLimited"
        );
        let count = self.sources.entry(source).or_default();
        ensure!(*count < 24, "AdmissionRateLimited");
        *count += 1;
        self.total += 1;
        Ok(())
    }
}
fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("native helper field absent"))
}
fn status(value: &Value) -> Result<&str> {
    field(value, "status")
}
fn boot_ms() -> Result<u64> {
    crate::authority_challenge::boot_time_ms()
}
fn wall_ms() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
impl Registrar {
    pub fn identity_pin(&self) -> String {
        protocol::digest(self.key.verifying_key().as_bytes())
    }
    pub fn open(config: Configuration) -> Result<Self> {
        config.validate()?;
        let bytes = zeroize::Zeroizing::new(crate::files::read_bounded(
            &config.descriptor_key_file,
            true,
        )?);
        let text = std::str::from_utf8(&bytes)?.trim();
        ensure!(
            protocol::identifier(text),
            "descriptor key must contain 32 secret bytes as hexadecimal"
        );
        let mut raw = zeroize::Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(text, &mut *raw)?;
        let key = SigningKey::from_bytes(&raw);
        let store = Locked::open(&config.directory)?;
        Ok(Self {
            config,
            store,
            key,
            boot: crate::random_hex::<32>(),
            budget: Budget::new(),
        })
    }
    fn native_description(&self, stop: &AtomicBool) -> Result<Value> {
        let description = self
            .config
            .native
            .call(json!({"operation":"describe"}), stop)?;
        ensure!(
            status(&description)? == "descriptor",
            "NativeAdmissionUnavailable"
        );
        let key = hex::encode(self.key.verifying_key().as_bytes());
        ensure!(
            field(&description, "signingKey")? == key
                && field(&description, "currentKey")?
                    == protocol::digest(self.key.verifying_key().as_bytes()),
            "native policy does not certify this descriptor key"
        );
        Ok(description)
    }
    fn metadata(&self, native: &Value, stop: &AtomicBool) -> Result<Metadata> {
        let state = self.store.state()?;
        let hrc = if let Some(binding) = &self.config.hrc {
            let description = binding.call(json!({"operation":"describe"}), stop)?;
            ensure!(
                status(&description)? == "described",
                "HrcAdmissionUnavailable"
            );
            let descriptor = self.config.hrc_descriptor.as_ref().unwrap();
            ensure!(
                description.get("home") == descriptor.get("home")
                    && description.get("serviceKey") == descriptor.get("signingKey"),
                "HRC descriptor differs from configured Home"
            );
            Some(
                json!({"descriptor":descriptor,"policy":description.get("policy").ok_or_else(||anyhow::anyhow!("HRC policy absent"))?}),
            )
        } else {
            None
        };
        let agents = hrc
            .as_ref()
            .and_then(|v| v.pointer("/policy/agentsEnabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let mut modes = vec![store::Mode::InviteOnly];
        if state.mode != store::Mode::InviteOnly {
            modes.push(state.mode);
        }
        let bootstrap = hex::decode(field(native, "bootstrap")?)?;
        let metadata = Metadata {
            origin: self.config.origin.clone(),
            name: self.config.name.clone(),
            network: field(native, "network")?.into(),
            incarnation: field(native, "incarnation")?.into(),
            policy: field(native, "policy")?.into(),
            generation: native
                .get("policyGeneration")
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow::anyhow!("native policy generation absent"))?,
            bootstrap_digest: protocol::digest(&bootstrap),
            signing_key: hex::encode(self.key.verifying_key().as_bytes()),
            permissions: Permissions {
                modes,
                access: state.access.clone(),
                reader: self.config.reader,
                chat: self.config.hrc.is_some(),
                room_creation: false,
                moderation: false,
                publishing: false,
                hosting: false,
                agents,
                maximum_members: state.maximum_members,
                hrc,
            },
            welcome: self.config.welcome.clone(),
        };
        protocol::native_permissions(native, &metadata.permissions)?;
        Ok(metadata)
    }
    pub fn descriptor(&self, stop: &AtomicBool) -> Result<Descriptor> {
        let native = self.native_description(stop)?;
        let metadata = self.metadata(&native, stop)?;
        // Home inspection may outlive a short native proof. Refresh after it completes.
        let fresh = self.native_description(stop)?;
        for field in [
            "network",
            "incarnation",
            "policy",
            "policyGeneration",
            "currentKey",
            "bootstrap",
            "accessEnd",
            "maximumParticipants",
            "roles",
        ] {
            ensure!(
                fresh.get(field) == native.get(field),
                "native descriptor changed during inspection"
            );
        }
        let native = fresh;
        let metadata = Signed::new("descriptor", &metadata, &self.key)?;
        Ok(Descriptor {
            format: protocol::FORMAT.into(),
            native,
            metadata,
        })
    }
    pub fn challenge(&mut self, request: ChallengeRequest, stop: &AtomicBool) -> Result<Signed> {
        let terminal = self.store.state()?.retirement(
            &request.attempt,
            &request.control_key,
            &request.intent_digest,
        )?;
        let floor = if terminal.is_some() {
            0
        } else {
            self.native_description(stop)?
                .get("claimFloor")
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow::anyhow!("native claim floor absent"))?
        };
        let previous = request
            .previous
            .as_ref()
            .map(|p| {
                p.verify::<Challenge>(
                    "challenge",
                    &hex::encode(self.key.verifying_key().as_bytes()),
                    4096,
                )
            })
            .transpose()?;
        let retained = self
            .store
            .state()?
            .claim(
                &request.attempt,
                &request.control_key,
                &request.intent_digest,
            )?
            .is_some();
        let reusable = previous
            .as_ref()
            .filter(|p| {
                p.origin == self.config.origin
                    && p.attempt == request.attempt
                    && p.control_key == request.control_key
                    && p.intent_digest == request.intent_digest
            })
            .filter(|p| {
                store::ordinal(&p.native_claim).is_ok_and(|n| {
                    n > floor.max(
                        self.store
                            .state()
                            .map(|s| s.retired_floor)
                            .unwrap_or(u64::MAX),
                    ) && n <= self.store.state().map(|s| s.counter).unwrap_or(0)
                })
            });
        let native_claim = if let Some(receipt) = terminal {
            receipt.native_claim
        } else if let Some(previous) = reusable.filter(|_| !retained) {
            previous.native_claim.clone()
        } else {
            self.store.transact(|s| s.allocate(&request, floor))?
        };
        Signed::new(
            "challenge",
            &Challenge {
                origin: self.config.origin.clone(),
                boot: self.boot.clone(),
                nonce: crate::random_hex::<32>(),
                expires_boot_ms: boot_ms()?
                    .checked_add(30000)
                    .ok_or_else(|| anyhow::anyhow!("clock overflow"))?,
                attempt: request.attempt,
                control_key: request.control_key,
                intent_digest: request.intent_digest,
                native_claim,
            },
            &self.key,
        )
    }
    fn authenticated(&self, signed: &Signed) -> Result<(Challenge, Request)> {
        let request: Request = signed.verify("request", &signed.key, protocol::REQUEST_BYTES)?;
        let challenge: Challenge = request.challenge.verify(
            "challenge",
            &hex::encode(self.key.verifying_key().as_bytes()),
            4096,
        )?;
        ensure!(
            challenge.origin == self.config.origin
                && challenge.boot == self.boot
                && challenge.control_key == signed.key
                && challenge.expires_boot_ms > boot_ms()?
                && challenge.expires_boot_ms <= boot_ms()?.saturating_add(30000)
                && protocol::identifier(&challenge.nonce),
            "AdmissionChallengeExpired"
        );
        Ok((challenge, request))
    }
    fn retained(&self, c: &Challenge) -> Result<Claim> {
        let claim = self
            .store
            .state()?
            .claim(&c.attempt, &c.control_key, &c.intent_digest)?
            .ok_or_else(|| anyhow::anyhow!("AdmissionClaimAbsent"))?;
        ensure!(
            claim.native_claim == c.native_claim,
            "AdmissionClaimChanged"
        );
        Ok(claim.clone())
    }
    fn save(&mut self, claim: Claim) -> Result<()> {
        self.store.transact(|s| {
            let old = s
                .claims
                .iter_mut()
                .find(|c| c.native_claim == claim.native_claim)
                .ok_or_else(|| anyhow::anyhow!("AdmissionClaimAbsent"))?;
            *old = claim;
            Ok(())
        })
    }
    fn begin_native(&mut self, mut claim: Claim, stop: &AtomicBool) -> Result<Response> {
        let native=self.config.native.call(json!({"operation":"challenge","claim":claim.native_claim,"requestDigest":claim.intent_digest,"roles":claim.intent.roles,"applicationBinding":claim.intent.application_binding()?}),stop)?;
        match status(&native)? {
            "challenge" => {
                let challenge = field(&native, "challenge")?.to_owned();
                let binding = native
                    .get("binding")
                    .ok_or_else(|| anyhow::anyhow!("native claim binding absent"))?
                    .clone();
                ensure!(
                    binding.get("claim").and_then(Value::as_str) == Some(&claim.native_claim)
                        && binding.get("requestDigest").and_then(Value::as_str)
                            == Some(&claim.intent_digest),
                    "native challenge differs from reservation"
                );
                if let Some(old) = &claim.native_binding {
                    ensure!(old == &binding, "native slot generation changed");
                }
                claim.native_binding = Some(binding);
                claim.challenge = Some(challenge.clone());
                claim.challenge_expires_ms = native.get("expiresMs").and_then(Value::as_u64);
                claim.phase = Phase::Challenged;
                self.save(claim)?;
                Ok(Response::NativeChallenge { challenge })
            }
            "ready" => self.native_ready(claim, native, stop),
            "pending" => Ok(Response::Pending {
                code: "NativeAdmissionPending".into(),
            }),
            "refused" => Ok(Response::Refused {
                code: "NativeAdmissionRefused".into(),
            }),
            _ => anyhow::bail!("unsupported native admission response"),
        }
    }
    fn native_ready(
        &mut self,
        mut claim: Claim,
        native: Value,
        stop: &AtomicBool,
    ) -> Result<Response> {
        ensure!(status(&native)? == "ready", "NativeAdmissionPending");
        let binding = native
            .get("binding")
            .ok_or_else(|| anyhow::anyhow!("native binding absent"))?;
        ensure!(
            binding.get("claim").and_then(Value::as_str) == Some(&claim.native_claim)
                && binding.get("requestDigest").and_then(Value::as_str)
                    == Some(&claim.intent_digest)
                && claim.native_binding.as_ref().is_none_or(|b| b == binding),
            "native result changed its binding"
        );
        let principals = native
            .get("principals")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("native principals absent"))?;
        ensure!(
            principals.len() == claim.intent.roles.len()
                && principals.iter().zip(&claim.intent.roles).all(|(p, r)| p
                    .get("role")
                    .and_then(Value::as_u64)
                    == Some(r.role)
                    && p.get("member").and_then(Value::as_str) == Some(&r.member)
                    && p.get("relay").and_then(Value::as_str) == Some(&r.relay)),
            "certified native principals differ from join intent"
        );
        claim.native_binding = Some(binding.clone());
        claim.phase = if claim.hrc_result.is_some() || claim.intent.hrc.is_none() {
            Phase::Ready
        } else {
            Phase::NativeReady
        };
        self.save(claim.clone())?;
        if claim.intent.hrc.is_none() || claim.hrc_result.is_some() {
            return Ok(Response::Ready {
                native,
                hrc: claim.hrc_result,
            });
        }
        {
            let request = claim.intent.hrc.as_ref().unwrap().request.clone();
            let mut action = request;
            action
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("invalid HRC extension"))?
                .insert("operation".into(), json!("prepare"));
            let hrc = self
                .config
                .hrc
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("HRC extension unavailable"))?
                .call(action, stop)?;
            if status(&hrc)? == "complete" {
                ensure!(
                    hrc.get("claimId").and_then(Value::as_str) == Some(&claim.intent.attempt),
                    "HRC outcome differs from attempt"
                );
                claim.hrc_result = Some(hrc);
                claim.phase = Phase::Ready;
                self.save(claim.clone())?;
                return Ok(Response::Ready {
                    native,
                    hrc: claim.hrc_result,
                });
            }
            if status(&hrc)? == "refused" {
                return Ok(Response::Refused {
                    code: hrc
                        .get("code")
                        .and_then(Value::as_str)
                        .filter(|s| s.len() <= 64 && s.bytes().all(|c| c.is_ascii_alphanumeric()))
                        .unwrap_or("HrcAdmissionRefused")
                        .into(),
                });
            }
            ensure!(
                status(&hrc)? == "prepared"
                    && hrc.get("claimId").and_then(Value::as_str) == Some(&claim.intent.attempt),
                "HRC preparation differs from attempt"
            );
            claim.hrc_invitation = Some(hrc);
            self.save(claim.clone())?;
        }
        Ok(Response::NativeReady {
            result: field(&native, "result")?.into(),
            hrc: claim.hrc_invitation,
        })
    }
    fn recover(&mut self, claim: Claim, stop: &AtomicBool) -> Result<Response> {
        if matches!(claim.phase, Phase::Revoking | Phase::Retired) {
            return Ok(Response::Refused {
                code: "ParticipantRemoved".into(),
            });
        }
        if claim.native_binding.is_none() {
            return self.begin_native(claim, stop);
        }
        let native = self.config.native.call(
            json!({"operation":"status","binding":claim.native_binding}),
            stop,
        )?;
        match status(&native)? {
            "ready" => self.native_ready(claim, native, stop),
            "challenge" | "pending" => self.begin_native(claim, stop),
            "retired" | "refused" => Ok(Response::Refused {
                code: "NativeAccessUnavailable".into(),
            }),
            _ => anyhow::bail!("unsupported native recovery response"),
        }
    }
    fn operator_authorization(
        &self,
        intent: &protocol::Intent,
        stop: &AtomicBool,
    ) -> Result<store::OperatorAuthorization> {
        let request = &intent
            .hrc
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("OperatorConsentRequired"))?
            .request;
        ensure!(
            request
                .pointer("/classification/kind")
                .and_then(Value::as_str)
                == Some("agent"),
            "OperatorConsentRequired"
        );
        let operator = request
            .pointer("/classification/operator")
            .ok_or_else(|| anyhow::anyhow!("OperatorConsentRequired"))?
            .clone();
        let binding = self
            .config
            .hrc
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("HRC extension unavailable"))?;
        let description = binding.call(json!({"operation":"describe"}), stop)?;
        ensure!(
            status(&description)? == "described"
                && description
                    .pointer("/policy/enabled")
                    .and_then(Value::as_bool)
                    == Some(true)
                && description
                    .pointer("/policy/agentsEnabled")
                    .and_then(Value::as_bool)
                    == Some(true),
            "AgentParticipationDisabled"
        );
        let maximum = description
            .pointer("/policy/maxAgentsPerOperator")
            .and_then(Value::as_u64)
            .filter(|n| (1..=8).contains(n))
            .ok_or_else(|| anyhow::anyhow!("invalid operator quota"))?
            as usize;
        let mut action = request.clone();
        action
            .as_object_mut()
            .unwrap()
            .insert("operation".into(), json!("prepare"));
        let checked = binding.call(action, stop)?;
        ensure!(
            status(&checked)? == "prepared"
                && checked.get("claimId").and_then(Value::as_str) == Some(&intent.attempt),
            "OperatorConsentRequired"
        );
        Ok(store::OperatorAuthorization { operator, maximum })
    }
    pub fn request(&mut self, signed: Signed, stop: &AtomicBool) -> Result<Response> {
        let (challenge, request) = self.authenticated(&signed)?;
        if let Some(receipt) = self.store.state()?.retirement(
            &challenge.attempt,
            &challenge.control_key,
            &challenge.intent_digest,
        )? {
            if let protocol::Action::AcknowledgeRemoval { result_digest } = &request.action {
                self.store
                    .transact(|s| s.acknowledge_retirement(&receipt, result_digest))?;
                return Ok(Response::RemovalAcknowledged);
            }
            return Ok(Response::Removed {
                result: receipt.result,
            });
        }
        match request.action {
            protocol::Action::AcknowledgeRemoval { .. } => Ok(Response::Refused {
                code: "RemovalReceiptAbsent".into(),
            }),
            protocol::Action::Start { intent, admission } => {
                ensure!(
                    intent.attempt == challenge.attempt
                        && intent.control_key == challenge.control_key
                        && intent.digest()? == challenge.intent_digest,
                    "join intent differs from challenge"
                );
                let existing = self
                    .store
                    .state()?
                    .claim(
                        &intent.attempt,
                        &intent.control_key,
                        &challenge.intent_digest,
                    )?
                    .is_some();
                let native = self.native_description(stop)?;
                if !existing {
                    ensure!(
                        protocol::digest_value(&self.metadata(&native, stop)?)?
                            == intent.descriptor_digest,
                        "ServerPermissionsChanged"
                    );
                    ensure!(
                        intent.roles.iter().all(|r| if r.role == 0 {
                            self.config.reader
                        } else {
                            self.config.hrc.is_some()
                        }),
                        "SelectedServiceUnavailable"
                    );
                }
                let floor = native
                    .get("claimFloor")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow::anyhow!("native claim floor absent"))?;
                let agent = intent.hrc.as_ref().is_some_and(|h| {
                    h.request
                        .pointer("/classification/kind")
                        .and_then(Value::as_str)
                        == Some("agent")
                });
                let operator =
                    if !existing && (agent || matches!(admission, protocol::Admission::Operator)) {
                        Some(self.operator_authorization(&intent, stop)?)
                    } else {
                        None
                    };
                let claim = self.store.transact(|s| {
                    s.reserve(
                        intent,
                        &challenge.native_claim,
                        &admission,
                        wall_ms()?,
                        floor,
                        operator.as_ref(),
                    )
                })?;
                if claim.phase == Phase::Reserved {
                    self.begin_native(claim, stop)
                } else {
                    self.recover(claim, stop)
                }
            }
            protocol::Action::Status => self.recover(self.retained(&challenge)?, stop),
            protocol::Action::AcceptNative { acceptance } => {
                ensure!(
                    protocol::artifact(&acceptance, 16384),
                    "invalid native acceptance"
                );
                let claim = self.retained(&challenge)?;
                if claim.phase != Phase::Challenged {
                    return self.recover(claim, stop);
                }
                let native=self.config.native.call(json!({"operation":"enrol","challenge":claim.challenge,"acceptance":acceptance}),stop)?;
                match status(&native)? {
                    "ready" => self.native_ready(claim, native, stop),
                    "pending" => Ok(Response::Pending {
                        code: "NativeAdmissionPending".into(),
                    }),
                    "refused" => Ok(Response::Refused {
                        code: "NativeAdmissionRefused".into(),
                    }),
                    _ => anyhow::bail!("unsupported native enrolment response"),
                }
            }
            protocol::Action::AcceptHrc { registration } => {
                let mut claim = self.retained(&challenge)?;
                ensure!(
                    claim.intent.hrc.is_some()
                        && claim.hrc_invitation.is_some()
                        && matches!(claim.phase, Phase::NativeReady | Phase::Ready),
                    "HRC enrolment is not prepared"
                );
                let response=self.config.hrc.as_ref().unwrap().call(json!({"operation":"enrol","claimId":claim.intent.attempt,"registration":registration}),stop)?;
                ensure!(
                    status(&response)? == "complete"
                        && response.get("claimId").and_then(Value::as_str)
                            == Some(&claim.intent.attempt),
                    "HRC enrolment not complete"
                );
                if let Some(old) = &claim.hrc_result {
                    ensure!(old == &response, "HRC retained outcome changed");
                }
                claim.hrc_result = Some(response);
                claim.phase = Phase::Ready;
                self.save(claim.clone())?;
                self.recover(claim, stop)
            }
            protocol::Action::RenewalChallenge => {
                let claim = self.retained(&challenge)?;
                ensure!(
                    claim.phase == Phase::Ready,
                    "participant is not ready for renewal"
                );
                let native = self.config.native.call(
                    json!({"operation":"renewalChallenge","binding":claim.native_binding}),
                    stop,
                )?;
                ensure!(status(&native)? == "challenge", "NativeRenewalUnavailable");
                Ok(Response::RenewalChallenge {
                    challenge: field(&native, "challenge")?.into(),
                })
            }
            protocol::Action::Renew { proof } => {
                let claim = self.retained(&challenge)?;
                ensure!(
                    claim.phase == Phase::Ready && protocol::artifact(&proof, 16384),
                    "invalid native renewal"
                );
                let native = self.config.native.call(
                    json!({"operation":"renew","binding":claim.native_binding,"proof":proof}),
                    stop,
                )?;
                self.native_ready(claim, native, stop)
            }
        }
    }
    pub fn edge(
        &mut self,
        request: super::edge::RegistrarRequest,
        stop: &AtomicBool,
    ) -> Result<Value> {
        ensure!(
            request.format == "HyperNetAdmissionEdge/1",
            "unsupported admission edge format"
        );
        self.budget.admit(&request.source)?;
        match request.action {
            super::edge::Operation::Descriptor => Ok(serde_json::to_value(self.descriptor(stop)?)?),
            super::edge::Operation::Challenge { body } => Ok(serde_json::to_value(
                self.challenge(serde_json::from_value(body)?, stop)?,
            )?),
            super::edge::Operation::Claim { body } => Ok(serde_json::to_value(
                self.request(serde_json::from_value(body)?, stop)?,
            )?),
        }
    }
}
