// SPDX-License-Identifier: MIT
// A local candidate signs only its own prepared roles and retains an exact claim before acceptance.
use super::*;
use std::{
    ffi::OsStr,
    time::{SystemTime, UNIX_EPOCH},
};
const STATE: &str = "Candidate.json";
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalRole {
    request: RoleRequest,
    profile: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct State {
    format: String,
    bootstrap: String,
    expected_key: String,
    policy: String,
    minimum_route: u64,
    roles: Vec<LocalRole>,
    binding: Option<Claim>,
    application_binding: Option<String>,
    retired: bool,
    retirement_proof: Option<String>,
    profiles: Vec<RoleProfile>,
}
fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn load(directory: &Path) -> Result<Option<State>> {
    let bytes = match files::read_single(&directory.join(STATE), MAX_INPUT_BYTES, true) {
        Ok(bytes) => bytes,
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    let s: State = serde_json::from_slice(&bytes)?;
    ensure!(
        s.format == "HyperNetNativeCandidate/1"
            && !s.roles.is_empty()
            && s.roles.len() <= MAX_ROLES,
        "invalid retained native candidate"
    );
    Ok(Some(s))
}
fn save(directory: &Path, state: &State) -> Result<()> {
    files::atomic_at(
        &files::private_directory(directory)?,
        OsStr::new(STATE),
        &serde_json::to_vec(state)?,
        true,
    )
}
fn inspect(
    bootstrap: &str,
    proof: &str,
    expected: Option<&str>,
) -> Result<(trust_bootstrap::Verified, native::Disclosure)> {
    use sha2::Digest as _;
    let b = bytes(bootstrap)?;
    let bootstrap = trust_bootstrap::inspect(&b, true)?;
    let d = client::Certificate::verify(&bootstrap, &bytes(proof)?, now()?)?;
    let scope = bootstrap.descriptor().scope();
    let governance = crate::authority_governance::Governance::parse(
        scope.network,
        scope.incarnation,
        &d.records,
    )?;
    d.policy.authorise(&governance, scope.network, now()?)?;
    let key = hex::encode(Sha256::digest(d.policy.descriptor));
    ensure!(
        d.policy.enabled && crate::authority_membership::current(now()?, d.policy.validity),
        "server admission policy is withdrawn or expired"
    );
    if let Some(expected) = expected {
        ensure!(
            expected == key,
            "server descriptor key differs from pinned link"
        );
    }
    Ok((bootstrap, d))
}
fn local_context(
    state: &State,
    proof: &str,
    fresh: bool,
) -> Result<(trust_bootstrap::Verified, native::Disclosure)> {
    use sha2::Digest as _;
    let bootstrap = trust_bootstrap::inspect(&bytes(&state.bootstrap)?, true)?;
    let d = if fresh {
        client::Certificate::verify(&bootstrap, &bytes(proof)?, now()?)?
    } else {
        client::Certificate::authenticate(&bootstrap, &bytes(proof)?)?
    };
    ensure!(
        hex::encode(d.policy.reference.id) == state.policy
            && hex::encode(Sha256::digest(d.policy.descriptor)) == state.expected_key,
        "native proof has another retained server purpose"
    );
    if let Some(slot) = &d.selected {
        ensure!(
            slot.roles.len() == state.roles.len(),
            "native proof changes local role count"
        );
        for (remote, local) in slot.roles.iter().zip(&state.roles) {
            ensure!(
                remote.role == local.request.role
                    && hex::encode(remote.member) == local.request.member
                    && hex::encode(remote.relay) == local.request.relay
                    && hex::encode(&remote.request) == local.request.request,
                "native proof changes prepared role identities"
            );
        }
    }
    Ok((bootstrap, d))
}
fn prepared(state: &State) -> Result<Response> {
    use sha2::Digest as _;
    let roles = state
        .roles
        .iter()
        .map(|r| r.request.clone())
        .collect::<Vec<_>>();
    let digest = hex::encode(Sha256::digest(serde_json::to_vec(&roles)?));
    Ok(Response::Prepared {
        roles,
        candidate_digest: digest,
    })
}
pub(super) fn run(
    directory: &Path,
    clock: &Path,
    adopt: &[String],
    request: CandidateRequest,
) -> Result<Response> {
    if !directory.exists() {
        files::create_directory(directory)?;
    }
    let root = files::private_directory(directory)?;
    ensure!(
        directory.is_absolute() && directory.canonicalize()? == directory,
        "candidate root must be canonical and private"
    );
    let _lock = files::profile_lock(&root, OsStr::new(STATE))?;
    let existing = load(directory)?;
    match request {
        CandidateRequest::Inspect {
            bootstrap,
            proof,
            expected_key,
        } => {
            use sha2::Digest as _;
            let (b, d) = inspect(&bootstrap, &proof, expected_key.as_deref())?;
            if let Some(s) = &existing {
                ensure!(
                    s.bootstrap == bootstrap
                        && s.expected_key == hex::encode(Sha256::digest(d.policy.descriptor)),
                    "saved server trust differs"
                );
            }
            Ok(Response::Descriptor {
                bootstrap,
                proof,
                policy_generation: d.policy.reference.generation,
                current_key: hex::encode(Sha256::digest(d.policy.descriptor)),
                signing_key: hex::encode(d.policy.descriptor),
                network: hex::encode(b.descriptor().scope().network),
                incarnation: hex::encode(b.descriptor().scope().incarnation),
                policy: hex::encode(d.policy.reference.id),
                claim_floor: d.claim_floor,
                access_end: d.policy.validity.1,
                maximum_participants: d.policy.maximum_slots,
                roles: d.policy.templates.iter().map(|t| t.role).collect(),
            })
        }
        CandidateRequest::Prepare {
            bootstrap,
            proof,
            expected_key,
            roles,
            minimum_route,
        } => {
            let (_, d) = inspect(&bootstrap, &proof, Some(&expected_key))?;
            ensure!(
                !roles.is_empty()
                    && roles.len() <= MAX_ROLES
                    && roles.windows(2).all(|x| x[0] < x[1])
                    && roles.iter().all(|r| d.policy.template(*r).is_ok()),
                "selected roles exceed server policy"
            );
            if let Some(s) = existing {
                ensure!(
                    s.bootstrap == bootstrap
                        && s.expected_key == expected_key
                        && s.policy == hex::encode(d.policy.reference.id)
                        && s.minimum_route == minimum_route
                        && s.roles.iter().map(|r| r.request.role).collect::<Vec<_>>() == roles,
                    "candidate already binds another preparation"
                );
                return prepared(&s);
            }
            let role_root = directory.join("Roles");
            if !role_root.exists() {
                files::create_directory(&role_root)?;
            }
            files::private_directory(&role_root)?;
            let mut adopted = std::collections::BTreeMap::new();
            for item in adopt {
                let (role, path) = item
                    .split_once('=')
                    .context("adopt profile requires ROLE=PROFILE")?;
                let role: u64 = role.parse()?;
                ensure!(
                    roles.contains(&role) && adopted.insert(role, PathBuf::from(path)).is_none(),
                    "adopt profile role differs or repeats"
                );
            }
            let mut prepared_roles = vec![];
            for role in roles {
                let private = role_root.join(role.to_string());
                if !private.exists() {
                    files::create_directory(&private)?;
                }
                let path = adopted
                    .remove(&role)
                    .unwrap_or_else(|| private.join("Profile.json"));
                let request = crate::networks::admission::prepare(
                    &path,
                    &bytes(&bootstrap)?,
                    &bytes(&proof)?,
                    minimum_route,
                    role,
                )?;
                prepared_roles.push(LocalRole {
                    request,
                    profile: path,
                });
            }
            let s = State {
                format: "HyperNetNativeCandidate/1".into(),
                bootstrap,
                expected_key,
                policy: hex::encode(d.policy.reference.id),
                minimum_route,
                roles: prepared_roles,
                binding: None,
                application_binding: None,
                retired: false,
                retirement_proof: None,
                profiles: vec![],
            };
            save(directory, &s)?;
            prepared(&s)
        }
        CandidateRequest::AcceptChallenge {
            challenge,
            application_binding,
            request_digest,
            claim,
        } => {
            let mut s = existing.context("prepare local candidate roles first")?;
            let (bootstrap, d) = local_context(&s, &challenge, true)?;
            let slot = d.selected.context("native challenge has no candidate")?;
            ensure!(
                slot.state == 0
                    && slot.challenge_until > now()?.saturating_add(1250)
                    && slot.application == id(&application_binding)?
                    && slot.request == id(&request_digest)?
                    && slot.claim == id(&claim)?,
                "native challenge differs from the exact locally selected request"
            );
            let bound = binding(&slot);
            if let Some(old) = &s.binding {
                if !s.retired {
                    ensure!(
                        *old == bound
                            && s.application_binding.as_deref() == Some(&application_binding),
                        "candidate is already bound to another claim"
                    );
                } else {
                    ensure!(
                        native::claim_ordinal(&slot.claim)?
                            > native::claim_ordinal(&id(&old.claim)?)?,
                        "retired candidate claim cannot be reused"
                    );
                }
            }
            s.binding = Some(bound);
            s.application_binding = Some(application_binding);
            s.retired = false;
            s.retirement_proof = None;
            s.profiles.clear();
            save(directory, &s)?;
            let scope = bootstrap.descriptor().scope();
            let signatures = s
                .roles
                .iter()
                .map(|r| {
                    crate::networks::admission::acceptance(
                        &r.profile,
                        &slot,
                        scope.network,
                        scope.incarnation,
                    )
                    .map(V::Bytes)
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Response::Acceptance {
                acceptance: hex::encode(wire::encode(&V::Array(signatures))?),
            })
        }
        CandidateRequest::RenewalProof { challenge } => {
            let s = existing.context("candidate not prepared")?;
            let (bootstrap, d) = local_context(&s, &challenge, true)?;
            let slot = d.selected.context("renewal proof has no slot")?;
            exact_binding(&slot, s.binding.as_ref().context("candidate not bound")?)?;
            ensure!(
                !s.retired
                    && slot.state == 2
                    && slot.challenge_until > now()?.saturating_add(1250)
                    && s.application_binding.as_deref() == Some(&hex::encode(slot.application)),
                "renewal differs from the retained application acceptance"
            );
            let scope = bootstrap.descriptor().scope();
            let signatures = s
                .roles
                .iter()
                .map(|r| {
                    crate::networks::admission::acceptance(
                        &r.profile,
                        &slot,
                        scope.network,
                        scope.incarnation,
                    )
                    .map(V::Bytes)
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Response::Acceptance {
                acceptance: hex::encode(wire::encode(&V::Array(signatures))?),
            })
        }
        CandidateRequest::AcceptResult { result, roles } => {
            let mut s = existing.context("candidate not prepared")?;
            // A retired claim is terminal; its certified historical receipt remains valid after its finite read window.
            let (_, historical) = local_context(&s, &result, false)?;
            let slot = historical
                .selected
                .as_ref()
                .context("native result has no slot")?;
            let expected = s.binding.as_ref().context("candidate not bound")?.clone();
            exact_binding(slot, &expected)?;
            ensure!(
                s.application_binding.as_deref() == Some(&hex::encode(slot.application)),
                "native result changes accepted application binding"
            );
            if slot.state == 3 {
                s.retired = true;
                s.retirement_proof = Some(result.clone());
                s.profiles.clear();
                save(directory, &s)?;
                return Ok(Response::Retired {
                    binding: expected,
                    result,
                });
            }
            let (_, d) = local_context(&s, &result, true)?;
            ensure!(
                d.selected.as_ref().is_some_and(|slot| slot.active())
                    && d.policy.enabled
                    && !d.domains.is_empty(),
                "native result does not contain current enrolled routes"
            );
            if crate::authority_clock::Source::select(clock, None, None)?
                .health()
                .is_err()
            {
                return Ok(Response::Pending {
                    binding: Some(expected),
                    code: "ClockUnavailable".into(),
                });
            }
            let selected = if let Some(roles) = roles {
                ensure!(
                    s.profiles.len() == s.roles.len()
                        && !roles.is_empty()
                        && roles.windows(2).all(|r| r[0] < r[1])
                        && roles
                            .iter()
                            .all(|role| s.roles.iter().any(|r| r.request.role == *role)),
                    "partial refresh requires previously installed exact roles"
                );
                roles
            } else {
                s.roles.iter().map(|r| r.request.role).collect()
            };
            let mut profiles = s.profiles.clone();
            for role in s
                .roles
                .iter()
                .filter(|r| selected.contains(&r.request.role))
            {
                let profile = crate::networks::admission::install(
                    &role.profile,
                    clock,
                    &d,
                    role.request.role,
                    &expected,
                )?;
                profiles.retain(|p| p.role != role.request.role);
                profiles.push(profile);
            }
            profiles.sort_by_key(|p| p.role);
            s.profiles = profiles;
            save(directory, &s)?;
            Ok(Response::Installed {
                binding: expected,
                profiles: s.profiles,
            })
        }
        CandidateRequest::Status => {
            let s = existing.context("candidate not prepared")?;
            if s.retired {
                return Ok(Response::Retired {
                    binding: s.binding.context("retired candidate binding absent")?,
                    result: s.retirement_proof.context("retirement receipt absent")?,
                });
            }
            if let Some(binding) = s.binding {
                if s.profiles.len() == s.roles.len() {
                    return Ok(Response::Installed {
                        binding,
                        profiles: s.profiles,
                    });
                }
                return Ok(Response::Pending {
                    binding: Some(binding),
                    code: "CandidateAccepted".into(),
                });
            }
            prepared(&s)
        }
    }
}
