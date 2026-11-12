// SPDX-License-Identifier: MIT
// The registrar chooses only certified bounded slots and never accepts caller-selected native grants.
use super::*;
use rand::{RngCore, rngs::OsRng};
fn random() -> [u8; 32] {
    let mut out = [0; 32];
    OsRng.fill_bytes(&mut out);
    out
}
fn signed_roles(
    roles: Vec<RoleRequest>,
    scope: &crate::authority_proof::Scope,
) -> Result<Vec<native::Role>> {
    ensure!(
        !roles.is_empty()
            && roles.len() <= MAX_ROLES
            && roles.windows(2).all(|x| x[0].role < x[1].role),
        "roles must be sorted and unique"
    );
    roles
        .into_iter()
        .map(|r| {
            native::Role::parse(
                &V::Array(vec![
                    V::Uint(r.role),
                    V::Bytes(id(&r.member)?.to_vec()),
                    V::Bytes(id(&r.relay)?.to_vec()),
                    V::Bytes(bytes(&r.request)?),
                ]),
                scope.network,
                scope.incarnation,
            )
        })
        .collect()
}
fn response(d: native::Disclosure, proof: Vec<u8>) -> Result<Response> {
    let slot = d.selected.context("native claim is unavailable")?;
    Ok(match slot.state {
        0 | 2 => Response::Challenge {
            binding: binding(&slot),
            challenge: hex::encode(proof),
            expires_ms: slot.challenge_until,
        },
        1 if !d.domains.is_empty() && d.policy.enabled => Response::Ready {
            binding: binding(&slot),
            result: hex::encode(proof),
            principals: slot
                .roles
                .iter()
                .map(|r| Principal {
                    role: r.role,
                    member: hex::encode(r.member),
                    relay: hex::encode(r.relay),
                })
                .collect(),
        },
        1 => Response::Pending {
            binding: Some(binding(&slot)),
            code: "RenewalRequired".into(),
        },
        3 => Response::Retired {
            binding: binding(&slot),
            result: hex::encode(proof),
        },
        _ => unreachable!(),
    })
}
fn transition(
    c: &mut Connection,
    d: &native::Disclosure,
    kind: native::Transition,
    acceptance: Vec<Vec<u8>>,
) -> Result<()> {
    let old = d.selected.as_ref().context("native claim absent")?;
    let scope = c.store.descriptor().scope().clone();
    let mut snapshot = c.snapshot(
        &d.records,
        &d.policy,
        Some(old),
        kind != native::Transition::Retire,
    )?;
    let mut next = old.clone();
    let mut legacy = vec![];
    match kind {
        native::Transition::Enrol | native::Transition::Adopt => {
            next.state = 1;
            next.challenge_until = 0;
            let g = crate::authority_governance::Governance::parse(
                scope.network,
                scope.incarnation,
                &d.records,
            )?;
            let parent = wire::decode(g.record_bytes(102, d.policy.parent.id)?)?;
            let tier = crate::authority_membership::version(&parent.array(17)?[9])?;
            if kind == native::Transition::Adopt {
                for reference in &d.policy.legacy {
                    if let Ok(bytes) = g.record_bytes(125, reference.id) {
                        let v = wire::decode(bytes)?;
                        let f = v.array(12)?;
                        if old
                            .roles
                            .iter()
                            .any(|r| f[7].fixed::<32>().ok() == Some(r.member))
                        {
                            ensure!(
                                !f[9].boolean()? && wire::digest(bytes) == reference.digest,
                                "legacy membership already retired or changed"
                            );
                            legacy.push(bytes.to_vec());
                            snapshot.references.push(reference.clone());
                        }
                    }
                }
                snapshot
                    .references
                    .sort_by_key(crate::authority_proof::VersionRef::index);
                snapshot.references.dedup();
                let mut fields = snapshot.value.array(2)?.to_vec();
                fields[1] = V::Array(snapshot.references.iter().map(reference).collect());
                snapshot.value = V::Array(fields);
            }
            next.legacy_streams = legacy
                .iter()
                .map(|bytes| wire::decode(bytes)?.array(12)?[7].fixed::<32>())
                .collect::<Result<Vec<_>>>()?;
            next.legacy_streams.sort();
            next.material = native::enrol_material(
                &d.policy,
                old,
                &tier,
                &snapshot,
                scope.network,
                scope.incarnation,
            )?;
        }
        native::Transition::RenewalChallenge => {
            next.state = 2;
            next.challenge_until = c
                .clock
                .health()?
                .observe()?
                .wall_ms
                .saturating_add(native::CHALLENGE_MS - 1250);
            next.nonce = random();
        }
        native::Transition::Renew => {
            next.state = 1;
            next.challenge_until = 0;
        }
        native::Transition::Retire => {
            next.state = 3;
            next.challenge_until = 0;
        }
        _ => anyhow::bail!("unsupported registrar transition"),
    }
    let next = record(
        native::SLOT,
        old.reference.id,
        next.payload(),
        &snapshot,
        &scope,
        Some(&old.bytes),
    )?;
    c.apply(native::Operation {
        transition: kind,
        policy: d.policy.bytes.clone(),
        previous: Some(old.bytes.clone()),
        next,
        acceptance,
        legacy,
        snapshot,
    })
}
pub(super) fn run(config: &Configuration, request: RegistrarRequest) -> Result<Response> {
    let mut c = Connection::open(&config.location(), &config.key_file, &config.socket)?;
    let policy = id(&config.policy)?;
    let scope = c.store.descriptor().scope().clone();
    let (describe, proof) = c.query(policy, None)?;
    ensure!(
        describe.policy.registrar == c.key.verifying_key().to_bytes(),
        "configuration key is not the certified registrar"
    );
    if matches!(request, RegistrarRequest::Describe) {
        use sha2::Digest as _;
        return Ok(Response::Descriptor {
            bootstrap: hex::encode(files::read_single(&config.bootstrap, wire::MAXIMUM, true)?),
            proof: hex::encode(proof),
            policy_generation: describe.policy.reference.generation,
            current_key: hex::encode(Sha256::digest(describe.policy.descriptor)),
            signing_key: hex::encode(describe.policy.descriptor),
            network: hex::encode(scope.network),
            incarnation: hex::encode(scope.incarnation),
            policy: config.policy.clone(),
            claim_floor: describe.claim_floor,
            access_end: describe.policy.validity.1,
            maximum_participants: describe.policy.maximum_slots,
            roles: describe.policy.templates.iter().map(|t| t.role).collect(),
        });
    }
    match request {
        RegistrarRequest::Challenge {
            claim,
            request_digest,
            roles,
            application_binding,
        } => {
            let claim = id(&claim)?;
            let request = id(&request_digest)?;
            let application = id(&application_binding)?;
            let roles = signed_roles(roles, &scope)?;
            let (d, proof) = c.query(policy, Some(claim))?;
            if let Some(old) = d.selected.as_ref().filter(|s| s.claim == claim) {
                ensure!(
                    old.request == request
                        && old.application == application
                        && V::Array(old.roles.iter().map(native::Role::value).collect())
                            == V::Array(roles.iter().map(native::Role::value).collect()),
                    "native claim replay changes its exact request"
                );
                if old.state == 0
                    && old.challenge_until
                        <= c.clock.health()?.observe()?.wall_ms.saturating_add(1250)
                {
                    transition(&mut c, &d, native::Transition::Retire, vec![])?;
                    let (d, proof) = c.query(policy, Some(claim))?;
                    return response(d, proof);
                }
                return response(d, proof);
            }
            ensure!(
                native::claim_ordinal(&claim)? > d.claim_floor,
                "native claim ordinal already retired"
            );
            let slot = d.available.context("native member capacity reached")?;
            let old = d.selected.as_ref();
            let snapshot = c.snapshot(&d.records, &d.policy, old, true)?;
            let payload = V::Array(vec![
                V::Bytes(policy.to_vec()),
                V::Uint(slot),
                V::Uint(old.map_or(Ok(1), |s| {
                    s.assignment
                        .checked_add(1)
                        .context("slot assignment exhausted")
                })?),
                V::Bytes(claim.to_vec()),
                V::Bytes(request.to_vec()),
                V::Bytes(application.to_vec()),
                V::Uint(0),
                V::Uint(
                    c.clock
                        .health()?
                        .observe()?
                        .wall_ms
                        .saturating_add(native::CHALLENGE_MS - 1250),
                ),
                V::Array(roles.iter().map(native::Role::value).collect()),
                V::Bytes(random().to_vec()),
                V::Uint(1),
                V::Array(old.map_or(vec![], |s| {
                    s.material.iter().map(|x| V::Bytes(x.clone())).collect()
                })),
                V::Array(vec![]),
            ]);
            let next = record(
                native::SLOT,
                native::identifier(policy, slot, 0, 0)?,
                payload,
                &snapshot,
                &scope,
                old.map(|s| s.bytes.as_slice()),
            )?;
            c.apply(native::Operation {
                transition: native::Transition::Reserve,
                policy: d.policy.bytes.clone(),
                previous: old.map(|s| s.bytes.clone()),
                next,
                acceptance: vec![],
                legacy: vec![],
                snapshot,
            })?;
            let (d, proof) = c.query(policy, Some(claim))?;
            response(d, proof)
        }
        RegistrarRequest::Enrol {
            challenge,
            acceptance,
        }
        | RegistrarRequest::Adopt {
            challenge,
            acceptance,
        } => {
            let historical = client::Certificate::authenticate(&c.bootstrap, &bytes(&challenge)?)?;
            let offered = historical
                .selected
                .context("enrolment proof has no candidate")?;
            ensure!(offered.policy == policy, "enrolment policy differs");
            let (d, proof) = c.query(policy, Some(offered.claim))?;
            let current = d.selected.as_ref().context("native claim absent")?;
            if current.active() {
                ensure!(
                    current.claim == offered.claim && current.request == offered.request,
                    "enrolment replay differs"
                );
                return response(d, proof);
            }
            ensure!(
                current.reference == offered.reference,
                "candidate challenge changed"
            );
            let acceptance = wire::decode(&bytes(&acceptance)?)?
                .list(MAX_ROLES)?
                .iter()
                .map(|x| Ok(x.bytes()?.to_vec()))
                .collect::<Result<Vec<_>>>()?;
            // Only owner-rostered existing manual memberships select adoption.
            let adoption = d.records.iter().any(|bytes| {
                wire::decode(bytes).is_ok_and(|v| {
                    v.list(32).is_ok_and(|f| {
                        f[0].uint().ok() == Some(125)
                            && d.policy
                                .legacy
                                .iter()
                                .any(|r| f[6].fixed::<32>().ok() == Some(r.id))
                            && f[9].boolean().ok() == Some(false)
                            && offered
                                .roles
                                .iter()
                                .any(|r| f[7].fixed::<32>().ok() == Some(r.member))
                    })
                })
            });
            transition(
                &mut c,
                &d,
                if adoption {
                    native::Transition::Adopt
                } else {
                    native::Transition::Enrol
                },
                acceptance,
            )?;
            let (d, proof) = c.query(policy, Some(offered.claim))?;
            response(d, proof)
        }
        RegistrarRequest::Status { binding: expected } => {
            let (d, proof) = c.query(policy, Some(id(&expected.claim)?))?;
            exact_binding(
                d.selected.as_ref().context("native claim absent")?,
                &expected,
            )?;
            response(d, proof)
        }
        RegistrarRequest::RenewalChallenge { binding: expected } => {
            let (d, proof) = c.query(policy, Some(id(&expected.claim)?))?;
            let old = d.selected.as_ref().context("native claim absent")?;
            exact_binding(old, &expected)?;
            if old.state == 3 {
                return response(d, proof);
            }
            if old.state == 2
                && old.challenge_until > c.clock.health()?.observe()?.wall_ms.saturating_add(1250)
            {
                return response(d, proof);
            }
            transition(&mut c, &d, native::Transition::RenewalChallenge, vec![])?;
            let (d, proof) = c.query(policy, Some(id(&expected.claim)?))?;
            response(d, proof)
        }
        RegistrarRequest::Renew {
            binding: expected,
            proof,
        } => {
            let (d, current) = c.query(policy, Some(id(&expected.claim)?))?;
            let old = d.selected.as_ref().context("native claim absent")?;
            exact_binding(old, &expected)?;
            if old.state == 1 && !d.domains.is_empty() {
                return response(d, current);
            }
            let acceptance = wire::decode(&bytes(&proof)?)?
                .list(MAX_ROLES)?
                .iter()
                .map(|x| Ok(x.bytes()?.to_vec()))
                .collect::<Result<Vec<_>>>()?;
            transition(&mut c, &d, native::Transition::Renew, acceptance)?;
            let (d, proof) = c.query(policy, Some(id(&expected.claim)?))?;
            response(d, proof)
        }
        RegistrarRequest::Revoke {
            binding: expected,
            reason,
        } => {
            ensure!(
                !reason.is_empty() && reason.len() <= 256 && !reason.chars().any(char::is_control),
                "invalid retirement reason"
            );
            let (d, proof) = c.query(policy, Some(id(&expected.claim)?))?;
            let old = d.selected.as_ref().context("native claim absent")?;
            exact_binding(old, &expected)?;
            if old.state == 3 {
                return response(d, proof);
            }
            transition(&mut c, &d, native::Transition::Retire, vec![])?;
            let (d, proof) = c.query(policy, Some(id(&expected.claim)?))?;
            response(d, proof)
        }
        RegistrarRequest::Describe => unreachable!(),
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicySpec {
    id: String,
    parent: String,
    registrar: String,
    descriptor: String,
    maximum_slots: u64,
    validity: crate::trust_validity::Validity,
    relay: String,
    authority: String,
    templates: Vec<TemplateSpec>,
    #[serde(default)]
    legacy: Vec<String>,
    #[serde(default = "enabled")]
    enabled: bool,
}
fn enabled() -> bool {
    true
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TemplateSpec {
    role: u64,
    destination: String,
    application: Option<String>,
    page: Option<String>,
    limits: [u64; 4],
    connections: u64,
    bytes: u64,
    voucher_ms: u64,
}
pub(super) fn policy(online: domain_cli::Online, path: &Path) -> Result<()> {
    let spec: PolicySpec = serde_json::from_slice(&files::read_single(path, 65536, true)?)?;
    let mut c = Connection::open(&online.location, &online.key, &online.socket)?;
    let records = if spec.enabled {
        let context = crate::authority_inspection::ContextState::refresh_local(
            &c.bootstrap,
            &c.socket,
            id(&spec.parent)?,
            &c.key,
            &mut c.store,
            &mut c.session,
            || c.clock.health(),
        )?;
        context.current_records(&c.store)?
    } else {
        c.query(id(&spec.id)?, None)?;
        client::retained(&c.bootstrap, &c.store)?
    };
    let scope = c.store.descriptor().scope().clone();
    let g =
        crate::authority_governance::Governance::parse(scope.network, scope.incarnation, &records)?;
    let parent = g
        .versions()
        .into_iter()
        .find(|r| r.kind == 102 && id(&spec.parent).ok() == Some(r.id))
        .context("admission parent grant absent")?;
    let previous = g.admission().policies.get(&id(&spec.id)?);
    let legacy = spec
        .legacy
        .iter()
        .map(|id_text| {
            let id = id(id_text)?;
            if let Some(old) = previous.filter(|_| !spec.enabled) {
                old.legacy
                    .iter()
                    .find(|r| r.id == id)
                    .cloned()
                    .context("legacy membership absent from original policy")
            } else {
                g.versions()
                    .into_iter()
                    .find(|r| r.kind == 125 && r.id == id)
                    .context("legacy membership absent")
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let templates = spec
        .templates
        .into_iter()
        .map(|t| {
            Ok(native::Template {
                role: t.role,
                destination: id(&t.destination)?,
                application: t.application.as_deref().map(id).transpose()?,
                page: t.page.as_deref().map(id).transpose()?,
                limits: t.limits,
                connections: t.connections,
                bytes: t.bytes,
                voucher_ms: t.voucher_ms,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let p = native::Policy {
        reference: crate::authority_proof::VersionRef {
            kind: native::POLICY,
            id: id(&spec.id)?,
            generation: 1,
            digest: [0; 32],
        },
        owner: c.key.verifying_key().to_bytes(),
        parent,
        registrar: id(&spec.registrar)?,
        descriptor: id(&spec.descriptor)?,
        enabled: spec.enabled,
        maximum_slots: spec.maximum_slots,
        validity: spec.validity,
        relay: id(&spec.relay)?,
        authority: id(&spec.authority)?,
        templates,
        legacy,
        bytes: vec![],
    };
    let mut snapshot = c.snapshot(&records, &p, None, spec.enabled)?;
    if let Some(old) = previous {
        snapshot.references.push(old.reference.clone());
        snapshot
            .references
            .sort_by_key(crate::authority_proof::VersionRef::index);
        snapshot.references.dedup();
        let mut v = snapshot.value.array(2)?.to_vec();
        v[1] = V::Array(snapshot.references.iter().map(reference).collect());
        snapshot.value = V::Array(v);
    }
    let next = record(
        native::POLICY,
        p.reference.id,
        p.payload(),
        &snapshot,
        &scope,
        previous.map(|p| p.bytes.as_slice()),
    )?;
    native::Policy::parse(&next, scope.network, scope.incarnation)?;
    c.apply(native::Operation {
        transition: native::Transition::Policy,
        policy: next.clone(),
        previous: previous.map(|p| p.bytes.clone()),
        next: next.clone(),
        acceptance: vec![],
        legacy: vec![],
        snapshot,
    })?;
    crate::print_value(
        &json!({"status":"AdmissionPolicyApplied","policy":spec.id,"recordDigest":hex::encode(wire::digest(&next)),"enabled":spec.enabled}),
    )
}
