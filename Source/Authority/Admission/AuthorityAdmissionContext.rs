// SPDX-License-Identifier: MIT
// Fresh admission disclosure binds policy purpose, bounded slot selection and exact route material.
use super::*;
use crate::authority_domains;

pub struct Disclosure {
    pub policy: Policy,
    pub selected: Option<Slot>,
    pub claim_floor: u64,
    pub available: Option<u64>,
    pub records: Vec<Vec<u8>>,
    pub domains: Vec<Vec<u8>>,
    pub versions: Vec<VersionRef>,
}
impl Disclosure {
    pub fn parse(
        v: &V,
        n: Digest,
        i: Digest,
        requester: Key,
        policy: Digest,
        claim: Option<Digest>,
        at: u64,
    ) -> Result<Self> {
        let f = v.array(5)?;
        ensure!(
            f[0].uint()? == 201 && f[1].uint()? == 1 && f[2].text()? == "AuthorityAdmissionContext",
            "admission context schema differs"
        );
        let body = f[4].array(6)?;
        let available = if body[5] == V::Null {
            None
        } else {
            Some(body[5].uint()?)
        };
        ensure!(
            id(&body[0])? == policy,
            "admission context has another policy"
        );
        let claim_floor = body[1].uint()?;
        let selected = if body[2] == V::Null {
            None
        } else {
            Some(id(&body[2])?)
        };
        let records = body[3]
            .list(64)?
            .iter()
            .map(|x| Ok(x.bytes()?.to_vec()))
            .collect::<Result<Vec<_>>>()?;
        let domains = body[4]
            .list(16)?
            .iter()
            .map(|x| Ok(x.bytes()?.to_vec()))
            .collect::<Result<Vec<_>>>()?;
        let g = Governance::parse(n, i, &records)?;
        let p = g
            .admission()
            .policies
            .get(&policy)
            .context("admission policy absent from proof")?
            .clone();
        // Status remains inspectable after withdrawal; usable route results require current authority.
        if !domains.is_empty() {
            p.authorise(&g, n, at)?;
        }
        let selected = selected
            .map(|id| {
                g.admission()
                    .slots
                    .get(&id)
                    .cloned()
                    .context("admission slot absent from proof")
            })
            .transpose()?;
        ensure!(
            available.is_none_or(|s| s < p.maximum_slots)
                && (claim.is_some() || available.is_none()),
            "admission available slot differs"
        );
        if let Some(s) = &selected {
            ensure!(
                available == Some(s.slot) && s.policy == policy && s.ordinal <= claim_floor,
                "admission slot or claim floor differs"
            );
            ensure!(
                requester == p.registrar
                    || requester == p.owner
                    || s.roles.iter().any(|r| r.member == requester),
                "admission slot disclosure belongs to another identity"
            );
            if claim != Some(s.claim) {
                ensure!(
                    requester == p.registrar
                        && (s.state == 3
                            || s.state == 0 && at > s.challenge_until.saturating_add(1250)),
                    "admission selected another live claim"
                );
            }
        }
        let mut versions = Governance::record_versions(n, i, &records)?;
        let mut domain_refs = vec![];
        for bytes in &domains {
            let r = authority_domains::Record::parse(bytes, n, i)?;
            ensure!(
                matches!(r.reference.kind, 165 | 166),
                "admission disclosure includes unrelated domain data"
            );
            domain_refs.push(r.reference);
        }
        crate::authority_proof::validate_versions(&domain_refs, 16)?;
        versions.extend(domain_refs);
        versions.sort_by_key(VersionRef::index);
        crate::authority_proof::validate_versions(&versions, 64)?;
        ensure!(
            f[3] == a(versions.iter().map(reference).collect()),
            "admission context references differ from exact returned records"
        );
        if let Some(slot) = selected
            .as_ref()
            .filter(|s| s.active() && !domains.is_empty())
        {
            verify_routes(&p, slot, &domains, n, i, at)?;
        }
        Ok(Self {
            policy: p,
            selected,
            claim_floor,
            available,
            records,
            domains,
            versions,
        })
    }
}
fn verify_routes(
    p: &Policy,
    s: &Slot,
    domains: &[Vec<u8>],
    n: Digest,
    i: Digest,
    at: u64,
) -> Result<()> {
    let records = domains
        .iter()
        .map(|b| authority_domains::Record::parse(b, n, i))
        .collect::<Result<Vec<_>>>()?;
    for role in &s.roles {
        for (purpose, destination) in [(4, p.authority), (5, p.template(role.role)?.destination)] {
            let id = identifier(s.policy, s.slot, role.role, purpose)?;
            let v = records
                .iter()
                .find(|r| r.reference.kind == 166 && r.reference.id == id)
                .context("scoped voucher absent")?;
            let voucher = authority_domains::routes::Voucher::parse(&v.payload)?;
            let relay = records
                .iter()
                .find(|r| r.reference == voucher.relay)
                .context("scoped relay absent")?;
            let target = records
                .iter()
                .find(|r| r.reference == voucher.destination)
                .context("scoped destination absent")?;
            let relay = authority_domains::routes::Service::parse(&relay.payload, n, i)?;
            let target = authority_domains::routes::Service::parse(&target.payload, n, i)?;
            let template = p.template(role.role)?;
            ensure!(
                !relay.withdrawn
                    && !target.withdrawn
                    && relay.profile.mode == 1
                    && target.profile.mode != 1
                    && voucher.relay.id == p.relay
                    && voucher.destination.id == destination
                    && voucher.sponsor == role.member
                    && voucher.possession == role.relay
                    && voucher.grant.id == identifier(s.policy, s.slot, role.role, 2)?
                    && voucher.action == 0
                    && voucher.scope == (3, destination)
                    && voucher.connections == template.connections
                    && voucher.bytes == template.bytes
                    && voucher.expires > at.saturating_add(1250),
                "scoped route differs from current member or fixed template"
            );
        }
    }
    Ok(())
}
