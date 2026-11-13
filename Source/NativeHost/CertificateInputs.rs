// SPDX-License-Identifier: Apache-2.0
//! Issue only same-key public transport successors from the retained private issuer and requests.
use super::*;
use crate::runtime_manifest::certificates as tls;
use std::collections::BTreeMap;

pub(super) fn peer_identity(peer: &Value) -> Result<(String, String)> {
    let service = string(&peer["request"], "identity")?;
    let transport = string(&peer["request"], "transport")?;
    crate::trust_bootstrap::hex32(&service)?;
    crate::trust_bootstrap::hex32(&transport)?;
    ensure!(
        service != transport,
        "transport identity must remain separate"
    );
    Ok((service, transport))
}
pub(super) fn role_names(hrc: bool) -> Vec<String> {
    let mut names = (1..=4).map(|n| format!("Voter{n}")).collect::<Vec<_>>();
    names.extend(["Relay", "AuthorityEndpoint", "PageEndpoint"].map(Into::into));
    if hrc {
        names.push("ApplicationEndpoint".into());
    }
    names
}
pub(super) fn path(root: &Path, generation: u64) -> PathBuf {
    root.join(format!("Successor/Certificates/Generation{generation:020}"))
}
pub(super) fn peer_path(root: &Path, state: &State, role: &str) -> PathBuf {
    let original = root.join(format!("Peers/{role}.json"));
    state.current.as_ref().map_or(original.clone(), |g| {
        let current = path(root, g.number).join(format!("Peers/{role}.json"));
        if current.exists() { current } else { original }
    })
}
pub(super) fn issuer_path(root: &Path, state: &State) -> PathBuf {
    state.current.as_ref().map_or_else(
        || root.join("Recovery/Issuer/Authority.pem"),
        |g| path(root, g.number).join("Authority.pem"),
    )
}
pub(super) fn interval(peer: &Value) -> Result<(u64, u64)> {
    let issuer = tls::der(&string(peer, "authorityPem")?)?;
    let leaf = tls::der(&string(peer, "certificatePem")?)?;
    let a = tls::interval(&issuer)?;
    let b = tls::interval(&leaf)?;
    Ok((
        a.0.max(b.0)
            .checked_mul(1000)
            .context("certificate time overflow")?,
        a.1.min(b.1)
            .checked_mul(1000)
            .context("certificate time overflow")?,
    ))
}
pub(super) fn issue(host: &mut Host<'_>, state: &State, generation: &mut Generation) -> Result<()> {
    let folder = path(&host.c.root, generation.number);
    host.dir(&format!(
        "Successor/Certificates/Generation{:020}",
        generation.number
    ))?;
    files::directory(&folder.join("Peers"))?;
    files::directory(&folder.join("Services"))?;
    let old_issuer = issuer_path(&host.c.root, state);
    let old_bytes = files::public_file(&old_issuer, 16384)?;
    let old_pem = String::from_utf8(old_bytes.clone())?;
    let issuer = folder.join("Authority.pem");
    if !issuer.exists() {
        let (_, end) = tls::interval(&tls::der(&old_pem)?)?;
        if end.saturating_mul(1000) <= now()?.saturating_add(366 * DAY) {
            host.core(&bytes(&[
                "runtime",
                "provision",
                "renew-issuer",
                "--directory",
                &text(&host.c.recovery_directory.join("Issuer"))?,
                "--issuer-certificate",
                &text(&old_issuer)?,
                "--issuer-digest",
                &digest(&old_bytes),
                "--days",
                "3650",
                "--output",
                &text(&issuer)?,
            ]))?;
        } else {
            files::exact_file(&issuer, &old_bytes)?;
        }
    }
    let pem = String::from_utf8(files::public_file(&issuer, 16384)?)?;
    tls::issuer_successor(&tls::der(&old_pem)?, &tls::der(&pem)?)?;
    host.artifact(&issuer)?;
    for role in role_names(host.c.hrc.is_some()) {
        let old_path = peer_path(&host.c.root, state, &role);
        if !old_path.exists() {
            continue;
        }
        let previous = public_read(&old_path)?;
        let destination = folder.join(format!("Peers/{role}.json"));
        if !destination.exists() {
            let request = host.p(&format!("Keys/{role}/TransportRequest.json"));
            host.core(&bytes(&[
                "runtime",
                "provision",
                "issue",
                "--directory",
                &text(&host.c.recovery_directory.join("Issuer"))?,
                "--issuer-certificate",
                &text(&issuer)?,
                "--issuer-digest",
                &digest(pem.as_bytes()),
                "--request",
                &text(&request)?,
                "--request-digest",
                &digest(&files::public_file(&request, 16384)?),
                "--days",
                "365",
                "--output",
                &text(&destination)?,
            ]))?;
        }
        let next = public_read(&destination)?;
        ensure!(
            next["request"] == previous["request"] && next["request"].is_object(),
            "renewed peer changes retained signed request"
        );
        tls::leaf_successor(
            &tls::der(&string(&previous, "certificatePem")?)?,
            &tls::der(&string(&next, "certificatePem")?)?,
            &tls::der(&string(&previous, "authorityPem")?)?,
            &tls::der(&string(&next, "authorityPem")?)?,
        )?;
        host.artifact(&destination)?;
    }
    generation.issued = true;
    Ok(())
}
pub(super) fn bundle(
    host: &mut Host<'_>,
    generation: &Generation,
    manifest: &crate::runtime_manifest::Manifest,
    destination: &Path,
) -> Result<()> {
    let folder = path(&host.c.root, generation.number);
    let issuer = String::from_utf8(files::public_file(&folder.join("Authority.pem"), 16384)?)?;
    let mut identities = BTreeMap::new();
    for role in role_names(host.c.hrc.is_some()) {
        let peer = folder.join(format!("Peers/{role}.json"));
        if peer.exists() {
            let value = public_read(&peer)?;
            ensure!(
                identities.insert(peer_identity(&value)?, value).is_none(),
                "repeated renewed transport identity"
            );
        }
    }
    let selected=manifest.endpoints.iter().map(|e| {
        let peer=identities.get(&(hex::encode(e.service_key),hex::encode(e.transport_key)))
            .context("retained certificate request for endpoint absent")?;
        ensure!(string(peer,"authorityPem")? == issuer, "renewed issuer set differs");
        Ok(json!({"endpoint":hex::encode(e.endpoint_id),"serviceKey":hex::encode(e.service_key),
            "transportKey":hex::encode(e.transport_key),"certificatePem":string(peer,"certificatePem")?}))
    }).collect::<Result<Vec<_>>>()?;
    host.immutable_json(destination,&json!({"format":"HyperNetTransportCertificates/1","issuerPem":issuer,"certificates":selected}))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn issued_peer_uses_its_signed_request_identity() {
        let service = "12".repeat(32);
        let transport = "34".repeat(32);
        let peer = json!({"identity":"56".repeat(32),"transport":"78".repeat(32),
            "request":{"identity":service,"transport":transport}});
        assert_eq!(
            peer_identity(&peer).unwrap(),
            (service.clone(), transport.clone())
        );
        assert!(peer_identity(&json!({"identity":service,"transport":transport})).is_err());
        assert!(
            peer_identity(&json!({"request":{"identity":service,"transport":service}})).is_err()
        );
    }
}
