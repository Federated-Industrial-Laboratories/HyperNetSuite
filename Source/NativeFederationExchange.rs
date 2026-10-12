// SPDX-License-Identifier: MIT
// An operator-selected installed bridge transports finite packets; local quorum verification grants access.
use super::*;
use std::process::Command as Process;
pub(super) fn exchange(route: &cli::Route, directory: &Path, packet: &[u8]) -> Result<Vec<u8>> {
    files::private_directory(directory)?;
    ensure!(
        packet.len() <= wire::MAXIMUM,
        "bridge packet exceeds its wire bound"
    );
    ensure!(
        route.exchange_timeout_ms > 0,
        "bridge exchange timeout is zero"
    );
    if let Some(socket) = &route.service_socket {
        return crate::authority_local_transport::LocalControl::open(socket)?.exchange_limit(
            packet,
            crate::authority_challenge::boot_time_ms()?
                .checked_add(route.exchange_timeout_ms)
                .context("bridge transport deadline overflow")?,
            4 * wire::MAXIMUM,
        );
    }
    let service_directory = route
        .service_directory
        .as_ref()
        .context("installed bridge directory absent")?;
    let suffix = crate::random_hex::<16>();
    let input = directory.join(format!("BridgePacket{suffix}.cbor"));
    let output = directory.join(format!("BridgeReply{suffix}.cbor"));
    struct Cleanup(PathBuf, PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_file(&self.1);
        }
    }
    let _cleanup = Cleanup(input.clone(), output.clone());
    files::write_new(&input, packet)?;
    let r = Process::new(&route.core)
        .args(["runtime", "services", "exchange", "--directory"])
        .arg(service_directory)
        .arg("--packet")
        .arg(&input)
        .arg("--receipt")
        .arg(&output)
        .output()?;
    ensure!(
        r.status.success(),
        "installed bridge exchange failed: {}",
        crate::reader::bounded_status(&String::from_utf8_lossy(
            &r.stderr[..r.stderr.len().min(2048)]
        ))
    );
    files::read_single(&output, 4 * wire::MAXIMUM, true)
}
pub(super) fn sync(
    route: &cli::Route,
    directory: &Path,
    agreement: Digest,
    page: Option<[u8; 16]>,
) -> Result<()> {
    let packet = wire::encode(&V::Array(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("BridgeSync".into()),
        V::Bytes(agreement.to_vec()),
        page.map_or(V::Null, |p| V::Bytes(p.to_vec())),
    ]))?;
    let bytes = exchange(route, directory, &packet)?;
    let value = wire::decode_state(&bytes)?;
    let f = value.array(4)?;
    ensure!(
        f[0].uint()? == 201 && f[1].uint()? == 1 && f[2].text()? == "BridgeSync",
        "bridge sync result differs"
    );
    let pages = f[3]
        .list(crate::authority_capacity::MAX_RECORDS)?
        .iter()
        .map(|v| Ok(hex::encode(v.fixed::<32>()?)))
        .collect::<Result<Vec<_>>>()?;
    crate::print_value(
        &json!({"status":"BridgeSyncReported","agreement":hex::encode(agreement),"pages":pages,
        "currentReaderPermission":false,"localReviewRequired":true}),
    )
}
#[allow(clippy::too_many_arguments)]
pub(super) fn lease(
    c: &Client,
    route: &cli::Route,
    agreement: Digest,
    page: Option<[u8; 16]>,
    revision: Option<VersionRef>,
    after: Option<Digest>,
) -> Result<fed::ForeignProof> {
    let cache = c.cache()?;
    let (n, i) = c.scope();
    let agreement_record = cache.state.record(151, agreement)?;
    let accepted = fed::Agreement::parse(&agreement_record.payload, n, i)?;
    ensure!(
        !accepted.treaty.source_side(n, i)?,
        "local read leases require the destination network"
    );
    let trust = cache.state.record(150, accepted.foreign.id)?;
    let floor = cache.state.record(157, accepted.foreign.id)?;
    let packet = wire::encode(&V::Array(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("BridgeLease".into()),
        V::Bytes(agreement.to_vec()),
        page.map_or(V::Null, |p| V::Bytes(p.to_vec())),
        revision
            .as_ref()
            .map_or(V::Null, crate::authority_membership::reference),
        after.map_or(V::Null, |p| V::Bytes(p.to_vec())),
        V::Bytes(trust.bytes.clone()),
        V::Bytes(floor.bytes.clone()),
        V::Bool(false),
    ]))?;
    let bytes = exchange(route, &c.directory, &packet)?;
    parse_lease(
        &bytes,
        trust,
        floor,
        &accepted.treaty,
        page,
        revision.as_ref(),
        after,
    )
}
pub(super) fn parse_lease(
    bytes: &[u8],
    trust: &domain::Record,
    floor: &domain::Record,
    treaty: &fed::Treaty,
    page: Option<[u8; 16]>,
    revision: Option<&VersionRef>,
    after: Option<Digest>,
) -> Result<fed::ForeignProof> {
    let value = wire::decode_state(bytes)?;
    let f = value.array(5)?;
    ensure!(
        f[0].uint()? == 201 && f[1].uint()? == 1 && f[2].text()? == "BridgeLease",
        "bridge lease reply differs"
    );
    let proof = fed::ForeignProof::parse(f[3].bytes()?)?;
    ensure!(
        proof.trust == trust.reference
            && proof.floor == floor.reference
            && proof.anchor == floor.bytes,
        "bridge lease substituted the local independently accepted authority floor"
    );
    let Action::Export {
        agreement,
        admission,
        include_bundle: false,
        ..
    } = proof.command()?
    else {
        anyhow::bail!("bridge lease is not finite metadata Export")
    };
    let Action::Admission {
        agreement: destination,
        page: p,
        revision: r,
        after: a,
        ..
    } = admission.command()?
    else {
        anyhow::bail!("bridge lease lacks matched Admission")
    };
    ensure!(
        agreement.id == treaty.id
            && destination.id == treaty.id
            && p == page
            && r.as_ref() == revision
            && a == after,
        "bridge lease names another agreement, page, revision or inventory cursor"
    );
    let intent = proof.intent()?;
    ensure!(
        treaty.source.matches(intent.network, intent.incarnation),
        "bridge Export belongs to another source network"
    );
    // Metadata leases never deliver Page bytes. The local authorised operation returns its exact sidecar.
    Resolved::parse(&[], &f[4])?;
    Ok(proof)
}
