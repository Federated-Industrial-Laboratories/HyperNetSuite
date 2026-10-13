// SPDX-License-Identifier: MIT
// An operator-selected installed bridge transports finite packets; local quorum verification grants access.
use super::*;
use std::process::Command as Process;
pub(super) fn exchange(route: &cli::Route, directory: &Path, packet: &[u8]) -> Result<Vec<u8>> {
    let control = route
        .service_socket
        .as_deref()
        .map(crate::authority_local_transport::LocalControl::open)
        .transpose()?;
    exchange_prepared(route, directory, packet, control.as_ref())
}
fn exchange_prepared(
    route: &cli::Route,
    directory: &Path,
    packet: &[u8],
    control: Option<&crate::authority_local_transport::LocalControl>,
) -> Result<Vec<u8>> {
    files::private_directory(directory)?;
    ensure!(
        packet.len() <= wire::MAXIMUM,
        "bridge packet exceeds its wire bound"
    );
    ensure!(
        route.exchange_timeout_ms > 0,
        "bridge exchange timeout is zero"
    );
    if let Some(control) = control {
        return control.exchange_limit(
            packet,
            crate::authority_challenge::boot_time_ms()?
                .checked_add(route.exchange_timeout_ms)
                .context("bridge transport deadline overflow")?,
            4 * wire::MAXIMUM,
        );
    }
    crate::private_route_client::require_local_allowed()?;
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
pub(super) fn lease(
    c: &Client,
    route: &cli::Route,
    agreement: Digest,
    page: Option<[u8; 16]>,
    revision: Option<VersionRef>,
    after: Option<Digest>,
    access: (&VersionRef, u64),
) -> Result<fed::ForeignProof> {
    Ok(lease_exchange(c, route, agreement, page, revision, after, false, access)?.0)
}
pub(super) fn body(
    c: &Client,
    route: &cli::Route,
    revision: &fed::ForeignRevision,
    access: (&VersionRef, u64),
) -> Result<Resolved> {
    let (proof, objects) = lease_exchange(
        c,
        route,
        revision.agreement,
        Some(revision.metadata.author.raw_page),
        Some(revision.native.clone()),
        None,
        true,
        access,
    )?;
    let (share, metadata) = proof.exported_share_metadata()?;
    ensure!(
        share == revision.share && metadata.value() == revision.metadata.value(),
        "direct body lease differs from locally authorised foreign revision"
    );
    let bytes = objects.get(&revision.bundle)?;
    let bundle =
        page::objects::Bundle::parse(bytes, revision.source.network, revision.source.incarnation)?;
    ensure!(
        proof.rebuild_bundle(&bundle.source)?.bytes == bundle.bytes,
        "Bridge body differs from exact signed publication"
    );
    Ok(objects)
}
#[allow(clippy::too_many_arguments)]
fn lease_exchange(
    c: &Client,
    route: &cli::Route,
    agreement: Digest,
    page: Option<[u8; 16]>,
    revision: Option<VersionRef>,
    after: Option<Digest>,
    include_body: bool,
    access: (&VersionRef, u64),
) -> Result<(fed::ForeignProof, Resolved)> {
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
        V::Bool(include_body),
    ]))?;
    let control = route
        .service_socket
        .as_deref()
        .map(crate::authority_local_transport::LocalControl::open)
        .transpose()?;
    let wrapped = if let Some(endpoint) = control.as_ref().and_then(|c| c.route()) {
        ensure!(
            endpoint.protocol == 6,
            "foreign reader requires a bridge reader route"
        );
        Some(crate::authority_route_reader::sign(
            n,
            i,
            endpoint.destination.service,
            access.0,
            access.1,
            c.clock
                .health()?
                .observe()?
                .wall_ms
                .checked_add(5000)
                .context("reader route expiry overflow")?,
            rand::random(),
            &packet,
            &c.key,
        )?)
    } else {
        None
    };
    let bytes = exchange_prepared(
        route,
        &c.directory,
        wrapped.as_deref().unwrap_or(&packet),
        control.as_ref(),
    )?;
    let proof = parse_lease_mode(
        &bytes,
        trust,
        floor,
        &accepted.treaty,
        page,
        revision.as_ref(),
        after,
        include_body,
    )?;
    let refs = if include_body {
        vec![
            proof
                .exported_publication()?
                .1
                .bundle
                .context("source approval has no bundle")?,
        ]
    } else {
        vec![]
    };
    let value = wire::decode_state(&bytes)?;
    let objects = Resolved::parse(&refs, &value.array(5)?[4])?;
    proof.verify(
        &cache.state,
        &accepted.treaty,
        c.clock.health()?.observe()?.wall_ms,
        &Resolved::default(),
        false,
    )?;
    Ok((proof, objects))
}
#[allow(clippy::too_many_arguments)]
fn parse_lease_mode(
    bytes: &[u8],
    trust: &domain::Record,
    floor: &domain::Record,
    treaty: &fed::Treaty,
    page: Option<[u8; 16]>,
    revision: Option<&VersionRef>,
    after: Option<Digest>,
    include_body: bool,
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
        include_bundle,
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
        include_bundle == include_body
            && agreement.id == treaty.id
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
    if !include_body {
        Resolved::parse(&[], &f[4])?;
    }
    Ok(proof)
}
