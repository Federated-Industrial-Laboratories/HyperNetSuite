// SPDX-License-Identifier: MIT
// A freshly accepted view reads exact retained bytes without another authority exchange.
use super::*;
use crate::authority_deployment_tests as deployment;

pub(crate) fn consume(
    c: &mut Client,
    grant: &VersionRef,
    placement: &VersionRef,
    view: &ResultState,
    source: &[u8],
) {
    let value =
        content::Placement::parse(&view.cache.state.record(159, placement.id).unwrap().payload)
            .unwrap();
    let host = value.hosts[0].clone();
    assert_eq!(host.id, deployment::key(100).verifying_key().to_bytes());
    assert_eq!(
        view.cache.state.record(147, host.id).unwrap().reference,
        host
    );
    let directory = files::private_directory(&c.directory).unwrap();
    let directory_path = c.directory.clone();
    let route = |host: Digest| {
        serde_json::to_vec(&serde_json::json!([{
            "host":hex::encode(host), "serviceSocket":directory_path.join("UnavailableContent.sock"),
            "serviceDirectory":null, "core":"HyperNet"
        }]))
        .unwrap()
    };
    files::atomic_at(
        &directory,
        std::ffi::OsStr::new("ContentRoutes.json"),
        &route(host.id),
        true,
    )
    .unwrap();
    let path = c.directory.join(format!(
        "Content{}Host{}Effect1",
        hex::encode(placement.digest),
        hex::encode(host.id)
    ));
    let scope = view.prefix.scope();
    let mut progress = Progress::open(
        &path,
        (scope.network, scope.incarnation, c.store.requester()),
        &view.cache.state,
        placement,
        host.id,
        Effect::Read,
        None,
    )
    .unwrap();
    let operation = domain::Operation {
        grant: Some(grant.clone()),
        command: Action::Content(content::Command::Authorise {
            placement: placement.clone(),
            host: host.clone(),
            effect: Effect::Read,
            offset: 0,
            bytes: source.len() as u64,
            digest: None,
        })
        .into(),
        snapshot: domain::snapshot(&deployment::snapshot(&[])).unwrap(),
    };
    let request = page::MediaRequest::parse(&deployment::signed(
        &c.key,
        "AuthorityDomain",
        operation.command.resource(),
        0,
        wire::decode(&operation.parameters().unwrap()).unwrap(),
        vec![],
    ))
    .unwrap();
    let mut copy = content::Copy {
        placement: placement.clone(),
        host: host.clone(),
        request: [66; 32],
        digest: digest(source),
        bytes: source.len() as u64,
        recorded_ms: 5000,
        expires_ms: value.expires_ms,
        envelope: vec![],
    };
    copy.envelope = wire::sign_envelope(
        &copy.payload(scope.network, scope.incarnation).unwrap(),
        &deployment::key(100),
    )
    .unwrap();
    let response = wire::encode(&V::Array(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("PageContentEffect".into()),
        crate::authority_membership::reference(placement),
        crate::authority_membership::reference(&host),
        V::Uint(1),
        V::Uint(0),
        V::Uint(source.len() as u64),
        V::Bytes(digest(source).to_vec()),
        V::Bytes(source.to_vec()),
        V::Bytes(copy.envelope),
    ]))
    .unwrap();
    progress.apply(&request, &response).unwrap();
    drop(progress);
    // Neither clock nor authority/content socket exists. A redundant metadata or
    // transfer request would fail instead of returning this verified retained source.
    assert_eq!(
        fetch_view_source(c, grant, placement, view).unwrap(),
        source
    );
    let mut changed = placement.clone();
    changed.generation += 1;
    assert!(fetch_view_source(c, grant, &changed, view).is_err());
    changed = placement.clone();
    changed.digest[0] ^= 1;
    assert!(fetch_view_source(c, grant, &changed, view).is_err());
    files::atomic_at(
        &directory,
        std::ffi::OsStr::new("ContentRoutes.json"),
        &route([99; 32]),
        true,
    )
    .unwrap();
    assert!(
        fetch_view_source(c, grant, placement, view)
            .unwrap_err()
            .to_string()
            .contains("no explicitly selected content route")
    );
}
