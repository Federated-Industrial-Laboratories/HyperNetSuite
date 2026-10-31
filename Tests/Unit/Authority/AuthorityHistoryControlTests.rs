// SPDX-License-Identifier: MIT
// Local operator catch-up retains the original request while verifying checkpoint ancestry.
use super::*;
use sha2::{Digest as _, Sha256};
fn signed(payload: &[u8]) -> Vec<u8> {
    wire::encode(&a(vec![
        V::Uint(0),
        V::Uint(1),
        b(payload),
        a(voters()[..3]
            .iter()
            .map(|key| {
                let public = key.verifying_key().to_bytes();
                a(vec![
                    b(&public),
                    b(&key
                        .sign(&wire::signature_message(payload, &public))
                        .to_bytes()),
                ])
            })
            .collect()),
    ]))
    .unwrap()
}
fn tree(nodes: &[Vec<u8>]) -> [u8; 32] {
    if nodes.len() == 1 {
        return Sha256::digest([vec![0], wire::digest(&nodes[0]).to_vec()].concat()).into();
    }
    let split = 1usize << ((nodes.len() - 1).ilog2());
    Sha256::digest(
        [
            vec![1],
            tree(&nodes[..split]).to_vec(),
            tree(&nodes[split..]).to_vec(),
        ]
        .concat(),
    )
    .into()
}
fn inclusion(nodes: &[Vec<u8>], index: usize) -> Vec<[u8; 32]> {
    if nodes.len() == 1 {
        return Vec::new();
    }
    let split = 1usize << ((nodes.len() - 1).ilog2());
    let (mut proof, sibling) = if index < split {
        (inclusion(&nodes[..split], index), tree(&nodes[split..]))
    } else {
        (
            inclusion(&nodes[split..], index - split),
            tree(&nodes[..split]),
        )
    };
    proof.push(sibling);
    proof
}
fn packets(
    pending: &Prepared,
    height: usize,
    time: u64,
    status_node: &[u8],
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let scope = pending.context.descriptor.scope();
    let mut parent = wire::digest(status_node);
    let mut nodes = vec![status_node.to_vec()];
    for height in 2..height {
        let node = wire::encode(&a(vec![
            V::Uint(14),
            V::Uint(1),
            scope.value(),
            V::Uint(height as u64),
            V::Uint(height as u64),
            b(&parent),
            b(&[80; 32]),
            V::Uint(time),
            b(&[81; 32]),
        ]))
        .unwrap();
        parent = wire::digest(&node);
        nodes.push(node);
    }
    let (reply, target) = certified(pending, result_value(pending), time, parent, height as u64);
    nodes.push(target.clone());
    let anchor = height - 1;
    let anchor_digest = wire::digest(&nodes[anchor - 1]);
    let statement = wire::encode(&a(vec![
        V::Uint(45),
        V::Uint(1),
        scope.value(),
        V::Uint(anchor as u64),
        b(&anchor_digest),
        V::Uint(time),
        b(&[81; 32]),
        V::Uint(anchor as u64),
        b(&tree(&nodes[..anchor])),
        V::Bool(false),
    ]))
    .unwrap();
    let checkpoint = wire::encode(&a(vec![
        V::Uint(46),
        V::Uint(1),
        b(&signed(&statement)),
        b(&nodes[anchor - 1]),
    ]))
    .unwrap();
    let history = wire::encode(&a(vec![
        V::Uint(47),
        V::Uint(1),
        scope.value(),
        V::Uint(1),
        b(&wire::digest(status_node)),
        b(&wire::digest(&statement)),
        a(inclusion(&nodes[..anchor], 0)
            .iter()
            .map(|v| b(v))
            .collect()),
        V::Uint(0),
        V::Null,
        a(vec![]),
    ]))
    .unwrap();
    let response = wire::encode(&a(vec![
        V::Uint(54),
        V::Uint(1),
        scope.value(),
        b(&wire::digest(&target)),
        b(&checkpoint),
        b(&history),
        a(vec![b(&target)]),
    ]))
    .unwrap();
    (reply, target, response)
}
fn receive(listener: &std::os::unix::net::UnixListener) -> (UnixStream, Vec<u8>) {
    let (mut stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(6)))
        .unwrap();
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).unwrap();
    let count = u32::from_be_bytes(prefix) as usize;
    assert!(count <= wire::MAXIMUM);
    let mut bytes = vec![0; count];
    stream.read_exact(&mut bytes).unwrap();
    (stream, bytes)
}
fn send(mut stream: UnixStream, bytes: &[u8]) {
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(bytes).unwrap();
}
fn local_workflow(height: usize) {
    let mut f = Fixture::new();
    let socket = f.directory.0.join("History.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let pending = f
        .context
        .prepare(request(), &f.signer, &mut f.store, &mut f.session, f.issued)
        .unwrap();
    pending.cancel(&mut f.session).unwrap();
    assert!(f.store.resume_ordinary().unwrap().is_some());
    let context = &f.context;
    let status_node = f.status_node.clone();
    let result = std::thread::scope(|scope| {
        let server = scope.spawn(move || {
            let (stream, bytes) = receive(&listener);
            let control = wire::decode(&bytes).unwrap();
            let control = record(&control, 41, 5).unwrap();
            assert_eq!(control[3].uint().unwrap(), 0);
            let submission = wire::decode(control[4].bytes().unwrap()).unwrap();
            let submission = submission.array(2).unwrap();
            submission[1].array(0).unwrap();
            let ordered = submission[0].bytes().unwrap().to_vec();
            let order = wire::decode(&ordered).unwrap();
            let order = record(&order, 22, 6).unwrap();
            let intent = order[3].bytes().unwrap().to_vec();
            let parsed = Intent::from_signed(&intent).unwrap();
            let challenge = order[4].bytes().unwrap().to_vec();
            let start = Challenge::from_signed(&challenge).unwrap().created_at_ms;
            let pending = Prepared {
                context,
                request: request(),
                target: context
                    .governance
                    .versions()
                    .into_iter()
                    .find(|v| v.kind == 100)
                    .unwrap(),
                expected: parsed.expected,
                intent,
                challenge,
                ordered,
                deadline: boot_time_ms().unwrap() + 5000,
            };
            while wall() < start + crate::authority_governance::UNCERTAINTY_MS {
                std::thread::sleep(Duration::from_millis(10));
            }
            let (reply, target, packet) = packets(&pending, height, wall(), &status_node);
            send(stream, &reply);
            if height <= 128 {
                let (stream, bytes) = receive(&listener);
                let control = wire::decode(&bytes).unwrap();
                assert_eq!(record(&control, 41, 5).unwrap()[3].uint().unwrap(), 3);
                let unavailable = wire::encode(&a(vec![
                    V::Uint(42),
                    V::Uint(1),
                    context.descriptor.scope().value(),
                    V::Uint(2),
                    V::Uint(1),
                    V::Null,
                    V::Null,
                    V::Null,
                    V::Null,
                    a(vec![]),
                ]))
                .unwrap();
                send(stream, &unavailable);
            }
            let (stream, bytes) = receive(&listener);
            let control = wire::decode(&bytes).unwrap();
            let control = record(&control, 41, 5).unwrap();
            assert_eq!(control[3].uint().unwrap(), 4);
            let query = wire::decode(control[4].bytes().unwrap()).unwrap();
            assert_eq!(
                query,
                a(vec![
                    V::Uint(1),
                    b(&wire::digest(&status_node)),
                    b(&wire::digest(&target)),
                    V::Uint(0),
                    V::Null
                ])
            );
            send(stream, &packet);
        });
        let result = context.inspect_local(
            &socket,
            request(),
            &f.signer,
            &mut f.store,
            &mut f.session,
            || {
                let boot = boot_time_ms()?;
                ClockHealth::new(wall(), boot, boot + 30000, 100)
            },
        );
        server.join().unwrap();
        result
    })
    .unwrap();
    assert_eq!(result.reference().kind, 100);
    assert_eq!(result.prefix().height(), height as u64);
    assert_eq!(f.store.tree_head().unwrap().size(), height as u64 - 1);
    drop(f.store);
    let reopened = Store::open(&f.directory.0, f.bootstrap.descriptor().clone()).unwrap();
    assert_eq!(reopened.prefix(), result.prefix());
    assert_eq!(reopened.tree_head().unwrap().size(), height as u64 - 1);
}
#[test]
fn local_inspection_catches_up_beyond_short_ancestry_limit() {
    local_workflow(161);
}
#[test]
fn local_inspection_uses_checkpoint_when_short_history_is_unavailable() {
    local_workflow(33);
}
#[test]
fn checkpoint_reply_rejects_target_substitution_omitted_suffix_and_original_deadline_expiry() {
    let mut f = Fixture::new();
    let pending = f
        .context
        .prepare(request(), &f.signer, &mut f.store, &mut f.session, f.issued)
        .unwrap();
    let (_, target, packet) = packets(
        &pending,
        161,
        f.current.observe().unwrap().wall_ms,
        &f.status_node,
    );
    let valid = AncestryEvidence::checkpoint_reply(&f.store, &target, &packet).unwrap();
    assert_eq!(valid.nodes, vec![target.clone()]);
    for index in [3, 6] {
        let V::Array(mut fields) = wire::decode(&packet).unwrap() else {
            unreachable!()
        };
        fields[index] = if index == 3 { b(&[90; 32]) } else { a(vec![]) };
        assert!(
            AncestryEvidence::checkpoint_reply(
                &f.store,
                &target,
                &wire::encode(&a(fields)).unwrap()
            )
            .is_err()
        );
    }
    let socket = f.directory.0.join("Expired.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let control = LocalControl::open(&socket).unwrap();
    assert!(AncestryEvidence::fetch(&control, &f.store, &target, boot_time_ms().unwrap()).is_err());
    assert_eq!(f.store.prefix().height(), 1);
    assert!(f.store.tree_head().is_none());
}

#[test]
fn malformed_short_history_response_cannot_start_checkpoint_repair() {
    let mut f = Fixture::new();
    let pending = f
        .context
        .prepare(request(), &f.signer, &mut f.store, &mut f.session, f.issued)
        .unwrap();
    let (_, target, _) = packets(
        &pending,
        33,
        f.current.observe().unwrap().wall_ms,
        &f.status_node,
    );
    let socket = f.directory.0.join("Malformed.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let control = LocalControl::open(&socket).unwrap();
    let scope = f.store.prefix().scope().clone();
    let server = std::thread::spawn(move || {
        let (stream, bytes) = receive(&listener);
        let request = wire::decode(&bytes).unwrap();
        assert_eq!(record(&request, 41, 5).unwrap()[3].uint().unwrap(), 3);
        let malformed = wire::encode(&a(vec![
            V::Uint(42),
            V::Uint(1),
            scope.value(),
            V::Uint(2),
            V::Uint(2),
            V::Null,
            V::Null,
            V::Null,
            V::Null,
            a(vec![]),
        ]))
        .unwrap();
        send(stream, &malformed);
    });
    let error =
        AncestryEvidence::fetch(&control, &f.store, &target, boot_time_ms().unwrap() + 1000)
            .err()
            .unwrap();
    server.join().unwrap();
    assert!(
        error
            .to_string()
            .contains("without an unavailable response")
    );
    assert_eq!(f.store.prefix().height(), 1);
    assert!(f.store.tree_head().is_none());
}

#[path = "AuthorityHistoryPrefetchTests.rs"]
mod prefetch_tests;
