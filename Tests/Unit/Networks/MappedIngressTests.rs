// SPDX-License-Identifier: MIT
use super::*;
#[test]
fn only_two_fixed_tags_carry_exactly_one_descriptor() {
    let (parent, helper) = UnixStream::pair().unwrap();
    for kind in [DescriptorKind::Payload, DescriptorKind::Checks] {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        send(&helper, &stream, kind).unwrap();
        let (actual, mut received) = receive(&parent).unwrap().unwrap();
        assert_eq!(actual, kind);
        received.write_all(b"payload").unwrap();
        let mut bytes = [0; 7];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"payload");
    }
    (&helper).write_all(&[3]).unwrap();
    assert!(receive(&parent).is_err());
    (&helper).write_all(&[2]).unwrap();
    assert!(receive(&parent).is_err());
}
#[test]
fn listener_names_do_not_create_a_general_socket_broker() {
    assert!(ipc::Listener::bind_named(Path::new("/tmp"), "Another.sock").is_err());
}

#[test]
fn intake_readiness_preserves_descriptor_tags_and_exact_ack() {
    let (mut parent, mut helper) = UnixStream::pair().unwrap();
    helper.set_nonblocking(true).unwrap();
    for kind in [DescriptorKind::Payload, DescriptorKind::Checks] {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        send(&helper, &stream, kind).unwrap();
        assert!(
            ipc::wait_for_intake(
                &[parent.as_fd()],
                None,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap()
        );
        // Readiness cannot acknowledge a descriptor or consume its SCM_RIGHTS message.
        assert_eq!(
            helper.read(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
        );
        let (received_kind, mut received) = receive(&parent).unwrap().unwrap();
        assert_eq!(received_kind, kind);
        parent.write_all(&[1]).unwrap();
        let mut ack = [0];
        helper.read_exact(&mut ack).unwrap();
        assert_eq!(ack, [1]);
        received.write_all(b"after ack").unwrap();
        let mut bytes = [0; 9];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"after ack");
    }
}

#[test]
fn idle_ingress_watches_parent_hangup_without_consuming_or_waking_on_ack_data() {
    let (reader, _writer) = UnixStream::pair().unwrap();
    let (mut parent, mut helper) = UnixStream::pair().unwrap();
    parent.write_all(&[1]).unwrap();
    assert!(
        !ipc::wait_for_intake(
            &[reader.as_fd()],
            Some(helper.as_fd()),
            Instant::now() + Duration::from_millis(1),
        )
        .unwrap()
    );
    let mut ack = [0];
    helper.read_exact(&mut ack).unwrap();
    assert_eq!(ack, [1]);
    drop(parent);
    assert!(
        ipc::wait_for_intake(
            &[reader.as_fd()],
            Some(helper.as_fd()),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap()
    );
    assert!(ipc::disconnected(&helper).unwrap());
}
