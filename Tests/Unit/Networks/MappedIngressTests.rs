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
