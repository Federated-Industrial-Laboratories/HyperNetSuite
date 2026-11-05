// SPDX-License-Identifier: MIT
// Unit tests for LocalStreamIpc.
use super::*;
use std::os::fd::AsFd;

#[test]
fn intake_wakes_for_each_ready_source_without_consuming_data() {
    let pairs = (0..3)
        .map(|_| UnixStream::pair().unwrap())
        .collect::<Vec<_>>();
    let descriptors = pairs
        .iter()
        .map(|(read, _)| read.as_fd())
        .collect::<Vec<_>>();
    for (reader, writer) in &pairs {
        let (mut read, mut write) = (reader, writer);
        write.write_all(b"ready").unwrap();
        assert!(
            wait_for_intake(&descriptors, None, Instant::now() + Duration::from_secs(1),).unwrap()
        );
        let mut bytes = [0; 5];
        read.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"ready");
    }
    assert!(
        !wait_for_intake(
            &descriptors,
            None,
            Instant::now() + Duration::from_millis(1),
        )
        .unwrap()
    );
    (&pairs[0].1).write_all(b"late").unwrap();
    assert!(!wait_for_intake(&descriptors, None, Instant::now()).unwrap());
}

#[test]
fn intake_bounds_descriptors_and_returns_interruptions_to_its_owner() {
    let (reader, _writer) = UnixStream::pair().unwrap();
    let end = Instant::now() + Duration::from_secs(1);
    for descriptors in [&[][..], &[reader.as_fd(); 4][..]] {
        assert_eq!(
            wait_for_intake(descriptors, None, end).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput,
        );
    }
    assert_eq!(
        wait_for_intake(&[reader.as_fd(); 3], Some(reader.as_fd()), end)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidInput,
    );
    assert!(!intake_ready(Err(std::io::Error::from_raw_os_error(libc::EINTR)), &[]).unwrap());
    assert_eq!(
        intake_ready(Err(std::io::Error::from_raw_os_error(libc::EACCES)), &[])
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied,
    );
    for (revents, expected) in [
        (libc::POLLNVAL, std::io::ErrorKind::InvalidInput),
        (libc::POLLERR, std::io::ErrorKind::ConnectionAborted),
    ] {
        assert_eq!(
            intake_ready(
                Ok(1),
                &[libc::pollfd {
                    fd: reader.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: revents | libc::POLLIN,
                }],
            )
            .unwrap_err()
            .kind(),
            expected,
        );
    }
}

#[test]
fn intake_reader_hangup_wakes_for_owner_disconnect_handling() {
    let (mut reader, writer) = UnixStream::pair().unwrap();
    drop(writer);
    assert!(
        wait_for_intake(
            &[reader.as_fd()],
            None,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap()
    );
    assert_eq!(reader.read(&mut [0]).unwrap(), 0);
}

#[test]
fn authority_cleanup_alias_uses_the_same_private_listener_and_lifetime() {
    let parent = std::env::temp_dir();
    let mut name = format!("A{}", crate::random_hex::<8>());
    let target = 105 - parent.as_os_str().as_encoded_bytes().len() - 2 - "Control.sock".len();
    name.push_str(
        &"x".repeat(
            target
                .checked_sub(name.len())
                .expect("private fixture parent is too long"),
        ),
    );
    let directory = parent.join(name);
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.join("Control.sock");
    let alias = directory.join("ReadAcknowledgements.sock");
    let mut listener = Listener::bind(&directory)
        .unwrap()
        .with_read_acknowledgements()
        .unwrap();
    assert_eq!(metadata(&path).unwrap(), metadata(&alias).unwrap());
    assert_eq!(path.as_os_str().as_encoded_bytes().len(), 105);
    assert!(alias.as_os_str().as_encoded_bytes().len() >= 108);
    let owned = File::open(&directory).unwrap();
    let endpoint = Path::new("/proc/self/fd")
        .join(owned.as_raw_fd().to_string())
        .join("ReadAcknowledgements.sock");
    let mut caller = UnixStream::connect(endpoint).unwrap();
    assert!(
        wait_for_intake(
            &[listener.socket.as_fd()],
            None,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap()
    );
    let (mut accepted, _) = listener.socket.accept().unwrap();
    write_frame(&mut caller, b"same listener").unwrap();
    assert_eq!(read_frame(&mut accepted).unwrap(), b"same listener");
    drop((caller, accepted));
    // Retain the dead alias as after a stopped process; replacement must use the short owned path.
    listener.acknowledgement = None;
    drop(listener);
    assert!(!path.exists() && alias.exists());
    let listener = Listener::bind(&directory)
        .unwrap()
        .with_read_acknowledgements()
        .unwrap();
    assert_eq!(metadata(&path).unwrap(), metadata(&alias).unwrap());
    drop(listener);
    assert!(!path.exists() && !alias.exists());
    std::fs::write(&alias, b"unrelated").unwrap();
    assert!(
        Listener::bind(&directory)
            .unwrap()
            .with_read_acknowledgements()
            .is_err()
    );
    assert_eq!(std::fs::read(&alias).unwrap(), b"unrelated");
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn bounded_control_frames_reject_lengths_before_allocation() {
    for length in [0u32, MAXIMUM as u32 + 1, u32::MAX] {
        assert!(read_frame(&mut length.to_be_bytes().as_slice()).is_err());
    }
    let mut encoded = Vec::new();
    write_frame(&mut encoded, b"context").unwrap();
    assert_eq!(read_frame(&mut encoded.as_slice()).unwrap(), b"context");
}

#[test]
fn local_duplex_preserves_half_close_and_bounds_cancel_and_bytes() {
    let (mut caller, left) = UnixStream::pair().unwrap();
    let (right, mut application) = UnixStream::pair().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let worker = std::thread::spawn(move || {
        pump(
            left,
            right,
            65536,
            Duration::from_secs(5),
            Duration::from_secs(2),
            cancel,
        )
    });
    caller.write_all(&[7; 32768]).unwrap();
    caller.shutdown(Shutdown::Write).unwrap();
    let mut request = Vec::new();
    application.read_to_end(&mut request).unwrap();
    assert_eq!(request, [7; 32768]);
    application.write_all(&[8; 32768]).unwrap();
    application.shutdown(Shutdown::Write).unwrap();
    let mut response = Vec::new();
    caller.read_to_end(&mut response).unwrap();
    assert_eq!(response, [8; 32768]);
    worker.join().unwrap().unwrap();

    let (mut caller, left) = UnixStream::pair().unwrap();
    let (right, mut application) = UnixStream::pair().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let worker = std::thread::spawn(move || {
        pump(
            left,
            right,
            3,
            Duration::from_secs(5),
            Duration::from_secs(2),
            cancel,
        )
    });
    caller.write_all(b"four").unwrap();
    caller.shutdown(Shutdown::Write).unwrap();
    let mut rejected = Vec::new();
    application.read_to_end(&mut rejected).unwrap();
    assert!(rejected.is_empty());
    assert!(worker.join().unwrap().is_err());

    let (_caller, left) = UnixStream::pair().unwrap();
    let (right, _application) = UnixStream::pair().unwrap();
    let cancel = Arc::new(AtomicBool::new(true));
    let started = Instant::now();
    assert!(
        pump(
            left,
            right,
            3,
            Duration::from_secs(5),
            Duration::from_secs(2),
            cancel
        )
        .is_err()
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn v1_schema_stays_strict_and_v2_checks_are_exactly_scoped() {
    let mut value = json!({"version":2,"action":"checkAuthority","id":"01".repeat(32),"nonce":"02".repeat(32),"actionDigest":"03".repeat(32),"timeoutMs":5000});
    serde_json::from_value::<RequestV2>(value.clone())
        .unwrap()
        .validate()
        .unwrap();
    value["version"] = json!(1);
    assert!(serde_json::from_value::<Request>(value.clone()).is_err());
    value["version"] = json!(2);
    for field in ["principal", "session", "grant", "service"] {
        let mut extra = value.clone();
        extra[field] = json!("substitute");
        assert!(
            serde_json::from_value::<RequestV2>(extra)
                .and_then(|r| r.validate().map_err(serde::de::Error::custom))
                .is_err()
        );
    }
    for timeout in [0, 99, 5001] {
        value["timeoutMs"] = json!(timeout);
        assert!(
            serde_json::from_value::<RequestV2>(value.clone())
                .unwrap()
                .validate()
                .is_err()
        );
    }
    value["timeoutMs"] = json!(100);
    value["nonce"] = json!("AA".repeat(32));
    assert!(
        serde_json::from_value::<RequestV2>(value)
            .unwrap()
            .validate()
            .is_err()
    );
}
