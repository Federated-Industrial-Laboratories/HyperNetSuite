// SPDX-License-Identifier: MIT
// Unit tests for LocalStreamIpc.
use super::*;

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
