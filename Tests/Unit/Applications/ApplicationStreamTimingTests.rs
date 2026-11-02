// SPDX-License-Identifier: MIT
use super::*;

#[test]
fn exhausted_timing_samples_emit_nothing_and_keep_the_counter_bounded() {
    let counter = AtomicU64::new(0);
    let first = Timing::new(&counter, 1, "Preparation", 123);
    let mut output = Vec::new();
    first.write(&mut output, 100, "Enqueue", "Complete");
    let record = String::from_utf8(output).unwrap();
    assert!(record.contains("sample=1 phase=Enqueue state=Complete bootMs=100"));
    assert!(record.ends_with("deadlineBootMs=123\n"));
    assert!(record.len() < 256);
    for _ in 0..100 {
        let capped = Timing::new(&counter, 1, "Preparation", u64::MAX);
        let mut output = Vec::new();
        capped.write(&mut output, u64::MAX, "SlotLookup", "Failed");
        assert!(output.is_empty());
    }
    assert_eq!(counter.load(Ordering::Relaxed), 1);
}

#[test]
fn diagnostic_output_failure_does_not_replace_the_operation_result() {
    struct Failed;
    impl Write for Failed {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let counter = AtomicU64::new(0);
    let timing = Timing::new(&counter, 1, "Cleanup", 123);
    timing.write(&mut Failed, 100, "Work", "Failed");
    let capped = Timing::new(&counter, 1, "Cleanup", 123);
    assert_eq!(capped.run("Work", || Ok::<_, u8>(17)), Ok(17));
    assert_eq!(capped.run("Work", || Err::<u8, _>(19)), Err(19));
}

#[test]
fn stalled_diagnostic_sink_drops_overflow_without_waiting_for_output() {
    use std::time::Duration;
    struct Stalled {
        entered: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    }
    impl Write for Stalled {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            self.entered.send(()).unwrap();
            let _ = self.release.recv();
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let (entered, blocked) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let sender = writer(Stalled {
        entered,
        release: released,
    })
    .unwrap();
    submit(&sender, b"first\n".to_vec());
    blocked.recv_timeout(Duration::from_secs(2)).unwrap();
    for _ in 0..64 {
        sender.try_send(b"queued\n".to_vec()).unwrap();
    }
    assert!(matches!(
        sender.try_send(vec![]),
        Err(mpsc::TrySendError::Full(_))
    ));
    let (done, completion) = mpsc::channel();
    let producer = std::thread::spawn(move || {
        submit(&sender, b"overflow\n".to_vec());
        done.send(()).unwrap();
    });
    let completed = completion.recv_timeout(Duration::from_secs(2));
    // Release even on failure, so the regression cannot leave a blocked worker.
    release.send(()).unwrap();
    producer.join().unwrap();
    assert!(completed.is_ok());
}
