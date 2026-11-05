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
    timing.write_resume_failure(
        &mut Failed,
        100,
        ResumeStage::RefusalStatus,
        &anyhow::anyhow!("unreported private detail"),
    );
    let capped = Timing::new(&counter, 1, "Cleanup", 123);
    assert_eq!(capped.run("Work", || Ok::<_, u8>(17)), Ok(17));
    assert_eq!(capped.run("Work", || Err::<u8, _>(19)), Err(19));
}

#[test]
fn resume_failure_records_do_not_format_errors_and_obey_the_existing_cap() {
    #[derive(Debug)]
    struct PrivateError;
    impl std::fmt::Display for PrivateError {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("diagnostics must not format private error text")
        }
    }
    impl std::error::Error for PrivateError {}
    let error = anyhow::Error::new(PrivateError).context("private target and signed payload");
    let counter = AtomicU64::new(0);
    let timing = Timing::new(&counter, 1, "Preparation", u64::MAX);
    for (stage, phase) in [
        (ResumeStage::RefusalStatus, "ResumeRefusalStatus"),
        (ResumeStage::RetainedOperation, "ResumeRetainedOperation"),
    ] {
        let mut output = Vec::new();
        timing.write_resume_failure(&mut output, u64::MAX, stage, &error);
        let record = String::from_utf8(output).unwrap();
        assert!(record.contains(&format!("phase={phase} state=Failed reason=Other ")));
        assert!(!record.contains("private"));
        assert!(!record.contains("payload"));
        assert_eq!(record.lines().count(), 1);
        assert!(record.len() < 256);
    }
    assert!(error.is::<PrivateError>());
    let capped = Timing::new(&counter, 1, "Preparation", u64::MAX);
    let mut output = Vec::new();
    capped.write_resume_failure(
        &mut output,
        u64::MAX,
        ResumeStage::RetainedOperation,
        &error,
    );
    assert!(output.is_empty());
    assert_eq!(counter.load(Ordering::Relaxed), 1);
}

#[test]
fn resume_reasons_use_typed_causes_without_interpreting_refusal_text() {
    let cases = [
        (
            anyhow::Error::new(crate::authority_local_transport::RequestDeadlineExpired {
                deadline: u64::MAX,
            }),
            "DeadlineExpired",
        ),
        (
            anyhow::Error::new(crate::authority_clock::ObservationExpired),
            "ClockObservationExpired",
        ),
        (
            anyhow::Error::new(crate::authority_challenge::ChallengeExpired),
            "ChallengeExpired",
        ),
        (
            anyhow::Error::new(io::Error::new(io::ErrorKind::UnexpectedEof, "private path")),
            "IoEof",
        ),
        (
            anyhow::anyhow!("stream control refused with code 3"),
            "Other",
        ),
        (
            anyhow::Error::new(crate::authority_inspection::domain_client::Refusal { code: 3 }),
            "AuthorityRefusal",
        ),
    ];
    let counter = AtomicU64::new(0);
    let timing = Timing::new(&counter, 1, "Preparation", u64::MAX);
    for (error, reason) in cases {
        let error = error.context("private recovery context");
        assert_eq!(resume_failure_reason(&error), reason);
        let mut output = Vec::new();
        timing.write_resume_failure(
            &mut output,
            u64::MAX,
            ResumeStage::RetainedOperation,
            &error,
        );
        let record = String::from_utf8(output).unwrap();
        assert!(record.contains(&format!(" reason={reason} ")));
        assert!(!record.contains("private"));
        assert!(!record.contains("code 3"));
        assert!(record.len() < 256);
    }
}

#[test]
fn retained_command_timing_uses_static_names_without_request_fields() {
    let counter = AtomicU64::new(0);
    let timing = Timing::new(&counter, 1, "Preparation", u64::MAX);
    let command = crate::authority_domains::streams::Command::RetirementContext {
        session: crate::authority_proof::VersionRef {
            kind: 173,
            id: [91; 32],
            generation: 123,
            digest: [92; 32],
        },
    };
    let mut output = Vec::new();
    timing.write(&mut output, u64::MAX, command.name(), "ResumeRetained");
    let record = String::from_utf8(output).unwrap();
    assert!(record.contains("phase=StreamRetirementContext state=ResumeRetained"));
    assert!(!record.contains(&hex::encode([91; 32])));
    assert!(!record.contains(&hex::encode([92; 32])));
    assert!(record.len() < 256);
    let capped = Timing::new(&counter, 1, "Preparation", u64::MAX);
    let mut output = Vec::new();
    capped.write(&mut output, u64::MAX, command.name(), "ResumeRetained");
    assert!(output.is_empty());
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
