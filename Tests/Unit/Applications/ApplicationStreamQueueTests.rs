// SPDX-License-Identifier: MIT
// Exercise the production actor queue with original job identities, bounds and shutdown.
use super::super::{Target, streams, timing};
use super::*;
use crate::{authority_inspection::read_client::RetryBudget, authority_proof::VersionRef};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

fn plan(id: u8, deadline: u64, cancelled: Arc<AtomicBool>) -> Job {
    let (reply, _) = mpsc::sync_channel(1);
    Job::Plan(
        Target {
            service: id.to_string(),
            protocol: "test".into(),
            grant: String::new(),
            route: "UnusedRoute".into(),
            renewal_ms: 0,
        },
        RetryBudget::new(deadline, move || cancelled.load(Ordering::Acquire)),
        timing::Timing::plan(deadline),
        reply,
    )
}

fn preparation(id: u8) -> Job {
    plan(id, u64::MAX, Arc::new(AtomicBool::new(false)))
}

fn cleanup(id: u8, deadline: u64) -> Job {
    let reference = |kind| VersionRef {
        kind,
        id: [31; 32],
        generation: 7,
        digest: [32; 32],
    };
    Job::Done(
        Box::new(streams::Proof {
            service: reference(172),
            principal: [33; 32],
            grant: reference(102),
            protocol: "test".into(),
            slot: 3,
            generation: 8,
            nonce: [id; 32],
            challenge: [34; 32],
            exporter: [35; 32],
            limits: crate::route_profile::Limits {
                bytes: 4096,
                duration_ms: 10000,
                idle_ms: 5000,
            },
            expires: 90000,
            envelope: vec![id, 37, 38],
        }),
        deadline,
        timing::Timing::cleanup(deadline),
    )
}

fn identity(job: Job) -> (bool, u8) {
    match job {
        Job::Plan(target, ..) => (true, target.service.parse().unwrap()),
        Job::Done(proof, ..) => (false, proof.nonce[0]),
    }
}

#[test]
fn preparation_arriving_during_cleanup_is_selected_before_queued_cleanup_burst() {
    let (sender, receiver) = channel();
    for id in 0..4 {
        assert!(sender.try_send(cleanup(id, 100 + u64::from(id))).is_ok());
    }
    let active = receiver.recv().unwrap();
    assert!(matches!(&active, Job::Done(proof, ..) if proof.nonce[0] == 0));
    // The actor owns the first cleanup while a concurrent producer enqueues a plan.
    let producer = sender.clone();
    thread::spawn(move || assert!(producer.try_send(preparation(10)).is_ok()))
        .join()
        .unwrap();
    drop(active);
    assert_eq!(identity(receiver.recv().unwrap()), (true, 10));
    for id in 1..4 {
        assert_eq!(identity(receiver.recv().unwrap()), (false, id));
    }
    // An idle cleanup class cannot consume a turn or stall preparation-only work.
    assert!(sender.try_send(preparation(11)).is_ok());
    assert!(sender.try_send(preparation(12)).is_ok());
    assert_eq!(identity(receiver.recv().unwrap()), (true, 11));
    assert_eq!(identity(receiver.recv().unwrap()), (true, 12));
}

#[test]
fn sustained_mixed_work_alternates_and_preserves_fifo_with_one_sixteen_job_limit() {
    let (sender, receiver) = channel();
    for id in 0..8 {
        assert!(sender.try_send(cleanup(id, u64::from(id))).is_ok());
        assert!(sender.try_send(preparation(id)).is_ok());
    }
    assert!(matches!(
        sender.try_send(preparation(99)),
        Err(TrySendError::Full(_))
    ));
    assert!(matches!(
        sender.try_send(cleanup(99, 0)),
        Err(TrySendError::Full(_))
    ));
    for id in 0..32 {
        assert_eq!(identity(receiver.recv().unwrap()), (true, id));
        assert!(sender.try_send(preparation(id + 8)).is_ok());
        assert_eq!(identity(receiver.recv().unwrap()), (false, id));
        assert!(sender.try_send(cleanup(id + 8, u64::from(id + 8))).is_ok());
        assert!(matches!(
            sender.try_send(preparation(99)),
            Err(TrySendError::Full(_))
        ));
    }
    drop(sender);
    for id in 32..40 {
        assert_eq!(identity(receiver.recv().unwrap()), (true, id));
        assert_eq!(identity(receiver.recv().unwrap()), (false, id));
    }
    assert!(receiver.recv().is_err());
}

#[test]
fn reordering_preserves_expired_and_cancelled_budgets_and_exact_cleanup_proof() {
    let (sender, receiver) = channel();
    let cancelled = Arc::new(AtomicBool::new(false));
    assert!(sender.try_send(cleanup(41, 1)).is_ok());
    assert!(
        sender
            .try_send(plan(42, 0, Arc::new(AtomicBool::new(false))))
            .is_ok()
    );
    assert!(
        sender
            .try_send(plan(43, u64::MAX, cancelled.clone()))
            .is_ok()
    );
    cancelled.store(true, Ordering::Release);
    let Job::Plan(_, budget, _, _) = receiver.recv().unwrap() else {
        panic!("preparation turn")
    };
    assert_eq!(budget.transport().deadline, 0);
    assert!(budget.check().is_err());
    let Job::Done(proof, deadline, _) = receiver.recv().unwrap() else {
        panic!("cleanup turn")
    };
    assert_eq!(deadline, 1);
    assert_eq!(proof.generation, 8);
    assert_eq!(proof.nonce, [41; 32]);
    assert_eq!(proof.envelope, [41, 37, 38]);
    let Job::Plan(_, budget, _, _) = receiver.recv().unwrap() else {
        panic!("remaining preparation")
    };
    assert_eq!(budget.transport().deadline, u64::MAX);
    assert!(budget.transport().cancelled());
    assert!(budget.check().is_err());
}

#[test]
fn completion_sender_backpressure_releases_on_space_and_receiver_shutdown() {
    for disconnect in [false, true] {
        let (sender, receiver) = channel();
        for id in 0..16 {
            assert!(sender.try_send(preparation(id)).is_ok());
        }
        let (entered, starting) = mpsc::channel();
        let (finished, result) = mpsc::channel();
        let producer = sender.clone();
        let worker = thread::spawn(move || {
            entered.send(()).unwrap();
            let outcome = producer.send(cleanup(42, 9));
            finished.send(outcome.is_ok()).unwrap();
        });
        starting.recv_timeout(Duration::from_secs(2)).unwrap();
        let early = result.recv_timeout(Duration::from_millis(20));
        if disconnect {
            drop(receiver);
        } else {
            assert_eq!(identity(receiver.recv().unwrap()), (true, 0));
            // Keep the receiver alive until the blocked completion is accepted.
            let accepted = result.recv_timeout(Duration::from_secs(2));
            drop(receiver);
            worker.join().unwrap();
            assert!(early.is_err());
            assert!(accepted.unwrap());
            continue;
        }
        let accepted = result.recv_timeout(Duration::from_secs(2));
        worker.join().unwrap();
        assert!(early.is_err());
        assert!(!accepted.unwrap());
        assert!(matches!(
            sender.try_send(preparation(99)),
            Err(TrySendError::Disconnected(_))
        ));
    }
}

#[test]
fn last_sender_wakes_empty_receiver_and_dropped_receiver_releases_queued_reply() {
    let (sender, receiver) = channel();
    let (finished, result) = mpsc::channel();
    let worker = thread::spawn(move || finished.send(receiver.recv().is_err()).unwrap());
    drop(sender);
    let completed = result.recv_timeout(Duration::from_secs(2));
    // A failure must not wait indefinitely in join on an unnotified receiver.
    assert!(completed.is_ok());
    worker.join().unwrap();
    assert!(completed.unwrap());

    let (sender, receiver) = channel();
    let Job::Plan(target, budget, timing, _) = preparation(1) else {
        unreachable!()
    };
    let (reply, waiting) = mpsc::sync_channel(1);
    assert!(
        sender
            .try_send(Job::Plan(target, budget, timing, reply))
            .is_ok()
    );
    drop(receiver);
    assert!(matches!(
        waiting.recv_timeout(Duration::from_secs(2)),
        Err(mpsc::RecvTimeoutError::Disconnected)
    ));
}

#[test]
fn poisoned_queue_refuses_jobs_and_shutdown_releases_waiting_replies() {
    let (sender, receiver) = channel();
    let Job::Plan(target, budget, timing, _) = preparation(1) else {
        unreachable!()
    };
    let (reply, waiting) = mpsc::sync_channel(1);
    assert!(
        sender
            .try_send(Job::Plan(target, budget, timing, reply))
            .is_ok()
    );
    let shared = sender.0.clone();
    assert!(
        thread::spawn(move || {
            let _state = shared.state.lock().unwrap();
            panic!("queue poison fixture");
        })
        .join()
        .is_err()
    );
    assert!(receiver.recv().is_err());
    assert!(matches!(
        sender.try_send(preparation(2)),
        Err(TrySendError::Disconnected(_))
    ));
    assert!(sender.send(cleanup(3, 0)).is_err());
    drop(receiver);
    drop(sender);
    assert!(matches!(
        waiting.recv_timeout(Duration::from_secs(2)),
        Err(mpsc::RecvTimeoutError::Disconnected)
    ));
}
