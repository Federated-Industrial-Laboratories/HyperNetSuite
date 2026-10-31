// SPDX-License-Identifier: MIT
// Unit tests for Session.
use super::*;

fn session() -> (Session, Receiver<Message>) {
    let (sender, receiver) = sync_channel(1);
    (
        Session {
            sender,
            context: egui::Context::default(),
            closed: Arc::new(AtomicBool::new(false)),
        },
        receiver,
    )
}

#[test]
fn closing_confirmation_never_confirms_a_submission() {
    let (session, receiver) = session();
    let worker = std::thread::spawn(move || {
        session.confirm_form(&serde_json::json!({"recipientAddress":"ExactRecipient"}))
    });
    let Message::Confirm(value, reply) = receiver.recv().unwrap() else {
        panic!("expected review");
    };
    assert_eq!(value["recipientAddress"], "ExactRecipient");
    drop(reply);
    assert_eq!(worker.join().unwrap().unwrap(), None);
}

#[test]
fn closed_window_prevents_new_network_work() {
    let (session, _receiver) = session();
    session.closed.store(true, Ordering::Release);
    assert!(
        session
            .request::<(), _>(|| panic!("network operation after close"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn oversized_review_is_refused_before_delivery() {
    let (session, receiver) = session();
    assert!(session.confirm_form(&"x".repeat(32769)).is_err());
    assert!(receiver.try_recv().is_err());
}
