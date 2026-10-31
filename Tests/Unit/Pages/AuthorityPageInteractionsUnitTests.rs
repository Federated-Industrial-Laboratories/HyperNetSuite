// SPDX-License-Identifier: MIT
// Unit tests for AuthorityPageInteractions.
use super::*;

#[test]
fn form_delivery_reports_incomplete_placement_and_exact_message() {
    let message = "ab".repeat(32);
    let mut value = json!({"status":"MailStored", "message":message,
        "confirmedCopies":1, "requiredCopies":2, "delivered":false});
    let status = delivery_status(&value, &message).unwrap();
    assert!(status.contains("incomplete") && status.contains("1/2 copies"));
    assert!(status.contains(&format!("forms send --message {message}")));
    assert!(!status.contains("Form sent"));
    value["confirmedCopies"] = json!(2);
    value["delivered"] = json!(true);
    let status = delivery_status(&value, &message).unwrap();
    assert!(status.contains("Form sent") && status.contains("2/2 copies"));
    assert!(delivery_status(&value, &"cd".repeat(32)).is_err());
    value["delivered"] = json!(false);
    assert!(delivery_status(&value, &message).is_err());
}
