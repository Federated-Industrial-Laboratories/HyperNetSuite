// SPDX-License-Identifier: MIT
// Unit tests for TransferTime.
use super::*;
#[test]
fn expiry_respects_offer_store_and_fixed_review_time() {
    let now = 1_000_000;
    assert_eq!(
        acceptance(now, now + 10_000, 20_000, None).unwrap(),
        now + 10_000
    );
    assert_eq!(
        acceptance(now, now + 10_000, 5_000, None).unwrap(),
        now + 5_000
    );
    assert!(acceptance(now, now + 10_000, 5_000, Some(now + 6_000)).is_err());
    assert!(acceptance(now, now + 1250, 10_000, None).is_err());
    let duration = Duration {
        amount: 7,
        unit: Unit::Days,
    };
    let reviewed = duration.expiry(now).unwrap();
    assert_eq!(reviewed, now + MAXIMUM_LIFETIME_MS);
    assert_eq!(utc(1_000), "1970-01-01 00:00:01.000 UTC");
}
