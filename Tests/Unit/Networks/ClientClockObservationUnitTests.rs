// SPDX-License-Identifier: MIT
// Unit tests for ClientClockObservation.
use super::*;
const BOOT: &str = "12345678-1234-1234-1234-123456789abc";
#[test]
fn decimal_bounds_round_up_and_refuse_unknown_values() {
    assert_eq!(decimal_nanos("-0.0000000001", true).unwrap(), 1);
    assert_eq!(decimal_nanos("0.9999999999", false).unwrap(), 1_000_000_000);
    for value in ["NaN", "inf", "1e-9", "-0.1", "1..0", "18446744073709551615"] {
        assert!(decimal_nanos(value, false).is_err());
    }
}
fn reports() -> (String, String, String, String) {
    let tracking = "C0000201,192.0.2.1,2,1000.000000000,0.001000000,0.001,0.001,0.010,0.001,0.020,0.020,0.001,16.0,Normal\n".into();
    let sources = "^,*,192.0.2.1,1,4,377,0,0.001,0.001,0.001\n".into();
    let auth = "192.0.2.1,NTS,1,15,256,1,0,0,8,100\n".into();
    let mut ntp = vec!["0"; 38];
    ntp[0] = "192.0.2.1";
    ntp[1] = "C0000201";
    ntp[5] = "Normal";
    ntp[6] = "4";
    ntp[7] = "Server";
    ntp[27] = "Yes";
    ntp[33] = "8";
    (tracking, sources, auth, ntp.join(","))
}
#[test]
fn all_six_queries_share_one_budget_and_no_query_starts_after_expiry() {
    use std::cell::Cell;
    let (tracking, sources, auth, ntp) = reports();
    for elapsed_per_query in [20, MAXIMUM_PROBE_MS] {
        let elapsed = Cell::new(0);
        let mut commands = Vec::new();
        let result = probe_with_clock(
            |command, deadline| {
                assert_eq!(deadline, 100 + MAXIMUM_PROBE_MS);
                commands.push(command.to_owned());
                elapsed.set(elapsed.get() + elapsed_per_query);
                Ok(match command {
                    "tracking" => tracking.clone(),
                    "sources" => sources.clone(),
                    "authdata" => auth.clone(),
                    "ntpdata" => ntp.clone(),
                    _ => panic!("unsupported query"),
                })
            },
            || {
                Ok(Moment {
                    wall_ms: 1000010 + elapsed.get(),
                    boot_ms: 100 + elapsed.get(),
                })
            },
        );
        if elapsed_per_query == 20 {
            let witness = result.unwrap();
            assert_eq!(
                commands,
                [
                    "tracking", "sources", "authdata", "ntpdata", "sources", "tracking"
                ]
            );
            assert_eq!(witness.sample_boot_ms, 220);
            assert_eq!(witness.valid_until_boot_ms, 1220);
        } else {
            assert!(result.is_err());
            assert_eq!(commands, ["tracking"]);
        }
    }
}
#[test]
fn expiry_does_not_mask_invalid_clock_progression_or_error() {
    let (t, s, a, n) = reports();
    let before = Moment {
        wall_ms: 1000010,
        boot_ms: 100,
    };
    let after = Moment {
        wall_ms: 1000030,
        boot_ms: 120,
    };
    let witness = qualify(BOOT, before, after, &t, &t, &s, &s, &a, &n).unwrap();
    let expired = Moment {
        wall_ms: after.wall_ms + 1000,
        boot_ms: after.boot_ms + 1000,
    };
    assert!(
        witness
            .health(BOOT, expired)
            .unwrap_err()
            .is::<crate::authority_clock::ObservationExpired>()
    );
    let mut invalid = witness.clone();
    invalid.maximum_error_ms = 251;
    assert!(
        !invalid
            .health(BOOT, expired)
            .unwrap_err()
            .is::<crate::authority_clock::ObservationExpired>()
    );
    assert!(
        !witness
            .health(
                BOOT,
                Moment {
                    wall_ms: expired.wall_ms + 251,
                    ..expired
                }
            )
            .unwrap_err()
            .is::<crate::authority_clock::ObservationExpired>()
    );
}
#[test]
fn health_requires_matching_authenticated_fresh_observations() {
    let (t, s, a, n) = reports();
    let before = Moment {
        wall_ms: 1000010,
        boot_ms: 100,
    };
    let after = Moment {
        wall_ms: 1000030,
        boot_ms: 120,
    };
    let w = qualify(BOOT, before, after, &t, &t, &s, &s, &a, &n).unwrap();
    assert!(w.maximum_error_ms >= 35);
    assert!(
        w.health(
            BOOT,
            Moment {
                wall_ms: 1001030,
                boot_ms: 1120
            }
        )
        .is_err()
    );
    assert!(
        w.health("22345678-1234-1234-1234-123456789abc", after)
            .is_err()
    );
    assert!(
        w.health(
            BOOT,
            Moment {
                wall_ms: 1001030,
                boot_ms: 121
            }
        )
        .is_err()
    );
    assert!(
        qualify(
            BOOT,
            before,
            after,
            &t,
            &t,
            &s,
            &s,
            &a,
            &n.replace("Yes", "No")
        )
        .is_err()
    );
    assert!(
        qualify(
            BOOT,
            before,
            after,
            &t,
            &t,
            &s,
            &s,
            &a.replace("NTS", "-"),
            &n
        )
        .is_err()
    );
    assert!(
        qualify(
            BOOT,
            before,
            after,
            &t,
            &t.replace("Normal", "Not synchronised"),
            &s,
            &s,
            &a,
            &n
        )
        .is_err()
    );
    assert!(
        qualify(
            BOOT,
            before,
            after,
            &t,
            &t,
            &s,
            &s.replace("192.0.2.1", "192.0.2.2"),
            &a,
            &n
        )
        .is_err()
    );
}
