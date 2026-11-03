// SPDX-License-Identifier: MIT
// Exercise the companion's production candidate selection and reservation cursor.
use super::*;

#[test]
fn reservations_rotate_through_free_tail_before_revisiting_old_live_slots() {
    let service = [31; 32];
    let mut used = BTreeSet::new();
    let mut next = 0;
    let mut inspected = Vec::new();
    // A completed local connection can leave an authoritative slot unretired.
    // Its removal from local reservations must not imply authority to reuse it.
    let mut unretired = BTreeSet::new();
    for expected in 0..streams::SLOTS {
        let selected = client::select_slot(service, &used, next, |slot| {
            inspected.push(slot);
            Ok((!unretired.contains(&slot)).then_some(slot))
        })
        .unwrap();
        assert_eq!(selected, expected);
        reserve_slot(&mut used, &mut next, service, selected);
        assert!(used.remove(&(service, selected)));
        unretired.insert(selected);
    }
    assert_eq!(inspected, (0..streams::SLOTS).collect::<Vec<_>>());
    assert_eq!(next, 0);
    assert!(used.is_empty());
    let mut exhausted = Vec::new();
    let error = client::select_slot::<u64>(service, &used, next, |slot| {
        exhausted.push(slot);
        Ok(None)
    })
    .unwrap_err();
    assert!(error.is::<Capacity>());
    assert_eq!(exhausted, (0..streams::SLOTS).collect::<Vec<_>>());
    assert_eq!(next, 0);
}

#[test]
fn selection_wraps_once_skips_only_matching_reservations_and_keeps_current_lookup() {
    let service = [31; 32];
    let other = [32; 32];
    let mut used = BTreeSet::from([(service, 14), (other, 15)]);
    let mut next = 14;
    let mut inspected = Vec::new();
    let selected = client::select_slot(service, &used, next, |slot| {
        inspected.push(slot);
        // The first fresh result still has a live proof; the second is reusable.
        Ok((slot == 0).then_some((slot, 7)))
    })
    .unwrap();
    assert_eq!(inspected, [15, 0]);
    assert_eq!(selected, (0, 7));
    reserve_slot(&mut used, &mut next, service, selected.0);
    assert_eq!(next, 1);
    assert!(used.contains(&(service, 0)));
    // A failed reply removes the reservation, but does not rewind ordering.
    assert!(used.remove(&(service, 0)));
    assert_eq!(next, 1);
    let mut looked_up = false;
    let selected = client::select_slot(service, &used, next, |slot| {
        looked_up = true;
        assert_eq!(slot, 1);
        Ok(Some((slot, 19)))
    })
    .unwrap();
    assert!(looked_up);
    assert_eq!(selected, (1, 19));
    assert_eq!(next, 1); // Selection alone is not a reservation.
}

#[test]
fn fresh_lookup_failure_stops_selection_without_reclassifying_or_reserving() {
    let service = [31; 32];
    let used = BTreeSet::new();
    let next = 9;
    let mut inspected = Vec::new();
    let error = client::select_slot::<u64>(service, &used, next, |slot| {
        inspected.push(slot);
        anyhow::bail!("fresh authority denied")
    })
    .unwrap_err();
    assert_eq!(error.to_string(), "fresh authority denied");
    assert!(!error.is::<Capacity>());
    assert_eq!(inspected, [9]);
    assert_eq!(next, 9);
    assert!(used.is_empty());
}

#[test]
fn exhausted_candidates_are_bounded_and_cursors_are_independent_per_service() {
    let service = [31; 32];
    let other = [32; 32];
    let mut used = BTreeSet::new();
    let mut starts = BTreeMap::from([(service, 13), (other, 4)]);
    let mut inspected = Vec::new();
    let error = client::select_slot::<u64>(service, &used, starts[&service], |slot| {
        inspected.push(slot);
        Ok(None)
    })
    .unwrap_err();
    assert!(error.is::<Capacity>());
    assert_eq!(inspected.len(), 16);
    assert_eq!(inspected.iter().copied().collect::<BTreeSet<_>>().len(), 16);
    assert_eq!(&inspected[..4], &[13, 14, 15, 0]);
    assert_eq!(inspected.last(), Some(&12));
    let selected =
        client::select_slot(other, &used, starts[&other], |slot| Ok(Some(slot))).unwrap();
    reserve_slot(&mut used, starts.get_mut(&other).unwrap(), other, selected);
    assert_eq!(starts[&other], 5);
    assert_eq!(starts[&service], 13);
    used.extend((0..streams::SLOTS).map(|slot| (service, slot)));
    let error = client::select_slot::<u64>(service, &used, starts[&service], |_| {
        panic!("a locally reserved slot must not be looked up")
    })
    .unwrap_err();
    assert!(error.is::<Capacity>());
}
