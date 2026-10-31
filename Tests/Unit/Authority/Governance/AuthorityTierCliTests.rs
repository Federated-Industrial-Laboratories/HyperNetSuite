// SPDX-License-Identifier: MIT
// A reviewed edit requires every distinct impact in one unchanged certified policy view.
use super::*;

fn impact(id: u64) -> Value {
    let mut subject = [0; 32];
    subject[..8].copy_from_slice(&id.to_be_bytes());
    a(vec![
        Value::Uint(3),
        b(&subject),
        b(&[3; 32]),
        b(&[1; 32]),
        Value::Uint(4),
    ])
}
fn pages(rows: &[Value]) -> Vec<Value> {
    let digest = trust_wire::digest(&trust_wire::encode_state(&a(rows.to_vec())).unwrap());
    rows.chunks(128)
        .enumerate()
        .map(|(index, chunk)| {
            a(vec![
                Value::Uint(201),
                Value::Uint(1),
                Value::Text("AuthorityTierPreview".into()),
                a(vec![]),
                a(vec![
                    b(&[1; 32]),
                    b(&[2; 32]),
                    b(&digest),
                    Value::Uint(rows.len() as u64),
                    Value::Uint(index as u64),
                    a(chunk.to_vec()),
                    if (index + 1) * 128 < rows.len() {
                        b(&[9; 32])
                    } else {
                        Value::Null
                    },
                ]),
            ])
        })
        .collect()
}
fn collect(values: Vec<Value>) -> Result<CompletePreview> {
    let mut values = values.into_iter();
    collect_preview(|_| values.next().context("preview omitted a required page"))
}
#[test]
fn tier_preview_requires_complete_consecutive_unchanged_impact_pages() {
    let rows = (1..=129).map(impact).collect::<Vec<_>>();
    let values = pages(&rows);
    assert_eq!(collect(values.clone()).unwrap().3, rows);
    assert!(collect(vec![values[0].clone()]).is_err());
    assert!(collect(vec![values[1].clone(), values[0].clone()]).is_err());
    let mut changed = values.clone();
    let Value::Array(fields) = &mut changed[1] else {
        unreachable!()
    };
    let Value::Array(body) = &mut fields[4] else {
        unreachable!()
    };
    body[1] = b(&[8; 32]);
    assert!(collect(changed).is_err());
    let mut truncated = values;
    let Value::Array(fields) = &mut truncated[0] else {
        unreachable!()
    };
    let Value::Array(body) = &mut fields[4] else {
        unreachable!()
    };
    body[6] = Value::Null;
    assert!(collect(truncated).is_err());
}
#[test]
fn tier_preview_refuses_duplicate_subjects_and_forged_complete_digest() {
    assert!(collect(pages(&[impact(1), impact(1)])).is_err());
    let mut values = pages(&[impact(1)]);
    let Value::Array(fields) = &mut values[0] else {
        unreachable!()
    };
    let Value::Array(body) = &mut fields[4] else {
        unreachable!()
    };
    body[2] = b(&[9; 32]);
    assert!(collect(values).is_err());
}
