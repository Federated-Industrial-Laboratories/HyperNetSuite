// SPDX-License-Identifier: MIT
// Durable ranges survive a retry before acknowledgement and reject changed or corrupt content.
use super::*;
use crate::authority_deployment_tests as deployment;

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn media_progress_reopens_before_ack_and_rejects_conflicting_ranges_and_corruption() {
    progress_contract(page::MediaEffect::Read);
}
#[test]
fn repeated_media_repair_restarts_complete_jobs_but_preserves_unacknowledged_and_partial_ranges() {
    progress_contract(page::MediaEffect::Repair);
}
fn progress_contract(effect: page::MediaEffect) {
    let root = std::env::temp_dir().join(format!(
        "HyperNetMediaProgress{}",
        crate::random_hex::<16>()
    ));
    let _cleanup = Directory(root.clone());
    let context = (
        [20; 32],
        [21; 32],
        deployment::key(5).verifying_key().to_bytes(),
    );
    let host_key = deployment::key(101);
    let host = VersionRef {
        kind: 143,
        id: host_key.verifying_key().to_bytes(),
        generation: 1,
        digest: [61; 32],
    };
    let bytes = vec![73; 192 * 192 * 3];
    let asset = page::Asset {
        revision: VersionRef {
            kind: 141,
            id: [62; 32],
            generation: 1,
            digest: [63; 32],
        },
        manifest: crate::markup::media::Asset {
            id: "Poster".into(),
            profile: crate::markup::media::RASTER_PROFILE.into(),
            width: 192,
            height: 192,
            bytes: bytes.len() as u64,
            digest: hex::encode(digest(&bytes)),
            hosts: vec![hex::encode(host.id)],
            copies: 1,
        },
        hosts: vec![host.clone()],
        required_copies: 1,
        upload_expires_ms: 50000,
        expires_ms: 100000,
    };
    let mut state = domain::State::empty(context.0, context.1);
    let record =
        domain::Record::next(&state, 144, asset.identity().unwrap(), asset.value()).unwrap();
    let asset_ref = record.reference.clone();
    state.put(record).unwrap();
    let upload = effect.writes().then_some(bytes.as_slice());
    let request = |offset: usize, length: usize| {
        let operation = domain::Operation {
            grant: Some(VersionRef {
                kind: 102,
                id: [64; 32],
                generation: 1,
                digest: [65; 32],
            }),
            command: Action::MediaAuthorise {
                asset: asset_ref.clone(),
                host: host.clone(),
                effect,
                offset: offset as u64,
                bytes: length as u64,
                digest: upload.map(|v| digest(&v[offset..offset + length])),
            }
            .into(),
            snapshot: domain::snapshot(&deployment::snapshot(&[])).unwrap(),
        };
        page::MediaRequest::parse(&deployment::signed(
            &deployment::key(5),
            "AuthorityDomain",
            operation.command.resource(),
            0,
            wire::decode(&operation.parameters().unwrap()).unwrap(),
            vec![],
        ))
        .unwrap()
    };
    let mut receipt = page::CopyReceipt {
        asset: asset_ref.clone(),
        host: host.clone(),
        request: [66; 32],
        digest: digest(&bytes),
        bytes: bytes.len() as u64,
        recorded_ms: 1000,
        envelope: vec![],
    };
    receipt.envelope =
        wire::sign_envelope(&receipt.payload(context.0, context.1).unwrap(), &host_key).unwrap();
    let response = |offset: usize, payload: &[u8]| {
        wire::encode(&V::Array(vec![
            V::Uint(201),
            V::Uint(1),
            V::Text("PageMediaEffect".into()),
            crate::authority_membership::reference(&asset_ref),
            crate::authority_membership::reference(&host),
            V::Uint(effect.code()),
            V::Uint(offset as u64),
            V::Uint(payload.len() as u64),
            V::Bytes(digest(payload).to_vec()),
            V::Bytes(payload.to_vec()),
            V::Bytes(receipt.envelope.clone()),
        ]))
        .unwrap()
    };
    let mut job =
        Progress::open(&root, context, &state, &asset_ref, host.id, effect, upload).unwrap();
    let first = request(0, 32768);
    job.apply(&first, &response(0, &bytes[..32768])).unwrap();
    drop(job);
    let mut job =
        Progress::open(&root, context, &state, &asset_ref, host.id, effect, upload).unwrap();
    assert_eq!(job.offset, 32768);
    job.begin_repair(false).unwrap();
    assert_eq!(job.offset, 32768);
    job.apply(&first, &response(0, &bytes[..32768])).unwrap();
    let mut changed = bytes[..32768].to_vec();
    changed[0] ^= 1;
    if upload.is_none() {
        assert!(job.apply(&first, &response(0, &changed)).is_err());
    }
    for offset in (32768..bytes.len()).step_by(32768) {
        let end = (offset + 32768).min(bytes.len());
        job.apply(
            &request(offset, end - offset),
            &response(offset, &bytes[offset..end]),
        )
        .unwrap();
    }
    drop(job);
    let mut job =
        Progress::open(&root, context, &state, &asset_ref, host.id, effect, upload).unwrap();
    assert_eq!(job.bytes, bytes);
    assert_eq!(job.offset, bytes.len() as u64);
    assert!(job.receipt.is_some());
    job.begin_repair(true).unwrap();
    assert_eq!(job.offset, bytes.len() as u64);
    assert!(job.receipt.is_some());
    job.begin_repair(false).unwrap();
    let expected_offset = if upload.is_some() {
        0
    } else {
        bytes.len() as u64
    };
    assert_eq!(job.offset, expected_offset);
    assert_eq!(job.receipt.is_none(), upload.is_some());
    drop(job);
    let job = Progress::open(&root, context, &state, &asset_ref, host.id, effect, upload).unwrap();
    assert_eq!(job.offset, expected_offset);
    assert_eq!(job.bytes, bytes);
    drop(job);
    let mut other = context;
    other.2 = deployment::key(6).verifying_key().to_bytes();
    assert!(Progress::open(&root, other, &state, &asset_ref, host.id, effect, upload).is_err());
    let mut value = wire::decode_state(&std::fs::read(root.join(FILE)).unwrap()).unwrap();
    let V::Array(ref mut fields) = value else {
        unreachable!()
    };
    let V::Bytes(ref mut stored) = fields[11] else {
        unreachable!()
    };
    stored[0] ^= 1;
    std::fs::write(root.join(FILE), wire::encode_state(&value).unwrap()).unwrap();
    assert!(Progress::open(&root, context, &state, &asset_ref, host.id, effect, upload).is_err());
}
