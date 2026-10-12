// SPDX-License-Identifier: MIT
// Signed foreign bundles keep source identity and cannot become native Mail publications.
use super::*;
use crate::{
    authority_deployment_tests as fixture,
    authority_objects::{Class, Reference},
};
const N: Digest = [20; 32];
const I: Digest = [21; 32];
fn r(kind: u64, id: Digest) -> VersionRef {
    VersionRef {
        kind,
        id,
        generation: 1,
        digest: [91; 32],
    }
}
fn inspection() -> pages::Inspection {
    let source_identity = fed::NetworkIdentity {
        network: N,
        incarnation: I,
        file_digest: [81; 32],
        fingerprint: [82; 32],
    };
    let grant = r(102, [23; 32]);
    let now = crate::now().unwrap() * 1000;
    let source = format!(
        "HyperNetPage/2\n# Foreign forms\n@Form {{\"id\":\"Contact\",\"label\":\"Contact\",\"profile\":\"HyperNetFormMail/1\",\"recipient\":\"{}\",\"owner\":\"{}\"}}\n@Field {{\"id\":\"Name\",\"label\":\"Name\",\"kind\":\"Text\",\"maxBytes\":40,\"required\":true}}\n@Submit {{\"label\":\"Send\"}}\n@End\n",
        hex::encode([75; 32]),
        hex::encode(fixture::key(7).verifying_key().to_bytes())
    );
    let sr = Reference::for_bytes(Class::PageSource, source.as_bytes()).unwrap();
    let raw = [71; 16];
    let pageid = page::page_id(&raw).unwrap();
    let parameters = page::objects::Author::parameters(
        raw,
        "Books",
        source.as_bytes(),
        &grant,
        None,
        now + 600000,
    )
    .unwrap();
    let author = page::objects::Author::parse(
        &fixture::signed(
            &fixture::key(5),
            "PageAuthorStatement",
            pageid,
            1,
            wire::decode(&parameters).unwrap(),
            vec![],
        ),
        N,
        I,
    )
    .unwrap();
    let metadata = page::Revision::from_source(author.clone(), source.as_bytes()).unwrap();
    let state = domain::State::empty(N, I);
    let native =
        domain::Record::next(&state, 141, metadata.identity().unwrap(), metadata.value()).unwrap();
    let parameters = page::objects::Reviewer::parameters(
        &native.reference,
        &sr,
        author.intent.requester,
        author.intent.digest,
        &grant,
        None,
        true,
        0,
        None,
        now + page::REVIEW_LIFETIME_MS,
    )
    .unwrap();
    let reviewer = fixture::signed(
        &fixture::key(5),
        "PageReviewStatement",
        pageid,
        1,
        wire::decode(&parameters).unwrap(),
        vec![],
    );
    let bytes = page::objects::Bundle::encode(source.as_bytes(), &author.bytes, &reviewer).unwrap();
    let bundle = page::objects::Bundle::parse(&bytes, N, I).unwrap();
    let agreement = [83; 32];
    let qualified = fed::qualified_page(agreement, &source_identity, raw).unwrap();
    let revision = fed::ForeignRevision {
        page: qualified,
        agreement,
        source: source_identity,
        native: native.reference,
        share: r(153, fed::share_id(agreement, raw).unwrap()),
        bundle: Reference::for_bytes(Class::PageBundle, &bytes).unwrap(),
        imported_at_ms: now,
        evidence: [84; 32],
        metadata,
    };
    let destination = domain::State::empty([30; 32], [31; 32]);
    let record = domain::Record::next(
        &destination,
        155,
        revision.identity().unwrap(),
        revision.value(),
    )
    .unwrap();
    pages::Inspection {
        network: destination.network,
        incarnation: destination.incarnation,
        record,
        revision,
        bundle,
    }
}
#[test]
fn foreign_inspection_binds_source_sharing_and_never_converts_forms_to_local_mail() {
    let original = inspection();
    let bytes = wire::encode(&original.value()).unwrap();
    let decoded = pages::Inspection::parse(&bytes).unwrap();
    assert_eq!(decoded.bundle.author.intent.network, N);
    assert_eq!(decoded.revision.metadata.forms[0].recipient, [75; 32]);
    assert_eq!(decoded.revision.source.network, N);
    let identity = crate::authority_pages::publication::Identity {
        network: hex::encode(decoded.network),
        incarnation: hex::encode(decoded.incarnation),
        page: hex::encode(decoded.bundle.author.raw_page),
        ledger: String::new(),
        revision: String::new(),
        approval: String::new(),
        bundle: String::new(),
    };
    assert!(identity.validate(&decoded.bundle).is_err());
    let mut changed = decoded.revision.clone();
    changed.share.generation += 1;
    assert_ne!(changed.identity().unwrap(), decoded.record.reference.id);
    let record = domain::Record::next(
        &domain::State::empty(decoded.network, decoded.incarnation),
        155,
        decoded.record.reference.id,
        changed.value(),
    );
    assert!(record.is_err());
    let mut v = original.value().array(7).unwrap().to_vec();
    let mut bundle = wire::decode(&original.bundle.bytes)
        .unwrap()
        .array(6)
        .unwrap()
        .to_vec();
    bundle[3] = V::Bytes(b"HyperNetPage/2\n# Replaced\n".to_vec());
    v[6] = V::Bytes(wire::encode(&V::Array(bundle)).unwrap());
    assert!(pages::Inspection::parse(&wire::encode(&V::Array(v)).unwrap()).is_err());
}
#[test]
fn foreign_local_review_is_signed_for_the_exact_qualified_revision_and_destination() {
    let inspection = inspection();
    let key = fixture::key(8);
    let grant = r(102, [44; 32]);
    let mut review = fed::ForeignReview {
        revision: inspection.record.reference.clone(),
        reviewer: key.verifying_key().to_bytes(),
        grant,
        application: None,
        mode: 0,
        policy: None,
        approve: true,
        statement: vec![],
        decided_at_ms: crate::now().unwrap() * 1000,
    };
    let b = |v: &[u8]| V::Bytes(v.to_vec());
    let payload = wire::encode(&V::Array(vec![
        V::Uint(20),
        V::Uint(1),
        b(&inspection.network),
        b(&inspection.incarnation),
        V::Uint(1),
        b(&[87; 32]),
        V::Uint(1),
        V::Uint(0),
        b(&review.reviewer),
        V::Text("FederationReviewStatement".into()),
        b(&review.revision.id),
        V::Uint(0),
        V::Uint(0),
        V::Uint(0),
        V::Uint(0),
        V::Array(vec![]),
        b(&wire::encode(&review.statement_value()).unwrap()),
    ]))
    .unwrap();
    review.statement = wire::sign_envelope(&payload, &key).unwrap();
    fed::ForeignReview::parse(&review.value(), inspection.network, inspection.incarnation).unwrap();
    assert!(fed::ForeignReview::parse(&review.value(), N, I).is_err());
    let mut changed = review.clone();
    changed.approve = false;
    assert!(
        fed::ForeignReview::parse(&changed.value(), inspection.network, inspection.incarnation)
            .is_err()
    );
    changed = review.clone();
    changed.revision.generation += 1;
    assert!(
        fed::ForeignReview::parse(&changed.value(), inspection.network, inspection.incarnation)
            .is_err()
    );
    changed = review;
    changed.mode = 1;
    assert!(
        fed::ForeignReview::parse(&changed.value(), inspection.network, inspection.incarnation)
            .is_err()
    );
}
#[test]
fn native_federation_cli_exposes_explicit_bridge_and_media_routes() {
    use clap::{CommandFactory, Parser};
    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        command: Command,
    }
    Cli::command().debug_assert();
    let trust = Cli::try_parse_from([
        "Federation",
        "trust",
        "inspect",
        "--foreign-bootstrap",
        "Bootstrap.cbor",
        "--foreign-bootstrap-digest",
        &hex::encode([1; 32]),
    ]);
    assert!(trust.is_ok());
    let trust = Cli::try_parse_from([
        "Federation",
        "trust",
        "get",
        "--bootstrap",
        "Bootstrap.cbor",
        "--bootstrap-digest",
        &hex::encode([1; 32]),
        "--directory",
        "State",
        "--clock-witness",
        "ClockHealth.cbor",
        "--key",
        "Operator.key",
        "--socket",
        "Control.sock",
        "--trust",
        &hex::encode([2; 32]),
        "--retained-output",
        "ForeignRetained.json",
    ])
    .unwrap();
    assert!(matches!(
        trust.command,
        Command::Trust {
            command: cli::TrustCommand::Get {
                retained_output: Some(path),
                ..
            }
        } if path == Path::new("ForeignRetained.json")
    ));
    assert!(
        Cli::try_parse_from([
            "Federation",
            "bridge",
            "sync",
            "--agreement",
            &hex::encode([1; 32]),
            "--directory",
            "State",
            "--service-socket",
            "Control.sock"
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "Federation",
            "bridge",
            "sync",
            "--agreement",
            &hex::encode([1; 32]),
            "--directory",
            "State",
            "--service-socket",
            "Control.sock",
            "--service-directory",
            "Bridge"
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "Federation",
            "bridge",
            "sync",
            "--agreement",
            &hex::encode([1; 32]),
            "--directory",
            "State"
        ])
        .is_err()
    );
}
