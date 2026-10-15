// SPDX-License-Identifier: MIT
// Sealed readers verify current authority and decrypt source and media only into memory.
use super::*;
use crate::{markup, page_view, reader};

struct Frame {
    document: markup::Document,
    content: crypto::Container,
    metadata: Vec<String>,
}
pub(super) fn run(command: Command) -> Result<()> {
    match command {
        Command::Inspect {
            local,
            binding: binding_path,
            policy: policy_path,
            submission,
            display,
        } => {
            let verified = control::bootstrap(&local.location)?;
            let vault = vault(&local.vault, &verified)?;
            let device = binding(&read(&binding_path)?, &verified)?;
            let key = context::own_device(&vault, &device)?;
            let encrypted = files::read_public_single(&submission, crypto::MAXIMUM_CIPHERTEXT)?;
            let digest = crypto::ciphertext_digest(&encrypted);
            let s = verified.descriptor().scope();
            let submitted = data::Submission::open(
                &key,
                &encrypted,
                &device.reference,
                s.network,
                s.incarnation,
            )?;
            let policy = policy(&read(&policy_path)?, &verified)?;
            let author = submitted.validate(&policy, local_now()?)?;
            let document = submitted.document()?;
            let metadata = vec![
                "Private author submission; inspection grants no publication approval".into(),
                format!(
                    "Object {} revision {}",
                    hex::encode(author.object),
                    author.revision
                ),
                format!("Exact encrypted submission {}", hex::encode(digest)),
                format!("Publisher {}", hex::encode(author.publisher)),
            ];
            {
                let session = reader::Session::new(display.tui, display.ascii)?;
                session.configure_graphics(&display.graphics)?;
                let mut view = page_view::View::new();
                session.preflight(&document, &view)?;
                let mut status =
                    "Inspect the complete source and explicitly reveal each required image".into();
                loop {
                    match show(
                        &session,
                        &document,
                        &submitted.assets,
                        &metadata,
                        &mut view,
                        &mut status,
                    )? {
                        reader::Action::Quit => break,
                        reader::Action::Refresh => {
                            status = match submitted.validate(&policy, local_now()?) {
                                Ok(_) => "Exact retained submission is valid; current authority is checked at finalisation".into(),
                                Err(error) => reader::bounded_status(&format!("Submission validation refused: {error:#}")),
                            };
                        }
                        _ => status = "Private inspection does not navigate or submit forms".into(),
                    }
                }
            }
            crate::print_value(
                &json!({"status":"SealedSubmissionInspected","submissionDigest":hex::encode(digest),"object":hex::encode(author.object),"revision":author.revision}),
            )
        }
        Command::Read {
            local,
            socket,
            capability,
            device,
            object,
            display,
        } => {
            let verified = control::bootstrap(&local.location)?;
            let vault = vault(&local.vault, &verified)?;
            let device = id(&device)?;
            let key = vault.device_identity(device)?;
            let object = id(&object)?;
            let mut c = Client::owned(&local.location, &socket, vault.device_signer(device)?)?;
            let grant = c.grant(capability)?;
            let mut frame = fetch(&mut c, &grant, &vault, &key, device, object)?;
            let session = reader::Session::new(display.tui, display.ascii)?;
            session.configure_graphics(&display.graphics)?;
            let mut view = page_view::View::new();
            session.preflight(&frame.document, &view)?;
            let mut status =
                "Verified at fetch; retained display. Refresh checks current permission".into();
            loop {
                match show(&session, &frame.document, &frame.content.assets, &frame.metadata, &mut view, &mut status)? {
                    reader::Action::Quit => return Ok(()),
                    reader::Action::Refresh => {
                        match fetch(&mut c, &grant, &vault, &key, device, object) {
                            Ok(next) => {
                                let next_view = page_view::View::new();
                                session.preflight(&next.document, &next_view)?;
                                frame = next;
                                view = next_view;
                                status = "Fresh authority and encrypted content verified; display retained in memory".into();
                            }
                            Err(error) => status = reader::bounded_status(&format!("Current refresh refused; retained display: {error:#}")),
                        }
                    }
                    _ => status = "Use a separate sealed read for another object; forms and external navigation are unavailable".into(),
                }
            }
        }
        _ => anyhow::bail!("not a sealed reader command"),
    }
}

fn fetch(
    c: &mut Client,
    grant: &VersionRef,
    vault: &Vault,
    key: &age::x25519::Identity,
    device_id: Digest,
    object: Digest,
) -> Result<Frame> {
    Ok(acquire(c, grant, vault, key, device_id, object)?.0)
}
pub(crate) fn retain(
    c: &mut Client,
    grant: &VersionRef,
    vault: &Vault,
    device: Digest,
    object: Digest,
) -> Result<crate::search::library::Entry> {
    let key = vault.device_identity(device)?;
    Ok(acquire(c, grant, vault, &key, device, object)?.1)
}
fn acquire(
    c: &mut Client,
    grant: &VersionRef,
    vault: &Vault,
    key: &age::x25519::Identity,
    device_id: Digest,
    object: Digest,
) -> Result<(Frame, crate::search::library::Entry)> {
    resume(c, grant, device_id, object)?;
    let result = c.domain_action(
        identity::Command::Context {
            kind: 108,
            lookup: device_id,
        }
        .into(),
        None,
    )?;
    let s = c.bootstrap.descriptor().scope();
    let (n, i) = (s.network, s.incarnation);
    let device = identity::Binding::parse(
        &identity::payload(result.cache.state.record(108, device_id)?)?,
        n,
        i,
    )?;
    context::own_device(vault, &device)?;
    let result = c.domain_action(
        publication::Command::ReaderContext {
            object,
            device: device.reference.clone(),
        }
        .into(),
        Some(grant.clone()),
    )?;
    let head = publication::Head::parse(
        &result
            .cache
            .state
            .record(publication::OBJECT_HEAD, object)?
            .payload,
    )?;
    let reference = head
        .published
        .context("sealed object has no current publication")?;
    let outer =
        publication::Outer::parse(&result.cache.state.record(113, reference.id)?.bytes, n, i)?;
    ensure!(
        outer.reference == reference && outer.object == object,
        "sealed reader publication changed"
    );
    let result = c.domain_action(
        publication::Command::Read {
            outer: reference.clone(),
            device: device.reference,
        }
        .into(),
        Some(grant.clone()),
    )?;
    let state = publication::PublicationState::parse(
        &result
            .cache
            .state
            .record(publication::PUBLICATION_STATE, reference.id)?
            .payload,
    )?;
    ensure!(
        state.outer == reference && state.status == 1,
        "sealed publication is not currently published"
    );
    let policy = policy(&result.cache.state.record(104, object)?.bytes, &c.bootstrap)?;
    ensure!(
        policy.reference == state.policy,
        "sealed current policy differs from publication"
    );
    let ciphertext =
        content_cli::fetch_source(c, grant, &state.placement, page::content::Effect::Read)?;
    let content = crypto::open(
        key,
        &ciphertext,
        outer.ciphertext,
        &data::context(&outer, n, i),
        |content| {
            data::verify_container(content, &outer, &policy, now(c)?)?;
            Ok(())
        },
    )?;
    let document = data::verify_container(&content, &outer, &policy, now(c)?)?;
    let placement = page::content::Placement::parse(
        &result.cache.state.record(159, state.placement.id)?.payload,
    )?;
    ensure!(
        page::namespace_id(&placement.namespace)? == policy.namespace,
        "sealed retained namespace differs from approved policy"
    );
    let entry = crate::search::library::Entry {
        id: object,
        namespace: placement.namespace,
        grant: grant.clone(),
        publication: outer.reference.clone(),
        retained_at_ms: result.evaluated_at_ms,
        source: crate::search::library::Source::Sealed {
            ciphertext,
            outer: result
                .cache
                .state
                .record(113, outer.reference.id)?
                .bytes
                .clone(),
            policy: result.cache.state.record(104, object)?.bytes.clone(),
            binding: result.cache.state.record(108, device_id)?.bytes.clone(),
            device: device_id,
        },
        lease: None,
    };
    Ok((
        Frame {
            document,
            content,
            metadata: vec![
                "Sealed publication; author and reviewer signatures verified at fetch".into(),
                format!(
                    "Object {} revision {} encryption generation {}",
                    hex::encode(object),
                    outer.revision,
                    outer.encryption_generation
                ),
                format!("Publication {}", hex::encode(outer.reference.digest)),
                "Plaintext is held in this process; fresh access requires current authority".into(),
            ],
        },
        entry,
    ))
}

fn resume(c: &mut Client, grant: &VersionRef, device: Digest, object: Digest) -> Result<()> {
    let Some(pending) = c.store.resume_ordinary()? else {
        return Ok(());
    };
    let operation = domain::Operation::parse(&Intent::from_signed(pending.signed())?)?;
    let s = c.bootstrap.descriptor().scope();
    let cache = c.cache()?;
    let same_outer = |r: &VersionRef| -> Result<bool> {
        let record = cache.state.record(113, r.id)?;
        Ok(record.reference == *r
            && publication::Outer::parse(&record.bytes, s.network, s.incarnation)?.object == object)
    };
    if let domain::Command::Page(page::Command::Content(command)) = &operation.command {
        let placement = match command {
            page::content::Command::Get { placement } => placement,
            page::content::Command::Authorise {
                placement,
                effect: page::content::Effect::Read,
                ..
            } => placement,
            _ => anyhow::bail!("another content operation is pending before sealed read"),
        };
        let r = cache.state.record(159, placement.id)?;
        let p = page::content::Placement::parse(&r.payload)?;
        ensure!(
            r.reference == *placement
                && p.opaque
                && same_outer(&p.revision)?
                && operation.grant.as_ref() == Some(grant),
            "pending content read belongs to another sealed object or grant"
        );
        content_cli::fetch_source(c, grant, placement, page::content::Effect::Read)?;
        return Ok(());
    }
    let valid = match &operation.command {
        domain::Command::SealedIdentity(identity::Command::Context { kind: 108, lookup }) => {
            *lookup == device && operation.grant.is_none()
        }
        domain::Command::SealedPublication(publication::Command::ReaderContext {
            object: expected,
            device: d,
        }) => *expected == object && d.id == device && operation.grant.as_ref() == Some(grant),
        domain::Command::SealedPublication(publication::Command::Read { outer, device: d }) => {
            same_outer(outer)? && d.id == device && operation.grant.as_ref() == Some(grant)
        }
        _ => false,
    };
    ensure!(
        valid,
        "another exact operation is pending before sealed read"
    );
    c.domain_action(operation.command, operation.grant)?;
    Ok(())
}

fn show(
    session: &reader::Session,
    document: &markup::Document,
    assets: &[crypto::Asset],
    metadata: &[String],
    view: &mut page_view::View,
    status: &mut String,
) -> Result<reader::Action> {
    loop {
        let action = session.show(document, metadata, view, status, reader::Mode::Page)?;
        if let reader::Action::Reveal(target) = action {
            let result = (|| {
                let manifest = crate::media::image_asset(document, &target)?;
                let id = data::asset_id(&manifest.id)?;
                let asset = assets
                    .iter()
                    .find(|a| a.id == id)
                    .context("approved sealed media is absent")?;
                let pixels = crate::media_import::render_asset(&manifest, &asset.bytes)?;
                session.install_image(&manifest, pixels)?;
                view.revealed.insert(manifest.id);
                Ok::<_, anyhow::Error>(())
            })();
            *status = match result {
                Ok(()) => "Verified sealed media revealed from memory".into(),
                Err(error) => {
                    reader::bounded_status(&format!("Could not reveal sealed media: {error:#}"))
                }
            };
        } else {
            return Ok(action);
        }
    }
}
