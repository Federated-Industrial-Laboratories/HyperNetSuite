// SPDX-License-Identifier: MIT
// User actions retain exact signed inputs and expose verified source through the inert renderer.
use super::*;
fn display(bytes: &[u8], metadata: &[String], options: &Display) -> Result<()> {
    let document = crate::markup::parse(std::str::from_utf8(bytes)?).map_err(anyhow::Error::msg)?;
    crate::media::local_show(
        &document,
        metadata,
        options.tui,
        options.ascii,
        &options.graphics,
        &options.media,
    )
}
pub(super) fn run(command: Command) -> Result<()> {
    match command {
        Command::Host { command } => hosts::run(command),
        Command::Application { command } => applications::run(command),
        Command::ReplicaRequest {
            online,
            capability,
            page_id,
            host,
            host_generation,
            host_digest,
            expires_ms,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let host = VersionRef {
                kind: 147,
                id: id(&host)?,
                generation: host_generation,
                digest: id(&host_digest)?,
            };
            if c.store.resume_ordinary()?.is_none() {
                c.action(
                    Action::ReplicaContext {
                        page: raw(&page_id)?,
                        host: host.clone(),
                    },
                    Some(grant.clone()),
                    Resolved::default(),
                )?;
            }
            let (result, _) = c.action(
                Action::ReplicaRequest {
                    page: raw(&page_id)?,
                    host,
                    expires_ms,
                },
                Some(grant),
                Resolved::default(),
            )?;
            summary(&result)
        }
        Command::ReplicaResult {
            online,
            ticket,
            ticket_generation,
            ticket_digest,
            output,
        } => {
            let mut c = Client::new(&online)?;
            let ticket = VersionRef {
                kind: 146,
                id: id(&ticket)?,
                generation: ticket_generation,
                digest: id(&ticket_digest)?,
            };
            let (result, objects) = c.action(
                Action::ReplicaResult {
                    ticket: ticket.clone(),
                },
                None,
                Resolved::default(),
            )?;
            let current = page::Ticket::parse(&result.cache.state.record(146, ticket.id)?.payload)?;
            let delivered = current.delivered.is_some();
            if let Some(bundle) = &current.delivered {
                let bytes = objects.get(bundle)?;
                let scope = result.prefix.scope();
                Bundle::parse(bytes, scope.network, scope.incarnation)?;
                if let Some(output) = output {
                    files::write_new(&output, bytes)?;
                }
            }
            let f = result.value.array(5)?;
            let body = f[4].array(4)?;
            crate::print_value(
                &json!({"status":if delivered{"PageReplicaDelivered"}else{"PageReplicaPending"},"ticket":hex::encode(ticket.id),
                "height":result.prefix.height(),"records":body[1].list(page::MAXIMUM_CONTEXT_RECORDS)?.len()}),
            )
        }
        Command::Preview {
            file,
            display: options,
        } => display(
            &source(&file)?,
            &["UNAPPROVED local Page draft".into()],
            &options,
        ),
        Command::Author {
            online,
            capability,
            source,
            namespace,
            page_id,
            revision,
            expires_ms,
            output,
        } => statements::author(
            online, capability, source, namespace, page_id, revision, expires_ms, output,
        ),
        Command::Submit {
            online,
            statement,
            source: file,
        } => {
            let mut c = Client::new(&online)?;
            let scope = c.bootstrap.descriptor().scope();
            let author = Author::parse(
                &files::read_public_single(&statement, page::MAXIMUM_PROVENANCE)?,
                scope.network,
                scope.incarnation,
            )?;
            ensure!(
                author.intent.requester == c.key.verifying_key().to_bytes(),
                "Page author differs from the active requester"
            );
            let bytes = source(&file)?;
            author.source.verify(&bytes)?;
            let grant = author.grant.clone();
            let (result, _) = c.action(
                Action::Submit { author },
                Some(grant),
                input(Class::PageSource, bytes)?,
            )?;
            summary(&result)
        }
        Command::Queue {
            online,
            capability,
            namespace,
            after,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let (result, _) = c.action(
                Action::Queue {
                    namespace,
                    after: after.as_deref().map(id).transpose()?,
                },
                Some(grant),
                Resolved::default(),
            )?;
            summary(&result)
        }
        Command::Inspect {
            online,
            capability,
            page_id,
            output,
            display: options,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let page_id = raw(&page_id)?;
            let (result, objects) = c.action(
                Action::Inspect { page: page_id },
                Some(grant),
                Resolved::default(),
            )?;
            let inspected = statements::Inspection::from_result(&result, &objects, page_id)?;
            let scope = result.prefix.scope();
            files::write_new(
                &output,
                &inspected.encode(scope.network, scope.incarnation)?,
            )?;
            display(
                &inspected.source,
                &[
                    "Unapproved Page revision retained for review".into(),
                    format!(
                        "Page {} revision {}",
                        hex::encode(page_id),
                        inspected.revision.author.intent.revision
                    ),
                ],
                &options,
            )
        }
        Command::ReviewSign {
            online,
            capability,
            input,
            decision,
            expires_ms,
            output,
        } => statements::review(online, capability, input, decision, expires_ms, output),
        Command::Review {
            online,
            input: file,
        } => {
            let bytes = files::read_single(
                &file,
                crate::authority_objects::PAGE_BUNDLE_BYTES
                    + crate::authority_objects::PAGE_SOURCE_BYTES
                    + page::MAXIMUM_PROVENANCE
                    + 256,
                true,
            )?;
            let value = wire::decode(&bytes)?;
            let fields = value.array(6)?;
            ensure!(
                fields[0].uint()? == 200
                    && fields[1].uint()? == 1
                    && fields[2].text()? == "PageReviewDecision",
                "invalid retained Page decision"
            );
            let mut c = Client::new(&online)?;
            let scope = c.bootstrap.descriptor().scope();
            let review = Reviewer::parse(fields[3].bytes()?, scope.network, scope.incarnation)?;
            ensure!(
                review.intent.requester == c.key.verifying_key().to_bytes(),
                "Page reviewer differs from the active requester"
            );
            ensure!(
                review.approve == (fields[4] != V::Null),
                "Page decision bundle differs"
            );
            let retained_source = fields[5].bytes()?.to_vec();
            review.source.verify(&retained_source)?;
            let source_object = Object::verify(review.source.clone(), retained_source)?;
            let (reference, objects) = if review.approve {
                let bytes = fields[4].bytes()?.to_vec();
                let bundle = Bundle::parse(&bytes, scope.network, scope.incarnation)?;
                ensure!(
                    bundle.review.bytes == review.bytes,
                    "approved bundle has another review statement"
                );
                let reference = Reference::for_bytes(Class::PageBundle, &bytes)?;
                {
                    let mut references = vec![review.source.clone(), reference.clone()];
                    references.sort();
                    (
                        Some(reference.clone()),
                        Resolved::exact(
                            &references,
                            vec![source_object, Object::verify(reference, bytes)?],
                        )?,
                    )
                }
            } else {
                (
                    None,
                    Resolved::exact(std::slice::from_ref(&review.source), vec![source_object])?,
                )
            };
            let grant = review.grant.clone();
            let (result, _) = c.action(
                Action::Review {
                    review,
                    bundle: reference,
                },
                Some(grant),
                objects,
            )?;
            summary(&result)
        }
        Command::Withdraw {
            online,
            capability,
            page_id,
            as_reviewer,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let (result, _) = c.action(
                Action::Withdraw {
                    page: raw(&page_id)?,
                    as_reviewer,
                },
                Some(grant),
                Resolved::default(),
            )?;
            summary(&result)
        }
        Command::List {
            online,
            capability,
            namespace,
            after,
        } => {
            let mut c = Client::new(&online)?;
            let grant = c.grant(capability)?;
            let (result, _) = c.action(
                Action::List {
                    namespace,
                    after: after.as_deref().map(id).transpose()?,
                },
                Some(grant),
                Resolved::default(),
            )?;
            summary(&result)
        }
        Command::Read {
            online,
            capability,
            page_id,
            output,
            display: options,
        } => super::view::read(online, capability, page_id, output, options),
    }
}
