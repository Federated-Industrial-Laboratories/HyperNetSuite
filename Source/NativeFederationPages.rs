// SPDX-License-Identifier: MIT
// Foreign publications preserve source identity and a separate exact local review decision.
use super::*;
pub(super) struct Inspection {
    pub network: Digest,
    pub incarnation: Digest,
    pub record: domain::Record,
    pub revision: fed::ForeignRevision,
    pub bundle: page::objects::Bundle,
}
impl Inspection {
    pub fn from_result(
        result: &ResultState,
        objects: &Resolved,
        qualified: Digest,
        review: bool,
    ) -> Result<Self> {
        let scope = result.prefix.scope();
        let head = fed::ForeignPage::parse(&result.cache.state.record(154, qualified)?.payload)?;
        let r = selected(&result.cache.state, &head, review)?;
        let revision = fed::ForeignRevision::parse(&r.payload)?;
        let bundle = page::objects::Bundle::parse(
            objects.get(&revision.bundle)?,
            revision.source.network,
            revision.source.incarnation,
        )?;
        let out = Self {
            network: scope.network,
            incarnation: scope.incarnation,
            record: r.clone(),
            revision,
            bundle,
        };
        out.validate()?;
        Ok(out)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.record.reference.kind == 155
                && self.record.reference.id == self.revision.identity()?,
            "foreign inspection revision identity differs"
        );
        self.revision.bundle.verify(&self.bundle.bytes)?;
        ensure!(
            self.bundle.author.bytes == self.revision.metadata.author.bytes
                && self.bundle.review.revision == self.revision.native,
            "foreign bundle differs from exact signed source revision"
        );
        Ok(())
    }
    pub fn value(&self) -> V {
        V::Array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("ForeignPageInspection".into()),
            V::Bytes(self.network.to_vec()),
            V::Bytes(self.incarnation.to_vec()),
            V::Bytes(self.record.bytes.clone()),
            V::Bytes(self.bundle.bytes.clone()),
        ])
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let v = wire::decode(bytes)?;
        let f = v.array(7)?;
        ensure!(
            f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "ForeignPageInspection",
            "foreign inspection format differs"
        );
        let network = f[3].fixed()?;
        let incarnation = f[4].fixed()?;
        let record = domain::Record::parse(f[5].bytes()?, network, incarnation)?;
        let revision = fed::ForeignRevision::parse(&record.payload)?;
        let bundle = page::objects::Bundle::parse(
            f[6].bytes()?,
            revision.source.network,
            revision.source.incarnation,
        )?;
        let out = Self {
            network,
            incarnation,
            record,
            revision,
            bundle,
        };
        out.validate()?;
        Ok(out)
    }
    pub fn show(&self, display: cli::Display, height: u64, state: &domain::State) -> Result<()> {
        let document = crate::markup::parse(std::str::from_utf8(&self.bundle.source)?)
            .map_err(anyhow::Error::msg)?;
        let metadata = json!({"mediaAssets":state.records.values().filter(|r|r.reference.kind==144).filter_map(|r| page::Asset::parse(&r.payload).ok().filter(|a|a.revision==self.record.reference).map(|a| Ok(json!({"id":a.manifest.id,"reference":reference(&r.reference)?})))) .collect::<Result<Vec<_>>>()?,"status":"ForeignPublicationVerified","height":height,
            "network":hex::encode(self.network),"incarnation":hex::encode(self.incarnation),
            "qualifiedPage":hex::encode(self.revision.page),"sourceNetwork":hex::encode(self.revision.source.network),
            "sourceIncarnation":hex::encode(self.revision.source.incarnation),"sourcePage":hex::encode(self.bundle.author.raw_page),
            "nativeRevision":reference(&self.revision.native)?,"sourceSharingGeneration":self.revision.share.generation,
            "localRevision":reference(&self.record.reference)?,"forms":"Source-qualified; local Mail submission disabled"});
        // Preview mode exposes inert text and explicit local media only; no native Mail recipient conversion occurs.
        crate::media::local_show(
            &document,
            &[metadata.to_string()],
            display.tui,
            display.ascii,
            &display.graphics,
            &display.media,
        )
    }
}
pub(super) fn selected<'a>(
    state: &'a domain::State,
    head: &fed::ForeignPage,
    review: bool,
) -> Result<&'a domain::Record> {
    let reference = if review {
        head.pending
            .clone()
            .context("foreign Page has no pending revision")?
    } else {
        let published = head
            .published
            .as_ref()
            .context("foreign Page has no local publication")?;
        let record = state.record(156, published.id)?;
        ensure!(
            &record.reference == published,
            "foreign local review changed"
        );
        let review = fed::ForeignReview::parse(&record.payload, state.network, state.incarnation)?;
        ensure!(
            review.approve && !head.withdrawn,
            "foreign Page is withdrawn or rejected"
        );
        review.revision
    };
    let record = state.record(155, reference.id)?;
    ensure!(record.reference == reference, "foreign revision changed");
    Ok(record)
}
pub(super) fn qualified(c: &Client, agreement: Digest, raw: [u8; 16]) -> Result<Digest> {
    let cache = c.cache()?;
    let (n, i) = c.scope();
    let accepted = fed::Agreement::parse(&cache.state.record(151, agreement)?.payload, n, i)?;
    ensure!(
        !accepted.treaty.source_side(n, i)?,
        "foreign publication requires the destination network"
    );
    fed::qualified_page(agreement, &accepted.treaty.source, raw)
}
pub(super) fn publication_context(
    c: &mut Client,
    grant: &VersionRef,
    agreement: Digest,
    raw: [u8; 16],
    review: bool,
) -> Result<(Digest, fed::ForeignRevision)> {
    c.page_context(agreement, raw, if review { 3 } else { 0 }, grant)?;
    let q = qualified(c, agreement, raw)?;
    let cache = c.cache()?;
    let head = fed::ForeignPage::parse(&cache.state.record(154, q)?.payload)?;
    let record = selected(&cache.state, &head, review)?;
    Ok((q, fed::ForeignRevision::parse(&record.payload)?))
}
fn application(c: &Client) -> Result<Option<(VersionRef, page::ApplicationPolicy)>> {
    let cache = c.cache()?;
    let (n, i) = c.scope();
    cache
        .state
        .records
        .get(&(148, c.key.verifying_key().to_bytes()))
        .map(|r| {
            Ok((
                r.reference.clone(),
                page::ApplicationPolicy::parse(r.payload.bytes()?, n, i)?,
            ))
        })
        .transpose()
}
fn decision(
    c: &Client,
    inspection: &Inspection,
    grant: &VersionRef,
    approve: bool,
) -> Result<fed::ForeignReview> {
    ensure!(
        c.scope() == (inspection.network, inspection.incarnation),
        "inspection belongs to another destination"
    );
    let app = application(c)?;
    let mode = app
        .as_ref()
        .map(|(_, a)| a.review.context("application lacks ReviewDecide policy"))
        .transpose()?;
    let mut review = fed::ForeignReview {
        revision: inspection.record.reference.clone(),
        reviewer: c.key.verifying_key().to_bytes(),
        grant: grant.clone(),
        application: app.as_ref().map(|a| a.0.clone()),
        mode: mode.map_or(0, |m| m.0),
        policy: mode.map(|m| m.1),
        approve,
        statement: vec![],
        decided_at_ms: c.clock.health()?.observe()?.wall_ms,
    };
    review.statement = c.statement(
        "FederationReviewStatement",
        review.revision.id,
        0,
        wire::encode(&review.statement_value())?,
    )?;
    fed::ForeignReview::parse(&review.value(), inspection.network, inspection.incarnation)
}
fn review_artifact(inspection: &Inspection, review: &fed::ForeignReview) -> Result<Vec<u8>> {
    wire::encode(&V::Array(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("ForeignPageDecision".into()),
        inspection.value(),
        review.value(),
    ]))
}
fn parse_decision(bytes: &[u8]) -> Result<(Inspection, fed::ForeignReview)> {
    let value = wire::decode(bytes)?;
    let f = value.array(5)?;
    ensure!(
        f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "ForeignPageDecision",
        "foreign decision format differs"
    );
    let inspection = Inspection::parse(&wire::encode(&f[3])?)?;
    let review = fed::ForeignReview::parse(&f[4], inspection.network, inspection.incarnation)?;
    ensure!(
        review.revision == inspection.record.reference,
        "decision names another inspected foreign revision"
    );
    Ok((inspection, review))
}
pub(super) fn run(command: Command) -> Result<()> {
    match command {
        Command::Inspect {
            access,
            selection,
            route,
            display,
            output,
        } => fetch(access, selection, route, display, Some(output), true),
        Command::Read {
            access,
            selection,
            route,
            display,
            output,
        } => fetch(access, selection, route, display, output, false),
        Command::ReviewSign {
            access,
            input,
            decision: choice,
            output,
        } => {
            let inspection = Inspection::parse(&read(&input)?)?;
            let (mut c, grant) = connection::access(access)?;
            c.resume(|_| false)?;
            let (_, current) = publication_context(
                &mut c,
                &grant,
                inspection.revision.agreement,
                inspection.bundle.author.raw_page,
                true,
            )?;
            ensure!(
                current.value() == inspection.revision.value(),
                "pending foreign revision changed; inspect it again"
            );
            let review = decision(
                &c,
                &inspection,
                &grant,
                matches!(choice, cli::Decision::Approve),
            )?;
            files::write_new(&output, &review_artifact(&inspection, &review)?)?;
            crate::print_value(
                &json!({"status":"ForeignReviewDecisionSaved","revision":reference(&review.revision)?,"approve":review.approve,"mode":review.mode}),
            )
        }
        Command::Review {
            online,
            route,
            input,
        } => {
            let (inspection, review) = parse_decision(&read(&input)?)?;
            let mut c = Client::new(&online)?;
            ensure!(
                c.scope() == (inspection.network, inspection.incarnation)
                    && c.key.verifying_key().to_bytes() == review.reviewer,
                "decision belongs to another destination or reviewer"
            );
            if let Some((r, _)) =
                c.resume(|a| matches!(a,Action::Review{review:r,..} if r.value()==review.value()))?
            {
                return summary(&r);
            }
            let (_, current) = publication_context(
                &mut c,
                &review.grant,
                inspection.revision.agreement,
                inspection.bundle.author.raw_page,
                true,
            )?;
            ensure!(
                current.value() == inspection.revision.value(),
                "pending foreign revision changed; inspect and decide again"
            );
            let export = exchange::lease(
                &c,
                &route,
                current.agreement,
                Some(current.metadata.author.raw_page),
                Some(current.native),
                None,
            )?;
            summary(
                &c.action(
                    Action::Review {
                        review: review.clone(),
                        export,
                    },
                    Some(review.grant),
                    Resolved::default(),
                )?
                .0,
            )
        }
        Command::Queue {
            access,
            agreement,
            after,
        } => {
            let (mut c, g) = connection::access(access)?;
            let agreement = id(&agreement)?;
            let after = after.as_deref().map(id).transpose()?;
            if let Some((r, _)) = c.resume(
                |a| matches!(a,Action::Queue{agreement:x,after:y} if *x==agreement&&*y==after),
            )? {
                return summary(&r);
            }
            c.inventory_context(agreement, 3, &g)?;
            summary(
                &c.action(
                    Action::Queue { agreement, after },
                    Some(g),
                    Resolved::default(),
                )?
                .0,
            )
        }
        Command::List {
            access,
            route,
            agreement,
            after,
        } => {
            let (mut c, g) = connection::access(access)?;
            let agreement = id(&agreement)?;
            let after = after.as_deref().map(id).transpose()?;
            if let Some((r,_))=c.resume(|a|matches!(a,Action::List{agreement:x,export} if *x==agreement&&matches!(export.command(),Ok(Action::Export{admission,..}) if matches!(admission.command(),Ok(Action::Admission{after:a,..}) if a==after))))? {return summary(&r)}
            c.inventory_context(agreement, 0, &g)?;
            let export = exchange::lease(&c, &route, agreement, None, None, after)?;
            summary(
                &c.action(
                    Action::List { agreement, export },
                    Some(g),
                    Resolved::default(),
                )?
                .0,
            )
        }
        Command::Withdraw { access, selection } => {
            let (mut c, g) = connection::access(access)?;
            let agreement = id(&selection.agreement)?;
            let raw = raw(&selection.source_page_id)?;
            if let Some((Action::PageWithdraw { page }, _)) = c.pending()? {
                let q = qualified(&c, agreement, raw)?;
                ensure!(page.id == q, "another withdrawal is pending");
                if let Some((r, _)) =
                    c.resume(|a| matches!(a,Action::PageWithdraw{page:p} if p.id==q))?
                {
                    return summary(&r);
                }
            }
            c.resume(|_| false)?;
            c.page_context(agreement, raw, 3, &g)?;
            let q = qualified(&c, agreement, raw)?;
            let r = c.cache()?.state.record(154, q)?.reference.clone();
            summary(
                &c.action(
                    Action::PageWithdraw { page: r },
                    Some(g),
                    Resolved::default(),
                )?
                .0,
            )
        }
        _ => anyhow::bail!("not a foreign Page command"),
    }
}
fn fetch(
    access: cli::Access,
    selection: cli::PageSelection,
    route: cli::Route,
    display: cli::Display,
    output: Option<PathBuf>,
    review: bool,
) -> Result<()> {
    let (mut c, g) = connection::access(access)?;
    let agreement = id(&selection.agreement)?;
    let raw = raw(&selection.source_page_id)?;
    // A retained request already carries the exact treaty and source selection; no fresh lease replaces it.
    let resumed = c.resume(|a| match a {
        Action::Inspect { export, .. } if review => {
            matches!(export.exported_revision(),Ok((p,_)) if p==raw)
                && matches!(export.command(),Ok(Action::Export{agreement:a,..}) if a.id==agreement)
        }
        Action::Read { export, .. } if !review => {
            matches!(export.exported_revision(),Ok((p,_)) if p==raw)
                && matches!(export.command(),Ok(Action::Export{agreement:a,..}) if a.id==agreement)
        }
        _ => false,
    })?;
    let (result, objects) = if let Some(r) = resumed {
        r
    } else {
        let (q, current) = publication_context(&mut c, &g, agreement, raw, review)?;
        let export = exchange::lease(&c, &route, agreement, Some(raw), Some(current.native), None)?;
        c.action(
            if review {
                Action::Inspect { page: q, export }
            } else {
                Action::Read { page: q, export }
            },
            Some(g),
            Resolved::default(),
        )?
    };
    let q = qualified(&c, agreement, raw)?;
    let inspection = Inspection::from_result(&result, &objects, q, review)?;
    if let Some(output) = output {
        files::write_new(&output, &wire::encode(&inspection.value())?)?;
    }
    inspection.show(display, result.prefix.height(), &result.cache.state)
}
