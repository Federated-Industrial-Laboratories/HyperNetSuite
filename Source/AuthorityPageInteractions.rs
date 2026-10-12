// SPDX-License-Identifier: MIT
// Page actions use explicit operator-selected media routes and a separate Mail device.
use super::*;
use crate::{authority_mail, markup, reader};
use std::collections::BTreeMap;

#[derive(Clone, Args)]
#[group(id = "PageInteractions")]
pub(super) struct Options {
    /// Bind a media host key to an explicitly selected private control socket.
    #[arg(long = "media-route", requires = "media_directory")]
    media_routes: Vec<String>,
    /// Bind a media host key to an explicitly selected installed service directory.
    #[arg(long = "media-service", requires = "media_directory")]
    media_services: Vec<String>,
    /// Existing private persistent directory for resumable media reads.
    #[arg(long)]
    media_directory: Option<PathBuf>,
    #[arg(long, default_value = "HyperNet")]
    media_core: PathBuf,
    #[arg(long, requires_all = ["form_vault", "form_age_key", "form_mailbox", "form_service"])]
    form_directory: Option<PathBuf>,
    #[arg(long, requires = "form_directory")]
    form_vault: Option<PathBuf>,
    #[arg(long, requires = "form_directory")]
    form_age_key: Option<PathBuf>,
    #[arg(long, requires = "form_directory")]
    form_mailbox: Option<String>,
    #[arg(long, requires = "form_directory")]
    form_service: Option<String>,
    #[arg(
        long,
        conflicts_with = "form_service_directory",
        requires = "form_directory"
    )]
    form_socket: Option<PathBuf>,
    #[arg(long, conflicts_with = "form_socket", requires = "form_directory")]
    form_service_directory: Option<PathBuf>,
    #[arg(long, default_value = "HyperNet")]
    form_core: PathBuf,
    /// Requested form retention; current Mail policy must also permit this duration.
    #[arg(long, default_value_t = 3600)]
    form_retention_seconds: u64,
}
impl Options {
    fn routes(&self) -> Result<BTreeMap<Digest, media::Transport>> {
        let mut routes = BTreeMap::new();
        for (mappings, installed) in [(&self.media_routes, false), (&self.media_services, true)] {
            for mapping in mappings {
                let (host, path) = mapping
                    .split_once('=')
                    .context("media route requires HostKey=/explicit/path")?;
                let host = id(host)?;
                let path = PathBuf::from(path);
                ensure!(path.is_absolute(), "media route requires an absolute path");
                let route = if installed {
                    media::Transport::installed(host, path, self.media_core.clone())
                } else {
                    media::Transport::socket(host, path)
                };
                ensure!(
                    routes.insert(host, route).is_none(),
                    "duplicate media host route"
                );
            }
        }
        Ok(routes)
    }
    pub(super) fn check(&self) -> Result<()> {
        self.routes()?;
        if let Some(path) = &self.media_directory {
            files::private_directory(path)?;
        }
        if self.form_directory.is_some() {
            self.form_transport()?;
            ensure!(
                self.form_retention_seconds > 0,
                "form retention must be positive"
            );
        }
        Ok(())
    }
    fn form_transport(&self) -> Result<authority_mail::Transport> {
        let service = id(self
            .form_service
            .as_deref()
            .context("select --form-service")?)?;
        match (&self.form_socket, &self.form_service_directory) {
            (Some(path), None) => Ok(authority_mail::Transport::socket(service, path.clone())),
            (None, Some(path)) => Ok(authority_mail::Transport::installed(
                service,
                path.clone(),
                self.form_core.clone(),
            )),
            _ => anyhow::bail!("select one explicit form socket or installed service directory"),
        }
    }
    fn device(&self, online: &Online) -> Result<authority_mail::DeviceOnline> {
        let access = authority_mail::forms::Access {
            directory: self
                .form_directory
                .clone()
                .context("configure --form-directory before submitting")?,
            vault: self.form_vault.clone().context("select --form-vault")?,
            age_key: self.form_age_key.clone().context("select --form-age-key")?,
            mailbox: self.form_mailbox.clone().context("select --form-mailbox")?,
        };
        Ok(access.device(&online.location, &online.socket))
    }
}

/// Return the client even on ordinary failure, preserving its exact pending operation.
pub(super) fn request<T, F>(
    session: &reader::Session,
    client: &mut Option<Client>,
    operation: F,
) -> Result<Option<Result<T>>>
where
    T: Send + 'static,
    F: FnOnce(&mut Client) -> Result<T> + Send + 'static,
{
    let mut c = client.take().context("Page client is unavailable")?;
    let Some((c, result)) = session.request(move || {
        let result = operation(&mut c);
        Ok((c, result))
    })?
    else {
        return Ok(None);
    };
    *client = Some(c);
    Ok(Some(result))
}

pub(super) fn media_bytes(
    c: &mut Client,
    grant: &VersionRef,
    expected: &publication::Identity,
    references: &[VersionRef],
    asset: &markup::media::Asset,
    options: &Options,
) -> Result<Vec<u8>> {
    // An interrupted transfer must reconcile its exact retained operation first.
    if c.store.resume_ordinary()?.is_none() {
        ensure!(
            publication::fetch(c, grant, expected.page_id()?)?.identity == *expected,
            "displayed Page changed before media retrieval"
        );
    }
    let cache = c.cache()?;
    let reference = references
        .iter()
        .find(|r| {
            cache
                .state
                .record(r.kind, r.id)
                .ok()
                .filter(|record| record.reference == **r)
                .and_then(|record| page::Asset::parse(&record.payload).ok())
                .is_some_and(|a| a.manifest == *asset)
        })
        .context("exact displayed media record is absent")?;
    let routes = options.routes()?;
    let (host, transport) = asset
        .hosts
        .iter()
        .map(|h| id(h))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .find_map(|h| routes.get(&h).map(|t| (h, t)))
        .context("configure an explicit route for one of this asset's approved hosts")?;
    let base = options
        .media_directory
        .as_ref()
        .context("select a persistent --media-directory")?;
    files::private_directory(base)?;
    let scope = c.store.descriptor().scope();
    let identity = wire::encode(&V::Array(vec![
        V::Bytes(scope.network.to_vec()),
        V::Bytes(scope.incarnation.to_vec()),
        V::Bytes(c.store.requester().to_vec()),
        crate::authority_membership::reference(reference),
        V::Bytes(host.to_vec()),
    ]))?;
    let directory = base.join(format!("Asset{}", hex::encode(wire::digest(&identity))));
    let bytes = media::read_asset(c, grant, reference.clone(), transport, &directory)?;
    ensure!(
        publication::fetch(c, grant, expected.page_id()?)?.identity == *expected,
        "displayed Page changed during media retrieval; refresh before revealing"
    );
    Ok(bytes)
}

#[allow(
    clippy::too_many_arguments,
    reason = "Keep protocol inputs, state and validation callbacks explicit."
)]
pub(super) fn submit(
    session: &reader::Session,
    client: &mut Option<Client>,
    grant: &VersionRef,
    online: &Online,
    options: &Options,
    publication: publication::Identity,
    form: String,
    values: BTreeMap<String, serde_json::Value>,
) -> Result<Option<String>> {
    let device = options.device(online)?;
    let transport = options.form_transport()?;
    let expires = crate::now()?
        .checked_add(options.form_retention_seconds)
        .context("form expiry overflow")?;
    let g = grant.clone();
    let d = device.clone();
    let Some(review) = request(session, client, move |c| {
        authority_mail::forms::prepare(c, &g, &d, &publication, &form, values, expires)
    })?
    else {
        return Ok(None);
    };
    let review = review?;
    match session.confirm_form(&review)? {
        None => return Ok(None),
        Some(false) => {
            return Ok(Some(format!(
                "Nothing sent; draft {} retained for review or cancellation",
                review.review_id
            )));
        }
        Some(true) => {}
    }
    let g = grant.clone();
    let d = device.clone();
    let review_id = review.review_id.clone();
    let Some(confirmed) = request(session, client, move |c| {
        authority_mail::forms::confirm(c, &g, &d, &review_id, true)
    })?
    else {
        return Ok(None);
    };
    let confirmed = confirmed?;
    let message = confirmed.submission_id;
    let retained = message.clone();
    let Some(sent) =
        session.request(move || Ok(authority_mail::forms::send(&device, &transport, &message)))?
    else {
        return Ok(None);
    };
    match sent {
        Ok(_) => Ok(Some(format!("Form sent; message {retained}"))),
        Err(error) => anyhow::bail!(
            "confirmed message {retained} remains in the outbox; retry its exact Forms Send command: {error:#}"
        ),
    }
}
