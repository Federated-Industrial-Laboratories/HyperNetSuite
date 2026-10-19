// SPDX-License-Identifier: MIT
// Native applications inherit the same pinned routes and requester floors as network connect.
use super::*;
use crate::authority_inspection_cli::{Location, domain_cli::Online};

#[derive(Clone)]
pub(crate) struct Route {
    pub service: String,
    pub subject: String,
    pub path: PathBuf,
}

pub(crate) struct Connection {
    _selection: crate::private_route_client::Selection,
    directory: PathBuf,
    location: Location,
    routes: Vec<workflow::SavedRoute>,
}

impl Connection {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let (profile, checked) = load(path)?;
        let joined = profile
            .joined
            .as_ref()
            .filter(|joined| joined.admitted)
            .context("network has no retained successful membership; run network join")?;
        files::private_directory(&joined.directory)?;
        let selection = crate::private_route_client::Selection::new(path)?;
        let routes = workflow::routes(&joined.directory)?;
        Ok(Self {
            _selection: selection,
            directory: joined.directory.clone(),
            location: Location::retained(
                joined.directory.join("Bootstrap.cbor"),
                hex::encode(checked.file_digest()),
                joined.directory.join("Requester"),
                joined.clock_witness.clone(),
            ),
            routes,
        })
    }

    pub(crate) fn location(&self) -> Location {
        self.location.clone()
    }

    pub(crate) fn mail_location(&self, mailbox: &str) -> Location {
        self.location.with_directory(self.directory.join(format!(
            "MailRequester{}",
            hex::encode(trust_wire::digest(mailbox.as_bytes()))
        )))
    }

    pub(crate) fn key(&self) -> PathBuf {
        self.directory.join("Device.json")
    }

    pub(crate) fn online(&self) -> Online {
        Online {
            location: self.location(),
            key: self.key(),
            socket: self.directory.join("AuthorityRoute.json"),
        }
    }

    pub(crate) fn routes(&self, protocol: u64) -> Vec<Route> {
        self.routes
            .iter()
            .filter(|route| route.protocol == protocol)
            .map(|route| Route {
                service: route.service.clone(),
                subject: route.subject.clone(),
                path: workflow::route_path(&self.directory, &route.service),
            })
            .collect()
    }
}
