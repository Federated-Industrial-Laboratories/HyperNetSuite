// SPDX-License-Identifier: MIT
// Only typed local summaries cross the diagnostic export boundary.
use super::{files, trust, workflow};
use anyhow::{Result, anyhow, ensure};
use clap::Args;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct Options {
    #[arg(long)]
    profile: PathBuf,
    /// New private file for the exact redacted snapshot accepted in the preview.
    #[arg(long, requires = "preview_digest")]
    output: Option<PathBuf>,
    /// SHA-256 printed by a prior diagnostic preview.
    #[arg(long, requires = "output")]
    preview_digest: Option<String>,
}

#[derive(Clone, Copy, Serialize)]
enum ProfileState {
    Valid,
    UnavailableOrInvalid,
}
#[derive(Clone, Copy, Serialize)]
enum ClientState {
    Prepared,
    JoinPending,
    Joined,
    Unknown,
}
#[derive(Clone, Copy, Serialize)]
enum InventoryState {
    NotConfigured,
    RetainedInventory,
    UnavailableOrInvalid,
}
#[derive(Clone, Copy, Serialize)]
enum ClockState {
    NotConfigured,
    HealthyAtCollection,
    Unavailable,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileSummary {
    state: ProfileState,
    client_state: ClientState,
    effective_minimum_route: Option<trust::Assurance>,
    accepts_host_readable: Option<bool>,
    accepts_sealed: Option<bool>,
    permits_network_search: Option<bool>,
    bootstrap_time_valid: Option<bool>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RouteSummary {
    state: InventoryState,
    count: Option<usize>,
    /// Protocols 1 through 6, in numeric order; no service or endpoint identities.
    counts_by_protocol: Option<[u16; 6]>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    format: &'static str,
    product: &'static str,
    software_version: &'static str,
    scope: &'static str,
    network_used: bool,
    current_authority: bool,
    operator_independence_verified: bool,
    profile: ProfileSummary,
    routes: RouteSummary,
    clock: ClockState,
}

fn routes(directory: &Path) -> RouteSummary {
    let retained = files::private_directory(directory).and_then(|_| workflow::inventory(directory));
    match retained {
        Ok(retained) => {
            let mut counts = [0; 6];
            for route in &retained {
                counts[(route.protocol - 1) as usize] += 1;
            }
            RouteSummary {
                state: InventoryState::RetainedInventory,
                count: Some(retained.len()),
                counts_by_protocol: Some(counts),
            }
        }
        Err(_) => RouteSummary {
            state: InventoryState::UnavailableOrInvalid,
            count: None,
            counts_by_protocol: None,
        },
    }
}

fn collect(path: &Path) -> Snapshot {
    let mut snapshot = Snapshot {
        format: "HyperNetDiagnostics/1",
        product: "HyperNetSuite",
        software_version: env!("CARGO_PKG_VERSION"),
        scope: "SelectedLocalProfile",
        network_used: false,
        current_authority: false,
        operator_independence_verified: false,
        profile: ProfileSummary {
            state: ProfileState::UnavailableOrInvalid,
            client_state: ClientState::Unknown,
            effective_minimum_route: None,
            accepts_host_readable: None,
            accepts_sealed: None,
            permits_network_search: None,
            bootstrap_time_valid: None,
        },
        routes: RouteSummary {
            state: InventoryState::UnavailableOrInvalid,
            count: None,
            counts_by_protocol: None,
        },
        clock: ClockState::Unavailable,
    };
    // load zeroizes the raw private profile and its key fields on drop. No private
    // string, parser error or connection observation is copied into the snapshot.
    let Ok((profile, checked)) = super::load(path) else {
        return snapshot;
    };
    snapshot.profile = ProfileSummary {
        state: ProfileState::Valid,
        client_state: match &profile.joined {
            Some(joined) if joined.admitted => ClientState::Joined,
            Some(_) => ClientState::JoinPending,
            None => ClientState::Prepared,
        },
        effective_minimum_route: Some(profile.minimum_route.max(checked.summary.minimum_route)),
        accepts_host_readable: Some(
            profile
                .required_publication_modes
                .iter()
                .any(|m| m == "HostReadable"),
        ),
        accepts_sealed: Some(
            profile
                .required_publication_modes
                .iter()
                .any(|m| m == "Sealed"),
        ),
        permits_network_search: Some(profile.permit_network_search),
        bootstrap_time_valid: super::time().ok().map(|now| {
            hex::decode(&profile.bootstrap)
                .ok()
                .is_some_and(|bytes| trust::check(&bytes, true, now).is_ok())
        }),
    };
    if let Some(joined) = &profile.joined {
        snapshot.routes = routes(&joined.directory);
        snapshot.clock = if crate::authority_clock::health(&joined.clock_witness).is_ok() {
            ClockState::HealthyAtCollection
        } else {
            ClockState::Unavailable
        };
    } else {
        snapshot.routes.state = InventoryState::NotConfigured;
        snapshot.clock = ClockState::NotConfigured;
    }
    snapshot
}

fn encode(snapshot: &Snapshot) -> Result<Vec<u8>> {
    let mut bytes =
        serde_json::to_vec(snapshot).map_err(|_| anyhow!("DiagnosticEncodingFailed"))?;
    bytes.push(b'\n');
    ensure!(bytes.len() <= 4096, "DiagnosticSnapshotTooLarge");
    Ok(bytes)
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn export(bytes: &[u8], expected: &str, output: &Path) -> Result<()> {
    ensure!(
        expected.len() == 64
            && expected
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "DiagnosticPreviewDigestInvalid"
    );
    ensure!(digest(bytes) == expected, "DiagnosticSnapshotChanged");
    files::Destination::open(output)
        .and_then(|destination| destination.publish(bytes))
        .map_err(|_| anyhow!("DiagnosticOutputUnavailable"))
}

pub fn run(options: Options) -> Result<()> {
    let snapshot = collect(&options.profile);
    let bytes = encode(&snapshot)?;
    let preview_digest = digest(&bytes);
    let report = match (options.output, options.preview_digest) {
        (None, None) => {
            json!({"status":"DiagnosticPreview", "previewDigest":preview_digest, "snapshot":snapshot})
        }
        (Some(output), Some(expected)) => {
            export(&bytes, &expected, &output)?;
            json!({"status":"DiagnosticExported", "previewDigest":preview_digest})
        }
        _ => return Err(anyhow!("DiagnosticExportArgumentsIncomplete")),
    };
    crate::print_value(&report).map_err(|_| anyhow!("DiagnosticDisplayUnavailable"))
}

#[cfg(test)]
#[path = "../../Tests/Unit/Networks/NetworkDiagnosticsTests.rs"]
mod tests;
