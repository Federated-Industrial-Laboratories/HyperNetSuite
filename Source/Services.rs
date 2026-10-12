// SPDX-License-Identifier: MIT
// Service management uses the same typed quorum workflow as local authority inspection.
pub use crate::authority_inspection_cli::domain_cli::Command;
use anyhow::Result;
use std::path::Path;
pub fn run(_configuration: Option<&Path>, command: Command) -> Result<()> {
    crate::authority_inspection_cli::domain_cli::run(command)
}
