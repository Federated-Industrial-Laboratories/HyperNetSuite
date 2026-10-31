// SPDX-License-Identifier: MIT
// Unit tests for AuthoritySealedIdentityCli.
use super::*;
use clap::{CommandFactory, Parser};
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[test]
fn recipient_cli_requires_explicit_separate_secret_and_authority_inputs() {
    Cli::command().debug_assert();
    assert!(Cli::try_parse_from(["recipients", "respond"]).is_err());
    assert!(Cli::try_parse_from(["recipients", "root-register"]).is_err());
    assert!(Cli::try_parse_from(["recipients", "admit"]).is_err());
}
