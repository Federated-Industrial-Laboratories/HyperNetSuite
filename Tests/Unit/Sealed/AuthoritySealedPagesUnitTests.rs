// SPDX-License-Identifier: MIT
// Unit tests for AuthoritySealedPages.
use super::*;
use clap::{CommandFactory, Parser};
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
fn local(command: &str) -> Vec<String> {
    [
        "sealed",
        command,
        "--bootstrap",
        "Bootstrap.cbor",
        "--bootstrap-digest",
        "pin",
        "--directory",
        "Private",
        "--clock-witness",
        "Clock.json",
        "--vault",
        "Vault",
        "--age-key",
        "Identity.age",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
#[test]
fn sealed_finalisation_requires_human_approval_and_exact_inspection() {
    Cli::command().debug_assert();
    let mut args = local("finalise");
    args.extend(
        [
            "--key",
            "Reviewer.json",
            "--socket",
            "Authority.sock",
            "--grant",
            "grant",
            "--binding",
            "Device.cbor",
            "--policy",
            "Policy.cbor",
            "--submission",
            "Submission.age",
            "--inspected-digest",
            "digest",
            "--approve",
            "--namespace",
            "Books",
            "--publication",
            "publication",
            "--encryption-generation",
            "1",
            "--expires-ms",
            "10000",
            "--attempt-directory",
            "Attempt",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    assert!(Cli::try_parse_from(&args).is_ok());
    let mut missing_approval = args.clone();
    missing_approval.retain(|v| v != "--approve");
    assert!(Cli::try_parse_from(missing_approval).is_err());
    let index = args.iter().position(|v| v == "--inspected-digest").unwrap();
    args.drain(index..index + 2);
    assert!(Cli::try_parse_from(args).is_err());
}
#[test]
fn sealed_reader_uses_device_vault_and_never_accepts_plaintext_output() {
    let mut args = local("read");
    args.extend(
        [
            "--socket",
            "Authority.sock",
            "--grant",
            "grant",
            "--device",
            "device",
            "--object",
            "object",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    assert!(Cli::try_parse_from(&args).is_ok());
    let mut output = args.clone();
    output.extend(["--output", "Plaintext.txt"].into_iter().map(str::to_owned));
    assert!(Cli::try_parse_from(output).is_err());
    args.extend(["--key", "Unrelated.json"].into_iter().map(str::to_owned));
    assert!(Cli::try_parse_from(args).is_err());
}
