// SPDX-License-Identifier: MIT
// Forms require independent Page and Mail requester floors throughout CLI parsing.
use super::*;
use clap::{CommandFactory, Parser};

#[test]
fn forms_cli_keeps_page_and_mail_requester_floors_distinct() {
    crate::Options::command().debug_assert();
    for action in [
        "prepare",
        "accept",
        "confirm",
        "reviews",
        "accepted",
        "review",
        "cancel",
        "receive-local",
    ] {
        let mut args = vec![
            "HyperNetSuite",
            "forms",
            action,
            "--bootstrap",
            "/Private/Bootstrap.cbor",
            "--bootstrap-digest",
            "BootstrapDigest",
            "--directory",
            "/Private/PageFloor",
            "--clock-witness",
            "/Private/Clock.json",
            "--mail-directory",
            "/Private/MailFloor",
            "--vault",
            "/Private/MailVault",
            "--age-key",
            "/Private/MailAge.key",
            "--mailbox",
            "Inbox",
        ];
        if matches!(action, "prepare" | "accept" | "confirm") {
            args.extend([
                "--key",
                "/Private/PageIdentity.json",
                "--socket",
                "/Private/Authority.sock",
                "--grant",
                "Grant",
            ]);
        }
        match action {
            "prepare" => args.extend([
                "--page",
                "Page",
                "--form",
                "Enquiry",
                "--values",
                "/Private/Values.json",
                "--expires",
                "1000",
            ]),
            "accept" => args.extend(["--page", "Page", "--form", "Enquiry"]),
            "confirm" | "review" | "cancel" => args.extend(["--review", "Review"]),
            "receive-local" => args.extend(["--message", "Message"]),
            _ => {}
        }
        let parsed = crate::Options::try_parse_from(&args).unwrap();
        let crate::Command::Forms(arguments) = parsed.command else {
            panic!("Forms command required")
        };
        let (location, mail) = match arguments.command {
            Command::Prepare { online, mail, .. }
            | Command::Accept { online, mail, .. }
            | Command::Confirm { online, mail, .. } => (online.location, mail),
            Command::Reviews { location, mail }
            | Command::Accepted { location, mail }
            | Command::Review { location, mail, .. }
            | Command::Cancel { location, mail, .. }
            | Command::ReceiveLocal { location, mail, .. } => (location, mail),
            _ => panic!("Forms access command required"),
        };
        assert_eq!(location.directory, Path::new("/Private/PageFloor"));
        assert_eq!(mail.directory, Path::new("/Private/MailFloor"));
        let device = mail.device(&location, Path::new("/Private/Authority.sock"));
        assert_eq!(device.location.directory, Path::new("/Private/MailFloor"));
        assert_eq!(location.directory, Path::new("/Private/PageFloor"));
        for required in ["--directory", "--mail-directory"] {
            let mut missing = args.clone();
            let index = missing.iter().position(|value| *value == required).unwrap();
            missing.drain(index..index + 2);
            assert!(crate::Options::try_parse_from(missing).is_err());
        }
    }
}
