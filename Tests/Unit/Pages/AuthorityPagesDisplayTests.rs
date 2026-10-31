// SPDX-License-Identifier: MIT
// Unit tests for AuthorityPages.
use super::*;
use clap::Parser;

#[test]
fn native_viewer_selection_is_explicit_and_mutually_exclusive() {
    for flag in [None, Some("--tui"), Some("--gui")] {
        let mut args = vec!["HyperNetSuite", "pages", "preview", "Draft.txt"];
        args.extend(flag);
        let parsed = crate::Options::try_parse_from(args).unwrap();
        let crate::Command::Pages(Command::Preview { display, .. }) = parsed.command else {
            panic!("preview command changed");
        };
        assert_eq!(display.gui, flag == Some("--gui"));
        assert_eq!(display.tui, flag == Some("--tui"));
    }
    let error = crate::Options::try_parse_from([
        "HyperNetSuite",
        "pages",
        "preview",
        "Draft.txt",
        "--gui",
        "--tui",
    ])
    .err()
    .expect("conflicting viewer flags were accepted");
    assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
}
