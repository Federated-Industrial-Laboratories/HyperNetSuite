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

#[test]
fn browser_theme_requires_explicit_gui_and_retains_address() {
    let address = "hypernet://network/author/News/page";
    let base = [
        "HyperNetSuite",
        "browse",
        "--theme-file",
        "/Private/Theme.json",
        address,
        "--bootstrap",
        "Bootstrap.json",
        "--bootstrap-digest",
        "digest",
        "--directory",
        "State",
        "--clock-witness",
        "Clock.json",
        "--key",
        "Key.json",
        "--socket",
        "Control.sock",
        "--grant",
        "grant",
    ];
    let error = crate::Options::try_parse_from(base).err().unwrap();
    assert_eq!(
        error.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );
    let parsed = crate::Options::try_parse_from(base.into_iter().chain(["--gui"])).unwrap();
    let crate::Command::Browse(args) = parsed.command else {
        panic!("browse command changed")
    };
    assert_eq!(args.uri.as_deref(), Some(address));
    assert_eq!(
        args.display.theme_file,
        Some(PathBuf::from("/Private/Theme.json"))
    );
}

#[test]
fn local_preview_uses_the_same_explicit_theme_option() {
    let args = [
        "HyperNetSuite",
        "pages",
        "preview",
        "Draft.txt",
        "--theme-file",
        "Theme.json",
    ];
    assert!(crate::Options::try_parse_from(args).is_err());
    let parsed = crate::Options::try_parse_from(args.into_iter().chain(["--gui"])).unwrap();
    let crate::Command::Pages(Command::Preview { display, .. }) = parsed.command else {
        panic!("preview command changed");
    };
    assert_eq!(display.theme_file, Some(PathBuf::from("Theme.json")));
}
