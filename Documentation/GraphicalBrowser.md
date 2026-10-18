# Graphical browser

[Documentation](ReadMe.md) | [Project README](../ReadMe.md)

The native Linux browser displays the same signed `HyperNetPage/2` documents as
the terminal reader. Panels, weighted rows, scroll boxes, local controls, Forms
and approved media keep their existing meanings. Graphical layout does not change
publication bytes, identities or permissions. HyperNet infrastructure remains a
separate service and repository.

The dark interface uses hard-edged boxes with a small top-right corner cut.
This graphical treatment applies to controls and panels without changing Page source.

## Open a page

Use an already joined profile and its retained routes:

```sh
HyperNetSuite network connect --profile /Private/Client/Profile.json -- browse --gui --namespace News
HyperNetSuite network connect --profile /Private/Client/Profile.json -- browse --gui hypernet://NETWORK/AUTHOR/News/PAGE
```

For explicit local operator connections, `browse [online options] --grant GRANT
--gui` and `pages read [read options] --gui` use the same native window. See
[Browser](Browser.md) for addresses, grants and connection options, and
[Private routes](PrivateRoutes.md) for joining and retaining routes. One browser
process uses one selected network. Its Settings and Help windows share that
selection; they cannot open a different network or credential profile.

Preview a local document without a network connection:

```sh
HyperNetSuite pages preview Draft.txt --gui
HyperNetSuite pages preview Draft.txt --gui --media Diagram=Artwork/Diagram.Vector
HyperNetSuite pages preview Examples/GraphicalPage.txt --gui
```

Local preview is unapproved content. Its controls cannot navigate the network or
send Forms. A local media mapping reads only the explicitly named canonical file
when Reveal is activated. `--gui` and `--tui` cannot be combined. Omitting `--gui`
keeps the existing terminal and plain-output behavior.

## Navigation and review

The toolbar provides Back, Refresh, Catalogue, address entry and Page information.
The Page links sidebar filters links in the current document; filtering sends no
network query. Catalogue and navigation requests are explicit. HTTPS references
remain display-only and never launch an external application.

| Shortcut | Action |
| --- | --- |
| Ctrl+L | Focus the address field |
| Ctrl+R | Refresh the current view |
| Alt+Left | Return to the previous retained view |
| Ctrl+, | Open Settings |
| F1 | Open Help |
| Tab / Shift+Tab | Move keyboard focus |
| Enter / Space | Activate the focused control |

Settings and searchable Help open in separate windows. Page information presents
the trusted publication metadata. Publisher content remains inside the page area
and cannot replace browser controls or submission review.

Network work runs outside the graphical event loop. A failed navigation or
refresh leaves the previous verified page available. Back restores retained
content; it does not establish current permission. Closing the browser cancels
pending transport work, but cannot recall a confirmed submission already sent.

Forms keep the same explicit sender selection, recipient verification, current
publication checks and encrypted recovery records as the terminal workflow.
Submission opens a separate review window. Read the recipient, field values,
storage and expiry, then type `SEND` and activate Send. Cancel or close the review
to decline transmission. See [Forms](Forms.md) for destination acceptance and
recovery of an uncertain send.

## Formatting and media

Text components support bounded Markdown headings, emphasis, lists, quotations,
tables, links and literal code blocks. HyperPage literal components stay literal.
HTML is displayed as text; scripts, fenced code and task-list markers do not
execute. Excessive Markdown nesting or event counts fall back to literal text.
Consecutive plain paragraph lines form one formatting block, so tables, lists
and fenced code can span lines. Prefix each source line with `: `. Components
with IDs, motion or explicit styling remain independent. Blank HyperPage lines
separate blocks. See `Examples/GraphicalPage.txt` for complete source.

Markdown links use the existing explicit navigation rules. A Markdown image must
name an asset in the document's approved manifest, either by asset ID or
`asset:ID`. It remains a placeholder until explicit Reveal. Remote URLs do not
become image downloads, and formatting never creates additional authority or
selects credentials. Media is verified and decoded through the existing confined
path before the graphical renderer receives pixels. See [Media](Media.md).

## Display preferences

Settings contains a global Animation switch, text size and monochrome Page
colours. Animation is off by default. Turning it off also prevents Page controls
from starting motion. Turning it on allows local bounded effects on retained
content; it does not reveal images or start network requests. The choice applies
across navigation and application restarts. Text size and monochrome are also
retained. These preferences do not change signed documents or authority policy.

Preferences are stored in `$XDG_CONFIG_HOME/HyperNetSuite/Settings.json`, or
`$HOME/.config/HyperNetSuite/Settings.json` when `XDG_CONFIG_HOME` is unset or empty.
The base path must be absolute. New directories use mode 0700 and files use mode 0600.
Reads are limited to 4096 bytes; unknown or repeated fields, invalid values,
symlinks, hardlinks and unsafe ownership or permissions are refused. Updates use
an atomic private-file replacement. No browsing history, page identity or
credential is written to this file.

If loading fails, the browser uses default preferences and shows a Settings error.
It will not replace that file. Repair the path, permissions or document and reopen
the application before saving preferences. A failure to save is also visible;
an unsaved preference applies only to the current process.

## Build and runtime

The default `gui` feature builds the native browser with Rust 1.95 or newer. Linux
builds need a C toolchain and linker, `pkg-config`, and the development libraries
for X11/XCB, Wayland and xkbcommon. The selected OpenGL renderer also needs usable
EGL or GLX libraries and a graphics driver at runtime. Distribution package names
vary; the upstream [eframe Linux build instructions](https://docs.rs/crate/eframe/0.37.0)
list common native dependencies. Suite enables X11 and Wayland, bundled fonts,
AccessKit and the OpenGL renderer with the other toolkit defaults disabled.

```sh
cargo build --locked --release
```

A graphical session requires an available X11 or Wayland display. The terminal
client remains available on systems without a desktop. Omit graphical dependencies
with:

```sh
cargo build --locked --release --no-default-features
```

That binary reports a clear error for `--gui`; terminal, CLI and plain-output
commands retain their existing behavior. The graphical viewer does not embed
WebKit, HTML rendering or a script runtime. See [Supported platforms](SupportedPlatforms.md)
for qualification boundaries and [Installation](Installation.md) for packages.
