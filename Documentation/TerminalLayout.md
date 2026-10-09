# Terminal layout and controls

The interactive reader lays out the validated component tree in integer terminal
cells. It never interprets browser styles, scripts, expressions or publisher escape
sequences. Ordinary links and Navigate buttons retain the existing verified
navigation workflow. Focus and Scroll buttons act only on named scrollboxes in
the current document. No action runs automatically when the page opens.

## Layout

Columns flow vertically, with their declared padding and gaps. A Row keeps its
children side by side when every child can receive `minChildColumns`, including
the spaces between children. Remaining cells are distributed by Column weight;
other child types have weight 1. Integer rounding favours document order. A narrow
row stacks children in the same order and uses its gap between stacked children.

Panels draw a label and border around their padded content. ScrollBox `rows`
selects its content viewport height, with a separate label and border. Every
scrollbox retains its own offset during scrolling and resizing. Its descendants
are clipped before terminal output, including nested scrollboxes and buttons.
A page cannot overwrite the approval status or reader controls outside its
content rectangle.

Text wraps by Unicode grapheme clusters and display width. A grapheme wider than
its available row is replaced by `?`; no partial wide character is painted.
Combining clusters without a display cell are escaped. ASCII mode renders
non-ASCII characters as explicit code-point escapes before measuring them.
Terminal font and Unicode support can still vary; use ASCII mode when needed.
Deeply nested borders shrink to their available width without crossing a parent.

The active viewport is at most 300 columns by 120 rows, even on larger terminals.
Layout retains at most 262144 terminal cells across its intermediate and final
buffers. Browser navigation refuses a page that exceeds this bound and retains
the previous view. A resize failure keeps trusted recovery controls available;
shrinking the terminal retries layout. Plain output remains available. Preview
wide and narrow layouts before publishing.
Very small terminals request resizing. Static pages redraw only after input or
resize. Motion starts only through an explicit reader action and remains bounded
and client-side; there is no background refresh. See [MediaViewer](MediaViewer.md).

## Keyboard

| Key | Reader operation |
| --- | --- |
| Tab / Shift-Tab | Move through scrollboxes, fields and buttons in document order |
| Enter | Edit the selected field or activate the selected button |
| Arrows or j/k | Scroll the selected scrollbox or the button's nearest scrollbox |
| Page Up / Page Down | Scroll by that viewport's height |
| Home / End or g/G | Move to the selected viewport's start or end |
| p | Select whole-page scrolling instead of a control |
| i | Show or hide trusted publication details and the full selected destination |
| m | Toggle publisher colours and monochrome |
| r | Revalidate the current publication |
| b | Return through the existing bounded navigation history |
| q / Escape / Ctrl-C | Exit the reader |

When no control is selected, scrolling keys move the whole page. Moving focus
reveals its first line through every enclosing viewport. Resize keeps the same
control and clamps offsets to the new layout. Scrolling can subsequently move
that control out of view; Tab reveals the next control. A local Scroll button
changes its named viewport without implicitly moving focus. Global reader keys
remain available in every control.

A native form field opens a separate local editor. Its input cannot become
browser shortcuts. Submit opens the trusted confirmation screen described in
[Forms](Forms.md); it never sends directly from page content. Draft previews
and foreign pages display form fields without accepting input.

The `i` view is reader-owned. It shows all retained approval, network, identity
and source metadata, plus the selected action and its complete wrapped destination.
Its scrolling is independent of page content. A clipped footer is a summary;
inspect this details view before following a long destination. External HTTPS
references remain display-only under the existing navigation policy.

The [Browser](Browser.md) retains per-page focus and scroll state across Back.
It adds trusted catalogue, address and help views. An unchanged exact publication
keeps its view on Refresh; a changed publication resets document state. Local
preview and moderation use the same layout without network navigation.

## Colour and plain output

Pages may use Default and the terminal's sixteen logical foreground colours.
Container colour is inherited unless a child selects another colour; headings
are bold. Pages cannot redefine the palette or set arbitrary terminal colours.
Actual contrast depends on the terminal theme. Selection uses a trusted reverse
attribute and labels remain present without colour.

Monochrome uses the terminal's default foreground while retaining emphasis and
selection. A nonempty `NO_COLOR` environment variable forces monochrome, including
when `m` is pressed. ASCII mode changes text representation independently of colour.

Plain output, pipes and `TERM=dumb` print all flattened content in document order,
including text clipped in scrollboxes and every action destination. They emit no
terminal styling and perform no action. Moderation and accessibility workflows
can therefore inspect the complete document without visiting each viewport.

Normal exit and handled interrupt, termination and hangup signals restore terminal
attributes, cursor visibility and the alternate screen. Forced process termination,
a process abort or terminal failure cannot guarantee restoration; `stty sane` and
`reset` recover a shell terminal.
