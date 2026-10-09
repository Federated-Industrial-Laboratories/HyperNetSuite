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
buffers. A page that exceeds this bound reports an error and restores the terminal;
plain output remains available. Preview wide and narrow layouts before publishing.
Very small terminals request resizing. Static pages redraw only after input or
resize, and do no animation or background refresh.

## Keyboard

| Key | Reader operation |
| --- | --- |
| Tab / Shift-Tab | Move through scrollboxes and buttons in document order |
| Enter | Activate the selected button; a selected scrollbox needs no activation |
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

The `i` view is reader-owned. It shows all retained approval, network, identity
and source metadata, plus the selected action and its complete wrapped destination.
Its scrolling is independent of page content. A clipped footer is a summary;
inspect this details view before following a long destination. External HTTPS
references remain display-only under the existing navigation policy.

Refresh and Back keep their existing fetch/history behaviour. This renderer does
not add a catalogue, address editor or cross-page scroll-state persistence.

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
