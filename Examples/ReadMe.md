# Example Pages

[Documentation](../Documentation/ReadMe.md) | [Project README](../ReadMe.md)

## Preview without preparation

From a source checkout or the root of a signed package, with `HyperNetSuite` on
PATH:

```sh
HyperNetSuite pages preview Examples/GraphicalPage.txt --gui
```

For a source installation, use the `Examples/GraphicalPage.txt` file within its
installation prefix. Replace `--gui` with `--tui` for the terminal viewer, or omit
both for plain output. This example needs no network profile, imported assets
or Python. Its Markdown formatting is visible in the native browser; the terminal
retains readable text. Animation is off by default in the native browser; enable
it in Settings to use the local motion controls. Close the window to exit, or use
`q` / Escape in the terminal viewer.

Local preview is unapproved content. It cannot navigate a network or send Forms.
See [Graphical browser](../Documentation/GraphicalBrowser.md) and
[terminal controls](../Documentation/TerminalLayout.md).

## Prepare the Willowmere examples

The optional generator needs Python 3.11 or newer and a built client. Run it
from the checkout or package root; use a new output directory in a private
workspace outside the installation prefix.

Prepare a fictional market square, cafe, bookshop, plant studio and field guide:

```sh
mkdir -m 700 "$HOME/HyperNetExamples"
python3 Examples/Prepare.py --suite /Chosen/Bin/HyperNetSuite --output "$HOME/HyperNetExamples/Pages"
```

The command imports the supplied photograph and static SVG illustrations through
the confined client worker. It writes five current-format pages, four canonical
assets, their manifests and `Index.json`. It validates every complete source with
the client. It makes no network requests. The output directory must be new.

The default public identifiers are placeholders for local preview only. Preview
the square in the native browser and activate its Reveal control:

```sh
/Chosen/Bin/HyperNetSuite pages preview "$HOME/HyperNetExamples/Pages/MarketSquare.Page" --gui \
  --media "Square=$HOME/HyperNetExamples/Pages/Media/Square.Vector"
```

For terminal graphics, replace `--gui` with `--tui --graphics i-term2` only in a
supported iTerm2-protocol terminal, or use `--graphics sixel` in a supported Sixel
terminal. See [terminal media support](../Documentation/MediaViewer.md). Use
`--tui --graphics off` for alt text. The cafe uses `Cafe.Raster`; the bookshop uses
`Books.Vector`; the plant studio uses `Botanical.Vector`. The field guide reuses
the square illustration. All media lives under the prepared `Media` directory.
In the terminal viewer, Tab selects a control, Enter activates it, and `a` starts
or pauses local effects. The native browser uses its Settings animation switch
and the Page's local controls.
Local preview cannot navigate the network or submit a form.

## Publish with explicit network authority

For publication, supply `--bindings Bindings.json` with exactly these fields:

```json
{
  "network": "YOUR_NETWORK_ID",
  "author": "AUTHOR_PUBLIC_KEY",
  "mediaHost": "CONSENTED_MEDIA_HOST_PUBLIC_KEY",
  "recipient": "CAFE_MAILBOX_ADDRESS_ID",
  "recipientOwner": "CAFE_MAILBOX_OWNER_PUBLIC_KEY"
}
```

Every value must be 64 lowercase hexadecimal characters. The media host must
consent to the `Showcase` namespace. Each asset declares one required copy;
prepare a different manifest when the network policy requires additional copies.
The fixed page IDs in `Index.json` are independent of the network and are supplied
explicitly to `pages author --page-id` before submitting that signed statement.
Reusing an existing ID creates a new draft;
use a dedicated example author or network to avoid replacing unrelated content.

Follow [Pages](../Documentation/Pages.md) and [Media](../Documentation/Media.md)
to submit each source, upload its assets, inspect them
as a separate reviewer and approve the exact page. The cafe form additionally
needs a private mailbox, sender contact verification and receiver acceptance of
that exact approved form. Its explicit confirmation sends encrypted sample data;
it does not perform a booking or purchase. The other pages use no network action
beyond explicit navigation and media reveal.

The examples exercise responsive rows, panels, colours, scrollboxes, typed form
fields, static photos, retained vectors and finite text/primitive/image effects.
Rounded cafe panels, double bookshop frames, light plant panels and a heavy
noticeboard demonstrate the border styles. Menu and noticeboard separators join
their containing borders. Pass `--ascii` for the character-only border fallback.
Labels and descriptive text remain available without colour, graphics or motion.
All businesses, book titles, events and opening hours are fictional.
