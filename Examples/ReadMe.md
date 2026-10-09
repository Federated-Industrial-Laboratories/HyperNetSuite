# Willowmere sample pages

Prepare a fictional market square, cafe, bookshop, plant studio and field guide:

```sh
mkdir -m 700 Workspace
python3 Examples/Prepare.py --suite /Chosen/Bin/HyperNetSuite --output Workspace/Pages
```

The command imports the supplied photograph and static SVG illustrations through
the confined client worker. It writes five current-format pages, four canonical
assets, their manifests and `Index.json`. It validates every complete source with
the client. It makes no network requests. The output directory must be new.

The default public identifiers are placeholders for local preview only. Preview
the square and reveal its illustration with a supported graphics adapter:

```sh
/Chosen/Bin/HyperNetSuite pages preview Workspace/Pages/MarketSquare.Page --tui \
  --graphics i-term2 --media Square=Workspace/Pages/Media/Square.Vector
```

Use `--graphics off` for alt text. The cafe uses `Cafe.Raster`; the bookshop uses
`Books.Vector`; the plant studio uses `Botanical.Vector`. The field guide reuses
the square illustration. All media lives under the prepared `Media` directory.
Tab selects a control, Enter activates it, and `a` starts or pauses local effects.
Local preview cannot navigate the network or submit a form.

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
explicitly to `pages submit --page-id`. Reusing an existing ID creates a new draft;
use a dedicated example author or network to avoid replacing unrelated content.

Follow the Media manual to submit each source, upload its assets, inspect them
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
