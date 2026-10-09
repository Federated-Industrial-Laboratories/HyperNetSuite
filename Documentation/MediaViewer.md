# Media import and display

`media import` converts a PNG, JPEG or static SVG file into a canonical media
asset and a separate Asset declaration. The original file is never published.
Select an asset ID, its consented host identities and required copy count. Both
output paths must be new files in directories owned by the current user with
mode 0700. Symlink traversal and special-file inputs are refused. Inspect the converted asset and the import report
before including the declaration in a page. If a race prevents the manifest
publication, the already published canonical asset is retained.

```text
HyperNetSuite media import --input Diagram.svg --output Diagram.Vector \
  --manifest Diagram.Asset --id Diagram --host HOST_PUBLIC_KEY
```

The import worker reads at most 16 MiB and accepts at most 16 megapixels. It fits
the result within 1024 pixels per axis and 262144 pixels. PNG transparency is
composited onto white; JPEG orientation is applied. Metadata is removed. Animated
PNG and other image formats are rejected. Raster sampling uses nearest-neighbour
reduction, so inspect photographs and small text after conversion.

Linux import uses a fresh process with an empty environment, anonymous pipes and
no inherited descriptors beyond its fixed input, output and null error stream.
Before decoding, it closes other descriptors and installs a default-deny seccomp
filter. Filesystem, sockets, network connections, process creation and execution
are unavailable. Both import and canonical-vector rasterisation use this boundary.
Address space is limited to 256 MiB, CPU time to two seconds and
wall time to five seconds. The parent independently checks the bounded output.
Import fails closed when this boundary is unavailable. It does not use a shell,
ImageMagick, a browser or a display connection.

## Static SVG subset

SVG import preserves geometry as `HyperNetVector/1` rather than publishing XML.
The profile supports paths, rectangles (including rounded corners), circles,
ellipses, lines, polylines, polygons, groups and numeric transforms. SVG path
shorthand and arcs are normalised into absolute line, quadratic and cubic
commands. Literal fill and stroke colours, fill rules and individual paint opacity
are supported. Shape opacity below one is supported for a single paint.
Presentation attributes and an allowlisted inline `style` syntax can
set these properties. CSS stylesheets and selectors are unsupported.

The importer removes scripts, event attributes and nonvisual metadata and lists
those removals. Resource references and DTDs are refused. Text/fonts, external
images, `use`, gradients, filters, masks, clip paths, animation, foreign objects,
unsupported attributes and unsupported visual semantics are refused. Group
opacity below one is refused because flattening it changes compositing. Partial
shape opacity with both fill and a nonzero stroke is refused for the same reason.
Strokes under a nonuniform transform or skew are refused. The default centred `meet`
viewBox alignment and `preserveAspectRatio="none"` are supported. Unsupported
alignment is refused.

Vectors use fixed-point coordinates, bounded paths and literal paints only.
Transparent regions use a white background. SVG export emits a minimal static
SVG containing only the validated geometry. A graphical client can render the
same geometry directly. Text, controls, focus, reflow and permissions belong to
HyperPage components; vector decorations occupy a clipped Image viewport.

## Terminal graphics

Graphics are off by default. Select `--graphics kitty`, `--graphics i-term2` or
`--graphics sixel` explicitly. An image remains alt text until a Reveal control
is activated. Text reading and motion never fetch media automatically. Revealed
pixels share one browser cache; history retains source and view state, not pixel
copies. Cache eviction requires another explicit reveal to retrieve missing data.

The reader uses verified terminal cell geometry to scale and crop images before
encoding. An explicit pair `--graphics-cell-width` and `--graphics-cell-height`
can supply measured geometry when the terminal omits it. Incorrect values can
misplace graphics; use the terminal's actual cell dimensions. Large physical viewports reduce the rendered image within the pixel budget.
Unknown terminals, pipes, `TERM=dumb`, tmux, screen and SSH sessions
retain the text fallback. No passthrough escapes are emitted.

Kitty uses direct RGB transfers with bounded chunks and reader-owned IDs. Every
chunk suppresses terminal replies. iTerm2
uses a freshly encoded PNG, inline only, without a filename. Sixel uses a fixed
64-colour palette. Complete paints are buffered; supported Kitty and WezTerm contexts use
synchronised updates to prevent partial frames. All output is bounded before a graphics sequence
is opened. Graphics cleanup occurs on repaint, navigation and exit. The protocol
selection does not itself prove that a particular terminal implements cleanup;
use the platform qualification results for supported terminal versions. The
current terminal contexts are Kitty for the Kitty protocol, WezTerm for iTerm2
and xterm with an XTERM_VERSION identity for Sixel. Native iTerm2 on
macOS remains unqualified and uses the fallback.

Native visual qualification checks that trusted header pixels remain unchanged
during reveal, motion, scrolling and resize, as well as checking the image and
cleanup. A visible image alone is insufficient to qualify a terminal.

Native display checks pass with xterm 390 for Sixel and WezTerm
20240203-110809-5046fc22 for iTerm2. The Kitty adapter remains experimental:
Kitty 0.48.2 and 0.49.2 with a software-rendered display can lose images and
adjacent text, including with the terminal's own image command. Kitty visual
qualification remains pending. Use `--graphics off` to retain alt text when
graphics do not display correctly.

## Local motion

Pages declare installed finite presets only: ColourPulse, TextFade, TextScroll,
BorderEmphasis, ProgressSweep, ImagePan and ImageFade. The `a` key starts or pauses
visible effects. Explicit Motion buttons can target a declared effect. Motion is
off initially; no more than eight visible effects run at once. Each activation
ends within ten seconds and stops when hidden. Help, details and input editing
pause effects. Completion restores useful static content.

BorderEmphasis accents the perimeter colour, corner marks and bottom rule. The
glyph changes remain visible in monochrome; labels and interior text stay intact.
Motion buttons acknowledge activation, target pause or an unavailable target in
the status line.

The reader owns clocks, frames, cropping, fades and colours. It transmits no
animation frames and performs no polling or background fetches. Text/layout
motion is limited to ten paints per second; displays containing revealed media
use at most two. Bitmap output is limited to two frames per second and two MiB
per operation and per second. Exhausted budgets leave alt text. TextFade changes
logical emphasis; it does not rely on terminal alpha. These bounds are resource
and presentation limits, not a claim of medical flash safety.
