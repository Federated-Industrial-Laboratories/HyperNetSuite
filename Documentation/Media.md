# Page media

[Documentation](ReadMe.md) | [Project README](../ReadMe.md)

Media is immutable content bound to one exact signed Page revision. HyperNetSuite
imports canonical assets, uploads to explicitly selected consenting hosts, and
independently validates complete downloaded assets. Pages cannot select a local
file, external URL, decoder, graphics protocol or executable. Effects use the
viewer's clock and cached pixels; animation frames are not network messages.

## Prepare an asset

Find current consenting hosts with `pages host list [online options] --grant GRANT
--role media --namespace News`. Hosting and upload permissions are separate.
Import one local image or vector:

```sh
mkdir -m 700 Artwork
HyperNetSuite media import --input Diagram.svg --output Artwork/Diagram.Vector \
  --manifest Artwork/Diagram.Asset --id Diagram --host HOST_ONE --host HOST_TWO --copies 2
```

PNG and JPEG import produce canonical HyperNetRaster/1 RGB bytes. SVG import
produces bounded HyperNetVector/1 geometry through an isolated importer. Original
encoded input is never uploaded. Assets have bounded dimensions, pixel counts,
geometry and total Page bytes. See [HyperPage](HyperPage.md),
[MediaSchema](MediaSchema.json) and [MediaViewer](MediaViewer.md).

Place the exact manifest JSON after `@Asset` on one line in the draft. Every
asset needs an Image reference and an explicit Reveal control:

```text
@Image {"id":"DiagramView","asset":"Diagram","alt":"Network connections","rows":12,"fit":"Contain"}
@Button {"label":"Reveal diagram","action":{"kind":"Reveal","target":"DiagramView"}}
```

Use `pages preview Draft.txt --gui --media Diagram=Artwork/Diagram.Vector` to
inspect a local draft in the native browser. Replace `--gui` with `--tui` for
terminal viewing and select a supported [graphics protocol](MediaViewer.md). Local mappings are explicit and are read only on reveal.
Alt text remains available without a supported graphics protocol.

Sign and submit the Page with the separate `pages author` and `pages submit`
commands in [Pages](Pages.md). Submission returns immutable kind144 asset records.
For each asset, retain its `id`, `generation` and `digest`; the summary also shows
the source asset ID, byte count, raw content hash and selected hosts. The record
digest and raw asset SHA256 have different purposes and are not interchangeable.

## Upload and resume

Every finite media effect takes the exact asset record, capability, authority
connection and selected service route. For example:

```sh
HyperNetSuite media upload [online options] --grant AUTHOR_GRANT \
  --asset RECORD_ID --asset-generation GENERATION --asset-digest RECORD_DIGEST \
  --host HOST_ONE --service-socket /Private/MediaControl.sock \
  --progress-directory Artwork/UploadOne --input Artwork/Diagram.Vector
```

Repeat with each host in the signed manifest, using a separate progress directory.
The service route is either an explicit `--service-socket` or an installed
`--service-directory` with the Core executable selected by `--core`. These modes
cannot be combined. No arbitrary network route is inferred from Page content.

The client retains exact input, operation and completed ranges in private
persistent storage. Retry the same command, source, asset, host and directory
after interruption. It resumes an unresolved signed operation before preparing
another one. Received bytes and receipts are committed before acknowledgement.
Conflicting chunks, changed identities and gaps are refused. Completed progress
is checked against the retained certified asset and its complete-copy receipt.

Uploads use finite 32 KiB wire chunks. The host signs a complete-copy receipt only
after all canonical bytes pass length, raw SHA256, dimensions and decoder checks.
The author commits that receipt to authority metadata. Publication requires the
manifest's copy count and the current namespace minimum; no new host is selected
implicitly. Expiry, withdrawal or changed pending content can prevent a retry.

## Inspect and approve

A reviewer first retains the exact pending Page with `pages inspect`. Retrieve
and validate every declared asset:

```sh
HyperNetSuite media inspect [online options] --grant REVIEW_GRANT \
  --asset RECORD_ID --asset-generation GENERATION --asset-digest RECORD_DIGEST \
  --host HOST_ONE --service-socket /Private/MediaControl.sock \
  --progress-directory Moderation/DiagramProgress \
  --output Moderation/Diagram.Vector --expires-ms EXPIRY
```

Inspection downloads the entire exact asset and verifies its complete-copy
receipt before recording a media inspection. Its expiry is part of the explicit
review job. This does not itself approve a Page or establish that a person viewed
the image. Display the retained Page with `--media Diagram=Moderation/Diagram.Vector`
and activate Reveal before signing the separate Page decision.

`pages review-sign` rechecks the exact pending source. Publication requires current
copies and the reviewer's inspection for every asset. Reject unsuitable content
with a separate signed rejection. Canonical geometry prevents executable content;
it does not guarantee that an image is appropriate.

## Read and export

Use `media get` with the exact asset reference and a reader capability to inspect
its current metadata. `media read` takes the same connection, asset, host and
persistent progress options as inspection, with `--output` and no inspection
expiry. It rechecks current approved publication and host consent. The complete
validated result is written to a new private file; a retry can confirm an already
identical output without replacing unrelated content.

Remote reads reuse a verified relay connection across the asset's 32 KiB ranges
when its remaining admission covers the next bounded exchange. Otherwise they
open a fresh connection before submitting the next range. This does not increase
or reset an existing connection's byte or time limits. Every range still checks
current policy and receives fresh host/quorum
authorization. Reuse requires the same private client profile, route, protocol,
network and host; failed verification, interrupted progress or route changes
discard the connection. A connected signed completion can acknowledge its exact
pending range without another stream-status request. Missing continuity still
requires certified status, and unresolved requests remain retained for explicit
recovery. No received range is automatically retried after transport failure.

```sh
HyperNetSuite media export-svg --input Received/Diagram.Vector \
  --output Received/Diagram.svg
```

SVG export contains static numeric paths and literal paints, never the original
XML. Other graphical viewers can interpret the same validated geometry while
retaining native Page semantics. Local reveal mappings remain available to the
terminal viewer with complete alt-text fallback.

## Storage consent and policy

Role2 media hosts have a distinct operator-signed profile and deployment. Use
`pages host profile --role media`, then `pages host register` as an authorised
manager. Namespace, volume, physical state capacity, maximum asset bytes and
retention are explicit. The usable data budget accounts for both crash-safe
banks, headers and exact encoded metadata; physical storage is not counted twice.

An administrator with the namespace policy capability can use `media policy
--namespace News --copies N`. This does not alter an existing manifest or make
another machine consent to storage. The minimum copy policy applies when assets
are submitted and reviewed.

Signing and registration do not activate a service. Install and activate it
through the Core runtime's separate consent workflow. For local withdrawal, stop
the installed service; the manager or operator can also commit exact-generation
`pages host withdraw`. Withdrawal and expired permission deny new effects.
Previously received plaintext cannot be recalled or securely erased remotely.

The browser uses `--media-route` or `--media-service` and an existing private
`--media-directory` for these same verified, resumable reads. Retrieval occurs
only after Reveal. Current publication identity is checked before a fresh job
and after completion. Exact pending work can resume before that final check;
bytes are not displayed if the publication changed. See [Browser](Browser.md).
