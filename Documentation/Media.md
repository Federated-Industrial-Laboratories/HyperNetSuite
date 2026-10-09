# Page media

Media is immutable content bound to an exact signed page revision. HyperNet
stores canonical assets separately from page text. HyperNetSuite imports,
previews, uploads and independently verifies those assets. Every fetch requires
an explicit action and fresh permission. Pages cannot choose a local file,
external URL, decoder, graphics protocol or executable.

## Prepare and publish

List the network's currently consented media hosts and minimum copy policy:

```sh
HyperNetSuite --config Author.json media hosts
mkdir -m 700 Artwork
HyperNetSuite media import --input Diagram.svg --output Artwork/Diagram.Vector \
  --manifest Artwork/Diagram.Asset --id Diagram --host HOST_ONE --host HOST_TWO --copies 2
```

The host keys must consent to the intended namespace. The manifest contains
`id`, `profile`, `width`, `height`, `bytes`, `digest`, `hosts` and `copies`.
Copy its exact compact JSON object after `@Asset` on one line in the draft.
Add an Image and an explicit Reveal button:

```text
@Image {"id":"DiagramView","asset":"Diagram","alt":"Network connections","rows":12,"fit":"Contain"}
@Button {"label":"Reveal diagram","action":{"kind":"Reveal","target":"DiagramView"}}
```

Each declared asset must appear in an Image. Its ID, digest, dimensions, hosts
and copy count are part of the signed page, not mutable rendering hints. Assets
are at most 1024 pixels per axis and 262144 pixels; a page permits eight assets
and four MiB total. Vectors have additional geometry bounds. See
[HyperPage](HyperPage.md), [MediaSchema](MediaSchema.json) and the
[import and display guide](MediaViewer.md). The JSON schema describes structure;
canonical byte ordering, digest, arithmetic and reference checks also apply.

```sh
HyperNetSuite pages preview Draft.txt --tui --graphics kitty \
  --media Diagram=Artwork/Diagram.Vector
HyperNetSuite --config Author.json pages submit --file Draft.txt --namespace News \
  --output Artwork/Submission.json
HyperNetSuite --config Author.json media upload --submission Artwork/Submission.json \
  --asset Diagram --input Artwork/Diagram.Vector
```

Preview uses only the explicitly mapped local files and loads an asset only on
Reveal. Select a supported graphics protocol or retain the complete alt-text
fallback. Preview cannot submit forms or navigate the network. PNG and JPEG import
produce `HyperNetRaster/1` RGB bytes; SVG import produces `HyperNetVector/1` geometry.
Original encoded files are never uploaded.

Upload uses the exact saved author submission. It checks local bytes before
sending, resumes immutable 32 KiB chunks, and seals independently validated
content at each selected host. `--host HOST_KEY` selects one manifest host;
omitting it attempts all. An exact repeated chunk is accepted, while conflicting
bytes at the same offset fail. Partial failure does not erase successful copies.
Retry the same asset and submission. Store expiry, withdrawal or changed page
state can prevent a retry; those conditions require fresh consent or a new draft.
The required copies must satisfy both the signed manifest and current network
policy before publication.

## Inspect and approve

Use a separate administrator or appropriately scoped review identity. Save the
exact pending inspection, then retrieve and verify each asset:

```sh
mkdir -m 700 Moderation
HyperNetSuite --config Administrator.json pages inspect --page-id PAGE_ID \
  --output Moderation/Review.json
HyperNetSuite --config Administrator.json media inspect --review Moderation/Review.json \
  --asset Diagram --output Moderation/Diagram.Vector
HyperNetSuite --config Administrator.json pages inspect --page-id PAGE_ID --output Moderation/DisplayedReview.json --tui \
  --media Diagram=Moderation/Diagram.Vector --graphics kitty
HyperNetSuite --config Administrator.json pages review --input Moderation/DisplayedReview.json \
  --decision approve
```

`media inspect` rechecks the exact pending source, independently validates all
asset bytes and records that identity's media inspection attestation. It does
not approve the page or establish that a person examined the image. Activate
Reveal and assess the converted content before deciding. Publication requires
an inspection attestation for every asset and enough current sealed copies.
A changed revision invalidates the saved page review. Use `--decision reject`
when content is unsuitable. Media content can be offensive despite valid geometry.

Review adapters remain explicit file exchanges. `adapters review-export` contains
text and manifests only. A separate `adapters media-export` with
`--consent-media-disclosure` releases one verified asset for that exact job; see
[Adapters](Adapters.md). It does not start a provider or send credentials.

## Read, replicate and withdraw

```sh
mkdir -m 700 Received
HyperNetSuite --config Reader.json media read --page-id PAGE_ID --asset Diagram \
  --output Received/Diagram.Vector
HyperNetSuite media export-svg --input Received/Diagram.Vector --output Received/Diagram.svg
HyperNetSuite --config Reader.json pages read --page-id PAGE_ID --tui --graphics kitty
HyperNetSuite --config Author.json media replicate --page-id PAGE_ID --asset Diagram \
  --source-host HOST_ONE --destination-host HOST_TWO
```

Read selects a current manifest host, or an explicit `--host`. It verifies the
complete digest, length, dimensions and canonical encoding before publishing a
new private output file. Replication requires the original author's rights and
both hosts in the immutable manifest. Ordinary readers cannot create copies in
a store. Exported SVG contains only static numeric paths and literal paints;
it never restores original XML. Alternate graphical viewers can interpret the
same validated geometry directly and retain HyperPage's semantic layout and
controls.

A browser reveal independently rechecks the exact current page and media route.
Motion uses local clocks and cached pixels only. Withdrawal and loss of current
permission deny new fetches; previously received or exported bytes cannot be
recalled. Store cleanup follows consented retention, not a guarantee of remote
secure erasure. Foreign reads require the explicit bilateral media terms in
[Federation](Federation.md).

## Separate storage consent

A Pages text-cache consent has zero media allowance. A PageMedia store needs its
own service identity, signed version 1 consent, namespace list, capacity,
retention and pinned authority route. It cannot reuse a mail, transfer, bridge or
ordinary member identity. Follow HyperNet's PageMedia guide to prepare the exact
specification and confined store configuration:

```sh
HyperNetSuite --config MediaHost.json media host-consent --input Specification.json \
  --output Consent.json
HyperNetSuite --config MediaHost.json media host-register --input Consent.json
HyperNetSuite --config Administrator.json media policy-set --minimum-copies 2
HyperNetSuite --config MediaHost.json media host-withdraw --host-key HOST_KEY \
  --expected-generation 1
```

Signing and registration do not start a service. The hardware operator starts
and stops it using HyperNet's separate PageMediaStore tool. For emergency local
withdrawal, stop the store first. Registration requires a current host grant and
exact resource consent. Catalogue and per-chunk permissions are short-lived;
unavailable authority fails closed. Bytes and recovery overhead consume the
consented quota without deduplication credit. Increasing the copy policy does
not silently modify an author's manifest or select new hardware.
