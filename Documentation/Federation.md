# Federation

Federation joins independently administered HyperNet networks through explicitly
consenting role7 bridge services. Each side retains its own authority, membership,
capabilities, hosting consent and review policy. A treaty does not grant foreign
members local membership or let a bridge approve imported Pages.

Use `HyperNetSuite federation --help` for the finite native workflow. Online
commands take an independently accepted local bootstrap and digest, a private
requester directory, signing key, authority socket and clock evidence. Capability
arguments name the exact current native grant. Separate principals use separate
requester directories. Installed bridge transport is explicit; there is no reader
HTTP fallback or legacy online authority configuration.

Initialise each requester with `authority-inspection initialise` as described in
[Authority inspection](AuthorityInspection.md). Online options are `--bootstrap`,
`--bootstrap-digest`, `--directory`, `--key`, `--socket` and `--clock-witness`, plus
the monitor pins when using a signed clock witness. Capability-bearing operations
also take `--grant` and, for an uncached delegated grant, `--grant-record`.
`--source-page-id` is the source's raw 16-byte Page identity in lowercase hex,
not its qualified destination record ID. Federation `--expires-ms` values are
absolute Unix milliseconds.

## Bilateral consent

1. Exchange fully accepted bootstrap files through an independently authenticated
   channel. `federation trust inspect --foreign-bootstrap ...
   --foreign-bootstrap-digest ...` verifies the file SHA256 and prints its network,
   incarnation and record fingerprint. The file SHA256 and canonical record digest
   are different pins. `trust accept` requires all four independently supplied
   values plus the local Federation administration capability. Run acceptance on
   both networks; discovering a bootstrap through a bridge is not acceptance.
2. `federation treaty create` writes one immutable canonical treaty. It names both
   exact network identities, distinct bridge keys, source and destination
   namespaces, expiry and optional media profiles, consenting source/destination
   hosts, byte bound and copy count. `treaty inspect` displays these terms. Each
   administrator uses `treaty accept --input Treaty.cbor` on its own network.
   A file or signature alone is not a current committed agreement.
3. Admit each deployment through the native deployment workflow. The local
   operator uses `federation bridge profile` to sign the exact reviewed manifest,
   desired profile digest, role7 service, private volume, physical state size and
   treaty digests. `bridge inspect` displays this consent; the authorised manager
   uses `bridge register`. Install and activate that role7 service through
   `HyperNet runtime services`. Its own manifest and operator consent constrain
   network endpoints and resources. The other network never receives its key.
4. Publish the original source Page through the normal local review workflow.
   Its original author uses `federation share-sign --agreement ...
   --source-page-id ... --output Share.cbor`, then `federation share
   --input Share.cbor`. The saved signed statement binds the exact approved
   native revision and publication. A later revision or sharing generation needs
   a new exact consent; administrator approval cannot impersonate the author.

Federation administration is action22. Bridge registration is action26 under
exact operator/deployment consent. Author sharing is action4. Destination review
is action3 and reading is action0, with their current namespace/Page and
application restrictions. Hosting rights remain separately consented.

## Import, inspect and publish

`federation bridge sync --service-directory Bridge --directory PrivateExchange
--agreement ... [--source-page-id ...]` asks the explicitly selected installed
bridge to synchronise. The bridge obtains bilateral committed Admission and
Export proofs, imports their exact immutable Page bundle, and copies permitted
canonical media into consenting destination stores. Reported sync progress is
not reader permission or local approval.
An embedding client using the same authorised UID can select the private bridge
socket with `--service-socket` instead of `--service-directory`. The installed
route accepts `--core` to select the Core executable. Keep the exchange directory
private and persistent. `--exchange-timeout-ms` bounds the overall exchange; it
does not extend any authority proof's freshness or permissions.

The destination reviewer uses `federation queue`, then `federation inspect` with
an explicit local bridge directory (or private `--service-socket`), agreement, raw source Page identity and
`--output Inspection.cbor`. Inspect verifies a fresh bilateral lease through the
local authority and returns only the exact approved source bundle sidecar named
by the certified result. Its display names the source network, incarnation,
qualified local identity and sharing generation. Imported Pages remain pending
until independently reviewed locally; an older approved publication stays intact
while a replacement is pending.

After inspecting the content, use `federation review-sign --input Inspection.cbor
--decision approve|reject --output Decision.cbor`. This refreshes the current
pending revision and binds the signed local decision to the exact inspected
kind155 revision, grant and optional current application policy. Use
`federation review --input Decision.cbor --service-directory Bridge` to apply it.
Application review mode and policy require current dual-signed native consent.
Ordinary review is manual. Human reading does not consume the service's short
freshness window: apply obtains a new lease for the already inspected revision.

`federation list` and `federation read` require current local reading rights,
current source sharing, current bilateral consent and an exact fresh Export.
A returned continuation cursor is explicit; repeat list with `--after` and retain
the same agreement. `read --tui` is an inert foreign publication preview, not the
native browser's local navigation route. Refresh is a new explicit `read` command.
Only `--media AssetId=CanonicalFile` files selected locally are displayed.
Foreign links and Forms never automatically open local routes or submit to a
local mailbox. Source-qualified form recipients remain foreign identities.

## Media

Before inspection or reading, the client obtains certified context for the exact
foreign revision, its media placements, copy and inspection evidence, relevant
host authority and namespace placement policy. A cold client needs no manually
seeded asset cache. Metadata alone grants no media effect or publication approval;
the next operation rechecks current permissions and required inspections.

The inspected/read metadata prints canonical kind144 asset references as encoded
hexadecimal values. Pass that complete value unchanged to `federation media get
--asset-reference ...` to refresh exact destination placement. Add `--inspect`
when querying a pending revision as its reviewer. `federation media inspect` and
`federation media read` take the same reference, `--agreement`, `--source-page-id`,
and either `--bridge-directory` or private `--bridge-socket`. Select the destination
store with `--host` and either `--service-socket` or `--service-directory`. The
installed bridge and store executables use `--bridge-core` and `--core`
respectively. Supply a private `--progress-directory` and an explicit `--output`.
Inspection additionally takes `--expires-ms` for its approval evidence.

Each new bounded range obtains a fresh bilateral proof. The existing typed media
consumer verifies the local authority result and selected store's completion,
retains the changed foreign floor, and writes range progress before acknowledging
it. An interrupted operation resumes its exact signed request and original proof;
it cannot silently replace them with a new lease. Complete raw content hashes,
canonical raster/vector validation and exact copy receipts precede publication
or inspection. Original media manifests describe source provenance; they are
never interpreted as destination network routes.

A private progress directory is specific to one network, requester, asset, host
and effect. Keep it to resume interrupted transfers. An existing output file must
match the completed bytes. Canonical media conversion uses the same isolated
native import tools as local Pages. SVG has no scripts, external references or
executable content; animation remains a local viewer effect.

## Withdrawal and authority changes

`unshare`, `treaty withdraw`, `bridge withdraw`, `trust withdraw` and destination
`withdraw` restrict their respective current rights. The recorded author,
approver or operator can query its exact record for restrictive maintenance after
an ordinary grant expires, where the domain contract permits it. These reads do
not grant new publication, hosting, import or reader authority. Withdrawal cannot
erase copies already disclosed to a previously authorised reader.

Local requester and serving journals use the existing authenticated epoch adoption
workflow. The initial independent bootstrap remains immutable. For a healthy
foreign committee replacement, `trust seal` retains the exact terminal/history
proof and `trust activate` validates the successor readiness proof against that
archive. `trust get --trust ... --retained-output ForeignRetained.json` writes the
exact certified foreign prefix as a new private file. Supply this file to the
source authority's epoch history export; history must extend that retained
prefix. Exporting it neither advances the foreign floor nor grants a lease.
The bilateral service must adopt the corresponding current state before
new leases succeed. Historical receipts can finish their exact retained
completion; they cannot lower a floor or revive an expired permission. Exceptional
new-network recovery requires new independent identity acceptance and consent;
this workflow never silently substitutes a bootstrap or resets an archive.

The current interface covers native authority, bridge and local consent workflows.
Scope-safe public reader relay routes are separate. Native installed bilateral
qualification and platform qualification must be recorded against their exact
candidate before a deployment guarantee is claimed.

The bridge acquires certified source metadata before destination Admission. Its
metadata-only SourceContext uses the exact registered source role7 and current
treaty, author sharing and publication rights. Each inventory Export signs the
exact sorted share selection and its end cursor. The actual encoded result
budget may return a smaller complete prefix; a final empty round ends discovery.
Page exports carry no inventory selection. Current exact-dependency checks still
apply at commitment, and the source performs no general agreement lookup between
Admission and Export. No Page body is returned by the context query.

Page-specific destination Admission certifies the agreed media hosts, current
consent and governance dependencies, namespace placement policy and existing
state for that exact qualified import. The Bridge verifies this context before
Import, including after restart. Inventory Admission does not return unrelated
imported Pages, and ordinary certified-result size limits remain in force.

## Search consent

`federation bridge profile --search` explicitly includes network indexing in
the operator's signed consent. [Search](Search.md) uses the destination's retained
approved import and fresh bilateral evidence; query terms are never forwarded
to the source network. Query-free retention and local derivation continue to use
ordinary read consent and separate current reader search permission.
