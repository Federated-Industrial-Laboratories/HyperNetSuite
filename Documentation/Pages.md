# Pages

Pages contain inert HyperNetPage/2 components. The client does not execute Page
code, interpret HTML or fetch external links. Images have exact manifests and
require explicit reveal. Effects run on the viewer; animation frames are not
sent through the network. [HyperPage](HyperPage.md) defines the markup and its
rendering bounds. [Media](Media.md) describes canonical image and vector import.

Use separate reader, author, reviewer and host identities. Hosting consent does
not grant ordinary membership or publication rights. Every online Page command
uses a separately accepted bootstrap, a private requester directory, an identity,
a clock witness and the explicit authority control socket. Initialise the
requester directory with `authority-inspection initialise` before using it.
Capability-bearing commands take `--grant` and optionally the exact
`--grant-record` when that record is not already retained.
The shared online options are `--bootstrap`, `--bootstrap-digest`, `--directory`,
`--key`, `--socket` and `--clock-witness`, with both monitor pins when using a
signed clock witness. [Authority inspection](AuthorityInspection.md) describes
their trust requirements. Page `--expires-ms` values use absolute Unix milliseconds.

## Authoring and approval

A local draft starts with the profile and contains a final LF:

```text
HyperNetPage/2
# Welcome
: This paragraph is information.
## Notices
- A list item
=> https://example.com/ External reference
```

Inspect it with `pages preview Draft.txt --tui`. This preview is unapproved.
Omit `--tui` for plain output. `--ascii` escapes non-ASCII characters. The source
limit is 16 KiB. Unknown markup and terminal control characters are refused.

Authoring and submission are separate commands:

```sh
HyperNetSuite pages author [online options] --grant GRANT --source Draft.txt \
  --namespace News --page-id PAGE_ID --revision 1 --expires-ms EXPIRY \
  --output Author.cbor
HyperNetSuite pages submit [online options] --statement Author.cbor --source Draft.txt
```

`PAGE_ID` is a nonzero sixteen-byte identifier in canonical hexadecimal. A new
Page starts at revision one. Updates use the same author and namespace and the
next revision. The author signs the exact source hash, revision, capability and
application policy, if applicable. A pending replacement preserves the previous
approved publication. Retain the statement and exact source for retries.

A reviewer uses an independent identity and review capability:

```sh
HyperNetSuite pages queue [online options] --grant REVIEW_GRANT --namespace News
HyperNetSuite pages inspect [online options] --grant REVIEW_GRANT \
  --page-id PAGE_ID --output ReviewInput.cbor --tui
HyperNetSuite pages review-sign [online options] --grant REVIEW_GRANT \
  --input ReviewInput.cbor --decision approve --expires-ms EXPIRY \
  --output Decision.cbor
HyperNetSuite pages review [online options] --input Decision.cbor
```

Inspection retains the exact pending revision and verified source. Signing a
review rechecks that same pending content. The decision file atomically retains
the signed decision, inspected source and approved bundle. Use `--decision reject`
to reject only the pending replacement. Manual review is the default. The review
job expires after at most five minutes; an accepted publication is not repeatedly
expired by that job deadline.

Keep author, review and requester files private. An uncertain response can leave
an exact operation pending. Retry the same command and retained inputs. A fresh
command cannot replace an unresolved requester operation. A changed source or
permission requires a fresh inspection or author statement after resolving the
previous request.

An author withdraws both the current publication and pending replacement with
`pages withdraw [online options] --grant GRANT --page-id PAGE_ID`. A permitted
reviewer adds `--as-reviewer`. Historical signatures and previously received
plaintext cannot be recalled.

## Reading and replicas

```sh
HyperNetSuite pages list [online options] --grant READER_GRANT --namespace News
HyperNetSuite pages read [online options] --grant READER_GRANT --page-id PAGE_ID --tui
HyperNetSuite browse [online options] --grant READER_GRANT --namespace News
```

A list returns a finite page and an optional `next` cursor. Pass it as `--after`
for the following page. `pages read --output Bundle.cbor` also saves the exact
verified approval bundle. Current permission comes from a quorum-certified
result, independently checked against the selected records and retained floors.
Uncertified, substituted or missing result objects are not displayed.

Replica delivery uses one exact consenting role1 host. Obtain its current
identifier, generation and digest from host management. `pages replica-request`
takes `--page-id`, `--host`, `--host-generation`, `--host-digest`, `--expires-ms`
and the reader grant. Its authenticated context query supplies the current
publication and hosting consent without granting host-management rights. A
ticket reserves at most sixty seconds for the multi-step delivery workflow and
counts against signed concurrency limits. Each operation still requires its own
proof of at most five seconds and current permission. Delivery and result checks
retain a 1,250-millisecond margin before the ticket's absolute expiry.

Use the returned kind146 reference with `pages replica-result [online options]
--ticket ID --ticket-generation GENERATION --ticket-digest DIGEST --output Bundle.cbor`.
A finite response says `PageReplicaPending` or `PageReplicaDelivered`. Pending
results verify their current metadata without requiring bundle bytes. Only an
exact verified delivered bundle creates the output file; missing or substituted
bytes refuse completion. There is no implicit origin
fallback. The host's own service supplies the approved bytes through the ticket.

The screen distinguishes approval at fetch from current permission. `r` fetches
fresh authority state; retained history remains labelled as previously verified.
Withdrawals, revocations and outages prevent fresh authorised access. Internal
addresses bind network, author, namespace and Page identity. Foreign addresses
require an explicitly authorised federation route. External HTTPS references
are displayed only.

[TerminalLayout](TerminalLayout.md) describes responsive panels, scrollboxes,
Unicode clipping, colours and keyboard controls. Local actions remain inert.
Tab selects controls, Enter activates them, and arrow keys scroll. `b` returns
through retained history; `q`, Escape or Ctrl-C exits.

## Hosting consent

`pages host profile` signs the independently accepted deployment manifest as its
operator. Select `--role pages` or `--role media`, the exact `--volume`, repeated
`--namespace` values, `--state-bytes`, `--maximum-asset-bytes` and `--retention-ms`.
Supply the accepted bootstrap and desired `--profile-digest`. The profile has no
direct network endpoints and cannot exceed the manifest's role or volume limits.
Physical storage admission includes both crash-safe banks and their metadata.

A manager registers that retained profile with `pages host register`, requiring
both deployment-management and hosting capabilities. Deployment registration
remains a separate registrar capability. `pages host get` and `pages host list`
provide current exact references; listing takes a role and namespace. The manager
or operator can use `pages host withdraw --role ROLE --host ID --generation N`
without a new discretionary grant. Withdrawal blocks subsequent serving.
The first withdrawal obtains certified historical ownership context, including
from a fresh local cache or after deployment expiry or withdrawal. Only the
recorded manager or operator can obtain that context without a grant; it grants
no content access or serving permission. A pending withdrawal resumes its exact
signed request without inserting another context request.
A context read interrupted before completion is resumed first; unrelated pending
work must be completed or explicitly fenced instead.

The Core runtime installs the signed profile and checks its activation separately.
A signed profile or a profile digest alone does not activate a service. Role1
Page storage and role2 media storage have separate consent and state files.

## Application permissions

An admitted application requires additional dual consent for native Page actions.
The owner uses `pages application offer` with the application identity,
namespaces, optional Page IDs, permissions and expiry. Review decisions also
require an explicit `--review-mode` and `--review-policy` digest. Mode zero is
manual; mode one identifies an explicitly configured automated policy.

The application inspects the exact signed offer with `pages application inspect`,
then uses its own requester and signing key for `pages application accept`.
`--offer-sha256` binds acceptance to the inspected file. Its current registered
owner, admission, grant and prior Page policy must still match. The owner commits
the returned dual-signed file with `pages application install`.

Permissions are PagesRead, PagesSubmit, MediaRead, MediaSubmit, MediaInspect,
ReviewInspect and ReviewDecide. They only narrow the application's live capability;
they cannot create a grant or bypass withdrawal. The signed policy binds exact
namespaces, optional Pages, expiry and review policy. Page author and reviewer
statements identify the exact policy version they used.
