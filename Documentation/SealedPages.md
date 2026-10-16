# Sealed Pages

Sealed Pages encrypt the approved source and media to an exact admitted recipient
roster. Storage hosts receive ciphertext, its size and signed placement metadata.
The reviewer receives a separate encrypted author submission. The final reader
verifies the author, reviewer, current authority and exact ciphertext before display.

Create and independently accept recipient roots and devices as described in
[Recipients](Recipients.md). Host consent must permit opaque content, the selected
reviewer, volume, namespace, size, retention and failure domain. The network,
namespace and object policies must all permit sealed publication. No administrator
grant replaces an accepted contact root or a device possession proof.

## Arguments and private state

`[online options]` means the explicit `--bootstrap`, `--bootstrap-digest`,
`--directory`, `--clock-witness`, `--key` and `--socket` arguments. Include both
monitor pins when the clock witness is signed. `[local options]` omits `--key`
and `--socket`. `[vault options]` means `--vault` and `--age-key`.
[Authority inspection](AuthorityInspection.md) describes bootstrap acceptance
and requester initialization. Use each command's `--help` for exact arguments.
When a capability is not retained in that requester's directory, provide its
exact canonical `--grant-record` together with `--grant`. This includes a new
reader device floor using a delegated member grant.

Use separate private requester directories for publisher, reviewer and reader
device. The sealed reader takes its signer from the selected vault device.
Initialize that device floor with `authority-inspection recipients floor-initialise
[local options] [vault options] --role device --identity DEVICE`.
The reader grant belongs to the device's member and must authorize this object.

Object, publication, device, host, volume and grant identifiers are nonzero
32-byte hexadecimal values. An object retains its identity across revisions.
Each finalization uses a new publication identifier. Expiry arguments use absolute
Unix milliseconds. Keep source files, media inputs, vault keys, requester floors
and attempt directories on private persistent storage outside the software prefix.

## Select the audience and placement

The publisher independently pins every audience root in its vault. It creates
the exact audience with `authority-inspection recipients audience-set`. The
reviewer independently pins those same roots in its own vault. An authority
directory response alone does not establish either party's contact trust.

An authorized policy administrator sets the namespace modes:

```sh
HyperNetSuite pages sealed namespace [online options] --grant POLICY_GRANT \
  --namespace Books --mode sealed
```

The grant must explicitly authorize namespace policy administration. Repeat
`--mode host-readable` only when both publication modes are intended. Changing
the allowed modes does not disclose existing ciphertext as plaintext.

The publisher signs and commits the object policy:

```sh
HyperNetSuite pages sealed policy [online options] [vault options] \
  --grant AUTHOR_GRANT --object OBJECT --namespace Books --audience Audience.cbor \
  --host HOST --volume VOLUME --copies 1 --output Policy.cbor
```

Repeat `--host` and `--volume` for every permitted destination. The author grant
requires creation and sharing authority for the object. A separate retained
`--read-grant` can authorize the exact audience metadata query. It does not widen
the author's publication capability. The object policy fixes a private audience
and sealed mode. Host and volume selections are checked again during finalization.

## Encrypt and inspect the author submission

The publisher pins the reviewer's root independently and obtains its current,
root-signed device binding and admission. The reviewer device can be outside the
publication audience. Its metadata query needs explicit scope, supplied through
`--read-grant` when the author grant does not permit that member's records.
Before encryption, submission checks the reviewer's current network membership
or bootstrap authority, accepted root and exact device admission. The device
must permit sealed reading and its admission must cover the network or this
object. Expired or revoked membership, roots, bindings and admissions refuse new
submissions even when the contact remains independently pinned.

```sh
HyperNetSuite pages sealed submit [online options] [vault options] \
  --grant AUTHOR_GRANT --policy Policy.cbor --source Draft.Page \
  --asset Cover=/Private/Cover.rgb --reviewer-binding ReviewerDevice.cbor \
  --revision 1 --expires-ms AUTHOR_EXPIRY --output Submission.age
```

Omit `--asset` when there is no media. Each source asset needs one exact mapping.
The source limit is 16 KiB; at most 64 assets share a 4 MiB byte limit. Source
and media follow the inert [HyperPage](HyperPage.md) and [Media](Media.md) contracts.
The encrypted submission contains the author's signed exact hashes, object policy,
audience, revision, grant and expiry. Its plaintext never enters ordinary Page
submission or review queues. Deliver the ciphertext to the selected reviewer.

The reviewer opens that exact submission locally:

```sh
HyperNetSuite pages sealed inspect [local options] [vault options] \
  --binding ReviewerDevice.cbor --policy Policy.cbor \
  --submission Submission.age --tui
```

Inspect the entire source and explicitly reveal each required image. Inspection
prints the encrypted `submissionDigest` after the viewer closes. It grants no
publication approval. Omitting `--tui` prints text to standard output; protect
the terminal and any shell redirection. Media is decoded only from the encrypted
submission's verified bytes. External media files cannot substitute for them.

## Approve and retain one encrypted attempt

Finalization requires explicit manual approval and the exact inspected digest:

```sh
HyperNetSuite pages sealed finalise [online options] [vault options] \
  --grant REVIEW_GRANT --binding ReviewerDevice.cbor --policy Policy.cbor \
  --submission Submission.age --inspected-digest SUBMISSION_DIGEST --approve \
  --namespace Books --publication PUBLICATION --encryption-generation 1 \
  --failure-domains 1 --expires-ms STORAGE_EXPIRY --attempt-directory Attempt
```

The reviewer grant requires both inspect and decision authority for this object.
The command retrieves current policy and recipient evidence, freezes the complete
roster, and checks the exact author capability and hosting consent. It signs the
inner approval and encrypts the source and media with a fresh content key. The
outer signature binds that exact ciphertext, placement and authority snapshot.

Before staging any ciphertext, finalization saves `Attempt/SealedPublication.age`.
This immutable private file is encrypted to the selected reviewer device. It
contains the exact staging command, capability and ciphertext needed for retries.
Retain the reviewer vault, its age key, requester floor and attempt together.
The new attempt directory must not already exist. A successful finalization does
not yet upload or publish content.

## Upload and commit

Configure an explicit local route for each selected storage host in the reviewer's
requester directory:

```sh
HyperNetSuite pages content route --directory ReviewerFloor --host HOST \
  --service-socket /Private/Content.sock
HyperNetSuite pages sealed publish [online options] [vault options] \
  --grant REVIEW_GRANT --device REVIEWER_DEVICE --attempt-directory Attempt
```

Use `--service-directory` with an installed Core service instead of a socket when
required. `--core` selects that installed executable. There is no inferred network
destination or origin fallback. Routes must cover the required copies and failure
domains. Each route still requires the current exact host consent and proof.

Publishing stages the signed metadata, transfers only the retained ciphertext,
commits durable host receipts, and then requests publication commit. The command
reports success only after the required complete copies are accepted. A timeout
retains the exact pending request and transfer progress. Repeat the same `publish`
command with the same attempt, device, grant and requester directory.

Do not regenerate ciphertext for a transport retry or delete a pending floor.
Resolve the retained request first. A changed audience, device admission, policy
or other signed dependency can refuse the attempt. Re-finalization requires current
evidence, a new publication identifier, a higher encryption generation and a new
attempt directory. Every selected recipient must retain current membership and
device admission. An inactive member refuses the audience even when its device
binding remains valid; explicitly update the audience before fresh encryption. A replacement of an already published revision also needs a
higher author revision and a new author submission. Reinspect changed source or
author intent. Old ciphertext and already disclosed plaintext cannot be recalled.

## Read and withdraw

Configure content routes in the reader device's requester directory, then read:

```sh
HyperNetSuite pages sealed read [local options] [vault options] \
  --socket /Private/Authority.sock --grant MEMBER_READ_GRANT \
  --device DEVICE --object OBJECT --tui
```

The device signs its own requests. Current membership, capability, root, binding,
admission and frozen-roster inclusion must all pass. The client retrieves current
published metadata, obtains fresh content authority, checks the ciphertext digest,
and verifies both encrypted signatures against the outer publication and policy.
Expired author statements are refused. Durable transfer progress stores ciphertext;
decrypted source and media stay in process memory. There is no plaintext output
file option or persistent plaintext Page cache.

The screen labels content as verified at fetch. Refresh requests current authority
and content again. A refused refresh leaves the previously verified in-memory
display clearly marked as retained. Images require explicit reveal. Forms,
catalogues, internal navigation and external navigation are unavailable in this
sealed view; use a separate explicit sealed read for another object.

The publisher withdraws a publication with:

```sh
HyperNetSuite pages sealed withdraw [online options] --grant AUTHOR_GRANT \
  --object OBJECT
```

Withdrawal stops fresh authorized serving and creates the exact placement
tombstone. It cannot erase plaintext or keys already received by a recipient.
The successful `publish` result includes the placement's identifier, generation
and digest. After withdrawal, use those exact values with `pages content purge`,
the publisher grant, the selected host route and a private progress directory.
Purge removes that host's ciphertext through its current tombstone authority.

## Bounds

This interface uses manual review. No model receives sealed source automatically.
Reviewer contact encryption currently requires a directly root-signed binding;
the authority's delegated enrollment support does not imply local delegated
contact acceptance. Public anonymous sealed audiences are not enabled. The shared
proof bound can admit fewer recipients than the maximum wire roster; excessive
dependency closure is refused, never truncated.
All required control and content routes are explicitly selected local transports.

## Cold content backups

For [cold content backups](Backups.md), both the author's policy and the exact
approved outer placement must permit the named backup destination. The destination
must separately consent to the reviewer and opaque storage. The publisher may
read or repair its exact currently published ciphertext using current Submit
authority. This exposes no plaintext keys, adds no recipients and does not grant
approval for changed bytes. Restore rechecks the current publication and every
normal per-chunk placement/tombstone condition; archived search indexes and
authority journals are never imported.

An author names each permitted cold destination with `pages sealed policy
--backup DESTINATION_ID`. Repeat the option for multiple distinct destinations;
omitting it authorises no cold backup. Reviewer finalisation carries the exact
author placement into its signed outer publication and fetches current destination
consent before approval. A missing, withdrawn or incompatible opaque destination
refuses finalisation.
