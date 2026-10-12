# Transfers and services

The independent Suite clients use canonical authority proofs and separate local
requester state. A deployment service, its operator, the admitted manager and
ordinary participants have distinct keys and permissions. An SSH grant does not
grant transfer access, and a transfer agreement cannot authorize SSH execution.

## Transfer trust and storage

Each command uses an independently accepted bootstrap and its SHA256, a retained
requester directory, an authenticated clock witness, the requester's Ed25519 key
and a private authority control socket. Initialize that requester floor through
`authority-inspection` first. `transfers COMMAND --help` lists these shared options.
These explicit inputs select the transfer authority and its retained trust floor.

Create a new encrypted transfer vault with `transfers init`, adding `--vault`
and `--age-key`. The parent directories must already exist. The command creates
a private directory and age identity and prints `recipientAge`. Authenticate
that public encryption identity independently when exchanging it with a sender.
It is distinct from the participant's Ed25519 authority key. Keep its private
file separate from backups of the encrypted vault. Losing the key loses access;
compromise permits decryption of retained ciphertext. Static keys do not provide
forward secrecy.

The locked encrypted vault preserves immutable outgoing ciphertext and partial
receive progress across restarts. Its admission is a 64 MiB encrypted-snapshot
working limit, with no artificial per-sender entry count. Ciphertext is at most
8 MiB per transfer, including encryption and metadata overhead. Full storage
reservation is derived from the selected host's signed admission and actual
encoded state. Quota failure does not choose another store automatically.

## Offer and explicit acceptance

Run these commands with each participant's shared authority options:

| Command | Additional options | Result |
| --- | --- | --- |
| `transfers offer` | `--grant`, `--vault`, `--age-key`, `--recipient`, `--recipient-age`, `--file`, `--expires-ms`, `--label` | Encrypts and retains the file, then submits its immutable signed offer |
| `transfers outbox` | `--vault`, `--age-key` | Lists locally retained offer identifiers, including unpublished jobs |
| `transfers publish` | `--grant`, `--vault`, `--age-key`, `--transfer` | Resumes publication of an already retained exact offer |
| `transfers list` | `--grant`, optional `--action 18` or `--action 19`, `--after` | Lists participant offers and a continuation cursor |
| `transfers inspect` | `--transfer` | Verifies the exact agreement and its current context |
| `transfers hosts` | `--grant`, optional `--action`, `--after` | Lists consenting stores under the requested permission |
| `transfers accept` | `--grant`, `--vault`, `--age-key`, `--transfer`, `--service`, `--destination`, `--expires-ms` | Verifies the local recipient key and selects one exact store |

Sender capability 18 and recipient capability 19 are explicit grants. A grant
record may be supplied with `--grant-record` when it is not already retained.
Times are absolute Unix milliseconds. The non-sensitive label and destination
are bounded display values, never filesystem paths. The filename and plaintext
digest are present only inside the encrypted file. An acceptance cannot change
its offer, key or placement; cancel it and prepare a new offer for a change.

## Send, receive and interrupted requests

`transfers send` takes `--vault`, `--age-key` and `--transfer`. Choose the exact
installed local service with `--service-directory PROFILE`; `--core` can select
the installed Core executable. An embedding application sharing the service UID
can instead use its correctly owned private socket via `--service-socket`.
The installed wrapper forwards an opaque packet; it never receives a member key.
Remote reader access depends on the approved privacy relay integration. These
commands do not provide an alternate direct reader endpoint.

Upload sends 64 KiB chunks and commits only when the complete ciphertext size
and canonical ciphertext digest match. `--maximum-chunks 1` explicitly requests
one chunk of progress;
the default zero means continue to completion. This option is not a protocol
traffic cap. Check `committed` in the result before treating upload as complete.

Repeat the same command after interruption. The exact retained intent is
reconciled against its selected store before a new request is allocated. A
changed pending operation is refused; recover it or explicitly fence its stream.
A lost response does not justify blind repetition of an uncertain effect.

`transfers receive` takes the same vault, service and transfer options, plus
`--destination` matching acceptance and an explicit new `--output` path. Each
received chunk is retained in the encrypted vault before its requester
completion is acknowledged. Replay must match those bytes exactly. Once complete,
the ciphertext digest, age authentication and encrypted file context, size and
plaintext digest are verified. Atomic publication writes a private output file
without replacement. Parent traversal, symbolic components and existing targets
are refused. No partial output is exposed, and the sender's filename remains
informational. There is no execution or archive extraction.

`--maximum-chunks` also bounds one explicit receive invocation. Its partial
result reports `complete: false`; repeat receive to continue. A fully retained
ciphertext can be decrypted locally by its owner. A receipt reports a past
verified effect and is never presented as current authorization for a new one.

For headless use, `transfers packet` exports a tracked finite operation. Put
requires its exact `--offset` and `--bytes`. Supply `--vault` and `--age-key`
to obtain that chunk from the retained ciphertext, or supply an exact
`--payload` file. Other effects have no payload.
Pass `--reconcile` only to recover the exact previously claimed request. Forward
it with `HyperNet runtime services exchange --directory PROFILE --packet
Packet.cbor --receipt Receipt.cbor`, then import with `transfers receipt` and the
same requester and vault. Receipt import verifies the quorum proof, selected
service signature and original pending intent before recording completion.

## Cancellation, deletion and local retention

`transfers status --transfer ID` obtains a fresh selected-store report.
`transfers delete --transfer ID` lets the recipient remove store ciphertext.
Both take the same service transport choice. `transfers cancel --transfer ID`
is an intrinsic restrictive action available to either participant. Cancellation,
expiry, revoked permission and service withdrawal prevent future store effects.
Tombstones permit exact old-claim reconciliation without reopening an upload.

`transfers forget --transfer ID --vault PATH --age-key KEY` removes this local
vault's retained ciphertext. It needs no current network authorization and does
not claim that authority or a remote store changed. Deletion and revocation
cannot erase previously disclosed copies, backups or physical media remnants.
Participant identities, labels, sizes and access timings remain visible to
selected infrastructure.

## Store provisioning

The deployment operator signs a reviewed local role 4 profile using
`transfers profile`. Supply the accepted bootstrap, exact `--manifest` and
`--profile-digest`, operator `--key`, writable `--volume`, `--state-bytes`,
`--maximum-payload`, `--maximum-lifetime-ms` and new `--output` file. The profile
requires explicit opaque hosting consent and sufficient declared memory and
storage. It declares no direct network endpoints.

An admitted manager registers that signed profile with `transfers register`,
`--profile` and its current capability 26 `--grant`. The operator or exact service
can submit restrictive `transfers withdraw --service KEY` even after its grant
expires. Local shutdown and local withdrawal use the installed Core
`runtime services` commands; public authority withdrawal remains separate.
Follow Core's TransferStore documentation for configuration, activation and
confinement. Service setup never grants an operator ordinary member authority.

## Discover and approve an SSH service

`services` uses the canonical authority domain protocol and is also available as
`authority-inspection ssh`. The two command paths have identical validation and
private requester state. They require an independently accepted bootstrap, its
SHA256, a pinned clock witness, a private authority control socket and the exact
requester's signing key. The selected requester directory must already have an
explicitly initialized authority floor.

A deployment's role8 service, its operator, native host key and native client key
are separate identities. An admitted manager requires capability 26 for the exact
deployment to register an operator-signed profile. A member requires capability20
to discover the service or request a session. Neither membership nor a manager's
capability implies native SSH access.

Use these commands in order; `--help` lists the required files and pins:

| Command | Effect |
| --- | --- |
| `services profile` | Operator signs the canonical manifest/profile digest, fixed command, native host key, endpoint, purpose and maximum session duration |
| `services register` | Manager submits that exact profile under current26 and host consent |
| `services service` | Member inspects one service under20; its operator or service may inspect its own metadata |
| `services list` | Member lists up to16 service records with an explicit continuation key |
| `services request` | Member submits a32-byte session ID, purpose, millisecond expiry and native-key possession proof |
| `services session` | Member or operator inspects its exact session |
| `services accept` | Exact operator or service accepts the session and permanently reserves native-key ownership |
| `services revoke` | Member, operator or service permanently restricts the session |
| `services withdraw` | Operator or service permanently withdraws the service |

The native possession proof uses a maintained OpenSSH installation's sibling
`ssh-keygen`. Supply a dedicated private key and canonical comment-free
`ssh-ed25519` public key. The private key remains local. A proof cannot be reused
for another member or network and does not replace explicit acceptance.

The signed profile allows at most300seconds per session. Only one accepted,
unrevoked, unexpired session can exist per service. Acceptance rechecks current
member20, manager26, registrar13 and exact host consent. Revocation and local
withdrawal remain available after expiry. Previously reserved native identities
cannot become governance, transport, operator or service keys.

## Supervised execution

The installed Core role8 runtime validates the exact operator-accepted artifacts
and a current quorum activation before serving. Its supervisor independently
checks each quorum-authorised lease and durably claims the effect before starting
or extending the fixed OpenSSH command. A suspend-aware timer invokes the supervisor's explicit exit handler, ending
namespace PID1 and all descendants even when its event loop is blocked. Local withdrawal,
revocation, invalid clock evidence, proof failure or loss of quorum ends execution.

`services authorise` is a service-owned maintenance diagnostic. It validates and
consumes a fresh lease without launching OpenSSH. It grants no membership or
reader rights to the service key. The protected installed supervisor uses its own
private requester directory; activation uses a separate recipient directory.

The Suite does not open a direct remote-reader SSH connection. Remote invocation
must use the scope-safe relay workflow; that route is qualified separately.
These local management commands provide no automatic fallback around it.

## Independent application interfaces

Independent clients use the finite `AuthorityDomain` commands and their canonical
signed request, freshness challenge, quorum result and serving receipt formats.
A selected store receives only `Put`, `Commit`, `Fetch`, `Status` or `Delete`
packets through the installed private exchange. Each packet binds one immutable
participant intent and exact ciphertext extent. The store obtains fresh quorum
authorization before claiming an effect in its recipient journal.

A transfer receipt binds the original intent, quorum proof, selected service and
reported storage effect. It is historical evidence, not authorization for another
operation or proof of physical media erasure. Neither the authority operation nor
the store accepts an output filesystem path or executes file content. Transfer
metadata discovery uses explicit bounded continuation keys.

SSH commands provide discovery, native-key possession, session request, separate
operator acceptance, restrictive withdrawal and fresh supervisor leases. They do
not issue general shell access or share private SSH keys. Independent applications
can use the documented CLI, private packet and receipt files, JSON output and
ordinary exit status. They receive no special rights. Consult the Core protocol
contracts before implementing the canonical wire formats independently.

These interfaces do not establish a direct remote-reader route. Remote routes
must preserve their required relay policy, including during failure and retry.
This profile is not an independent security certification or a qualified
production Internet deployment.
