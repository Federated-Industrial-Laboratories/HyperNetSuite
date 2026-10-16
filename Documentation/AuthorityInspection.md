# Local authority inspection

The local operator client verifies a current governance record against a
three-of-four executed-result certificate. It uses the private authority control
socket. This command does not join a network, open a reader route or grant an
operator a new capability.

The operator needs a complete accepted bootstrap, its independently verified
SHA256 digest, an existing administrator identity with InspectAudit permission,
and a fresh observation from the trusted local clock monitor. Initialisation
creates a new private floor directory; it never recreates missing trust files in
an existing directory. Restore or independent recovery needs its own procedure.

```sh
HyperNetSuite authority-inspection initialise \
  --requester REQUESTER_PUBLIC_KEY \
  --bootstrap /Private/Bootstrap.cbor \
  --bootstrap-digest VERIFIED_SHA256 \
  --directory /Private/OperatorFloor \
  --clock-witness /Private/Clock/ClockHealth.json

HyperNetSuite authority-inspection inspect \
  --bootstrap /Private/Bootstrap.cbor \
  --bootstrap-digest VERIFIED_SHA256 \
  --directory /Private/OperatorFloor \
  --clock-witness /Private/Clock/ClockHealth.json \
  --key /Private/Administrator.json \
  --socket /Private/Replica/Control.sock \
  --grant ROOT_GRANT_ID \
  --kind 100 \
  --lookup NETWORK_ID
```

Replace the uppercase placeholders with independently accepted identifiers.
Record kind 100 is NetworkPolicy; 101 is TierPolicy; 102 is Grant; 114 is
RecoveryPolicy; 125 is MemberAdmission; 126 is GrantRevocation; 127 is
ApplicationAdmission; 128 is ApplicationWithdrawal. The lookup ID is defined by that record's
PolicyContract schema. The identity file uses the ordinary Suite key format.
Private files must belong to the operator and exclude group and other access.
The control socket must be private and owned by the same operating-system UID.

The request names the exact retained generation and complete grant-chain
references. It has one recipient challenge and a five-second boot-clock
lifetime. Waiting, retrying, consensus and disk writes consume that lifetime.
A clock observation expires after one second and must be refreshed by the
trusted monitor. Unknown clock health, missing quorum, stale governance and an
unlinked committed prefix refuse without displaying a protected result.

A successful JSON response contains the record kind, lookup ID, generation,
record digest, committed height and decoded canonical record. Byte strings use
an explicit `hex` object. The output is produced only after signature, schema,
ancestry, capability, current restriction, durable floor and single-use checks.
The floor can be reopened by a later invocation or used with another eligible
replica in the same accepted configuration.

Long gaps use a quorum-certified checkpoint when contiguous repair exceeds 128
nodes or the replica reports that short history is unavailable. The request
names the actual durable prefix and any retained history-tree head. The client
checks checkpoint signatures, the retained node's inclusion, prior-tree
consistency and the exact suffix to the requested result. The checkpoint proof,
committed prefix and restrictive generation floors share one durable floor and
witness update before output. Reopening independently verifies that proof.
Missing or conflicting history refuses without resetting the floor or extending
the original deadline. Terminal checkpoints cannot authorise ordinary effects.

For an isolated operator container, the host monitor can publish signed
`ClockHealth.cbor` observations. Select this source explicitly with both
`--clock-monitor-key` and `--host-kernel-boot`. The key is the independently
accepted monitor Ed25519 public key in lowercase hexadecimal. The boot value is
the independently accepted current host kernel boot identifier. It is not the
container's possibly virtualised boot identifier. The monitor key must differ
from every authority voter key. After a host reboot, accept the new boot pin
through the same trusted local provisioning procedure.

```sh
HyperNetSuite authority-inspection initialise \
  --requester REQUESTER_PUBLIC_KEY \
  --bootstrap /Client/Bootstrap.cbor \
  --bootstrap-digest VERIFIED_SHA256 \
  --directory /Client/OperatorFloor \
  --clock-witness /Clock/ClockHealth.cbor \
  --clock-monitor-key MONITOR_PUBLIC_KEY \
  --host-kernel-boot HOST_KERNEL_BOOT

HyperNetSuite authority-inspection inspect \
  --bootstrap /Client/Bootstrap.cbor \
  --bootstrap-digest VERIFIED_SHA256 \
  --directory /Client/OperatorFloor \
  --clock-witness /Clock/ClockHealth.cbor \
  --clock-monitor-key MONITOR_PUBLIC_KEY \
  --host-kernel-boot HOST_KERNEL_BOOT \
  --key /Client/Administrator.json \
  --socket /Control/Control.sock \
  --grant ROOT_GRANT_ID \
  --kind 100 \
  --lookup NETWORK_ID
```

The two pin options are a pair: supplying only one refuses. With neither option,
the observation remains the private JSON source above. Invalid or unavailable
signed observations never fall back to private JSON or an assumed healthy clock.
The signed source verifies the exact kind-44 schema, one pinned monitor
signature, host boot, canonical numeric source address, one-second validity and
the shared 250-millisecond total error bound. Both monotonic and boot-clock time
namespace offsets must be zero. These signatures convey clock health only.

Run the operator in its own rootless container with `nomap` user namespaces.
Give it only its own accepted bootstrap and administrator identity, its own
writable floor directory, a read-only bind of the authority `Control.sock`
inode, and a read-only bind of the public clock-export directory. Bind the whole
clock-export directory so atomic publication remains visible; a bind of one
clock file would retain an expired inode. A clock observation opened before
atomic replacement may finish reading after its old inode is unlinked. Its
original signature, pins and expiry still apply; replacement does not extend
its validity. This exception is limited to clock observations, including the
private source's ownership and permission checks. Keep the control socket's destination
directory private and owned by the operator UID. Replacing the authority socket
requires refreshing its explicit socket mount. Do not mount the replica signer
directory, expose the operator identity to the replica, or give either process
access to the container-management API.

Exact inspection refuses a stale governance cache. Use the explicit certified
refresh below to obtain current records. This is a local operator interface;
it supplies no online reader fallback or complete authority deployment manager.

## Refresh current governance

`initialise` writes the verified bootstrap records to the private
`Governance.cbor` cache. `inspect` reads this cache and requires its record
hashes to match the independently verified bootstrap and durable certified
version floors. A cached record never grants authority by itself.

Use the explicit `context` operation when the cache is absent, damaged or
stale. This requests the complete current governance set under the operator's
current network-scoped InspectAudit capability. The signed request carries the
minimum certified point. Known version minima remain local and must all appear
at equal or newer generations in the completed result.

```sh
HyperNetSuite authority-inspection context \
  --bootstrap /Client/Bootstrap.cbor --bootstrap-digest "$BootstrapDigest" \
  --directory /Client/OperatorFloor --key /Client/Administrator.json \
  --socket /Control/Control.sock --grant "$AuditGrant" \
  --clock-witness /Clock/ClockHealth.cbor \
  --clock-monitor-key "$MonitorKey" --host-kernel-boot "$HostBoot"
```

The response must contain every current governance record and its exact
VersionRef, including permanent grant revocations. The client verifies the
quorum, committed ancestry, complete typed record set, retained minimums and
current InspectAudit capability. It persists the certified floor before
returning any records. It saves the private cache within the protected workflow
before completing the tracked request. A cache-write failure leaves the newer
floor and exact pending request intact. Repeating the same context command
resumes those signed bytes with a fresh challenge; it does not create a new
operation. The command never resets trust to recover a cache.

Discovery transfers at most 64 records and 32768 encoded result bytes per page.
Every page binds the same ordered records root and total count. The authority
rechecks current InspectAudit permission on every page. Receipt updates can
advance the certified point without changing the records root. A governance
change refuses the continuation with code 12; pages from different views cannot
be combined. The bounded complete cache supports up to 2048 records.

Incomplete pages remain in the private `GovernancePages.cbor` staging file and
cannot serve as a governance context. Repeating the command resumes its exact
pending request or next page. After a refused or explicitly fenced request,
`context --restart-discovery` discards only this incomplete assembly and starts
a new read. It refuses to discard an unresolved immutable request. Version
floors and completed context remain intact. Ordinary exact inspection keeps
its exact revision rules and its 64-reference bound.

## Permanently revoke a grant

`revoke-grant` requires the exact target grant ID, generation and record digest
from the retained certified context, plus a current network-scoped RevokeGrant
capability. It binds the request to the retained committed point using the
application state digest, and to every applicable current dependency.

```sh
HyperNetSuite authority-inspection revoke-grant \
  --bootstrap /Client/Bootstrap.cbor --bootstrap-digest "$BootstrapDigest" \
  --directory /Client/OperatorFloor --key /Client/Administrator.json \
  --socket /Control/Control.sock --grant "$RevokerGrant" \
  --target "$TargetGrant" --target-generation "$TargetGeneration" \
  --target-digest "$TargetDigest" \
  --clock-witness /Clock/ClockHealth.cbor \
  --clock-monitor-key "$MonitorKey" --host-kernel-boot "$HostBoot"
```

A successful ordered operation creates a first-generation kind126 tombstone
for the target grant ID. The client independently constructs the exact expected
tombstone and verifies its certified result before updating its floor and cache.
Every subsequent capability use through that grant or a descendant is denied.
Revoking the authorising grant itself is permitted by its valid pre-operation
capability; the resulting tombstone then prevents further use.

This operation does not refresh permissions or retry a refused mutation. If
another operation changes the committed state first, refresh explicitly and
review the target again. A local timeout does not prove that a submitted
revocation failed to commit. Refresh through a different still-authorised grant
and inspect the target tombstone before deciding what to do next. No command
removes a tombstone or reuses its grant ID.

## Inspect or close a request stream

Initialisation requires the requester's public key. Every later signing identity
must match it. Use one private tracker per requester; copying a tracker into
concurrent writers is unsupported. Ordinary commands durably prepare their exact
signed bytes before submission. Repeating a pending command retains its sequence,
acknowledgement, expectations and parameters with a new five-second challenge.
A different command refuses until the prior workflow is resolved or explicitly
fenced. A timeout does not discard its pending request.
After a completed ordinary request, the client uses its retained current-epoch
stream metadata and exact completion to select the next sequence. It does not
request status again solely because that workflow completed. Initial use, an
epoch change and a refusal without a known original outcome still require status.
This reuse grants no current permission; every new operation needs its own fresh
challenge and verified quorum result. Invalid local completion state refuses
instead of triggering an automatic status request.

`stream-status` requires the usual bootstrap, directory, clock, key and socket
options, with no grant or domain target. It returns only certified own-stream
metadata, including the original completion digest and disposition. A refusal to
disclose an old protected body does not establish that the original operation
failed. Status does not consume an ordinary sequence or grant domain access.

`stream-fence` takes the same options. Invocation explicitly closes the previous
generation after comparing its exact verified metadata. It resumes an already
prepared fence unchanged. Successful output distinguishes Applied from
AlreadyApplied and reports the current metadata. A competing or superseding
fence refuses; it never selects another generation silently. A subsequent new
ordinary request uses only the accepted new generation.

Fencing preserves unresolved prior operations and any uncertain local effect.
It neither reverses a committed mutation nor recovers a protected result body.
If a pending mutation's governance cache cannot be validated, inspect its stream
and resolve the original outcome before choosing a fence and certified context
refresh. Never delete the floor or pending journal to make another command run.
The floor and retained uncertainty are bounded to 2 MiB; capacity refusal keeps
those records intact. No old outcome is evicted to admit new work.

## Delegate a grant and admit its holder

Delegation requires DelegateGrant through one complete current parent chain.
Admission separately requires AdmitMember. The administrator also supplies an
explicit InspectAudit grant for current context discovery. These may be different
grants. A delegated grant for an unadmitted candidate remains inert.

Use `delegate-grant` with the usual bootstrap, directory, clock, key and socket
options. Supply `--context-grant`, the exact current `--parent` grant ID, a new
`--id`, the candidate `--subject` public key, `--not-before-ms` and `--expires-ms`.
The default action is ReadPage0 and delegation depth is zero. Optional
`--actions`, `--scopes`, `--tier`, `--delegation-depth` and `--limits` select exact
restrictions within the parent chain. Actions use comma-separated numbers;
limits take four space-separated values in bytes, objects, connections and
concurrent-operations order, such as `--limits 10 10 2 2`. Scopes use
comma-separated `kind:hexId` pairs. No option can widen the
parent or tier. The successful output identifies the created grant and digest.

The invitation workflow is:

| Command | Required inputs beyond the selected bootstrap | Result |
| --- | --- | --- |
| `invite-member` | Administrator floor, clock and key; `--reader-grant`, new `--member`, `--not-before-ms`, `--expires-ms`, `--output` | Administrator-signed immutable offer and exact reader-grant bytes |
| `inspect-offer` | `--offer`; independent `--inviter-key` when required | Read-only display of the terms and complete reader grant |
| `accept-member` | Candidate `--key`, `--offer`, `--output`; independent `--inviter-key` when the inviter is not an accepted genesis administrator | Candidate signature over the same offer |
| `admit-member` | Administrator floor, clock, key and socket; separate `--context-grant`, authorising `--grant`, `--accepted`, `--receipt` | Certified member record and historical admission receipt |
| `confirm-member` | `--accepted`, `--receipt` | Verified historical admission, without current permission |

All commands require `--bootstrap` and its independently verified
`--bootstrap-digest`. The offline `inspect-offer`, `accept-member` and `confirm-member` commands
use no authority socket or requester floor. Keep each identity and floor private.
Give the candidate only the offer, its own key and accepted bootstrap. Do not
share the administrator's key, floor or full governance cache.

Use `inspect-offer` before signing. Review the member identity, signing key,
validity, inviter, grant actions, scopes, limits and delegation depth. The default acceptance window is one hour;
`--acceptance-ms` can narrow it or extend it up to24hours within member validity.
An altered grant digest, key, network or validity requires new acceptance.
Admission obtains fresh context after acceptance and binds its current state.
A concurrent change can refuse the mutation; the command does not silently alter
or broaden the signed terms.

Admission atomically creates the member, retained signed evidence and one request
stream. A successful exact retry does not reset a stream the candidate already
used. Grant or member IDs cannot be reused. Permanent stream and evidence limits
can refuse new admission; expiry and revocation do not reclaim those identities.

`confirm-member` verifies an executed-result quorum and the exact accepted terms.
For a receipt certified after committee replacement, add `--prior-epochs Epochs.json`.
The complete archive must verify from the independently accepted bootstrap. Its
matching historical committee verifies the receipt; this grants no current permission.
Its `HistoricalMemberAdmission` result has `currentPermission:false`. It does not
prove that the member or grant remains valid, and does not import the
administrator's challenge or floor. The candidate separately runs `initialise`
with its own requester key and then `stream-status` through its own private floor.
That fresh result proves only stream metadata. Ordinary members do not gain
InspectAudit or any other capability from these commands.

Revoking the initial reader grant prevents its use and use by its descendants.
It does not revoke the membership record or a separately granted capability.
Online invitation redemption and reader routing require their designated relay
workflow; this local operator interface supplies no direct-reader fallback.

## Application consent

[ApplicationAccess](ApplicationAccess.md) provides the separate application
workflow. Owners with DelegateGrant can use a scoped delegation context without
InspectAudit. Application identities retain their own floors and request streams.
Application lifecycle inspection and restrictive withdrawal do not disclose the
complete governance context or confer permission to execute a domain operation.

## Deployment consent and admission

`authority-inspection deployments` separates operator approval from registrar
admission. Registration records permanent ownership and reserves service identities.
It does not activate a domain service or grant access to its content.

Offline commands require `--bootstrap FILE --bootstrap-digest SHA256`. Authenticate
the complete accepted bootstrap digest through an independent channel. Keep keys,
offers and state in private directories. Output files are created without replacing
existing files. Public signed runtime artifacts may be mode 0444 or 0644; they
must be single-link files owned by the current user or root, without group or
other write permission. Every private key remains owned by the current user,
single-link and inaccessible to other users. Deployment `--key` accepts identity
JSON or the installed raw 32-byte Ed25519 seed, including `Keys/Operator.key`.

1. Run `deployments prepare --manifest-json Manifest.json --output Manifest.cbor`.
   This validates the canonical runtime manifest and displays every resource,
   endpoint, service key, placement, validity and the resulting `profileDigest`.
   JSON follows the runtime manifest schema; identifiers use arrays of 32 bytes.
   An installed host can supply its existing `Authorization/Manifest.cbor` instead.
2. The operator reviews that manifest and runs `deployments consent --manifest
   Manifest.cbor --profile-digest DIGEST --key Operator.json --output Consent.cbor`.
   This signs only its exact unwithdrawn HostConsent105. An installed host's signed
   `Authorization/Consent.cbor` can be imported without signing again.
3. Each key holder runs `deployments possess --manifest Manifest.cbor --class
   service --key Service.json --not-before-ms START --expires-ms END --output
   ServicePossession.cbor`. Repeat for each distinct service, owned TLS transport
   and clock monitor. Classes are `service`, `transport` and `monitor`. Transport
   supports `--tls-key Transport.pem` in place of `--key`, using Ed25519 PKCS8 PEM.
   Possession binds the exact profile and consent, a fresh nonce and an interval
   within consent, no longer than 24 hours. It cannot sign another key class.
4. Import the complete set with `deployments assemble --manifest Manifest.cbor
   --consent Consent.cbor --possession ServicePossession.cbor --possession
   TransportPossession.cbor --possession MonitorPossession.cbor --output Offer.cbor`.
   Repeat `--possession` for additional owned keys. The assembler sorts identities
   and refuses missing, repeated or mismatched signatures. `deployments
   inspect-offer --offer Offer.cbor` verifies and displays the same public contract.

Online commands use the existing inspection location flags: `--bootstrap`,
`--bootstrap-digest`, `--directory`, `--clock-witness`, `--key`, and `--socket`.
Signed clock observations additionally need `--clock-monitor-key` and
`--host-kernel-boot`. Each requester initializes its own private floor with
`authority-inspection initialise`; floors and request trackers are not shared
between the operator and registrar. The socket must be the selected replica's
private same-UID local control socket.

The registrar uses `deployments context --deployment ID --grant GRANT` to inspect
only its current RegisterService13 capability closure and immutable bootstrap roots.
InspectAudit25 is not required. `deployments register --offer Offer.cbor --grant
GRANT` obtains that context and submits the exact offer. Quorum verification binds
HostConsent105, DesiredDeploymentProfile117 and DeploymentRegistration129 together.
Registration advances the registrar's certified version floors. Before using
general `authority-inspection inspect` again, refresh its separate governance
cache with `authority-inspection context`. Deployment commands retain their own
scoped cache and do not update the general inspection cache.
The returned `DeploymentRegistered` does not authorize local activation.

After the installed service returns its activation receipt, use `deployments
activation-complete --receipt FILE` with the manager's original requester floor.
An independently verified receipt that extends that floor, or matches its retained
original completion, is recorded locally without another clock challenge or network
request. Receipt expiry does not erase a completion made within its valid interval.
If the receipt cannot connect to the retained floor, the command obtains fresh
own-stream status before recording it. A failed reconciliation leaves the exact
activation pending; preserve the receipt and resume the same completion command.
Reporting a receipt grants no current permission and cannot activate the service again.

Use `deployments get --deployment ID --grant GRANT` as a current registrar. The
recorded operator omits `--grant` and can inspect its deployment after consent or
capability expiry and after withdrawal. Get verifies the canonical manifest,
operator signature, profile digest, ownership and any withdrawal against the
certified references. It never substitutes metadata from another deployment.

Before `deployments withdraw --deployment ID --local-withdrawal FILE`, set the
host's durable local veto. The installed Core host provides `runtime withdraw
--directory ROOT --operation-id ID --expected-generation GENERATION
--profile-digest DIGEST`, followed by `runtime withdrawal-receipt --directory ROOT`.
Pass the returned `Authorization/WithdrawalReceipt.cbor` path to Suite. Other
hosts can produce the same purpose-bound operator assertion after durably recording
local withdrawal. Suite checks its exact network, incarnation, deployment, operator,
profile and positive generation. `cleanupComplete=false` still permits restrictive
network withdrawal; remaining local cleanup must be retried. The signature asserts
the operator's durable local veto, not independently verified physical shutdown.
Network withdrawal is permanent and has no consent-expiry dependency.

Scoped caches are authenticated against the requester's retained quorum floor.
Registration and withdrawal preserve the original signed intent across failures;
retry the same command and immutable input files. A different offer, grant,
deployment or withdrawal generation is refused while that request remains pending.
If a withdrawal commits before its cache is saved, retry reconstructs the missing
restriction only from the exact pending intent and its retained certified digest.
The existing floor and the original signed request remain unchanged.
Refused certified requests can be resolved through the existing stream mechanism;
explicit fencing retains uncertainty about an unresolved effect. A successful Get
refreshes lifecycle metadata but does not make an old grant current. No command
silently broadens discovery or starts a service.

## Sealed recipient identity

`authority-inspection recipients` manages separately encrypted user roots,
device admission, independently pinned contacts and frozen publication rosters.
Follow [Recipients](Recipients.md) for its custody, possession and revocation
boundaries. Ordinary membership and InspectAudit do not confer decryption access.

## Operational deployment successors

An initial manifest has `generation: 1`, `previousProfile: null` and
`previousConsent: null`. Every stopped successor names the exact preceding desired
profile117 and host consent105 hashes and advances by one. The immutable identity
and rights include all keys, routes, endpoint pins, resources, storage and placement.
Only finite validity, host boot, explicit Session/Managed policy and reviewed
software/image identity can change. A successor preserves existing domain profile
approvals and their independently shorter validity limits.

Installed `runtime transition` and `runtime services transition` retain public signed
offers under their deployment's `OperationalOffers` directory. After the initial
admission, use the normal requester and independently authenticated clock inputs:

```sh
HyperNetSuite authority-inspection deployments synchronise \
  --bootstrap /Private/Bootstrap.cbor --bootstrap-digest PIN \
  --directory /Private/RegistrarFloor --key /Private/Registrar.json \
  --socket /Private/Control.sock --clock-witness /Private/Clock/ClockHealth.cbor \
  --clock-monitor-key MONITOR_PUBLIC_KEY --host-kernel-boot CURRENT_HOST_BOOT \
  --grant REGISTER_SERVICE_GRANT \
  --offers-directory /Private/Service/OperationalOffers
```

Synchronisation submits each missing signed successor as a separate bounded durable
transaction. It retains exact requester retry state across interruptions. The
client can reconstruct an interrupted cache publication only when all three
derived successor references match its retained certified floors. Repeating the
command completes that same pending registration even when those floors already
contain its new generation; it does not submit another mutation or reset trust. The
currently certified manager capability, unchanged identity mapping, exact prior
105/117/129 references, and terminal withdrawal are checked for every generation.
Initial admission still requires all service, transport and monitor possession
proofs. Operational successors reuse those already admitted identities and do not
require new private signatures from the monitor or peers.

If an intermediate already expired, the signed request explicitly marks historical
admission. This is permitted only for a successor that is already expired; future
or initial consent cannot use it. It records continuity without enabling service.
Only fresh final admission can authorize serving, and local recovery markers still
require a fresh reviewed stopped successor. Network results never clear withdrawal
or revive expired local consent. Retain the offer directory until all intended
registrars and replica recovery steps have consumed its history.

Local terminal withdrawal assertions bind the deployment's stable operational
resource digest, operator and network identity. Their resource binding survives
renewed validity, host boot and software changes, so the operator can publish a
local veto even if a successor is incomplete or not yet registered. A changed
permanent identity, endpoint, permission or resource allocation does not match.
