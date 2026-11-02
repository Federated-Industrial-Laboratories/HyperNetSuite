# Native authority connector

[Documentation](ReadMe.md) | [Application streams](ApplicationStreams.md) |
[Private routes](PrivateRoutes.md)

An installed Core service can use a remote authority through a native Suite
connector. The connector exposes one private local socket and forwards only
same-network authority protocol packets through the joined profile's exact
retained relay route. It does not sign the Core request, advance Core's requester
floor, grant capabilities or supply a direct fallback. Core continues to verify
quorum evidence, clock observations, current permission and original deadlines.

Prepare and join a dedicated network profile through the normal client workflow.
Retain its protocol1 authority route. Give this profile exclusively to the
connector; an application stream companion uses a separate joined profile.
The connector holds the dedicated requester lock without modifying its state.

```sh
HyperNetSuite network authority-connector --profile /Private/Authority/Profile.json \
  --ipc-directory /Private/AuthorityConnector

HyperNetSuite network authority-connector-status \
  --directory /Private/AuthorityConnector
```

The native account owns the connector root, which must be canonical and mode0700.
The rootless helper creates `Ingress/Binding.json` and `Ingress/Control.sock`
under the exact subordinate account used by Core. The directory remains mode0700
and the socket mode0600. The helper confines its filesystem, drops privileges
and passes accepted descriptors over its inherited private channel. It receives
no route possession key, client profile or signing key.

Pass `/Private/AuthorityConnector/Ingress` to Core runtime setup's
`--authority-connector-directory`, instead of `--authority-directory`. Core pins
the network, incarnation, accepted bootstrap digest and public route target
digest. The target includes the exact relay address, TLS identities, domains,
assurance and limits. It excludes the renewable voucher. Core mounts only the
mapped ingress directory; the native credentials remain outside its container.
The connector must be ready before setup and remain running while Core needs it.

One authority TLS session is reused while its original transport budget permits.
At most16 local connections wait for its serial actor. Each connection carries
one bounded request and reply. Intake has a five-second deadline; the whole
queued exchange has a30-second maximum and cannot extend Core's own deadline.
Caller disconnection or process termination cancels an ordinary active exchange. Invalid,
foreign-network and management packets close without reaching the authority.

A consumed fresh read can send signed control operation8 as optional cleanup.
The mapped ingress publishes `ReadAcknowledgements.sock` as a private hard-link
alias of its existing `Control.sock`. It adds no listener, queue or connection
allowance. Core verifies the same owned socket device/inode before sending;
absence or substitution skips cleanup without contacting a legacy connector.
Both names share the existing socket's cleanup and replacement checks.
Its version1 acknowledgement binds the network scope, original read identifier,
complete statement digest, result digest and deadline. The Core recipient signs
it only after consuming that exact result. The authority releases only the
matching completed read; pending and unacknowledged reads retain their original
expiry and lost-response recovery.

Cleanup uses the same16-entry queue and only the existing admitted TLS session.
It cannot open a new session, renew a budget or retry a read. Its deadline is
the earlier of the original queued deadline and the signed deadline translated
through the healthy clock with the conservative clock margin. That signed
deadline is bounded by Core's original call and statement expiry. Invalid or
expired deadlines refuse cleanup. Cleanup requests and receipts are at most1024
bytes. The connector drains one exact, bound version1 receipt from the remote
authority. A connected forwarding caller receives the framed receipt; a closed
notification sender needs no reply. A false receipt can mean cleanup was skipped
for unsupported transport, or the exact entry was already released or expired.

Only protocol1 final-service TLS offers optional `HyperNetRoute/1+ReadAck1`,
followed by the existing `HyperNetRoute/1` fallback. The authenticated endpoint's
selection reports cleanup support. Relay TLS keeps its existing protocol. If
the final session selected legacy TLS, the connector skips cleanup and returns
a bound false receipt locally. It sends no probe or unsupported packet and keeps
the same usable session for ordinary requests.

Core never waits for cleanup, and a cleanup failure cannot change the consumed
result or reuse its authority. Supported combinations are:

| Consumer and transport | Cleanup behavior |
| --- | --- |
| Legacy Core consumer | No cleanup; existing start/poll semantics |
| Updated Core with legacy local connector | Missing alias skips cleanup without opening a socket |
| Updated connector with legacy collecting endpoint | Legacy final TLS skips cleanup; ordinary session reuse continues |
| Updated Core, connector and collecting endpoint | Exact consumed result can release its completed collection |

Skipped, lost or failed cleanup leaves the read retained until its original
expiry. Existing control operations and their reply semantics do not change.
Process termination still cancels cleanup.

Status includes the voucher expiry, completed/refused counts, the current bounded
error and the observation's boot timestamp. It is a local snapshot, not a claim
of current remote permission. An expired voucher refuses forwarding. Retain an
explicitly renewed same-target authority route through an independently valid
authority connection, then restart the connector if its profile must be used
for that operation. Normal `network retain-route` updates can be loaded while
the connector runs. A changed public target requires explicit stopped-service
reconfiguration and new Core consent. The connector never resets quota, rotates
identity or uses an expired route to authorise its own renewal.

SIGINT or SIGTERM stops admission, cancels the active exchange, drops queued
connections and reaps the mapped helper. Restart uses the same profile, current
retained route and binding. It does not replay a Core request on its own.
