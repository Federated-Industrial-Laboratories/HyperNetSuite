# Application context and authority checks

[Application streams](ApplicationStreams.md) | [Python SDK](../SDK/README.md)

Local IPC version2 adds typed, action-bound authority checks and directional
transport context. Version1 requests, responses, CLI commands and raw payload
streams retain their existing contract. An older endpoint can continue serving
version1 streams when the optional checks channel is absent.

## Discover capability

The SDK opts in with `Agent(directory, version=2)`. Its typed status distinguishes
three facts: the companion implements `checkAuthority-v2`; an authenticated Core
checks channel is ready; and a particular accepted incoming connection can be
checked. Outgoing connections have no receiving-end check capability. Readiness
never grants authority. A pending incoming handshake is not an accepted session.

Version2 `status`, `connect` and `accept` expose privacy separately from `peer`.
Status contains public identifiers and bounded connection metadata, without
private paths, keys, remote addresses or diagnostic prose. Version1 diagnostic
behaviour remains unchanged.

## Check one application action

The initial native frame remains a four-byte big-endian length followed by at
most16384 JSON bytes. A version2 check request has exactly these fields:

```json
{"version":2,"action":"checkAuthority","id":"LOCAL_CONNECTION_ID_64_HEX","nonce":"FRESH_NONCE_64_HEX","actionDigest":"ACTION_DIGEST_64_HEX","timeoutMs":1000}
```

The IDs and digests are lowercase hexadecimal. The nonce and digest must be
nonzero32-byte values. `timeoutMs` is required and ranges from100 to5000.
The companion looks up the exact active incoming connection, original verified
stream reference and cancellation state. Callers cannot supply another principal,
grant, session, network or service. The digest correlates an application-defined
canonical action; HyperNet does not interpret or authorise that application's
business semantics.

A successful IPC exchange returns `ok: true` with a typed `result.disposition`:

| Disposition | Meaning |
| --- | --- |
| `permitted` | A fresh certified authority result permits the original stream's current network authority. |
| `denied` | A fresh certified refusal, with its numeric authority code and certified observation. |
| `unavailable` | No usable current check could be obtained, including a full pending budget or unavailable endpoint. |
| `expired` | The bounded check or observation expired before use. |
| `notActive` | This exact incoming connection is absent, cancelled, finished or no longer active at the endpoint. |

Only permitted and denied receipts carry an authority observation. Its scope,
configuration, epoch, height, state and statement digests, evaluation time, expiry
and result code are explicit. Neither transport errors nor diagnostic text become
a certified denial. Malformed requests use an IPC error response instead.

The result echoes `id`, `nonce` and `actionDigest`. Endpoint receipts also bind
session ID and generation, companion and endpoint instances, control generation,
verified kernel boot, and an absolute boot-time bound. The companion checks the
endpoint signature and exact correlation before exposing the result. This is a
local verified observation, not a portable proof or a reusable application grant.

The wire names `callerStartedBootMs` and `callerDeadlineBootMs` mean the
companion's dispatch instant and derived absolute deadline. That deadline crosses
the Core queue and authority read unchanged; no retry restarts a relative timer.
`notAfterBootMs` further bounds a certified result by its authority and clock
validity. The SDK separately retains its original call-start timeout and uses the
minimum of that bound and the receipt bound. IPC delay therefore consumes the
application's own time budget. The signed observation is not rewritten.

One pending check is allowed per connection, with four across the companion.
The checks channel consumes none of the existing16 application connection slots.
An application must make a fresh check for each queued action, then enforce its
own current policy and operation order before performing that action. A check
does not prevent a later revocation, confer application permissions or approve a
changed digest.

## Local endpoint channel

The confined helper exposes `Ingress/Control.sock` for payload streams and
`Ingress/Checks.sock` for the single Core-initiated control connection. It passes
one descriptor with one of two fixed tags. Both sockets retain the same private
paths, mapped UID1001, peer credentials, chroot and syscall restrictions. No
arbitrary descriptor broker, listener or public control endpoint is added.

The companion challenges Core with a fresh nonce, binding digest, companion
instance, control generation and verified host boot. Core signs its readiness
with the binding's endpoint key and its own fresh endpoint instance. Both sides
require zero monotonic and boot-time namespace offsets, for private as well as
signed clock sources. A different boot or shifted time namespace refuses checks.
An active control channel cannot be replaced. Disconnect and restart invalidate
pending checks; a new channel requires a new challenge and generation.

Cancellation binds the exact original check. Closing the caller, cancelling the
application stream, losing the checks channel or stopping either process prevents
pending results from becoming success. A receipt already delivered to an
application cannot be retracted after an unobserved disconnect. The SDK invalidates
observations after known close, cancel, new check or observed control-generation
change, and rejects elapsed deadlines. Applications must not cache a permit.

## Directional privacy information

| Direction | Established facts | Limits |
| --- | --- | --- |
| Outgoing | The connection actually used authenticated nested TLS1.3 through the named relay and final service. | The selected minimum and configured assurance remain settings; saved labels do not prove physical operator independence or current certified profile state. |
| Incoming public mode2 | Endpoint-attested final-service TLS1.3, when an exact-session receipt is available. | A public endpoint cannot infer the caller's complete relay path; it reports `relayPath: unknown`. |
| Incoming attached mode3 | An exact-session receipt attests approved attachment arrival, relay service and attachment profile digest. | The attachment is not a claim of physical independence or fresh policy certification. |

When the already required certified service lookup names the same TLS destination
identity, outgoing metadata includes `certifiedEndpointProfile`: its exact
service generation, record/profile digests and observation times. This is bounded
provenance from connection preparation, not a claim that a saved label remains
current forever. `certifiedRelayProfile` remains null when no matching current
relay-profile observation was established. The metadata contains no profile file
paths, addresses or private key material.

A version2 accept attempts one bounded exact-session metadata check to obtain
arrival provenance. If that observation is unavailable, privacy remains unknown;
payload compatibility does not depend on checks readiness. Later successful
checks can supply the missing metadata. Status discards incoming provenance after
an observed control-generation change. No historical sidecar is consulted.

`physicalIndependenceVerified` and `profileCurrentnessAsserted` are false unless a
separately supported verifier establishes those properties. TLS transport
protection and application end-to-end message encryption are separate. The
companion reports the latter as application-defined. No selected route policy
can silently become a direct Internet connection.
