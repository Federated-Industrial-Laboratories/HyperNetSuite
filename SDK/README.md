# HyperNet application stream SDK

This Linux Python package uses the private HyperNetSuite companion. The companion
owns HyperNet cryptography, permission checks, requester floors and route renewal.
The package has no runtime dependencies. Install the included wheel with
`python3 -m pip install --no-index SDK/hypernet_streams-0.10.0-py3-none-any.whl`.
A source checkout also supports `python3 -m pip install ./SDK`, or adding the SDK
directory to `PYTHONPATH`. Build a wheel offline with
`python3 -m pip wheel --no-deps --no-build-isolation --wheel-dir dist ./SDK` from
the Suite repository, with setuptools available in the build environment.

See [ApplicationStreams.md](../Documentation/ApplicationStreams.md) for service
registration and companion setup. This API is shared by all applications.

```python
from hypernet_streams import Agent

agent = Agent("/Private/Companion")
print(agent.status())
with agent.connect("SERVICE_ID", "example/1") as connection:
    print(connection.peer)  # Verified target service, owner and endpoint.
    connection.sendall(b"application request")
    connection.shutdown_write()
    while data := connection.recv(65536):
        consume(data)
```

The receiving application uses `agent.accept()` and authorises
`connection.peer["principal"]` before reading its application protocol. Incoming
public keys and identifiers are lowercase hexadecimal strings. Cryptographic
verification already happened in the companion; application-specific permission is still the application's job.
The accepted context includes network, incarnation, service, protocol, principal,
grant, session generation, expiry and byte/time/idle bounds.

`connect(..., timeout=30)` and `accept(timeout=30)` bound local preparation.
`accept()` repeats finite waits until a connection arrives. The raw stream socket
is then blocking; callers may use `connection.socket.settimeout(seconds)`.
`connection.close()` cancels the duplex stream. `agent.cancel(connection.id)`
also cancels a known active connection. A cancellation never reconnects or
replays application work. `AgentError.code` identifies a local refusal.

The directory must be absolute, canonical, owned by the current UID and mode
0700. Its `Control.sock` must be owned by that UID and mode0600. The SDK checks
both path identity and Linux peer credentials. Use the same dedicated account
for the companion and its applications. Do not weaken directory/socket modes.

The initial control frame is a big-endian four-byte length plus at most16384
JSON bytes. After a successful connect/accept response the socket contains only
application bytes. The separate `peer` object is verified metadata, never a
prefix inside the application's stream. The SDK accepts no remote IP address,
TLS pin override, proxy or direct fallback.

The [example service](../Examples/ApplicationStreams/stream_service.py) provides
authorised echo events and resumable immutable file ranges. Its final SHA256 and
size are supplied independently by the receiver. It supports objects larger than
one HyperNet session by requesting finite ranges over new admitted sessions;
its application framing, integrity and publication remain separate from HyperNet.

The SDK is distributed under the existing [MIT licence](Licence.txt).

## Version2 context and checks

Version1 is the default and retains its API. Select version2 explicitly:

```python
import hashlib
from hypernet_streams import Agent, Disposition

agent = Agent("/Private/Companion", version=2)
status = agent.status()  # CompanionStatus, rather than the version1 dictionary.
print(status.check_authority.supported, status.check_authority.endpoint_ready)
with agent.accept(timeout=30) as connection:
    print(connection.privacy, connection.check_authority)
    # Decode and bound application input; identify and authorise its exact operation.
    canonical_action = obtain_bounded_canonical_action(connection)
    result = agent.check_authority(connection, hashlib.sha256(canonical_action).digest(), timeout=1)
    if result.disposition is Disposition.DENIED:
        reject_with_authority_code(result.authority.code)
    elif result.permitted:
        # Also check current application rights and operation ordering here.
        perform_exact_action(canonical_action)
    else:
        preserve_work_without_claiming_success(result.disposition)
```

`capabilities()` returns `AuthorityCapability`; status also supplies a tuple of
`ConnectionStatus` objects and the original public `raw` response. API support,
endpoint readiness and each incoming session's check capability are distinct.
`Stream.privacy` is directional metadata, separate from the verified `peer`.
Outgoing nested TLS, selected minimum settings and verified assurance are not
interchangeable. Incoming public-mode relay transit remains unknown; attached
arrival requires exact-session endpoint attestation.

`check_authority(stream, action_digest, timeout=1.0)` requires an open Stream
created by that Agent and a nonzero32-byte digest. It generates a fresh nonce and
returns an `AuthorityCheck`. `Disposition` has `PERMITTED`, `DENIED`, `UNAVAILABLE`,
`EXPIRED` and `NOT_ACTIVE`; no error-message parsing is needed. `authority` is a
typed `AuthorityObservation` only for a certified result. Local closed streams
raise `AgentError` with code `NotActive`; malformed companion responses raise
`Protocol`. Timeouts range from0.1 to5 seconds. The same user and unshifted Linux
boot-time namespace are required.

Every result exposes exact correlation, stream and control generations, endpoint
and companion instances, and the verified kernel boot. The companion-derived
bound remains in `companion_started_boot_ms`, `companion_deadline_boot_ms` and
`receipt_not_after_boot_ms`. `usable_until_boot_ms` additionally includes the
SDK call's original deadline. `receipt_disposition` preserves the endpoint's
reported outcome if the SDK marks a delayed result `EXPIRED` or a locally
invalidated result `NOT_ACTIVE`.

`result.permitted` checks expiry and locally observed stream/control changes at
use time. Close, cancel, a subsequent check on the same stream, or a status/check
that observes changed control identity invalidate previous local observations.
It cannot detect an unobserved remote disconnect or retract a delivered receipt.
Use a new check for every queued effect; reapply application policy and ordering.
A result never authorises another digest, substitutes for room/delegation policy
or becomes a stored grant.

The complete [authority example](../Examples/ApplicationStreams/authority_service.py)
accepts an explicit principal allow list and checks each echo action. Its client
uses the same `example/1` framed request as the version1 example:

```sh
python3 authority_service.py --agent /Private/ServerCompanion serve --allow-principal CLIENT_PUBLIC_KEY
python3 authority_service.py --agent /Private/ClientCompanion echo --service SERVICE_ID "hello"
```

See [the native contract](../Documentation/ApplicationContext.md) for exact frame
fields, capacity, cancellation, clock binding and privacy semantics.
