# HyperNet application stream SDK

This Linux Python package uses the private HyperNetSuite companion. The companion
owns HyperNet cryptography, permission checks, requester floors and route renewal.
The package has no runtime dependencies. Install the included wheel with
`python3 -m pip install --no-index SDK/hypernet_streams-0.9.1-py3-none-any.whl`.
A source checkout also supports `python3 -m pip install ./SDK`, or adding the SDK
directory to `PYTHONPATH`. Build a wheel offline with
`python3 -m pip wheel --no-deps --no-build-isolation --wheel-dir dist SDK` from
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
