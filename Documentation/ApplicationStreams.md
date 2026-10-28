# Application streams

[Documentation](ReadMe.md) | [Application access](ApplicationAccess.md) |
[Python SDK](../SDK/README.md)

Application streams connect a named service through an approved HyperNet relay.
Each connection authenticates its application principal, exact service and
protocol. The destination can be an attached endpoint without a public listener.
The same interface supports agents, HTTP clients, events and file applications.
Payloads do not enter Mail, Transfer storage or the ordered authority history.

A service owner grants finite access to its service. The endpoint operator
separately accepts the exact local binding and route. Action29 manages services;
action30 connects them. A grant's service scope is kind3 plus the service ID.
Use a stable enrolled application identity with only the required rights. See
[Application access](ApplicationAccess.md) for registration, renewal and permanent
withdrawal. An independently authorised route voucher carries transport rights;
its possession key differs from the application's signing key.

## Register a service

Prepare and register a role5 route with protocol `application` through the
[route workflow](PrivateRoutes.md#author-and-register-routes). An attached route
uses its approved relay and opens no direct application listener. The route
profile's endpoint service signing key is `ENDPOINT_KEY` below. Record the exact
registered route reference as `ID:generation:digest`.

The relay route's `maximumConnections` bounds its reader and parked attachment
pools separately. Choose this one setting to accommodate both intended loads,
including the sum of its attached endpoints' parking limits. Two endpoints that
each park up to 8 connections need a relay limit of at least 16. Choose
explicit headroom for the deployment; a relay capacity of 32 is one possible
configuration, not a new default or a minimum for every service. An undersized
relay refuses excess parked attachments even when each endpoint fits its own
approved limit.

All artifacts, keys and configuration files use an existing private directory.
`BOOTSTRAP_SHA256` is an independently accepted digest. Choose finite validity
and limits that fit the registered route. Times are Unix milliseconds.

```sh
HyperNetSuite streams offer --bootstrap Bootstrap.cbor \
  --bootstrap-digest BOOTSTRAP_SHA256 --key Owner.json \
  --service SERVICE_ID --route ROUTE_ID:GENERATION:DIGEST \
  --operator OPERATOR_KEY --endpoint ENDPOINT_KEY --protocol example/1 \
  --not-before-ms START_MS --expires-ms END_MS \
  --maximum-bytes 268435456 --duration-ms 120000 --idle-ms 30000 \
  --output ServiceOffer.cbor

HyperNetSuite streams inspect-offer --bootstrap Bootstrap.cbor \
  --bootstrap-digest BOOTSTRAP_SHA256 --offer ServiceOffer.cbor \
  --owner-key INDEPENDENT_OWNER_KEY

HyperNetSuite streams accept --bootstrap Bootstrap.cbor \
  --bootstrap-digest BOOTSTRAP_SHA256 --offer ServiceOffer.cbor \
  --owner-key INDEPENDENT_OWNER_KEY --key Operator.json \
  --route-profile RouteProfile.cbor --output ServiceAccepted.cbor

HyperNetSuite streams register --bootstrap Bootstrap.cbor \
  --bootstrap-digest BOOTSTRAP_SHA256 --directory /Private/OwnerFloor \
  --clock-witness /Private/Clock/ClockHealth.json --key Owner.json \
  --socket /Private/Authority/Control.sock --grant MANAGE_GRANT_ID \
  --accepted ServiceAccepted.cbor

HyperNetSuite streams endpoint-config --bootstrap Bootstrap.cbor \
  --bootstrap-digest BOOTSTRAP_SHA256 --accepted ServiceAccepted.cbor \
  --configuration RelayConfiguration.json --output ServiceConfig.json
```

Inspection prints the service, owner, operator, TLS endpoint, protocol, exact
route, binding, limits and validity before acceptance. It does not submit state.
The operator signs those exact bytes. `endpoint-config` accepts the existing
version1 relay configuration, preserves its relay identity/address and emits the
version2 Core configuration. It does not grant local execution or modify a
running service. Supply that configuration to the normal Core runtime setup.
Keep offers and the intermediate version1 relay file outside Core's fixed input
directory; that directory contains only the required runtime template files.

Initialise the requester floor through `authority-inspection initialise` before
using online commands. The [clock instructions](AuthorityInspection.md) cover
signed clock observations in separate containers. Core runtime setup, preview,
consent and activation remain explicit operator steps.

## Run the companion

For a joined client, use the existing network profile directly:

```sh
HyperNetSuite network connect --profile /Private/Profile.json -- \
  streams agent --ipc-directory /Private/Companion \
  --targets /Private/Targets.json
```

The wrapper retains the verified network selection for the entire agent process,
including its authority actor. It supplies the joined identity, requester floor,
clock and retained authority route. Authority operations travel through the
approved relay; this mode needs no local Core installation or authority socket.
Trust and transport overrides remain prohibited. Retain a protocol7 route through
`network retain-route`; its private endpoint is `Joined/Routes/ROUTE_ID.json`.
Use that path in the target configuration below. The optional incoming binding
can also be supplied through this wrapper.

The receiving Core endpoint also needs authority access. When its authority is
remote, run a [native authority connector](AuthorityConnector.md) under a
separate joined profile and pass its mapped ingress directory to Core setup.
The outgoing application companion and the Core authority connector share no
requester profile or signing state.

An operator with a trusted local authority socket can instead run the explicit
local mode below. Both modes use the same SDK and application payload transport.

The receiving companion uses the accepted artifact. Use the same dedicated Unix
account for it and applications that use its socket. Every directory below is
absolute, canonical, owned by that UID and mode0700; sockets are mode0600.

```sh
HyperNetSuite streams agent --bootstrap /Private/Bootstrap.cbor \
  --bootstrap-digest BOOTSTRAP_SHA256 --directory /Private/ApplicationFloor \
  --clock-witness /Private/Clock/ClockHealth.json --key /Private/Application.json \
  --socket /Private/Authority/Control.sock --ipc-directory /Private/Companion \
  --binding /Private/ServiceAccepted.cbor
```

The companion creates `/Private/Companion/Control.sock` for SDK requests. Its
rootless ingress helper creates `Ingress/{Binding.json,Control.sock}` under the
exact subordinate UID used by Core. The helper requires `/usr/bin/podman`, enters
its rootless namespace, confines its filesystem to Ingress, drops supplementary
groups and privileges, and permits only bounded local descriptor handoffs. It
receives no application signing key or requester floor. The main companion
verifies the signed endpoint context before handing a stream to the SDK. Pass only `/Private/Companion/Ingress` as Core runtime setup's
`--application-directory`. Core receives no SDK command socket, application
private key or requester floor. Core retains its `nomap` namespace and exact mapped socket owner. Native
applications use the host-owned SDK socket. A companion already running under
that mapped account can explicitly select `--ingress-mode local`; this does not
relax any owner or mode check.

For an outgoing companion, omit `--binding` and provide `--targets` with a private
JSON file. A single companion can both connect and accept. Each target references
a saved private endpoint whose route profile contains the current independent
voucher and possession profile, as produced by the normal route workflow.

```json
[
  {
    "service": "SERVICE_ID",
    "protocol": "example/1",
    "grant": "CONNECT_GRANT_ID",
    "route": "/Private/Endpoint.json",
    "renewalMs": 60000
  }
]
```

The companion keeps its own private copy of each target route. It automatically
renews an expired voucher only when the current application principal is its
sponsor and retains the required current capability. Renewal preserves voucher
identity and cumulative usage. It never resets an unexpired quota, changes a
possession identity or grants new rights. `renewalMs: 0` disables renewal.
Replacing a target route or possession profile requires explicit stopped-agent
reconfiguration. Application admission renewal is a separate dual-consent action.

One actor serialises authority operations and durable requester floors. Give
that profile exclusively to the running companion. Pending compatible reads,
closures and its own exact voucher renewal resume before readiness; unrelated
mutations require their original command. Never delete profile state to recover.

A read interrupted after its durable floor commits can leave older derived
domain metadata in the local cache. When no ordinary operation is pending, the
client discards that superseded domain context in memory and obtains a new
verified result. The authenticated floor and governance context remain intact.
Missing authentication, conflicting digests and future cache generations still
refuse. Loading the cache does not rewrite or reset retained state.

Connection preparation can replace one verified read proof that expires during
local persistence. The replacement is a new certified read within the caller's
original preparation deadline; the learned floor remains retained. This allowance
is shared across policy discovery and service lookup. It does not replay an
ordinary command, extend a certificate, retry a refusal or hide invalid clock or
identity evidence. Closing or cancelling the local request stops preparation.
If an otherwise authenticated clock observation expires, preparation waits for
a fresh valid observation within that same deadline. Every replacement is fully
validated. Waiting does not replay an authority command, extend an existing
proof, or treat a malformed, misbound or regressing clock as a temporary outage.

```sh
HyperNetSuite streams status --directory /Private/Companion
HyperNetSuite streams connect --directory /Private/Companion \
  --service SERVICE_ID --protocol example/1
HyperNetSuite streams receive --directory /Private/Companion
HyperNetSuite streams cancel --directory /Private/Companion --id CONNECTION_ID
```

Connect/receive use raw standard input/output and print verified peer context on
standard error. EOF closes one direction and still permits the peer's response.
The status response includes network, incarnation, principal, incoming binding,
approved targets, finite connections and recent local errors. Applications can
therefore discover their verified local setup without copying identity fields.

The companion permits at most16 approved targets and16 active connections.
Incoming handshakes and control requests have finite queues. Authority stores
one current service and bounded reusable session slots per client/service.
Generation fencing and endpoint retirement prevent reuse of a still-live slot.
Service/session expiry, byte budget, idle timeout, current revocation and explicit
cancellation close forwarding. A restart never restores spent allowance or
replays application requests. Applications decide how to resume their own work.

## Use the SDK and file example

Install the included [Python package](../SDK/README.md). A receiving application
must authorise `stream.peer["principal"]` before handling its payload. HyperNet
verifies identity and scoped network authority; it does not infer application
permissions. `Agent.connect` selects only an approved named target and exposes
verified owner/endpoint context separately from its raw socket.

The [generic example](../Examples/ApplicationStreams/stream_service.py) accepts
explicit caller keys, echoes events and serves immutable file ranges:

```sh
python3 stream_service.py --agent /Private/ServerCompanion serve \
  --allow-principal CLIENT_PUBLIC_KEY --file /Private/LargeObject.bin
python3 stream_service.py --agent /Private/ClientCompanion echo \
  --service SERVICE_ID "hello"
python3 stream_service.py --agent /Private/ClientCompanion download \
  --service SERVICE_ID --sha256 INDEPENDENT_SHA256 --size OBJECT_BYTES \
  --output /Private/Received.bin
```

An interrupted download retains a partial file and exact object metadata. Repeat
the same command to resume from the retained offset. Each range uses a fresh
finite stream; the object may exceed the1GiB session ceiling. Buffers stay64KiB.
Only a complete matching SHA256 publishes the destination, without overwriting
an existing file. This is an application example, separate from native Transfer's
existing size contract. Supply object size and hash through a trusted channel.

## Withdraw

`streams withdraw` accepts the service ID or an exact `ID:generation:digest`.
Use the owner's initialised floor, key, clock and authority socket as above.
The owner can retrieve its current metadata and withdraw even after expiry or
loss of a discretionary grant. Withdrawal is permanent for that service identity.
New sessions refuse and active forwarding stops at its next bounded permission
check. Pending exact withdrawal remains recoverable across process restart.
