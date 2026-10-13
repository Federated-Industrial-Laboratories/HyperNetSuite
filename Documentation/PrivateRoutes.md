# Private client routes

An ordinary member needs Suite, private local state and a healthy local clock.
Joining does not install Core, start a host daemon, open a listening port, donate
storage or grant voting, publishing or reviewing rights.

A reader connects to one approved relay. Suite authenticates its exact TLS leaf,
Ed25519 key and certificate chain, then authenticates the final service through
an inner TLS channel. Application credentials remain inside that inner channel.
Both channels require TLS 1.3. Early data and session resumption are disabled.
Only the relay's numeric address is used for a client connection. Final service
names are certificate identities, not DNS lookup or redirect targets. Proxy
environment variables do not select another path.

File pins named `--bootstrap-digest`, `--invitation-digest` and the retained route's
`--fingerprint` use SHA-256 of the complete file. `sha256sum FILE` computes these
pins. The existing network preparation fingerprint and signed record references
use their separate protocol digest; do not substitute them for file pins.

The saved profile contains the complete kind166 voucher record. `RouteOpen`
carries only its canonical `VersionRef`. The relay retrieves and rechecks that
exact current record before reserving a stream.

Suite establishes relay admission and pinned final TLS before creating an
application challenge. It checks `EndpointReady` for the exact network,
incarnation, destination and protocol. Submission, result polling and history
use that same finite connection; each application keeps its original deadline.
Core enforces its forwarding permission beneath TLS, including implicit writes
while reading TLS records. Expired permission pauses forwarding until a fresh
proof arrives; failure or the original transport deadline closes the channel.

For authority connections, Suite prepares certified historical evidence before
creating the application challenge. It verifies the checkpoint quorum, scope,
anchor and continuity from the exact retained floor and tree head. This temporary
evidence cannot update the floor, stream state or current permissions. After the
fresh result, Suite verifies its short suffix and accepts the result through the
normal durable checks. A missing usable checkpoint retains the existing bounded
history path; malformed evidence refuses preparation. The original connection
limits and five-second application challenge remain unchanged.

`RouteReady` reports remaining total transport time after admission. Suite
applies it from readiness receipt while retaining the original connection limit.
Byte admission is shared across frames; progress never restarts total duration.
The relay and endpoint separately revalidate current permission under fresh
5000-ms challenges. An expired permission stops forwarding; renewal cannot extend
an application deadline or restore a closed connection. I/O failure and cancellation
close the session without automatic reconnection or replay of an unresolved action.

Core reports at most four connection timing samples per process. Fixed stages
and elapsed monotonic times distinguish admission queue delay, voucher checks,
permission reservation, egress, readiness and final TLS. These diagnostics omit
identities and request data. Each sampled connection includes at most four frame
sequences and four permission renewals. Client failures identify authority
submission, result polling, ancestry or checkpoint retrieval using fixed labels.

For an attached endpoint, one certified lookup covers both endpoint and relay
permission closures. Core requires the exact current relay record and local
consent in that result; the same certificate bounds attachment admission.

## Author and register routes

An operator first prepares, reviews and admits the exact role5 deployment through
the [deployment workflow](AuthorityInspection.md#deployment-consent-and-admission). Keep route
artifacts in an existing directory owned by the current user with mode 0700.
`routes profile` signs the reviewed manifest's service key, TLS key and leaf,
owned endpoint, validity, deployment profile and consent references. The supplied
operator key must match that manifest. The opaque route identifier is distinct
from its service signing key.

```sh
HyperNetSuite routes profile --bootstrap Bootstrap.cbor \
  --bootstrap-digest VERIFIED_BOOTSTRAP_DIGEST --manifest Manifest.cbor \
  --profile-digest REVIEWED_DEPLOYMENT_PROFILE_DIGEST --key Operator.json \
  --service ROUTE_ID --endpoint MANIFEST_ENDPOINT_ID --domain CONTROL_DOMAIN \
  --mode public --protocol content --server-name Content.Example \
  --certificate-authority CertificateAuthority.pem --assurance Independent \
  --maximum-bytes 16777216 --maximum-duration-ms 60000 \
  --maximum-idle-ms 10000 --maximum-connections 16 \
  --output /Private/Route/RouteProfile.cbor
```

Identifiers and the control domain are 64 hexadecimal digits; the domain uses
lowercase. Budgets are explicit admission choices within the finite protocol
bounds and reviewed deployment limits. Select values for the intended workload.
For a relay, use `--mode relay --protocol relay`. A destination accepts protocols
`authority`, `content`, `media`, `mail`, `transfer` or `bridge-reader`. For an
outbound destination, use `--mode attached --relay RELAY_ROUTE_ID`. Its manifest
still owns the exact role5 TLS endpoint, but its profile publishes no listening
address. Signing a profile makes no connection and grants no current permission.

Register the resulting artifact through the operator's selected authority control
socket using the ordinary online flags:

```sh
HyperNetSuite routes register --bootstrap Bootstrap.cbor \
  --bootstrap-digest VERIFIED_BOOTSTRAP_DIGEST --directory /Private/Manager/Floor \
  --clock-witness /Private/Clock/ClockHealth.json --key Manager.json \
  --socket /Private/Authority/Control.sock --grant MANAGEMENT_GRANT \
  --profile /Private/Route/RouteProfile.cbor
```

The manager requires current `ManageLocalRuntime26` permission for that deployment.
A relay additionally requires `RelayTransit6` for its opaque route identifier on
the same grant. Registration verifies the admitted deployment and operator consent.
Supply the same signed artifact to Core's installed route service setup.

Create a client template from the exact signed relay and destination profiles:

```sh
HyperNetSuite routes template --bootstrap Bootstrap.cbor \
  --bootstrap-digest VERIFIED_BOOTSTRAP_DIGEST --relay-profile RelayProfile.cbor \
  --destination-profile ContentProfile.cbor --minimum-route Independent \
  --output /Private/Route/ContentTemplate.json
```

The template contains public TLS identities, finite intersected budgets and an
empty voucher. It cannot connect. `routes issue --route-template` checks both
profiles against current certified registrations and fills a new bounded voucher.
Its `issuedRoute.routeDigest` output is the resulting client file's SHA-256.
The signed operator profiles and the resulting client route JSON are different
artifacts. Authenticate the complete issued client route before retaining it.
All authoring outputs are published without replacing existing files.

## Prepare and join

Use absolute paths under an owner-only persistent directory. Receive the complete
bootstrap and independently authenticate its fingerprint. Prepare the profile as
described in [Networks](Networks.md), then publish a request containing public keys:

```sh
HyperNetSuite network request --profile /Private/Client/Profile.json \
  --output /Private/Client/Request.cbor
HyperNetSuite network inspect-request --request /Private/Client/Request.cbor
```

The request binds separate device and relay possession keys to the pinned network.
Send the public request to the inviter. Never send the profile or device secret.
The inviter delegates an exact reader grant, creates the existing candidate-specific
member offer, registers that pending offer with `routes invite`, and issues a
bootstrap voucher with `routes issue --action 10`. The voucher names the candidate's
relay key and only the authority service. A pending offer permits the scoped join
workflow; it is not membership. The inviter assembles the public delivery artifact:

```sh
HyperNetSuite network invitation --bootstrap Bootstrap.cbor \
  --bootstrap-digest VERIFIED_BOOTSTRAP_DIGEST --offer MemberOffer.cbor \
  --admission-grant INVITER_GRANT --authority-route AuthorityProfile.json \
  --output Invitation.json
```

Independently authenticate the complete invitation digest before joining. Its
TLS identities, possession-key voucher and candidate offer are accepted together.
A copied fingerprint arriving through the same untrusted channel is insufficient.

```sh
HyperNetSuite network join --profile /Private/Client/Profile.json \
  --invitation /Private/Client/Invitation.json \
  --invitation-digest VERIFIED_INVITATION_DIGEST \
  --directory /Private/Client/Connected \
  --clock-witness /Private/Clock/ClockHealth.json
```

The join signs the exact candidate acceptance, obtains its current dependency
closure and redeems it through the selected relay. It retains a quorum-verified
membership result, requester floor and admission receipt before reporting success.
The separate relay key is never usable as a general member credential. Retrying
an interrupted join keeps the original invitation, requester journal and identity.
A damaged or incomplete trust floor is reported; it is not silently recreated.

## Local clock health

Authority freshness depends on the client's clock and suspend-aware boot clock.
An observation from a remote server's boot cannot establish client clock health.
Use a locally managed observation or the Suite read-only chrony monitor:

```sh
mkdir -m 700 /Private/Clock
HyperNetSuite network clock monitor --directory /Private/Clock \
  --chronyc /usr/bin/chronyc --socket /run/chrony/chronyd.sock
HyperNetSuite network clock status --directory /Private/Clock
```

The selected local chrony socket must already be accessible under the machine's
clock-management policy. The monitor accepts authenticated selected time sources,
bounded measured error and stable observations; it does not change clock settings
or grant access to chrony. Do not grant broad clock-control rights merely to run
this command. A system administrator can instead provide a correctly protected
local observation through the same existing clock-health contract.

A healthy observation expires after one second and is bound to the current boot.
The monitor refreshes it while running. `clock observe` produces one observation
for diagnostics. Missing authentication, stale observations, a clock step, suspend
or a restart fail closed until a new valid observation is available. No fixed
accuracy assertion or server witness replaces these checks.

## Browse and select services

The wrapper supplies the accepted bootstrap, requester directory, device key,
clock witness, reader grant and authority endpoint:

```sh
HyperNetSuite network connect --profile /Private/Client/Profile.json -- browse --tui
HyperNetSuite network connect --profile /Private/Client/Profile.json -- pages list --namespace NAMESPACE
HyperNetSuite network status --profile /Private/Client/Profile.json
```

Normal commands keep their explicit publication, mailbox, media-reveal, form,
transfer and recipient approvals. They do not execute Page content. Mail device
commands use separate mailbox requester directories; an explicitly selected
requester directory remains available for application or additional-device state.

A storage endpoint must be explicitly accepted before bytes can be fetched.
Receive its route profile through an authenticated channel and retain its exact
fingerprint and domain subject. The destination identifier selects a registered
route; the subject identifies the Page host, media host, mailbox store or transfer
store from the domain metadata.

```sh
HyperNetSuite network retain-route --profile /Private/Client/Profile.json \
  --route-profile PageHost.json --fingerprint VERIFIED_ROUTE_DIGEST \
  --subject PAGE_HOST_KEY
```

Retained Page routes supply approved source and sealed ciphertext reads. Retained
media routes supply explicitly revealed graphics. Mail and transfer commands use
`network connect --route DESTINATION_ID` when their arguments do not identify one
unique stored route. Foreign reads use a separately retained bridge reader route;
foreign media also selects `--bridge-route DESTINATION_ID` for its proof discovery.
The remote bridge accepts only signed reader leases with current local capability
checks. It does not expose bridge synchronization or other operator commands.

`routes issue` obtains a normal voucher using an actual current reader, mailbox or
transfer capability. A route voucher adds no application permissions. Issue a
replacement before the current voucher expires or exhausts its bounded connection
budget, then retain the new route profile. Every connection rechecks sponsor
rights, consent, service withdrawal and the exact registered destination. Replacing
a voucher does not reset the requester floor or replay a mutation.

## Assurance, cancellation and diagnostics

The default minimum is `Independent`. The effective minimum is the stricter of
client and network policy. Both setup and subsequent connections refuse a weaker
route. An organisational route omits the reader address at the service boundary,
but its operator can correlate the two sides. Independent routing assumes separate,
noncolluding operators. Signed domain declarations cannot prove that independence.
Neither profile promises anonymous membership or resistance to global traffic
analysis. Sealed publication protects content separately from route encryption.

All authority requests, polling, history, receipt and selected store exchanges use
the same connector. Outage, refusal, expiry, reconnect and cancellation never
select a direct connection, local service process or another network. Ctrl-C and
termination cancel bounded socket waits and close the connection. An uncertain
mutation remains in the requester journal; cancellation is not proof of rollback.
Resume the exact operation or explicitly fence its generation through the ordinary
stream workflow.

`network status` reports retained authority height, pending work, accepted service
identities and the last successful local TLS observation. It does not label a
historical result as current permission. The observation identifies encryption
endpoints and selected assurance; it does not claim verified physical Internet
hops. These private diagnostics stay local and contain no public telemetry upload.
