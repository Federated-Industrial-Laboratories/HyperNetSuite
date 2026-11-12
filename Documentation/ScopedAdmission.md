# Scoped admission helpers

These optional helpers provide native authority operations for simple server
joining. They coexist with the original offline invitation and manual grant
commands. A shared listener can offer password, public or private-invitation
entry while its private registrar is limited by an owner-certified native policy.
The listener cannot choose arbitrary grants or change the policy.

## Owner setup

Create separate key files with `HyperNetSuite keygen --output FILE` for the
registrar and descriptor signer. Keep both and all requester state private. The
owner's parent grant must permit actions 0, 10 and 11, plus 30 for a chat template,
with remaining delegation depth. Register and consent the actual relay, authority
and destination services before accepting a candidate.

Create a private policy specification, using lowercase hexadecimal IDs and keys:

```json
{
  "id": "POLICY_ID",
  "parent": "OWNER_GRANT_ID",
  "registrar": "REGISTRAR_PUBLIC_KEY",
  "descriptor": "DESCRIPTOR_PUBLIC_KEY",
  "maximumSlots": 64,
  "validity": [0, {"untilWithdrawn": 1}],
  "relay": "RELAY_ROUTE_ID",
  "authority": "AUTHORITY_ROUTE_ID",
  "templates": [
    {"role": 0, "destination": "PAGE_ROUTE_ID", "application": null,
     "limits": [262144, 1024, 16, 16], "connections": 64,
     "bytes": 16777216, "voucherMs": 3600000},
    {"role": 1, "destination": "CHAT_ROUTE_ID", "application": "CHAT_SERVICE_ID",
     "limits": [262144, 1024, 16, 16], "connections": 64,
     "bytes": 16777216, "voucherMs": 3600000}
  ],
  "legacy": [],
  "enabled": true
}
```

Replace placeholders and the validity start with the actual approved values.
Use `[START_MS, EXPIRES_MS]` for finite validity. Authority ancestors must permit
the policy validity. Route vouchers also stop at the current host/service consent
deadline. Install with the normal owner
bootstrap, private floor, key, clock witness and authority socket arguments:

```text
HyperNetSuite authority-inspection admission policy [ONLINE OPTIONS] --spec Policy.json
```

The policy is immutable apart from withdrawal. To withdraw it, supply the same
specification with `enabled: false`; legacy entries continue to identify their
original owner-pinned memberships even after adoption. A new descriptor signing
key requires a new policy and explicit link acceptance. The locator pin is the
SHA-256 digest of the raw descriptor Ed25519 public key.

## Private registrar

The registrar command accepts one JSON request on stdin and returns one JSON
response on stdout. Requests cannot supply filesystem paths or grant templates.
Use a fixed private configuration:

```json
{
  "format": "HyperNetAdmissionRegistrar/1",
  "bootstrap": "/private/Bootstrap.cbor",
  "bootstrapDigest": "RAW_BOOTSTRAP_SHA256",
  "directory": "/private/RegistrarFloor",
  "clockWitness": "/private/Clock/ClockHealth.json",
  "keyFile": "/private/Registrar.json",
  "socket": "/private/Authority/Control.sock",
  "policy": "POLICY_ID"
}
```

```text
HyperNetSuite authority-inspection admission registrar --configuration Registrar.json --json-stdin
```

A signed public clock export is also supported: set `clockWitness` to its CBOR
path and provide both `clockMonitorKey` and `hostKernelBoot` pins.

The envelope is `{"format":"HyperNetNativeAdmission/1","body":REQUEST}`.
Requests are tagged by `operation`: `describe`, `challenge`, `enrol`, `status`,
`renewalChallenge`, `renew`, `revoke`, or `adopt`. The public DTO definitions are
`Source/Authority/Admission/AdmissionHelperTypes.rs`. Native artifacts are bounded
lowercase hexadecimal; their contents remain opaque to the outer listener.

`describe` returns bootstrap, fresh native purpose proof, descriptor public key,
its SHA-256 pin, policy generation and global claim floor. It also returns certified
`accessEnd` (finite milliseconds or `{"untilWithdrawn":1}`), `maximumParticipants`
and sorted template `roles`. Candidate `inspect` returns the same verified limits.
Outer advertised access and capacity must not exceed them. `challenge` takes an
ordinal claim ID, exact request digest, one or two signed role requests and an
application binding. Role 0 is a reader; role 1 is chat. Public `member` is the
native transport principal; `relay` is its separate route possession key. The
helper verifies these duplicate public fields against each signed join request.
`ready` returns the independently certified principals as well as its opaque
result. The shared listener must compare the result binding and principals to
its durable exact claim before forwarding application registration.

A repeated claim must have exactly the same request and role keys. Serialize
publication of newly allocated claim ordinals; allocate above both the durable
local counter and fresh native claim floor. Keep outer invitation capacity and
native active-member capacity distinct. Retirement is terminal and returns a
certified receipt. Old unknown ordinals cannot allocate effects after a slot is
reused. Keep unresolved reservations and retirement receipts until their recovery
or acknowledgement contract is satisfied.

## Local candidate

```text
HyperNetSuite authority-inspection admission candidate --directory /private/Candidate --json-stdin
```

The root may already contain its private `Clock` directory. The default witness
is `Clock/ClockHealth.json`, which can be produced by Core's local authority clock
monitor; `--clock-witness FILE` selects another supported private JSON witness.
No local Core authority server is required. Each role receives a normal separate
Suite profile and requester directory. The chat and Page reader must not share a
requester directory while running together.

Candidate requests are `inspect`, `prepare`, `acceptChallenge`, `acceptResult`,
`renewalProof` and `status`. `inspect` independently verifies the native descriptor
signing purpose and selected key pin. `prepare` retains locally generated role
keys. `acceptChallenge` requires the exact locally selected `applicationBinding`,
`requestDigest` and `claim`; it persists that binding before signing. It cannot
silently accept a different claim. `acceptResult` verifies the native result,
installs ordinary routes and profiles, obtains current authority state through
the private relay, and preserves the witnessed requester floor.

An installed role reports `profile`, `directory`, `member`, `readerGrant`, optional
`connectGrant`, `clockWitness`, `authorityRoute` and `destinationRoute`. A chat
companion starts normally with the role 1 profile:

```text
HyperNetSuite network connect --profile ROLE_PROFILE -- streams agent --ipc-directory COMPANION --targets Targets.json
```

`Targets.json` names the exact application service and protocol, reported
`connectGrant` and `destinationRoute`, with `renewalMs: 60000`. Use role 0 for a
separate read-only Page session. The local launcher owns clock and companion
startup/shutdown. An already installed candidate can pass `roles: [0]` to
`acceptResult` to refresh the idle Page reader while role 1 remains connected.
Use `roles: [1]` to install chat renewal while a Page reader owns role 0. The
helper preserves the other role and does not open its exclusive floor. Stop a
selected role's companion before installing its offline renewal result. Initial
installation always includes all prepared roles.

Membership may last until withdrawal. Challenges, current disclosures and route
vouchers are always finite. A running companion renews only fixed authorised
voucher IDs. When routes have expired offline, obtain `renewalChallenge`, sign
it with `renewalProof`, submit `renew`, then install its current result before
starting the companion. Fetch a fresh status result if its short proof expires in
transit; the same claim does not consume another invitation or slot.

For owner-rostered migration, explicitly select existing local profiles with
`--adopt-profile 0=PROFILE` or `--adopt-profile 1=PROFILE` during preparation.
The owner must pin those original manual memberships in `legacy`. Adoption
retains keys and floors and restricts future native authority to the role policy.
A retired candidate may bind a later claim only after accepting its certified
retirement receipt. An old link or response cannot silently reset saved trust,
replace keys or discard an uncertain effect.

A network retains at most four immutable registrar policies. Withdrawing a policy
does not erase its purpose or claim fences. Participant slots within each policy
remain reusable; changing passwords or invitations does not create a new policy.
