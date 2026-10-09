# Offline network preparation

The installed `HyperNetSuite network` commands prepare authenticated trust for
the replacement network contract. They do not join a running network, redeem
an invitation or connect to an endpoint. Their profiles cannot be used by the
existing `--config` commands. Online joining remains unavailable until the
approved privacy connector and current authority verification are implemented.

Client preparation needs only the installed binary and its declared Linux
libraries. It needs no Core installation, container runtime, authority service,
inbound listener, storage contribution or development script. It does not run
external programs, resolve DNS or use proxy environment variables.

## Prepare a client

Obtain the complete bootstrap file through an authenticated channel. Independently
verify its whole-bootstrap fingerprint with the network operator. Merely hashing
the received file does not establish who supplied it. The descriptor fingerprint
alone does not authenticate the adjacent relay and admission-service plan.

```sh
mkdir -m 700 Client
HyperNetSuite network inspect-bootstrap --bootstrap Bootstrap.cbor
HyperNetSuite network prepare --bootstrap Bootstrap.cbor \
  --fingerprint VERIFIED_WHOLE_BOOTSTRAP_DIGEST --output Client/Profile.json
HyperNetSuite network inspect --profile Client/Profile.json
```

Preparation checks canonical records, complete genesis policy references,
administrator tiers and grants, separated role identities and the proposed
recovery policy's actual acceptance signatures. It refuses unsigned drafts,
expired route or initial administrator validity, and a route below the effective
network/client privacy minimum. Missing or unknown records never mean permission.

The default client minimum is `Independent`. The bootstrap must declare different
relay and destination control domains. That declaration does not prove physical
independence or noncollusion. An organisation-operated route requires the explicit
option `--minimum-route Organisational`; the network may still require Independent.
The organisation can correlate reader and destination activity even when the
destination connection does not receive the reader's address.

Use `--publication-mode Sealed` to accept only sealed publications. Repeat
`--publication-mode` with `HostReadable` and `Sealed` to allow both. Without this
option, the client accepts the network's permitted modes. A requested mode that
the network excludes is refused. The profile accepts only its pinned relay
control domain. `--permit-network-search` records explicit local permission for
a later separately requested network search; it sends no query and enables no
current search connection. The default is false.

Preparation creates one new owner-only profile containing its complete trust
bytes and two separate locally generated keys: a device key and a relay-local
key. It publishes the complete file atomically and never overwrites a destination.
The parent directory must be private and owned by the current user. Paths cannot
traverse symbolic links or `..`. Profile and trust inputs must be regular files
with a single hard link. Private keys and profiles cannot be group/world-readable.
Creation and removal share a persistent private `Network<Digest>.lock` file in
that parent. The lock serialises cooperating commands across profile removal and
recreation. It is deliberately retained; concurrent attempts report that another
command owns the profile.

Inspection exposes public keys, policy choices, route assumptions and separate
whole-bootstrap/descriptor digests. It never prints private keys. `OfflinePrepared`
is not membership, current authority, service registration or an observed route.
`bootstrapTimeValid` reports whether the imported deadlines are currently valid.
Expired profiles remain inspectable and removable; they cannot be prepared again
as current bootstrap material.

The `trust.genesisGovernance` object exposes the complete public authority being
accepted. Its network policy includes named resource limits, the manual-review
default, the exact recovery-policy reference and every root-authority reference.
Each tier shows its identifier, rank, label, allowed action names and numeric
codes, scope kinds and identifiers, delegation depth and limits. Each root grant
shows issuer, subject, exact tier version/digest, action names/codes, scopes,
validity timestamps, parent grant, remaining delegation depth and limits.
The recovery policy includes its threshold, principals, signing keys and exact
acceptance fingerprints. Every record reference includes kind, identifier,
generation and record digest. The common genesis generation, null predecessor
and null expected snapshot are explicit. The descriptor's epoch, protocol and
`bootstrapTimeMs` are shown separately. Review these capabilities and validity
windows before accepting a fingerprint; an administrator key alone does not
describe the authority that key will receive.

```sh
HyperNetSuite network join --profile Client/Profile.json
```

This command returns `OnlineJoinUnavailable` locally. It does not attempt a direct
connection or use an older configuration as a fallback. No voucher or invitation
secret belongs in this offline profile. Later online enrolment must use a bounded
relay voucher and the authenticated inner admission-service channel.

Remove an unused offline profile explicitly:

```sh
HyperNetSuite network remove --profile Client/Profile.json \
  --fingerprint VERIFIED_WHOLE_BOOTSTRAP_DIGEST
```

Removal deletes only that verified profile and its unused local keys. Adjacent
files and the bootstrap remain. It does not contact the network or revoke network
rights. A profile used by a future online workflow will require that workflow's
explicit withdrawal and removal rules.

## Prepare governance and recovery acceptance

The native offline authoring workflow creates an explicit bootstrap from public
material. Generate each role key under its intended custody with the ordinary
`HyperNetSuite keygen --output Private/Identity.json` command. Only the public key
is copied into the governance specification. Keep voter, administrator, relay,
admission and offline recovery keys separate. File names or signatures do not
prove that keys have independent owners or protection.

Select one recovery policy:

| Custody | Keys and acceptance | Human assumption |
| --- | --- | --- |
| OwnerSingle | One principal, one key, one acceptance | One owner protects the offline key |
| OwnerThreshold | One principal, three distinct keys, at least two acceptances | The owner protects the keys independently |
| SharedThreshold | Three principals, one distinct key each, at least two acceptances | The principals are distinct independently enrolled custodians |

`immutableShared` can be true only for SharedThreshold. No owner override is
encoded. `acceptedKeys` selects the exact keys that will sign this policy; every
selected acceptance is required at assembly. Select two for the usual 2-of-3
acceptance, or all three when all three will approve the proposal. The resulting
policy's operational threshold remains two.

Create a JSON specification with these exact fields. Replace the uppercase
placeholders with the intended keys, logical identities and Unix millisecond
timestamps. Four voter public keys must be sorted in unsigned byte order. Recovery
keys must be sorted by `(principal, publicKey)`. Action codes are sorted unique
values from [PolicyContract](PolicyContract.md), not implicit tier permissions.
Principal and service/domain identifiers are nonzero 32-byte lowercase hexadecimal
identifiers agreed through the operator's identity process.

```json
{
  "voters": ["VOTER1", "VOTER2", "VOTER3", "VOTER4"],
  "administrator": "ADMINISTRATOR_KEY",
  "administratorActions": [9, 10, 11, 12, 13, 21, 22, 25, 27, 28],
  "enrolment": "InvitationOnly",
  "publicReading": false,
  "minimumRoute": "Independent",
  "publicationModes": ["HostReadable", "Sealed"],
  "defaultPublicationMode": "HostReadable",
  "limits": [262144, 1024, 16, 16],
  "recovery": {
    "custody": "OwnerThreshold",
    "keys": [
      {"principal": "OWNER_ID", "publicKey": "RECOVERY1"},
      {"principal": "OWNER_ID", "publicKey": "RECOVERY2"},
      {"principal": "OWNER_ID", "publicKey": "RECOVERY3"}
    ],
    "acceptedKeys": ["RECOVERY1", "RECOVERY2"],
    "immutableShared": false
  },
  "route": {
    "relayService": "RELAY_SERVICE_ID",
    "relayOrigin": "https://relay.example/",
    "relayTransportKey": "RELAY_TRANSPORT_KEY",
    "relayDomain": "RELAY_CONTROL_DOMAIN_ID",
    "admissionService": "ADMISSION_SERVICE_ID",
    "admissionOrigin": "https://admission.example/",
    "admissionTransportKey": "ADMISSION_TRANSPORT_KEY",
    "admissionDomain": "DESTINATION_CONTROL_DOMAIN_ID",
    "assurance": "Independent",
    "notBeforeMs": 0,
    "expiresMs": 1
  }
}
```

The example's timestamps and placeholders are deliberately unusable. Set a
bounded current validity interval before drafting. `limits` contains maximum
bytes, objects, connections and concurrent operations; zero permits none.
Enrolment can also be `ApprovedApplications`. Public reading is independent of
enrolment and does not open private object audiences. Publication modes are
ordered HostReadable then Sealed. The default mode must belong to that set.

The authoring command generates fresh network/incarnation and root tier/grant
identifiers. Its single Administrator tier and root grant have the exact supplied
actions, network scope, depth eight, limits and route validity. This is initial
governance admission for those capabilities, not ordinary membership, recipient
access, hosting consent or voting authority. Manual review is mandatory in this
genesis authoring profile because no scoped automated-review namespace exists.

```sh
mkdir -m 700 Bootstrap
HyperNetSuite network draft --spec Governance.json --output Bootstrap/Draft.cbor
HyperNetSuite network inspect-bootstrap --bootstrap Bootstrap/Draft.cbor
```

Each selected recovery custodian receives the same draft, inspects all public
policy and custody fields, independently verifies the draft fingerprint, and
signs under their own offline key custody:

```sh
HyperNetSuite network recovery-accept --draft Bootstrap/Draft.cbor \
  --fingerprint VERIFIED_DRAFT_DIGEST --identity Offline/Identity.json \
  --output Accepted.cbor
```

This signature accepts only the exact proposed recovery policy, with its network,
incarnation, custody identities and selected acceptance fingerprints. It is not a
signature approving live consensus or a direct service connection. Transfer the
acceptance file back; never transfer the private key for assembly. The public
bootstrap coordinator combines the acceptances:

```sh
HyperNetSuite network assemble --draft Bootstrap/Draft.cbor \
  --acceptance CustodianOne.cbor CustodianTwo.cbor --output Bootstrap/Bootstrap.cbor
HyperNetSuite network inspect-bootstrap --bootstrap Bootstrap/Bootstrap.cbor
```

Distribute the complete bootstrap and authenticate its resulting whole-bootstrap
fingerprint independently. Its kind-30 container binds exact descriptor,
governance, recovery acceptance and kind-31 route bytes. Record digest and strict
Ed25519 signature rules are in [WireContract](WireContract.md). Signed acceptance
cannot be replaced by a JSON assertion, a key fingerprint list or a co-located
set of generated private keys.

## Installed verification

```sh
python3 Tests/NetworkProvisioning.py /Chosen/HyperNetSuite/Bin/HyperNetSuite
```

This maintained check uses only the installed native commands for key creation,
drafting and acceptance. It checks malformed and re-pinned trust, policy/privacy
refusals, file protections, concurrent creation and safe removal. When `strace`
is available, it additionally checks offline commands for network system calls
with an empty PATH and hostile proxy settings. `strace` and Python are test
tools, not client-command dependencies. These checks do not qualify operational
custody, Byzantine consensus or an Internet privacy deployment.
