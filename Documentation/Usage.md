# Command-line use

Install the independently signed client as described in [Installation](Installation.md).
Keep identity files, private authority floors, Mail vaults and downloads outside
the software prefix, on persistent private storage. Package removal does not
revoke authority or erase those files. [Upgrade and recovery](UpgradeRecovery.md)
describes executable replacement without rolling back retained protocol state.

## Build and create an identity

Build from source with Rust 1.91 or newer. No Core checkout is required:

```sh
cargo build --locked --release
bash Tools/Check.sh
bash Tools/Install.sh /Chosen/Prefix
mkdir -m 700 Device
HyperNetSuite keygen --output Device/Identity.json
```

The identity command prints the public key and creates a new owner-only key file.
It refuses replacement and symbolic links. Transfer the public key through an
authenticated channel; retain the secret in separately protected storage.
Possession of a secret permits only its currently valid explicit capabilities.

The test gate uses persistent private storage. Set `HYPERNET_TEST_DIRECTORY`
to choose another directory. Interrupted test state must not be reused as live
network state. Qualification requires `--work-directory` to select an existing
private persistent directory.

## Authenticate network trust

Obtain the complete bootstrap through an authenticated channel and verify its
whole-file SHA256 fingerprint independently. A hash supplied beside an untrusted
file does not establish its identity.

```sh
HyperNetSuite network inspect-bootstrap --bootstrap /Private/Bootstrap.cbor
HyperNetSuite network prepare --bootstrap /Private/Bootstrap.cbor \
  --fingerprint INDEPENDENTLY_VERIFIED_SHA256 --output Device/Profile.json
HyperNetSuite network inspect --profile Device/Profile.json
```

Preparation is offline. It does not redeem an invitation, start a service or
open a reader connection. Online joining requires the approved privacy connector;
the client refuses a route that cannot meet its declared privacy requirement.
See [Networks](Networks.md) for policy inspection and custody acceptance.

## Local operator workflows

Current control operations select an independently pinned bootstrap, a private
requester floor, a trusted clock observation, a signing identity and an explicit
private authority socket. A network connection or SSH login alone supplies none
of that authority. See [Authority inspection](AuthorityInspection.md) for the
initialisation and command examples.

The installed command groups expose these workflows:

| Command | Workflow |
| --- | --- |
| `authority-inspection` | Current governance, membership, grants and durable requester streams |
| `authority-inspection deployments` | Exact host consent, admission and withdrawal |
| `authority-inspection epoch` | Healthy committee replacement and client adoption |
| `applications` | Separate application keys, grants, acceptance and withdrawal |
| `pages`, `browse`, `media` | Inert content, exact review, verified reads and explicit media |
| `mail`, `forms` | Scoped encrypted Mail and reviewed typed submissions |
| `transfers`, `services` | Consented file exchange and exact OpenSSH sessions |
| `federation` | Independent network trust, bilateral agreements and shared Pages |
| `adapters` | Explicit review disclosure and inert recommendations |
| `network recovery` | New-network recovery declarations and independent acceptance |

Use each command's `--help` for its exact arguments. A successful response is
printed only after the applicable signature, quorum, ancestry, capability and
durable-state checks. Keep pending request files after a timeout; retry the exact
request or inspect its outcome. Deleting a floor or changing a request identifier
does not safely resolve an uncertain operation.

These commands take explicit trust and connection arguments. There is no global
`--config` or `configure` command, and an offline `network prepare` profile does
not replace the bootstrap pin and requester floor used by local operator commands.
Expiry options ending in `-ms` use absolute Unix milliseconds. Mail and Forms
`--expires` use absolute Unix seconds; retention options name their own units.

A hosting owner separately accepts a canonical resource manifest. Neither a
network grant nor a remotely changed record can widen local consent. Core's
installed runtime manages the matching confined deployment. Stop a local service
for immediate local withdrawal, then publish the current restrictive authority
change. Hosting, application and administrator credentials are separate roles.

## Content and applications

[Pages](Pages.md), [Browser](Browser.md) and [Media](Media.md) describe author,
reviewer and reader workflows. Local preview needs no network profile:

```sh
HyperNetSuite pages preview /Private/Draft.Page --tui
```

[Sealed Pages](SealedPages.md) describes the separate `pages sealed` commands for
encrypted author submissions, explicit manual approval, durable ciphertext and
device-owned reading. [Recipients](Recipients.md) describes independent contact
trust and recipient device admission.

[Private Mail](PrivateMail.md) describes verified contacts, device keys, storage
placement and retained-state recovery. [Forms](Forms.md) separates prepare,
review, confirm, send and intake. Page content never supplies executable handlers.

[Transfers and services](TransfersAndServices.md) requires recipient acceptance
and service consent. Downloaded content is never executed automatically.
[Application access](ApplicationAccess.md) and [Adapters](Adapters.md) use exact
grants and explicit disclosure. External model processing receives no implicit
HyperNet credential or executable tool surface.

The client escapes terminal controls in JSON, errors and path output. Commands
return nonzero on failure. Missing quorum, stale state, unknown clock health and
incompatible routes refuse the operation without relaxing security policy.

[Catalogue and search](Search.md) describes explicit network queries, query-free
retention and synchronisation, encrypted local matching, and Historical access.
