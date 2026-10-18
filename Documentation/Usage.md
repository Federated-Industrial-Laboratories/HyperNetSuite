# Command-line use

[Documentation](ReadMe.md) | [Project README](../ReadMe.md)

Install the independently signed client as described in [Installation](Installation.md).
Keep identity files, private authority floors, Mail vaults and downloads outside
the software prefix, on persistent private storage. Package removal does not
revoke authority or erase those files. [Upgrade and recovery](UpgradeRecovery.md)
describes executable replacement without rolling back retained protocol state.

## Choose an interface

Install using [Installation](Installation.md). No Core checkout is required.
Use `HyperNetSuite --help` and each subcommand's `--help` for exact arguments.

| Workflow | Interface |
| --- | --- |
| Local Page preview or verified Page reading | Native GUI with `--gui`, terminal viewer with `--tui`, or plain output. |
| Network catalogue browsing | `browse --gui` for the native browser; `browse` for the terminal browser. |
| Publishing, Mail, transfers, services and administration | Explicit CLI command groups. |

The native browser includes Page Forms and explicit media reveal. It is not a
Mail inbox, file manager or administration console. See
[Graphical browser](GraphicalBrowser.md) and [terminal browser](Browser.md).

## Create a standalone signing identity

Some author and operator workflows require a separate signing key. In a private
persistent workspace outside the software prefix:

```sh
mkdir -m 700 Device
HyperNetSuite keygen --output Device/Identity.json
```

The identity command prints the public key and creates a new owner-only key file.
It refuses replacement and symbolic links. Transfer the public key through an
authenticated channel; retain the secret in separately protected storage.
Possession of a secret permits only its currently valid explicit capabilities.
`network prepare` generates its own separate device and relay keys; the standalone
key above is not a prerequisite for local preview or offline profile preparation.

## Authenticate network trust

Inspect the complete bootstrap, then independently authenticate the reported
`trust.fingerprint` through a trusted channel before preparing a profile. This is
the protocol fingerprint, not the whole-file value from `sha256sum`. A fingerprint
supplied beside an untrusted file does not establish its identity. Use an existing
private `Device` directory for the output.

```sh
HyperNetSuite network inspect-bootstrap --bootstrap /Private/Bootstrap.cbor
HyperNetSuite network prepare --bootstrap /Private/Bootstrap.cbor \
  --fingerprint INDEPENDENTLY_VERIFIED_PROTOCOL_FINGERPRINT --output Device/Profile.json
HyperNetSuite network inspect --profile Device/Profile.json
```

Preparation is offline. It does not redeem an invitation, start a service or
open a reader connection. Online joining requires the approved privacy connector;
the client refuses a route that cannot meet its declared privacy requirement.
See [Networks](Networks.md) for policy inspection and custody acceptance, and
[private routes](PrivateRoutes.md) for the distinct whole-file pins used by
`--bootstrap-digest`, `--invitation-digest` and retained-route fingerprints.

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
installed runtime manages the matching confined deployment. Stopping a service
retains consent and permits a later authorised restart. To withdraw consent, use
Core's `HyperNet runtime services withdraw --directory /Private/Service`, which
records a permanent local veto before cleanup; then publish the current
restrictive authority change. See the Core [service lifecycle](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/master/Documentation/ServiceRuntime.md#stop-withdraw-and-retain).
Hosting, application and administrator credentials are separate roles.

## Content and applications

[Pages](Pages.md), [Graphical browser](GraphicalBrowser.md),
[Browser](Browser.md) and [Media](Media.md) describe author,
reviewer and reader workflows. Local preview needs no network profile:

```sh
HyperNetSuite pages preview /Private/Draft.Page --gui
```

Use `--tui` instead of `--gui` for terminal viewing, or omit both for plain output.

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
