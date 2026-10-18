# Documentation

[Project README](../ReadMe.md) | [Installation](Installation.md) | [Security](Security.md)

HyperNetSuite supplies native graphical and terminal Page viewers plus command-line
workflows for publishing, Mail, files, services and administration. HyperNet runs
the separate infrastructure. These manuals distinguish local preview, ordinary
client access through accepted relay routes and local operator control.

## Start here

1. Check [supported platforms](SupportedPlatforms.md) and [install the client](Installation.md).
2. [Preview the supplied Page](Installation.md#try-a-local-page) without network access.
3. Learn the [native browser](GraphicalBrowser.md) or [terminal browser](Browser.md).
4. Read [security boundaries](Security.md) before accepting network trust or credentials.
5. [Prepare a profile](Networks.md#prepare-a-client), then [join through approved routes](PrivateRoutes.md#prepare-and-join).
6. Keep private state and software separate; use [upgrade and recovery](UpgradeRecovery.md) when replacing an installation.

Offline preparation does not join a network. The operator must provide trusted
bootstrap material, an approved invitation and suitable routes. Membership alone
does not grant the capabilities required by each application.

## Readers, authors and recipients

| Task | Manual |
| --- | --- |
| Select commands, identities and state locations | [Client use](Usage.md) |
| Browse with a native window and configure display preferences | [Graphical browser](GraphicalBrowser.md) |
| Navigate in a terminal or produce plain output | [Terminal browser](Browser.md), [layout and controls](TerminalLayout.md) |
| Try ready-made local content | [Examples](../Examples/ReadMe.md) |
| Write, submit, review and publish Pages | [Pages](Pages.md) |
| Understand the declarative document format | [HyperPage](HyperPage.md) |
| Import, review and explicitly reveal images | [Media](Media.md), [terminal graphics and decoding limits](MediaViewer.md) |
| Find native, imported or retained content | [Search](Search.md) |
| Publish encrypted content to selected devices | [Sealed Pages](SealedPages.md), [recipient identities](Recipients.md) |
| Set up an encrypted mailbox and exchange messages | [Private Mail](PrivateMail.md) |
| Review and send a Form, or accept typed submissions | [Forms](Forms.md) |
| Accept files or invoke an approved SSH service | [Transfers and services](TransfersAndServices.md) |
| Share Pages between separately governed networks | [Federation](Federation.md) |

Authors should read Pages before Media or Forms. Confidential publishing also
requires recipient trust and device setup. Forms use separate Page and Mail
permissions; a reviewed Page cannot choose a sender's credentials.

## Network operators and application integrators

These guides assume explicitly provisioned roles and private operator state.
They are not extra steps required for local Page preview. Infrastructure hosting
and runtime installation are documented by
[HyperNet](https://github.com/Federated-Industrial-Laboratories/HyperNet).

| Task | Manual |
| --- | --- |
| Inspect bootstrap policy and prepare independent client trust | [Networks](Networks.md) |
| Register relays, issue vouchers, join and retain service routes | [Private routes](PrivateRoutes.md) |
| Initialise requester state and inspect current governance | [Authority inspection](AuthorityInspection.md) |
| Review tier changes, delegate or revoke capabilities | [Administration](Administration.md) |
| Change network policy with explicit client acceptance | [Network policies](NetworkPolicies.md) |
| Replace a healthy authority committee | [Authority epochs](AuthorityEpochs.md) |
| Recover a network when normal authority is unavailable | [Network recovery](NetworkRecovery.md) |
| Back up content and reconcile a restore with current authority | [Content archives](Backups.md) |
| Inspect or export a bounded local diagnostic summary | [Diagnostics](Diagnostics.md) |
| Verify, replace or remove installed software | [Upgrade and recovery](UpgradeRecovery.md) |
| Grant an application its own scoped authority | [Application access](ApplicationAccess.md) |
| Disclose exact review data to an external processor | [Adapters](Adapters.md) |

Start operator work with Networks and Authority inspection, then choose the
manual for the intended action. Preserve requester floors and unresolved request
files. A timeout does not prove that a mutation failed; use its documented exact
retry or recovery procedure.

## Protocol and implementation reference

Contracts define obligations and byte formats; they do not certify a deployment.
Use the task manuals above for executable procedures and prerequisites.

| Reference | Purpose |
| --- | --- |
| [Requirements](Requirements.md) | Product scope and intended client behaviour. |
| [Contract index](Contracts.md) | Relationship between shared protocol and policy contracts. |
| [Wire](WireContract.md) | Canonical encodings, signed requests and verified result proofs. |
| [Authority](AuthorityContract.md) | Committee consensus, durable state, time and recovery rules. |
| [Policy](PolicyContract.md) | Capabilities, publication, custody and consent semantics. |
| [Runtime](RuntimeContract.md) | Management, readiness, relay coverage and replacement contracts. |
| [Tiers](Tiers.md) | Tier administration wire interface and delegation rules. |
| [Source layout](SourceLayout.md) | Implementation directories and their responsibilities. |
| [Dependencies](Dependencies.md) | Locked components, notices and separate licences. |

## Terms and command conventions

| Term | Meaning |
| --- | --- |
| Bootstrap | Independently authenticated initial network identity and policy material. |
| Profile | Private client trust, identity and accepted network configuration. |
| Capability or grant | Explicit permission scoped to an identity, resource and validity period. |
| Requester floor | Durable verified authority history and request state used to reject stale or conflicting results. |
| Host-readable Page | Approved content that its consenting storage host can read. |
| Sealed Page | Encrypted publication for explicitly authorised recipient devices. |
| Retained view | Previously received content; displaying it again does not establish current permission. |
| Receipt | Evidence for a particular operation or serving effect, with the scope stated by that workflow. |

Examples with `/Private/...`, uppercase IDs or `[online options]` are command
templates. Substitute the actual protected paths, exact identifiers and trust
options required by the linked guide; do not paste brackets as shell arguments.
Use `HyperNetSuite COMMAND --help` to inspect its current arguments.

Expiry options ending in `-ms` take absolute Unix milliseconds. Mail and Forms
`--expires` take absolute Unix seconds. Retention options name their own units.
Do not paste private keys, vault contents or credential-bearing profiles into
logs, issue reports or documentation.
