# HyperNetSuite

HyperNetSuite is an independent command-line client for
[HyperNet](https://github.com/Federated-Industrial-Laboratories/HyperNet).
It generates device identities, issues and redeems invitations, manages network
grants, signs bounded hosting consent and provides an independent Pages CLI/TUI. The client uses the same versioned
HTTPS interface available to other applications.

Build with `cargo build --locked --release`. See
[Installation](Documentation/Installation.md) for signed offline packages and
[Usage](Documentation/Usage.md) for enrolment and administration.
The node and client have separate source, build and package lifecycles.

[Browser](Documentation/Browser.md) provides a trusted paginated catalogue, explicit
address navigation, retained page state and recoverable errors in one terminal
session.

[Forms](Documentation/Forms.md) adds bounded typed fields, explicit browser and
CLI confirmation, encrypted mail delivery and independently accepted typed intake.

[Pages](Documentation/Pages.md) supports responsive inert components, exact-content manual review,
verified publication and reads from explicitly consenting replicas.
[HyperPage](Documentation/HyperPage.md) defines panels, rows, scroll boxes, colours
and explicit local controls. The reader adapts to terminal width and has a complete
plain-text fallback.
[Federation](Documentation/Federation.md) adds bilateral agreements, explicit
author sharing, destination review and independently verified foreign reads.
[Transfers and services](Documentation/TransfersAndServices.md) adds encrypted,
recipient-approved resumable file exchange and separately consented OpenSSH services.
[Applications and adapters](Documentation/Adapters.md) provides separate Pages
credentials, explicit review data exchange and selected-letter disclosure.
[Upgrade and recovery](Documentation/UpgradeRecovery.md),
[supported platforms](Documentation/SupportedPlatforms.md) and
[security boundaries](Documentation/Security.md) describe package operation.
It does not yet constitute a qualified production Internet deployment.
See [Requirements](Documentation/Requirements.md) for the wider product scope.

Licensed under the [MIT License](Licence.txt).

Private mail provides owner-controlled addresses, scoped devices, explicit encrypted
store placement, offline delivery and separate encrypted history transfer. See
[PrivateMail](Documentation/PrivateMail.md) for setup, recovery and security limits.
Build with Rust 1.91 or newer.
