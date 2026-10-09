# HyperNetSuite

HyperNetSuite is an independent command-line client for
[HyperNet](https://github.com/Federated-Industrial-Laboratories/HyperNet).
It generates device identities, issues and redeems invitations, manages network
grants, signs bounded hosting consent and provides an independent Pages CLI/TUI. The client uses the same versioned
HTTPS interface available to other applications.

Build with `cargo build --locked --release`. See
[Usage](Documentation/Usage.md) for installation, enrolment and administration.
The node and client have separate source, build and package lifecycles.

[Pages](Documentation/Pages.md) supports inert text, exact-content manual review,
verified publication and reads from explicitly consenting replicas.
[Federation](Documentation/Federation.md) adds bilateral agreements, explicit
author sharing, destination review and independently verified foreign reads.
[Transfers and services](Documentation/TransfersAndServices.md) adds encrypted,
recipient-approved resumable file exchange and separately consented OpenSSH services.
It does not yet constitute a qualified production Internet deployment.
See [Requirements](Documentation/Requirements.md) for the wider product scope.

Licensed under the [MIT License](Licence.txt).

Private mail provides owner-controlled addresses, scoped devices, explicit encrypted
store placement, offline delivery and separate encrypted history transfer. See
[PrivateMail](Documentation/PrivateMail.md) for setup, recovery and security limits.
Build with Rust 1.91 or newer.
