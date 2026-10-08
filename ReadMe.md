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
verified publication and reads from explicitly consenting replicas. Mailboxes,
file exchange and service connections remain future capabilities.
It does not yet constitute a qualified production Internet deployment.
See [Requirements](Documentation/Requirements.md) for the wider product scope.

Licensed under the [MIT License](Licence.txt).
