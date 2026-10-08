# HyperNetSuite

HyperNetSuite is an independent command-line client for
[HyperNet](https://github.com/Federated-Industrial-Laboratories/HyperNet).
It generates device identities, issues and redeems invitations, manages network
grants and signs bounded hosting consent. The client uses the same versioned
HTTPS interface available to other applications.

Build with `cargo build --locked --release`. See
[Usage](Documentation/Usage.md) for installation, enrolment and administration.
The node and client have separate source, build and package lifecycles.

The current implementation is an initial trust and hosting interface. Pages,
mailboxes, file exchange and service connections remain future capabilities.
It does not yet constitute a qualified production Internet deployment.
See [Requirements](Documentation/Requirements.md) for the wider product scope.

Licensed under the [MIT License](Licence.txt).
