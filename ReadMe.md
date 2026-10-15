# HyperNetSuite

HyperNetSuite is the independent terminal client for
[HyperNet](https://github.com/Federated-Industrial-Laboratories/HyperNet).
It provides inert HyperPages, explicit media reveal, encrypted Mail, reviewed
Forms, recipient-approved file transfers and separately consented OpenSSH services.
The client and infrastructure have separate repositories, builds and packages.

Current authority results require an independently accepted bootstrap, a verified
three-of-four executed-result certificate, exact capability references and durable
requester floors. Serving effects additionally require the selected service's
separate recipient journal. Applications receive separately scoped authority. Membership
alone never grants hosting, review, voting or confidential-content access.

Build with Rust 1.91 or newer:

```sh
cargo build --locked --release
bash Tools/Check.sh
```

The test gate uses a private persistent directory under the user's state home.
Set `HYPERNET_TEST_DIRECTORY` to another private persistent directory when needed.
See [Installation](Documentation/Installation.md) for signed offline packages and
[Usage](Documentation/Usage.md) for identity creation and operator workflows.

[Networks](Documentation/Networks.md) prepares authenticated trust and separate
client keys. [Private routes](Documentation/PrivateRoutes.md) joins through an
approved relay, retains verified membership and supplies normal client commands
with their selected network. Current operator workflows remain explicitly local.
Reader failures, reconnection and cancellation never select a direct fallback.

[Pages](Documentation/Pages.md) covers authoring, exact-content review and verified
publication. [HyperPage](Documentation/HyperPage.md) defines responsive panels,
rows, scroll boxes, borders, colours and explicit local controls without scripts.
[Browser](Documentation/Browser.md) covers terminal navigation and recoverable
errors. [Search](Documentation/Search.md) provides explicit selected-network
queries and encrypted retained local catalogues, including sealed publications. [Media](Documentation/Media.md) adds isolated bitmap/SVG import, explicit
asset inspection, terminal graphics and bounded client-side motion.
[Examples](Examples/ReadMe.md) contains fictional businesses for local preview.

[Private Mail](Documentation/PrivateMail.md) provides owner-controlled addresses,
scoped devices, explicit encrypted storage and protected history transfer.
[Forms](Documentation/Forms.md) adds typed input, explicit confirmation and
independently accepted intake. Foreign Forms cannot target a local mailbox through
Federation. [Transfers and services](Documentation/TransfersAndServices.md)
uses exact recipient acceptance and separate service consent.
[Federation](Documentation/Federation.md) defines bilateral agreements, original
author sharing and destination review without merging network membership.

[Application access](Documentation/ApplicationAccess.md) and
[Adapters](Documentation/Adapters.md) cover separately consented credentials and
explicit data disclosure. Model recommendations remain inert data.
[Authority inspection](Documentation/AuthorityInspection.md),
[tier and grant administration](Documentation/Administration.md),
[committee replacement](Documentation/AuthorityEpochs.md) and
[network recovery](Documentation/NetworkRecovery.md) describe installed control
workflows and independently authenticated recovery.

[Security](Documentation/Security.md), [supported platforms](Documentation/SupportedPlatforms.md)
and [runtime contracts](Documentation/Contracts.md) state the boundaries and
remaining qualification. Native ARM runtime qualification remains pending. This prerelease is not a qualified production
Internet deployment. Licensed under the [MIT License](Licence.txt).
