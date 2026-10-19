# Security boundaries

[Documentation](ReadMe.md) | [Project README](../ReadMe.md)

HyperNetSuite treats remote data as untrusted. Page markup is inert. Plain output
escapes terminal controls, and only trusted renderer operations generate terminal
sequences. Links, downloads and SSH sessions require explicit actions. Offline
network profiles pin an independently authenticated bootstrap and minimum route
policy; they do not establish a working reader connection. Current local operator
commands use that independent bootstrap pin and a retained requester floor with
an explicitly selected private control socket. Federation bridge endpoints are
separately constrained by their accepted manifests and certificate pins.

The native browser renders HyperPage components and bounded inert Markdown;
it embeds no web engine or script runtime. Browser controls and Form review stay
separate from publisher content. Media remains hidden until explicit Reveal and
passes the existing confined decoding path before display. Local preview cannot
navigate the network or send Forms. See [Graphical browser](GraphicalBrowser.md).

[Native Mail](NativeMail.md) binds confirmation to the exact letter, verified
recipient revision and selected store. [Native Transfers](NativeTransfers.md)
reviews immutable offers and exact acceptance, storage and output choices.
Both applications use retained relay routes and serialize requester operations.
Closing a window preserves uncertain requests for explicit recovery. Received
messages and files cannot execute code or choose local output paths.

Application grants and mail-device credentials retain their separate scopes.
Adapter exports require explicit disclosure consent. A policy digest, expiry or
revocation cannot recall plaintext that has already been exported. External
review processors must not receive authority keys or choose arbitrary actions.
See [Adapters](Adapters.md) and [Private mail](PrivateMail.md) for their contracts.

The signed package boundary authenticates an exact bounded archive before parsing
or installing it. Its SSHSIG namespace differs from HyperNet's node packages.
The verifier and publisher public key need independent trust. Installer input
paths cannot be links or special files; destinations must be new private
prefixes below real, non-writable-by-others parents. Root-owned sticky temporary
directories are permitted as parents for disposable installations.

The software prefix belongs to the operator account. It does not isolate code
from malicious processes already running with that same account's privileges or
from a compromised kernel. Keep that account and its package tools trustworthy.
Use a separate protected account where the host's threat model requires one.
Verification and removal require an idle prefix; concurrent same-account changes
are outside the package management boundary.

Signatures are not an automatic update policy, vulnerability assessment or
rollback authority. Maintain the independently expected version and signing-key
pin. Keep old software only when its security and data compatibility remain
acceptable. See [Upgrade and recovery](UpgradeRecovery.md).

The [dependency inventory](Dependencies.md) and retained upstream notices identify
the locked Rust inputs and known advisory qualifications. Host libraries and
external OpenSSH remain the operator's responsibility. The package does not
include their shared objects. A public Internet deployment requires a separate
independent security assessment; local qualification is not a certification.

## Report a security issue

Send suspected vulnerabilities privately to
[contact@federatedindustrial.com](mailto:contact@federatedindustrial.com).
Include the affected version, commands and a minimal reproduction using synthetic
data. Do not include private profiles, keys, vaults or unredacted operational logs.
Use the [diagnostic preview](Diagnostics.md) to inspect any proposed attachment
before sharing it.
