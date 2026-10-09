# Supported platforms

The initial client package profile is native GNU/Linux on x86_64. AArch64 is an
explicit pending qualification target. Cross compilation and emulation are not
native runtime evidence. Direct Windows and macOS support is not currently
qualified. The protocols and separate client interface remain open to other
implementations.

Each signed manifest records the exact ELF interpreter, required shared-library
names and minimum GLIBC symbol version of its binary. The host must supply those
maintained runtime libraries. A distribution name alone does not establish ABI
compatibility. Package installation checks native architecture and the GLIBC
minimum; native qualification exercises the actual installed executable.

The current target families are Ubuntu, Debian and Fedora on native x86_64.
A package's exact manifest remains the authority for its loader and GLIBC needs.
A rewritten contract requires qualification of the actual new binary; earlier
installed-client results are not current-version evidence. Native AArch64 and
other operating systems remain pending.

Client qualification covers signed installation, inventory verification, private
identity generation, overwrite refusal, plain output, responsive components,
pseudoterminal resize, signal restoration and malformed markup. These checks do
not establish network protocol operation or node confinement; those are separate
validation boundaries.

The package tools need Python 3.11 or newer, OpenSSH `ssh-keygen` with Ed25519
SSHSIG support and Linux `renameat2` with no-replace semantics. The ordinary client
binary does not need Python. Qualification uses a pseudoterminal for interactive
reader checks and also exercises redirected plain output. UTF-8 terminals get
Unicode text; ASCII output provides a safe fallback.

OpenSSH 10.6 or newer is an additional requirement only for explicitly requested
SSH service sessions. It is not bundled. Client trust, page reading, mail,
transfers and service functionality have separate prerequisites documented in
their respective manuals. Native client qualification does not establish node
confinement, authority quorum health, Internet reachability or SSH availability.

No public release or production Internet qualification is asserted. A deployment
still needs an operator-managed update policy, key custody, backups and an
independent security assessment appropriate to its exposure.
