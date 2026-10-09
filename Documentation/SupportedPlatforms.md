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

The qualified 0.7.0 x86_64 binary requires GLIBC 2.39 or newer,
`/lib64/ld-linux-x86-64.so.2`, `libc.so.6` and `libgcc_s.so.1`. The same binary
passed the following native installed client checks:

| Environment | Kernel | Host GLIBC | Client package status |
| --- | --- | --- | --- |
| Ubuntu 24.04.4 LTS x86_64 | 7.0.0-34-generic | 2.39 | Native client checks passed |
| Ubuntu 26.04.1 LTS x86_64 | 7.0.0-38-generic | 2.43 | Native client checks passed |
| Debian 13 x86_64 | 6.12.111+deb13-amd64 | 2.41 | Native client checks passed |
| Fedora 44 x86_64 | 6.19.10-300.fc44.x86_64 | 2.43 | Native client checks passed |
| Native AArch64 GNU/Linux | Not qualified | Not qualified | Pending hardware qualification |
| Other Linux distributions | Not qualified | 2.39 minimum | Run native qualification before use |

Each completed profile covers authenticated package installation and inventory
verification, the exact binary version, private identity generation with
overwrite refusal, safe plain output, pseudoterminal resize and signal
restoration, and the 260-input bounded markup corpus. These local client checks
make no network requests. They do not repeat every network protocol workflow or
qualify HyperNet node confinement; those are separate validation boundaries.

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
