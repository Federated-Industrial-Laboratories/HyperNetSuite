# Supported platforms

[Documentation](ReadMe.md) | [Project README](../ReadMe.md)

Release 0.8.0 is qualified on native Ubuntu 24.04 x86_64 with GNU libc 2.39. AArch64 is an
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

## Native browser

The default build includes the native Linux Page browser, Mail and Transfers. It needs an X11 or
Wayland display and working EGL or GLX libraries with a compatible graphics
driver. Native rendering has been exercised with NVIDIA and Mesa software
rendering on Linux x86_64; this is not qualification of every distribution or
display configuration. See [Graphical browser](GraphicalBrowser.md#build-and-runtime)
for dependencies and the terminal-only build.

The native browser supports ordinary Page browsing, explicit media reveal and
Forms. Mail and Transfers have separate native commands; administration uses
the CLI. A window opens only for an explicit graphical command.

## Terminal graphics and services

Tested graphics combinations are xterm 390 with Sixel and WezTerm
20240203-110809-5046fc22 with iTerm2. Kitty remains experimental: versions 0.48.2
and 0.49.2 with a software-rendered display can lose images or unrelated text.
Its native visual qualification is pending. Graphics are explicitly selected and
off by default; `--graphics off` retains the text and image descriptions. Native
iTerm2 on macOS remains unqualified.

OpenSSH 10.6 or newer is an additional requirement only for explicitly requested
SSH service sessions. It is not bundled. Client trust, page reading, mail,
transfers and service functionality have separate prerequisites documented in
their respective manuals. Native client qualification does not establish node
confinement, authority quorum health, Internet reachability or SSH availability.

This Linux release does not establish production Internet qualification. A deployment
still needs an operator-managed update policy, key custody, backups and an
independent security assessment appropriate to its exposure.
