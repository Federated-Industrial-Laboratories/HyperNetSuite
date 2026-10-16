# Installation

HyperNetSuite has an independent source tree, binary and package. It does not
require a HyperNet checkout. Installation never starts a service or creates an
identity. Keep profiles, keys, vaults, downloads and backups outside the software
prefix. See [Supported platforms](SupportedPlatforms.md) for runtime requirements.
The native [offline network commands](Networks.md) require no hosting runtime,
service, inbound listener or external command. They prepare complete authenticated
bootstrap material and private client profiles without making a connection.
The installed [diagnostic command](Diagnostics.md) previews a bounded local summary
and can export its exact redacted bytes to a new private file without host services.

## Signed offline package

Obtain `Tools/Bundle.py` from an authenticated source and authenticate its content
before executing it. A verifier copied from an untrusted archive cannot establish
trust in that archive. Obtain the Ed25519 publisher public key through a separate
authenticated channel and pin its fingerprint. A public key shipped beside an
archive is not sufficient evidence of publisher identity.

Use a dedicated non-root account and a new prefix below an existing directory.
Package operations require Python 3.11 or newer and OpenSSH `ssh-keygen` with
Ed25519 SSHSIG support. No package operation downloads software.
Before installation, initialise private package trust with `TrustInit` and an
independently authenticated root fingerprint, then obtain its authorised target
policy. [UpgradeRecovery](UpgradeRecovery.md) gives the complete trust and policy
procedure; archive integrity verification alone does not authorise installation.

```sh
python3 Tools/Bundle.py Verify --archive HyperNetSuite.tar \
  --signature HyperNetSuite.tar.sig --public-key Publisher.pub
python3 Tools/Bundle.py Install --archive HyperNetSuite.tar \
  --signature HyperNetSuite.tar.sig --public-key Publisher.pub \
  --trust-directory /Private/SuitePackageTrust \
  --policy Target.json --policy-signature Target.json.sig \
  --prefix /Chosen/HyperNetSuiteCurrent
python3 Tools/Bundle.py VerifyInstalled \
  --prefix /Chosen/HyperNetSuiteCurrent --public-key Publisher.pub
python3 Tools/Qualify.py --work-directory /Private/QualificationWork \
  --prefix /Chosen/HyperNetSuiteCurrent \
  --public-key Publisher.pub
```

Verification authenticates a private archive snapshot with the
`HyperNetSuiteBundle1` SSHSIG namespace before parsing the archive. The manifest
binds the product, version, native architecture, binary ABI and exact file
inventory. Extraction admits only bounded regular files. Paths, links, duplicate
members and undeclared files are rejected. Installation publishes a complete
private prefix atomically and refuses an existing destination. The binary uses
host-maintained dynamic libraries; the package does not copy system libraries.

The installed `Bin/HyperNetSuite` accepts the documented client commands. Use its
absolute path or add the chosen `Bin` directory to the shell's search path.
Qualification checks local identity generation, inert plain output, reader
terminal restoration, bounded markup, isolated media import and local motion.
It also prepares and validates the five supplied fictional business examples.
Its pseudoterminal checks do not establish native graphics support. It makes no network requests
and does not qualify a remote service or an entire deployment.
Qualification also exercises native governance drafting, independent recovery
acceptance, offline profile creation, privacy-policy refusals and safe removal.
It checks diagnostic redaction, exact preview-bound private export and refusal of
changed snapshots, existing files and symbolic-link destinations.
When `strace` is available, the provisioning check observes network system calls
under an empty PATH and hostile proxy variables. Its report states whether this
additional observation was available; `strace` is not a client runtime dependency.

`VerifyInstalled` reauthenticates the retained signed archive and checks every
installed file, directory, mode and digest. It is useful before execution and
after recovery. Signed packages do not prevent another process with the same
account privileges from modifying software after verification.

## Source installation

Install Rust 1.91 or newer, Cargo, a C linker and the platform development
libraries. Build from the authenticated source tree using the locked graph:

```sh
cargo build --locked --release
bash Tools/Check.sh
bash Tools/Install.sh /Chosen/SourcePrefix
```

This maintainer installer copies the binary, manuals and examples. It retains its original
interface and can refresh an existing source installation. It provides no
publisher-signature validation. Use a new prefix and do not mix source-installed
files with a signed package's managed inventory.

Maintainers can assemble an offline archive from a locked native release build:

```sh
python3 Tools/Bundle.py Create --binary target/release/HyperNetSuite \
  --output HyperNetSuite.tar --signing-key PublisherKey
python3 Tests/Bundle.py --binary target/release/HyperNetSuite
```

Assembly additionally requires GNU `readelf`. It records the binary's actual ELF
interpreter, shared-library names and minimum GLIBC symbol version. The signing
key is supplied explicitly and is never bundled. Archive creation does not
publish anything. Signing-key custody and any public distribution require a
separate operational decision.

## Native graphics checks

`Tests/NativeGraphics.py` drives actual Kitty, xterm and WezTerm executables on an
isolated X display. Supply `--suite`, `--kitty`, `--xterm`, `--wezterm` and a new
private `--output` directory. It needs Python Pillow, Xvfb, xdotool and ImageMagick
for test capture only; these are not client runtime dependencies. For example:

```sh
xvfb-run --auto-servernum --server-args='-screen 0 1440x1100x24 -nolisten tcp' \
  python3 Tests/NativeGraphics.py --suite /Chosen/HyperNetSuiteCurrent/Bin/HyperNetSuite \
  --kitty /Chosen/Kitty/bin/kitty --xterm /usr/bin/xterm \
  --wezterm /Chosen/WezTerm/wezterm --output /Chosen/GraphicsResults
```

The check exercises explicit reveal, nested clipping, local motion, scroll, resize
and exit restoration, retaining screenshots and exact executable identities.
Inspect the captured clipping and adjacent text before qualifying a terminal
version. Linux WezTerm checks the iTerm2 protocol implementation; it does not
qualify native iTerm2 or macOS. Multiplexer and SSH contexts remain text fallback.
Kitty visual qualification is still pending; the documented software-display
failure is described in [MediaViewer](MediaViewer.md). Use repeated `--adapter`
options to select only the terminal profiles being checked.
