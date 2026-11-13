# Installation

[Documentation](ReadMe.md) | [Project README](../ReadMe.md)

For signed packages, start with the [Linux 0.11.0 release notes](ReleaseNotes.md#version-0110).

HyperNetSuite has an independent source tree, binary and package. It does not
require a HyperNet checkout. Installation never starts a service or creates an
identity. Keep profiles, keys, vaults, downloads and backups outside the software
prefix. See [supported platforms](SupportedPlatforms.md) for runtime requirements.
The native [offline network commands](Networks.md) require no hosting runtime,
service, inbound listener or external command. They prepare complete authenticated
bootstrap material and private client profiles without making a connection.
The installed [diagnostic command](Diagnostics.md) previews a bounded local summary
and can export its exact redacted bytes to a new private file without host services.

## Requirements

The current runtime profile is native x86_64 GNU/Linux. The client binary uses
host-maintained shared libraries. A signed package records its exact loader,
shared-library names and minimum GLIBC version; consult that inventory before
choosing a host. Python is not required to run the client itself.

For a source build, install Rust 1.95 or newer, Cargo, a C toolchain and linker,
and `pkg-config`. The default build includes the native applications and their X11/XCB,
Wayland and xkbcommon development dependencies. A graphical session also needs
usable EGL or GLX libraries and an OpenGL 2.1 / OpenGL ES 2.0 compatible driver.
Mesa software rendering is supported. See the native dependency details in
[Graphical browser](GraphicalBrowser.md#build-and-runtime).

Package tools and the optional example generator require Python 3.11 or newer.
Signed package operations also require OpenSSH `ssh-keygen` with Ed25519 SSHSIG
support. Source installation uses Bash, GNU coreutils and Cargo; an uncached
build needs access to the locked crate sources. Installation does not install
system prerequisites or register network membership.

The source installer also requires Python, pip and setuptools to build the
included application SDK wheel offline. A signed package already includes that
wheel. Mapped application ingress and the native authority connector require
rootless Podman with configured subordinate UID/GID ranges; outgoing SDK clients
do not need that helper. See [application streams](ApplicationStreams.md) and
[the authority connector](AuthorityConnector.md) for the private socket setup.

## Source installation

From the authenticated source checkout, run as your normal account:

```sh
bash Tools/Install.sh "$HOME/.local/opt/HyperNetSuite"
export PATH="$HOME/.local/opt/HyperNetSuite/Bin:$PATH"
HyperNetSuite --help
```

The installer builds the locked release and copies the executable to `Bin/`,
examples to `Examples/`, and manuals to `Documentation/HyperNetSuite/` within the
prefix. Open its `ReadMe.md` for the installed documentation. The checkout can
be moved after installation. No desktop entry, background service or automatic
startup is created. Run the command from a terminal.

This source installer can refresh an existing source prefix and provides no
publisher-signature validation. Stop client processes before refreshing it.
Use a new prefix for a different build and keep private state outside both.
Never mix source installation with a signed package's managed inventory; see
[upgrade and recovery](UpgradeRecovery.md) before replacing installed software.

### Terminal-only build

To omit the native applications and their graphical dependencies:

```sh
cargo build --locked --release --no-default-features
./target/release/HyperNetSuite --help
```

Use that executable directly or copy it to a separate chosen binary directory.
If `CARGO_TARGET_DIR` is set, use its `release/HyperNetSuite` instead.
`Tools/Install.sh PREFIX` builds the default graphical feature set; it does not
install the terminal-only build. A terminal-only executable refuses `--gui`
before starting a browser connection. CLI, terminal and plain output remain
available. The `mail gui` and `transfers gui` subcommands require a graphical build.

## Coordinated simple access

The coordinated release includes Core and Suite packages for shared joining and
hosting. Use **Install / repair components** in the join window to verify and
install them from its local `Packages` folder. The installer uses pinned publisher
trust, signed target policies and retained rollback state. It makes no downloads
selected by a server invitation. Ordinary joining does not import a Podman image;
hosting loads the verified image when required.

After installation, choose **Join a server** or **Create / manage a server**.
See [Simple joining](SimpleJoining.md) and [Shared hosting](SharedHosting.md).
Registering native links is optional through `HyperNetSuite join install`.
That command creates the current user's desktop and private-bus activation
entries. Opening an invitation starts a review window; it does not silently join.

## Try a local Page

With the source installation above:

```sh
HyperNetSuite pages preview "$HOME/.local/opt/HyperNetSuite/Examples/GraphicalPage.txt" --gui
```

For a source build without installation, run
`./target/release/HyperNetSuite pages preview Examples/GraphicalPage.txt --gui`
from the checkout. For a signed package, use its `Bin/HyperNetSuite` and
`Examples/GraphicalPage.txt` paths.

Replace `--gui` with `--tui` for interactive terminal viewing. Omit both for plain
output; pipes and `TERM=dumb` also use plain output. Preview validates local
unapproved content, needs no identity or profile, and cannot navigate a network
or send Forms. No media preparation is needed for this example. See
[Examples](../Examples/ReadMe.md) for the optional fictional business Pages.

After preview, follow [Networks](Networks.md) and [Private routes](PrivateRoutes.md)
to accept trust, join and retain the approved service routes. Installation and
local preview do not perform those steps.

## Signed offline package

### Coordinated first installation

The coordinated release supplies `Packages/Core/` and `Packages/Suite/` with the
signed Core and Suite 0.11.0 archives, archive signatures, signed target policies
and publisher keys. After authenticating the outer release, run its
`bash Tools/Install.sh` with no arguments. This entry authenticates the inner
Suite with the pinned publisher and normal update policy, installs it directly
into its final private prefix, then runs its coordinated installer. After both
products verify, it registers the normal per-user desktop/link handler and opens
**Join a server** through that verified installed Suite. It never executes an
adjacent unverified `Bin/HyperNetSuite`. If link registration fails, the window
still opens and the installer reports the registration failure. The earlier
source-build command with an explicit prefix remains available.

For headless or machine-readable installation without opening a window, an
already authenticated Suite exposes the same installer directly:

```sh
/Installed/HyperNetSuite native-installation install \
  --release-directory /Release/Packages --json
/Installed/HyperNetSuite native-installation inspect --json
```

Both commands accept `--directory /Private/Installation`. The default is
`$XDG_STATE_HOME/HyperNetSuite/Installation`, or
`$HOME/.local/state/HyperNetSuite/Installation`. No packages are downloaded and
server links cannot select executables or trust keys. Core's complete package
is verified and installed without loading its OCI image. Joining therefore does
not require Podman; hosting later requests the explicit verified image load.

Each product keeps its existing update trust and exact signed target evidence.
The immutable archive digest selects its installation prefix. An existing exact
prefix is verified and reused; a different or modified prefix is preserved and
refused. The private `Installation.json` becomes available atomically only after
both products pass. If interrupted, retain the directory and retry the same
release. This preserves accepted update floors and existing identities.

`inspect` verifies all installed files, the historical signed targets and their
exact binding to retained update trust and the selected pair. Expiry of an update
policy does not expire already installed software or a separately authorised
host. Historical verification cannot select or admit a new package: installation,
software cutover and explicit image loading still require current signed policy.

The machine-readable result has format `HyperNetNativeInstallation/1`, status
`Ready`, `coreExecutable`, `suiteExecutable`, `coreImage` and the two `packages`.
Each package records its product, version, prefix, archive/manifest/binary SHA-256,
publisher root pin/generation, sequence, target/trust digest and state contract.
`Ready` describes the verified installation, not network or service readiness.

Only `Bin/HyperNetSuite` uses mode 0755 so an explicitly bound isolated registrar
can execute it. Its installed ancestors remain private 0700; helper executables,
package evidence and private state keep their existing restricted modes. The
same verifier still recognises earlier packages' exact 0700 binary mode.

### Individual offline package

Obtain `Tools/Bundle.py` and its adjacent `Tools/PackageTrust.py` from an
authenticated source and authenticate their contents before executing them. A verifier copied from an untrusted archive cannot establish
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

### Optional installed-client checks

Maintainers qualifying a package can select an existing, private persistent
work directory and run:

```sh
python3 Tools/Qualify.py --work-directory /Private/QualificationWork \
  --prefix /Chosen/HyperNetSuiteCurrent --public-key Publisher.pub
```

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

## Maintainer checks and archive assembly

Run the repository gate when changing the client:

```sh
bash Tools/Check.sh
```

It checks formatting, Clippy and release tests. It uses a private persistent
directory under the user's state home. Set `HYPERNET_TEST_DIRECTORY` to another
private persistent directory when needed. Use an absolute canonical path with
ancestors protected from replacement by other users. The gate rejects paths
too long for its Unix socket fixtures before building. Test state must not become live state.
The gate is not an installation step.

Maintainers can assemble an offline archive from a locked native release build:

```sh
python3 -m pip wheel --no-deps --no-build-isolation --wheel-dir dist ./SDK
python3 Tools/Bundle.py Create --binary target/release/HyperNetSuite \
  --streams-sdk-wheel dist/hypernet_streams-0.11.0-py3-none-any.whl \
  --output HyperNetSuite.tar --signing-key PublisherKey
python3 Tests/Bundle.py --binary target/release/HyperNetSuite \
  --streams-sdk-wheel dist/hypernet_streams-0.11.0-py3-none-any.whl
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
