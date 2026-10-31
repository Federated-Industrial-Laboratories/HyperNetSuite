# Linux release notes

[Documentation](ReadMe.md) | [Project](../ReadMe.md)

## Linux 0.10.0 application context and authority checks

Version 0.10.0 adds explicit current-authority observations and transport context
for native applications using HyperNet streams. Download the
[Linux 0.10.0 release](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/releases/tag/v0.10.0).
Read the [application context contract](ApplicationContext.md) before using these results
at an application permission boundary.

### Changes

- A separate, endpoint-initiated `Checks.sock` channel provides fresh authority
  checks for an exact active incoming stream. The signed result binds the service,
  stream generation, application action digest, nonce and control instances.
  The existing opaque payload channel and version 1 IPC contract remain compatible.
- Typed results distinguish certified permission and refusal from unavailable,
  expired and inactive checks. A busy requester does not fall back to an ordinary
  authority mutation. Applications still enforce their own permissions and action
  semantics; an observation is not a portable quorum proof or reusable grant.
- Directional context separates final-service TLS 1.3 from relay-path evidence.
  Public incoming endpoints report an unknown upstream relay path. Attached
  endpoints can attest their approved attachment without claiming physical
  operator independence or continuing profile currentness.
- Checks allow 100 through 5,000 ms caller waits, with a one-second SDK default.
  The authority challenge has a separate ceiling at the original companion start
  plus five seconds. Current clock health, original caller and stream deadlines,
  cancellation and local consent still bound every result.
- One pending check per connection and four per companion bound the check queue.
  The checks channel uses none of the existing 16 application connection slots.
  These are implementation limits, not a concurrent-user or latency guarantee.
- The Python SDK provides typed status, context and authority results through
  `Agent(directory, version=2)`. Existing applications keep version 1 unless they
  opt in. Missing endpoint support is reported as unavailable, without changing
  the payload connection or silently selecting a direct Internet route.

### Qualification and limits

The release target remains native Ubuntu 24.04 x86_64 with GNU libc 2.39. Native
AArch64, Windows, macOS and SELinux-enabled hosting remain unqualified.
Source-bound native feature validation exercised a confined attached endpoint,
separate companion and retained authority route with four local authority
replicas. It covered version 1 echo and a verified 1 MiB object, version 2 opaque
payloads, exact session/action/nonce binding, default one-second and explicit
five-second checks, receipt expiry, cancellation, closed streams and a certified
refusal after grant revocation. Incoming attachment and outgoing nested-TLS facts
were checked separately. The fixture was stopped and cleaned up after the run.

This bounded workflow is not a throughput, soak, service-level or independent
operator-separation guarantee. Release package and executable checks must name
the actual 0.10.0 artifacts. Earlier graphics, terminal and larger-transfer results
below retain their original executable identities; they are not repeated 0.10.0
measurements. No independent security certification is claimed.

### Upgrade scope

Use matching 0.10.0 Core endpoints and Suite companions to obtain the new checks.
Restart the companion and follow stopped service replacement with renewed local
artifact consent; copying a new executable does not update an active runtime's
accepted artifacts. Existing 0.9.1 payload-only peers remain compatible but cannot
supply the new observation. No grant replacement is required solely for this
additive feature.

The 0.9.1 permission fix remains in force. When upgrading from 0.9.0, complete the
[permission-scope migration](PermissionScopes.md), including the fully applied
old-committee boundary, before using patched semantics. Preserve complete state,
private identities, requester journals, package trust and all retained floors.
The package state contract remains `HyperNet080Client1`; its unchanged name does not
authorise opening newer state with an older executable.

### Package verification and installation

Use `Tools/Bundle.py` and its adjacent `Tools/PackageTrust.py` from an
independently authenticated `v0.10.0` checkout. Authenticate the publisher through
[PublisherKey.txt](PublisherKey.txt). The generation-1 pin remains
`6529f9e574e73409ec578c9e9a66e683fef6ae885704d22d75538781b4b43b1e`.
A key downloaded beside a signature does not establish publisher identity.

The release supplies `HyperNetSuite-0.10.0-linux-x86_64.tar`, its `.sig`,
`HyperNetSuite-0.10.0-linux-x86_64.target.json`, its `.sig`, `Publisher.pub`,
and signed checksums. The target uses sequence 6 and version floor 0.10.0.
Retain the existing product trust directory for upgrades; never reset its floor.
The Suite package includes the matching Python SDK wheel and source tree.
Its host-maintained runtime libraries are not bundled.
`HyperNetSuite-0.10.0-third-party-sources.tar.xz` supplies the exact MPL-2.0
HPKE crate sources from the unchanged dependency lockfile.

With authenticated tools and existing product trust:

```sh
python3 /Trusted/HyperNetSuite/Tools/Bundle.py Install \
  --archive HyperNetSuite-0.10.0-linux-x86_64.tar \
  --signature HyperNetSuite-0.10.0-linux-x86_64.tar.sig \
  --public-key Publisher.pub \
  --trust-directory "$HOME/.local/share/HyperNetSuite/PackageTrust" \
  --policy HyperNetSuite-0.10.0-linux-x86_64.target.json \
  --policy-signature HyperNetSuite-0.10.0-linux-x86_64.target.json.sig \
  --prefix "$HOME/.local/opt/HyperNetSuite-0.10.0"
python3 /Trusted/HyperNetSuite/Tools/Bundle.py VerifyInstalled \
  --prefix "$HOME/.local/opt/HyperNetSuite-0.10.0" --public-key Publisher.pub
```

For first-install trust setup, follow [installation](Installation.md). Package
installation does not activate a workload or renew network authority. Use
[upgrade and recovery](UpgradeRecovery.md) before resuming an installed service.

## Linux 0.9.1 permission hotfix

Version 0.9.1 restricts the overlapping action codes 29 and 30 to their explicit
resource purpose throughout the non-root grant chain. Stream operations require
Service-only terminal grants.
Sealed-page operations require Object/Namespace-only terminal grants. Network
and mixed-purpose terminal grants refuse both families. Review displays identify
the scope-dependent meaning.

Read [permission scopes and migration](PermissionScopes.md) before replacing
0.9.0. Existing signed records keep their bytes. Existing precise grants remain
eligible, while broad grants require deliberate scoped replacement and any
associated admission, service or publication renewal described in that guide.
In particular, application same-rights renewal cannot change a grant, a withdrawn
application key cannot be reused, and an old sealed review is not rewritten by
issuing a new grant. Upgrade the authority committee, endpoints and clients
together; mixed permission semantics are unsupported. Before replacement, every
voter must finish applying the same old-version committed boundary. The migration
guide specifies the quiescence, certified inspection and stopped-journal checks;
starting a lagging replica under the new permission rules is unsupported.

Download the [Linux 0.9.1 release](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/releases/tag/v0.9.1).
The supported platform remains native Ubuntu 24.04 x86_64 with the existing
library and runtime requirements. This hotfix does not qualify another platform,
change the transport protocol, or provide an independent security assessment.

### Package verification and installation

Use the trusted tools from the exact `v0.9.1` checkout and independently
authenticate the publisher using [PublisherKey.txt](PublisherKey.txt). The
generation-1 publisher pin remains
`6529f9e574e73409ec578c9e9a66e683fef6ae885704d22d75538781b4b43b1e`.
A public key downloaded beside its signature does not establish publisher trust.

The release contains `HyperNetSuite-0.9.1-linux-x86_64.tar`, its signature,
`HyperNetSuite-0.9.1-linux-x86_64.target.json`, its signature, `Publisher.pub`,
the corresponding source archive, and signed checksums. Verify those signatures
and use the existing product trust directory for an upgrade. The new signed
target uses sequence 5 and version floor 0.9.1; never reset a retained floor.

With authenticated tools and existing product trust:

```sh
python3 /Trusted/HyperNetSuite/Tools/Bundle.py Install \
  --archive HyperNetSuite-0.9.1-linux-x86_64.tar \
  --signature HyperNetSuite-0.9.1-linux-x86_64.tar.sig \
  --public-key Publisher.pub \
  --trust-directory "$HOME/.local/share/HyperNetSuite/PackageTrust" \
  --policy HyperNetSuite-0.9.1-linux-x86_64.target.json \
  --policy-signature HyperNetSuite-0.9.1-linux-x86_64.target.json.sig \
  --prefix "$HOME/.local/opt/HyperNetSuite-0.9.1"
python3 /Trusted/HyperNetSuite/Tools/Bundle.py VerifyInstalled \
  --prefix "$HOME/.local/opt/HyperNetSuite-0.9.1" --public-key Publisher.pub
```

For a first installation, initialise product trust through
[the installation guide](Installation.md). Installation does not activate a
runtime or alter network authority. Follow the stopped replacement and permission
migration procedures before resuming affected work.


## Linux 0.9.0

Version 0.9.0 adds reusable application streams for services that need private,
permissioned transport. Download the native x86_64 package from
[GitHub Releases](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/releases/tag/v0.9.0).
The historical 0.8.0 release notes and downloads remain below.

### Changes

- The native [application companion](ApplicationStreams.md) exposes bounded
  connect, accept, status and cancel operations over private local sockets.
  Application data travels through the existing relay and nested TLS transport,
  with exact service/protocol binding and separately verified peer context.
- A packaged Python SDK and runnable examples support arbitrary application
  protocols. The confined endpoint receives only the mapped ingress, while
  application keys, requester floors and command sockets stay private.
- The [authority connector](AuthorityConnector.md) provides installed Core
  endpoints with generic remote authority access from a separate joined profile.
- Explicit [same-rights renewal](ApplicationAccess.md#same-rights-renewal) retains
  application identity and permissions through owner/application consent.
  Existing monotonic floors and exact pending operations remain enforced.
- Joining refreshes clock health after durable artifact writes. Fresh reads can
  reacquire an expired proof within the original preparation budget. If a read
  persists a newer floor before cache publication is interrupted, the client
  discards superseded derived domain context and requires a new verified result.
  Missing authentication, conflicting digests and future cache generations
  remain errors; deadlines and authenticated floors are never reset.

### Platform and validation

The release uses native Ubuntu 24.04 x86_64 and GNU libc 2.39. The normal build
includes the native Browser, Mail and Transfers interfaces; native windows need
X11 or Wayland and working EGL/GLX libraries. The CLI and terminal do not require
a graphical session. Native ARM, macOS and Windows remain unqualified.

Signed installation, private IPC and bounded native application workflows were
exercised with separate application hosts and a remote relay. Application
integration transferred and SHA256-verified 4,079,434,577 bytes in ten files with
pause/resume and permission revocation. Transfer progress continued after a
natural proof expiry during persistence and a transport closure, using current
proofs and retained data. Actual remote inference, cancellation and active grant
revocation were also exercised. These observations do not establish a general
throughput guarantee, long-running soak, full screen-reader coverage, independent
operator separation or security certification. Unchanged graphical and offline
qualification retains its original executable identity.

### Upgrade scope

Protocol 7 requires matching Core and Suite support, with a compatible authority
committee before new stream records are used. The retained `HyperNet080Client1`
package contract does not make post-0.9 state readable by 0.8. Install side by side
through the accepted publisher and a fresh signed target policy. Stop active
client operations before selecting the new binary, and retain private profiles,
keys, journals, package trust and current floors. Do not delete state to retry a
join or recover a connection. See [upgrade and recovery](UpgradeRecovery.md).

### Download and authenticate

Download all five package inputs from the release: `HyperNetSuite-0.9.0-linux-x86_64.tar`,
its `.sig`, `HyperNetSuite-0.9.0-linux-x86_64.target.json`, its `.sig`, and `Publisher.pub`.
`SHA256SUMS` and `SHA256SUMS.sig` cover the downloadable artifacts.
The suite uses host-maintained shared libraries; it does not bundle them.
`HyperNetSuite-0.9.0-third-party-sources.tar.xz` supplies the exact MPL-2.0
HPKE crate sources from the lockfile, including optional implementations.
Keep their licences and source availability when redistributing the package.

Use `Tools/Bundle.py` and `Tools/PackageTrust.py` from an independently trusted
checkout of the `v0.9.0` tag. Python 3.11 or newer and OpenSSH `ssh-keygen` with
Ed25519 SSHSIG support are required. Do not execute tools extracted from an
unverified archive. Authenticate the publisher through a separate trusted channel
before accepting this release root:

```text
Root generation: 1
Root pin: 6529f9e574e73409ec578c9e9a66e683fef6ae885704d22d75538781b4b43b1e
```

The canonical public key is also recorded in [PublisherKey.txt](PublisherKey.txt).
This hexadecimal pin uses the package tool's canonical-key format, not OpenSSH's
base64 fingerprint. A key and signature downloaded together cannot establish
publisher identity by themselves.

From the download directory, using the trusted checkout's helper:

```sh
python3 /Trusted/HyperNetSuite/Tools/Bundle.py KeyPin --public-key Publisher.pub
sha256sum --check SHA256SUMS
```

Compare the computed pin with the independently accepted pin above. Checksums
alone detect corruption, not publisher identity. Verify the signed checksum file
with an independently trusted public key when checking the source accompaniment:

```sh
printf 'ReleasePublisher %s\n' "$(cat Publisher.pub)" > ReleaseSigners
ssh-keygen -Y verify -f ReleaseSigners -I ReleasePublisher \
  -n HyperNetSuiteRelease1 -s SHA256SUMS.sig < SHA256SUMS
```

### Fresh installation

Use a new private installation prefix. Initialise trust once per product;
Core and Suite use separate trust directories even with the same publisher.
These commands are for a fresh installation, not replacement of existing trust.

```sh
install -d -m 0700 "$HOME/.local/share/HyperNetSuite" "$HOME/.local/opt"
python3 /Trusted/HyperNetSuite/Tools/Bundle.py TrustInit \
  --trust-directory "$HOME/.local/share/HyperNetSuite/PackageTrust" \
  --public-key Publisher.pub \
  --root-pin 6529f9e574e73409ec578c9e9a66e683fef6ae885704d22d75538781b4b43b1e \
  --root-generation 1 --version-floor 0.9.0 --state-contract HyperNet080Client1
python3 /Trusted/HyperNetSuite/Tools/Bundle.py Install \
  --archive HyperNetSuite-0.9.0-linux-x86_64.tar \
  --signature HyperNetSuite-0.9.0-linux-x86_64.tar.sig --public-key Publisher.pub \
  --trust-directory "$HOME/.local/share/HyperNetSuite/PackageTrust" \
  --policy HyperNetSuite-0.9.0-linux-x86_64.target.json \
  --policy-signature HyperNetSuite-0.9.0-linux-x86_64.target.json.sig \
  --prefix "$HOME/.local/opt/HyperNetSuite-0.9.0"
python3 /Trusted/HyperNetSuite/Tools/Bundle.py VerifyInstalled \
  --prefix "$HOME/.local/opt/HyperNetSuite-0.9.0" --public-key Publisher.pub
"$HOME/.local/opt/HyperNetSuite-0.9.0/Bin/HyperNetSuite" pages preview \
  "$HOME/.local/opt/HyperNetSuite-0.9.0/Examples/GraphicalPage.txt" --gui
```

The signed target has a finite validity interval recorded in its `notBefore` and
`expires` fields. An expired target needs a newly authorised policy; do not bypass
expiry or reset retained trust. Installation starts no network services and
creates no membership. Keep profiles, keys, consent and data outside the prefix.

### Existing installations

The generation-1, sequence-3 target supports fresh release trust and existing
trust for this publisher with a lower retained sequence. It cannot migrate
an existing installation from a different publisher: root rotation must increase
the retained generation, and a migration target must match that new generation
and exceed the retained sequence. Existing development installations need a
separately authorised compatible migration target from the accepted publisher.

Preserve profiles, journals, backups, retained floors and original package trust.
Do not reset trust or create a replacement trust directory to bypass those floors.
Earlier packages are not automatically upgraded or activated. Follow
[upgrade and recovery](UpgradeRecovery.md) for independent root authentication,
state compatibility, migration targets and side-by-side installation.

## Linux 0.8.0 (published)

HyperNetSuite 0.8.0 is the first public Linux release. Download the native x86_64
package from [GitHub Releases](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/releases/tag/v0.8.0).

The suite brings native Browser, Mail and Transfers windows to the same
verified network workflows as its terminal and command-line clients. It includes
reviewed Forms, sealed Pages, scoped search, publication and recovery tools.
Mail enrolment and network administration use the CLI.

### Platform and release scope

The packaged profile is native Ubuntu 24.04 x86_64 with GNU libc 2.39 or newer.
Other Linux distributions need the exact ELF loader and libraries recorded in
`Manifest.json`; they are not separately qualified by this release. Native ARM,
macOS and Windows are not qualified. SELinux-enabled hosting remains unqualified.
Native windows require X11 or Wayland and working EGL/GLX graphics libraries.
The terminal and command-line interfaces do not need a graphical session.

The release includes requester/recipient clock refresh corrections across durable
writes and profile-lock ownership fixes. Existing proof deadlines, pending
requests and completed effects remain enforced. Source regressions and signed
installation checks cover this release. Earlier installed network, recovery,
Mail, Transfer and graphical checks remain relevant to the unchanged runtime
implementation; they do not become measurements of a different executable.

This release has no independent security certification. Saturation, long-running
soak tests, full screen-reader use and independent operator/failure-domain
qualification are outside the measured scope. Large file downloads remain slow:
a prior 1 MiB relay download took 12.246 seconds. Native administration is not
included; use the documented CLI. Read the security and platform guides before
planning an exposed deployment.

### Download and authenticate

Download all five package inputs from the release: `HyperNetSuite-0.8.0-linux-x86_64.tar`,
its `.sig`, `HyperNetSuite-0.8.0-linux-x86_64.target.json`, its `.sig`, and `Publisher.pub`.
`SHA256SUMS` and `SHA256SUMS.sig` cover the downloadable artifacts.
The suite uses host-maintained shared libraries; it does not bundle them.
`HyperNetSuite-0.8.0-third-party-sources.tar.xz` supplies the exact MPL-2.0
HPKE crate sources from the lockfile, including optional implementations.
Keep their licences and source availability when redistributing the package.

Use `Tools/Bundle.py` and `Tools/PackageTrust.py` from an independently trusted
checkout of the `v0.8.0` tag. Python 3.11 or newer and OpenSSH `ssh-keygen` with
Ed25519 SSHSIG support are required. Do not execute tools extracted from an
unverified archive. Authenticate the publisher through a separate trusted channel
before accepting this release root:

```text
Root generation: 1
Root pin: 6529f9e574e73409ec578c9e9a66e683fef6ae885704d22d75538781b4b43b1e
```

The canonical public key is also recorded in [PublisherKey.txt](PublisherKey.txt).
This hexadecimal pin uses the package tool's canonical-key format, not OpenSSH's
base64 fingerprint. A key and signature downloaded together cannot establish
publisher identity by themselves.

From the download directory, using the trusted checkout's helper:

```sh
python3 /Trusted/HyperNetSuite/Tools/Bundle.py KeyPin --public-key Publisher.pub
sha256sum --check SHA256SUMS
```

Compare the computed pin with the independently accepted pin above. Checksums
alone detect corruption, not publisher identity. Verify the signed checksum file
with an independently trusted public key when checking the source accompaniment:

```sh
printf 'ReleasePublisher %s\n' "$(cat Publisher.pub)" > ReleaseSigners
ssh-keygen -Y verify -f ReleaseSigners -I ReleasePublisher \
  -n HyperNetSuiteRelease1 -s SHA256SUMS.sig < SHA256SUMS
```

### Fresh installation

Use a new private installation prefix. Initialise trust once per product;
Core and Suite use separate trust directories even with the same publisher.
These commands are for a fresh installation, not replacement of existing trust.

```sh
install -d -m 0700 "$HOME/.local/share/HyperNetSuite" "$HOME/.local/opt"
python3 /Trusted/HyperNetSuite/Tools/Bundle.py TrustInit \
  --trust-directory "$HOME/.local/share/HyperNetSuite/PackageTrust" \
  --public-key Publisher.pub \
  --root-pin 6529f9e574e73409ec578c9e9a66e683fef6ae885704d22d75538781b4b43b1e \
  --root-generation 1 --version-floor 0.8.0 --state-contract HyperNet080Client1
python3 /Trusted/HyperNetSuite/Tools/Bundle.py Install \
  --archive HyperNetSuite-0.8.0-linux-x86_64.tar \
  --signature HyperNetSuite-0.8.0-linux-x86_64.tar.sig --public-key Publisher.pub \
  --trust-directory "$HOME/.local/share/HyperNetSuite/PackageTrust" \
  --policy HyperNetSuite-0.8.0-linux-x86_64.target.json \
  --policy-signature HyperNetSuite-0.8.0-linux-x86_64.target.json.sig \
  --prefix "$HOME/.local/opt/HyperNetSuite-0.8.0"
python3 /Trusted/HyperNetSuite/Tools/Bundle.py VerifyInstalled \
  --prefix "$HOME/.local/opt/HyperNetSuite-0.8.0" --public-key Publisher.pub
"$HOME/.local/opt/HyperNetSuite-0.8.0/Bin/HyperNetSuite" pages preview \
  "$HOME/.local/opt/HyperNetSuite-0.8.0/Examples/GraphicalPage.txt" --gui
```

The signed target has a finite validity interval recorded in its `notBefore` and
`expires` fields. An expired target needs a newly authorised policy; do not bypass
expiry or reset retained trust. Installation starts no network services and
creates no membership. Keep profiles, keys, consent and data outside the prefix.

### Existing installations

The published generation-1 target is for fresh release trust. It cannot migrate
an existing installation from a different publisher: root rotation must increase
the retained generation, and a migration target must match that new generation
and exceed the retained sequence. Existing development installations need a
separately authorised compatible migration target from the accepted publisher.

Preserve profiles, journals, backups, retained floors and original package trust.
Do not reset trust or create a replacement trust directory to bypass those floors.
Earlier packages are not automatically upgraded or activated. Follow
[upgrade and recovery](UpgradeRecovery.md) for independent root authentication,
state compatibility, migration targets and side-by-side installation.
