# Join a server

[Documentation](ReadMe.md) | [Hosting](SharedHosting.md) | [Manual joining](PrivateRoutes.md)

Open a server's native link, or choose **Join a server** and paste its address or
invitation. Import a PNG or JPEG QR image if that is easier. Review the server
name, address and permissions, choose a display name, enter its password when
requested, and join. A private invitation normally supplies the admission
credential itself. Opening the landing page or reviewing a link does not use it.

```sh
HyperNetSuite join desktop
```

Suite can join read-only Pages without RelayChat installed. RelayChat uses this
same native workflow and adds its own account and room registration. Where both
are available, the applications keep separate native chat and reader identities
behind one saved server entry. Following a chat Page link opens or focuses the
reader window; it does not disconnect chat. An active Page form is retained
until the reader explicitly chooses to leave it.

The current desktop packages support Linux. A QR or link is not a mobile client.
For a private certificate authority, use the native link or import the QR in the
application. An ordinary web browser does not automatically trust that authority.
Never bypass a browser certificate warning to submit a password.

## First installation

Use **Install / repair components** for the coordinated release's local Packages
folder. It verifies the pinned publisher, package signatures, compatible versions
and retained rollback policy. The invitation cannot select an executable,
download, signing key or privileged system action.

Python 3 and OpenSSH signature tools are installation prerequisites. Chrony
provides a private time observer; it does not change system time. Hosting also
needs rootless Podman and the normal native host prerequisites. Install missing
system prerequisites with the distribution's software manager. The installer
reports unsupported platforms or missing requirements rather than weakening the
verification rules.

Suite starts its private Chrony observer from a verified, byte-identical copy of
the configured `chronyd` executable inside the saved server directory. This keeps
the private observer separate from the distribution's system Chrony service.
The copy follows trusted executable updates at the next stopped startup; it does
not change the selected source, system configuration or retained clock identity.
Advanced configurations that select an existing Chrony socket continue to use
that socket and do not prepare or start another observer.

The coordinated Suite and HRC installers register the shared native-link handler.
A chat invitation finds HRC in its normal per-user installation, including a
custom `XDG_DATA_HOME`, without requiring a PATH change. Manual installations
can retain their existing sibling executable or PATH setup.

To register or repair the installed native-link handler explicitly:

```sh
HyperNetSuite join install
```

Supported desktops deliver the invitation through the private user bus. It is
passed to the join window on stdin, not in process arguments. Desktops without
that activation support open the paste window. This registration does not join
any server or start hosting.

## Saved identity and lifetime

The saved server retains local keys, the reviewed server identity, profiles and
unfinished signed operations. Reconnect the saved entry after a restart or a
long offline period. Do not delete it to retry a failed operation: a new identity
may require another invitation and cannot recover the previous account.

**Access until removed** is a native entitlement with matching parent authority.
It has no membership expiry. Transport vouchers and freshness proofs are still
finite and renewed under the current policy. Withdrawal or removal remains
binding. A finite server advertises its actual access expiry instead.

**Stay offline** persists until explicit reconnection. The runtime does not
reconnect a saved offline entry. Retained chat history remains local. A verified
native retirement is shown as removal, distinct from temporary unavailability;
old certificates do not restore access after removal.

## Trust and useful failures

A native link pins the server's descriptor key. A private-CA link also pins its
TLS authority key while retaining hostname, signature and time validation.
Publicly trusted HTTPS addresses retain ordinary WebPKI verification. Redirects,
embedded credentials, unsupported paths and oversized or ambiguous QR images are
refused. Invitations are private credentials: share them only with their intended
recipients and be aware of clipboard history.

A changed descriptor or permission policy requires a new review. A wrong password,
paused joining, full capacity, expired invitation and missing Agent consent do
not grant partial extra rights. Interrupted native operations keep their exact
keys and outcomes for recovery. Repair missing local components before retrying;
do not replace trust pins or private files to suppress an error.

Manual bootstrap inspection, explicit file exchange, stronger route requirements,
finite leases and existing authority commands remain available. Simple joining
does not change an existing manual profile's privacy selection.

## Command integration

The graphical join helper accepts one bounded stdin object:

```json
{"location":"hypernet-join://server.example:25445/v1#v=1&pin=PUBLIC_PIN&app=native"}
```

A completed join reports `status: Joined`, the private saved server directory,
optional chat and reader profile paths, and its runtime configuration path.
Secrets are never required as command-line arguments. Scripts can also use
`join client --directory PATH` with the documented typed operation object on
stdin; keep the directory private and reuse it for exact retries.

`join status`, `join desire --online|--offline`, `join session` and `join pages`
operate on an existing saved server. The session owns the local observer and
chat companion until stopped or disconnected; it has no service lifetime timer.
The Page helper returns only after the real reader window has attached, and the
window remains available for later links.
