<p align="center">
  <img src=".github/assets/header.svg" width="720" alt="HyperNetSuite. Native clients for HyperNet. Graphite wordmark and connected nodes on a silver engineering grid.">
</p>

<p align="center">Native graphical, terminal and command-line clients for HyperNet.</p>

<p align="center">
  <a href="https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/releases/tag/v0.10.0">Linux 0.10.0</a> |
  <a href="Documentation/Installation.md">Install</a> |
  <a href="Documentation/ReadMe.md">Documentation</a> |
  <a href="Documentation/Security.md">Security</a> |
  <a href="https://github.com/Federated-Industrial-Laboratories/HyperNet">HyperNet infrastructure</a>
</p>

HyperNetSuite is the desktop and terminal companion to HyperNet. Browse and
publish reviewed Pages, exchange encrypted mail and files, and use services your
network has approved. You can install it without running a HyperNet host, and
try local Page previews without a network or account.

The Linux browser opens Pages in a native window, lets you choose when to reveal
images, and shows a Form's contents before you send it. Separate Mail and
Transfers windows handle messages, file offers and resumable downloads. The
command line provides publishing and administration; terminal browsing and
plain output work without a graphical desktop.

> [!NOTE]
> **Linux 0.10.0** uses the native Ubuntu x86_64 release profile and its documented limits.
> Other Linux distributions need compatible runtime libraries and graphics
> support. AArch64, Windows and macOS remain unqualified; SELinux-enabled
> deployment is also unqualified. This release has no independent security
> certification. See the [release notes](Documentation/ReleaseNotes.md) and
> [supported platforms](Documentation/SupportedPlatforms.md).

Version 0.10.0 adds [application context and fresh authority checks](Documentation/ApplicationContext.md)
with bounded caller deadlines and explicit transport facts. Existing version 1
payload workflows remain compatible.

Version 0.9.1 fixes overlapping stream and sealed-page permission scopes.
Read [the migration guide](Documentation/PermissionScopes.md) before upgrading;
network-wide grants no longer authorise those effects.

## Features

| Capability | What you can do |
| --- | --- |
| Pages and browsing | Write Pages without scripts, review exact revisions and browse verified publications in native or terminal views. |
| Media and layout | Use panels, rows, scroll boxes and optional decorative motion; choose when to reveal approved images. |
| Search | Query a selected network or search an explicitly retained encrypted local catalogue. |
| Sealed Pages | Publish encrypted content for trusted recipient devices through the command line. |
| Private Mail and Forms | Exchange encrypted messages and review Form submissions before sending. |
| Transfers and services | Review file offers before accepting them and approve separately consented OpenSSH sessions. |
| Federation and archives | Share reviewed Pages between agreed networks and restore authorised encrypted content archives. |
| Application integration | Use the native companion and packaged Python SDK for consented application streams, typed context and fresh authority checks. |
| Administration | Inspect network authority, manage permissions and approve policy or recovery changes. |

Page content cannot run scripts, choose local credentials or submit a Form
automatically. Membership alone grants no hosting, review or confidential-content
access. Network operations require independently accepted trust, current verified
authority and the capability for that operation. Read the
[security boundaries](Documentation/Security.md) before connecting.

## Requirements

| Use | Requirements |
| --- | --- |
| Installed client | Native x86_64 GNU/Linux and the host libraries recorded by its package manifest. |
| Native applications | A graphical build, X11 or Wayland session, and usable EGL/GLX libraries and graphics driver. |
| Source build | Rust 1.95 or newer, Cargo, a C toolchain/linker and native graphical development dependencies. |
| Terminal viewer | An interactive terminal; text works without a terminal graphics protocol. |
| Signed package tools | Python 3.11 or newer and OpenSSH `ssh-keygen` with Ed25519 SSHSIG support. |
| Network access | Authenticated bootstrap, approved membership and grants, current clock health and accepted relay/service routes. |
| SSH service sessions | Separately consented service access and OpenSSH 10.6 or newer. |

Python is not needed to run the client binary. It is needed for package tools
and the optional example generator. The [installation guide](Documentation/Installation.md)
covers graphical dependencies, a terminal-only build and signed offline packages.

## Install

Download the [Linux 0.10.0 release](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/releases/tag/v0.10.0)
and follow [signed offline installation](Documentation/Installation.md#signed-offline-package).
Authenticate the publisher independently and follow the required update-trust
procedure before installing a package.

### Build from source

From an authenticated checkout with the build prerequisites installed:

```sh
bash Tools/Install.sh "$HOME/.local/opt/HyperNetSuite"
export PATH="$HOME/.local/opt/HyperNetSuite/Bin:$PATH"
HyperNetSuite --help
```

The installer builds the locked release and copies the executable, manuals and
examples into the chosen prefix. It needs no elevation and starts no services.
Keep private profiles, keys, vaults and downloads outside that prefix. Installed
manuals start at `Documentation/HyperNetSuite/ReadMe.md` within the prefix.

## Try a local Page

After the source installation above, open the supplied example:

```sh
HyperNetSuite pages preview "$HOME/.local/opt/HyperNetSuite/Examples/GraphicalPage.txt" --gui
```

Use `--tui` instead of `--gui` for the terminal viewer, or omit both for plain
output. The example needs no profile or media preparation. It shows panels,
Markdown formatting in the native viewer and local controls. Preview is visibly
unapproved; it cannot navigate a network or send Forms. Animation is off by
default in the native browser and can be enabled in Settings.

[Examples](Examples/ReadMe.md) also provides five fictional business Pages with
explicitly imported media. [Graphical browser](Documentation/GraphicalBrowser.md)
and [terminal controls](Documentation/TerminalLayout.md) explain the viewers.
[Native Mail](Documentation/NativeMail.md) and
[Native Transfers](Documentation/NativeTransfers.md) cover their separate windows.

## Connect to a network

Obtain and independently authenticate the network's bootstrap and route material.
Follow [network preparation](Documentation/Networks.md), then
[join and retain routes](Documentation/PrivateRoutes.md#prepare-and-join).
Preparation is offline and does not grant membership. Once joined, with current
routes retained, select that profile explicitly:

```sh
HyperNetSuite network connect --profile /Private/Client/Profile.json -- browse --gui --namespace News
```

Replace the path and namespace with your approved values. Omit `--gui` for terminal
browsing. Expired authority, missing routes or insufficient privacy cause refusal;
the client never silently selects a direct connection.

## Documentation

The [release notes](Documentation/ReleaseNotes.md) describe the 0.10.0 scope and
known limits. The [documentation index](Documentation/ReadMe.md) separates reader and author
guides, operator workflows and protocol references. Start with
[installation](Documentation/Installation.md), [client use](Documentation/Usage.md)
and the viewer of your choice.

For maintenance, use [upgrade and recovery](Documentation/UpgradeRecovery.md),
[local diagnostics](Documentation/Diagnostics.md) and
[content backups](Documentation/Backups.md). Developers can consult
[source layout](Documentation/SourceLayout.md),
[contracts](Documentation/Contracts.md) and
[dependency licences](Documentation/Dependencies.md).

Licensed under the [MIT License](Licence.txt).
