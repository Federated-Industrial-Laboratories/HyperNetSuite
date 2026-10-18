<h1 align="center">HyperNetSuite</h1>
<p align="center">Native graphical, terminal and command-line clients for HyperNet.</p>
<p align="center"><a href="Documentation/ReadMe.md">Documentation</a> | <a href="Documentation/Installation.md">Installation</a> | <a href="Documentation/Security.md">Security</a> | <a href="https://github.com/Federated-Industrial-Laboratories/HyperNet">HyperNet infrastructure</a></p>

Read and publish reviewed Pages, exchange encrypted Mail and files, and use
explicitly approved services on a selected HyperNet network. HyperNetSuite is
independently installed from HyperNet infrastructure. Local Page preview works
without a network, account or hosting service.

The native Linux browser supports Page navigation, explicit media reveal and
reviewed Forms. Mail, transfers and administration use the command line.
Terminal browsing and plain output remain available without a graphical desktop.

**In development.** The current package version is 0.7.5, with the evolving
0.8.0 network contracts documented separately. This is not a qualified production
Internet deployment. Native x86_64 GNU/Linux is the current platform;
AArch64, Windows and macOS remain unqualified. See
[supported platforms](Documentation/SupportedPlatforms.md).

## Features

| Capability | What you can do |
| --- | --- |
| Pages and browsing | Author inert HyperPages, review exact revisions and navigate verified publications in native or terminal views. |
| Media and layout | Use panels, rows, scroll boxes and bounded local motion; reveal approved images explicitly. |
| Search | Query a selected network or search an explicitly retained encrypted local catalogue. |
| Sealed Pages | Publish encrypted content for independently accepted recipient devices through the CLI. |
| Private Mail and Forms | Exchange encrypted messages and review typed submissions before sending. |
| Transfers and services | Accept exact file offers and approve separately consented OpenSSH sessions. |
| Federation and archives | Share reviewed Pages between agreed networks and restore consented encrypted content archives. |
| Administration | Inspect authority, manage scoped grants and accept explicit policy or recovery changes. |

Page content cannot run scripts, choose local credentials or submit a Form
automatically. Membership alone grants no hosting, review or confidential-content
access. Network operations require independently accepted trust, current verified
authority and the capability for that operation. Read the
[security boundaries](Documentation/Security.md) before connecting.

## Requirements

| Use | Requirements |
| --- | --- |
| Installed client | Native x86_64 GNU/Linux and the host libraries recorded by its package manifest. |
| Native browser | A graphical build, X11 or Wayland session, and usable EGL/GLX libraries and graphics driver. |
| Source build | Rust 1.95 or newer, Cargo, a C toolchain/linker and native graphical development dependencies. |
| Terminal viewer | An interactive terminal; text works without a terminal graphics protocol. |
| Signed package tools | Python 3.11 or newer and OpenSSH `ssh-keygen` with Ed25519 SSHSIG support. |
| Network access | Authenticated bootstrap, approved membership and grants, current clock health and accepted relay/service routes. |
| SSH service sessions | Separately consented service access and OpenSSH 10.6 or newer. |

Python is not needed to run the client binary. It is needed for package tools
and the optional example generator. The [installation guide](Documentation/Installation.md)
covers graphical dependencies, a terminal-only build and signed offline packages.

## Install from source

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

For an independently authenticated signed package, follow
[offline installation](Documentation/Installation.md#signed-offline-package)
and its required update-trust procedure. No public release download is assumed.

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

The [documentation index](Documentation/ReadMe.md) separates reader and author
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
