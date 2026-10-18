# Local diagnostics

[Documentation](ReadMe.md) | [Project README](../ReadMe.md)

`network diagnose` previews a bounded, redacted snapshot of one selected local
profile. It requires only the installed client. It does not connect, probe a
service, run an external program, start a monitor or upload anything.

```sh
HyperNetSuite network diagnose --profile Client/Profile.json
HyperNetSuite network diagnose --profile Client/Profile.json \
  --preview-digest SHA256_FROM_PREVIEW --output Private/Diagnostics.json
```

The first command returns `DiagnosticPreview`, `previewDigest` and `snapshot`.
Review that snapshot before exporting. The second command collects it again and
requires an exact digest match. It writes the snapshot alone as compact UTF-8
JSON followed by one newline. `previewDigest` is the lowercase SHA-256 of those
exact file bytes. Success returns `DiagnosticExported` and the digest; it does
not print the destination path.

The destination must be a new file under a private directory owned by the current
user. Publication is atomic and creates mode 0600. Existing files, symbolic links
and paths traversing symbolic links or `..` are refused. No export replaces or
appends to an existing report. Sharing the resulting file is a separate action.

## Selected information

The `HyperNetDiagnostics/1` snapshot has a fixed schema:

| Field | Meaning |
| --- | --- |
| `product`, `softwareVersion` | The running client product and version. |
| `scope` | Always `SelectedLocalProfile`. |
| `networkUsed`, `currentAuthority`, `operatorIndependenceVerified` | Always false. |
| `profile.state` | `Valid` means the bounded profile and pinned bootstrap passed local validation. Otherwise `UnavailableOrInvalid`. |
| `profile.clientState` | The retained local state: `Prepared`, `JoinPending`, `Joined` or `Unknown`. This is not a current membership check. |
| `profile.effectiveMinimumRoute` | The locally selected effective privacy minimum, or null when unknown. |
| `profile.acceptsHostReadable`, `acceptsSealed`, `permitsNetworkSearch` | Retained client choices. Null means unknown, not false. |
| `profile.bootstrapTimeValid` | Whether retained bootstrap deadlines passed at collection, or null when unavailable. This does not renew authority. |
| `routes.state` | `NotConfigured`, `RetainedInventory` or `UnavailableOrInvalid`. |
| `routes.count`, `countsByProtocol` | Validated inventory count and counts for protocols 1 through 6; null if unavailable. |
| `clock` | `NotConfigured`, `HealthyAtCollection` or `Unavailable`. |

The report contains no network, member, device, grant or service identifiers;
profile paths, route addresses, public or private keys; payloads, query terms,
logs, browsing history, timestamps or arbitrary error text. The software version,
local policy choices and route counts are still operational information; inspect
them before sharing.

Collection reads the selected private profile (at most 600000 bytes), its retained
route inventory when configured (65536 bytes, at most 128 entries), and its local
clock witness when configured (4096 bytes). Bootstrap validation is local. The
clock check also reads the current kernel boot identifier and local clocks. It
does not traverse directories, read service profiles or content stores, open
authority state for recovery, collect connection observations or parse logs.
Private profile buffers and key fields are erased on drop.

Inventory validity describes its local structure only. It does not establish
that endpoint profiles are present, reachable, currently authorised or unchanged.
`HealthyAtCollection` describes one local witness observation with the normal
clock bounds; it is not a reusable freshness receipt. No diagnostic field grants
permission, proves operator independence or certifies the physical network path.
Files are observed separately, so the snapshot is not an atomic authority view.

## Export refusals

`DiagnosticSnapshotChanged` means the selected redacted bytes changed since the
preview, including a change in local clock health or bootstrap validity. Preview
again and inspect the new report. Equivalent redacted snapshots have the same
digest even when excluded private information differs; the digest does not
authenticate hidden profile bytes or attest completeness.

`DiagnosticPreviewDigestInvalid` requires a 64-character lowercase hexadecimal
digest. `DiagnosticOutputUnavailable` covers unsafe, nonprivate, existing or
unwritable destinations without printing their paths or underlying errors.
`DiagnosticDisplayUnavailable` reports a local output failure. Unavailable input
is represented by fixed snapshot states, without echoing malformed file contents.
Check local ownership and permissions separately with an appropriately private
operator inspection. [Network inspection](Networks.md) and
[connection status](PrivateRoutes.md) intentionally expose more local detail;
their outputs are not this redacted export.

## Recover a refused connection

Keep the selected profile, requester floor and pending operation files intact.
Start with local inspection; a diagnostic snapshot cannot repair or renew authority.

| Symptom | Next step |
| --- | --- |
| Clock unavailable or stale | Check `network clock status --directory /Private/Clock` for the selected local monitor. Confirm that it is running, uses the intended chrony socket and publishes a current observation for this boot. Follow [local clock health](PrivateRoutes.md#local-clock-health). |
| Missing or changed route | Inspect `network status --profile /Private/Client/Profile.json`. Authenticate replacement route material independently and accept it through `network retain-route`; keep the existing requester floor. |
| Expired invitation, voucher, grant or consent | Obtain the corresponding authorised renewal from its issuer or host owner. Rejoining or deleting local state does not extend an expired permission. |
| Authority unavailable or no quorum | Ask the network operator to restore the required authority and service readiness. Retain any unresolved request and use that operation's exact retry or recovery procedure. |
| Unsafe local path or private-state refusal | Check the intended file's ownership, permissions and path without printing its contents. Preserve state before repairing it; do not replace it with a newly initialised floor. |

Clock observations expire quickly and must continue to be refreshed while the
client operates. A one-time observation is not a replacement for a running
monitor. Never change the clock, edit an expiry, reset a floor or weaken privacy
requirements to make a refusal disappear. A failed refresh can leave a previously
verified Page on screen; that retained display is not current permission.

If a send or mutation times out, its effect may already have occurred. Inspect the
retained outbox or request state before retrying. Do not issue a new identity for
the same intended operation merely because its acknowledgement was lost.
