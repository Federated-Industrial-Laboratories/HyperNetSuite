# Command-line use

Build with Rust and Cargo. No HyperNet source checkout is required:

```sh
cargo build --locked --release
bash Tools/Check.sh
bash Tools/Install.sh /Chosen/Prefix
```

The installer writes `Bin/HyperNetSuite` and its documentation. It does not
create a service or change shell profiles. Remove those installed files to
uninstall. Preserve device keys until their memberships have been revoked.
Linux is the current supported client platform. Run
`python3 Tests/ReaderTerminal.py /Chosen/Prefix/Bin/HyperNetSuite` to check
the installed terminal workflow and `python3 Tests/MarkupRobustness.py
/Chosen/Prefix/Bin/HyperNetSuite` for the bounded parser mutation check.

Create a private directory and generate a device identity:

```sh
mkdir -m 700 Device
HyperNetSuite keygen --output Device/Identity.json
```

The command prints the public key. Send that public key to the administrator
through an authenticated channel. The private key stays in its file. Key and
invitation files require owner-only permissions; symbolic links are refused.
Back up keys only through a separately protected storage process. Anyone with
a device secret can exercise that device's current grants.

Obtain the network identity, HTTPS endpoint and CA certificate from the
administrator. Verify the network identity and certificate fingerprint through
an independent authenticated channel before configuring them:

```sh
openssl x509 -in NetworkCa.pem -noout -fingerprint -sha256
HyperNetSuite configure --network NETWORK_HEX --endpoint https://authority.example:8443 \
  --ca NetworkCa.pem --identity Device/Identity.json --output Device/Profile.json
```

Only the supplied trust root is accepted. TLS 1.3, hostname verification and
request signatures are mandatory. Redirects and environment proxy settings are
not used. A hosting profile also supplies `--client-certificate` and
`--client-key`, issued through the network's separate transport certificate
procedure. The authority never needs the offline CA private key.

An administrator issues an invitation for the joining device's public key:

```sh
HyperNetSuite --config Administrator/Profile.json invite --device-key DEVICE_HEX \
  --grants 3 --expires UNIX_SECONDS --output Invitation.json
```

Grant masks are 1 for membership, 3 for membership and hosting, 5 for membership
and administration, and 7 for all three. Grant 9 selects membership and the
separate federation bridge service. It cannot combine with hosting or
administration. See [Federation](Federation.md) for that workflow.
Administrators cannot register hosting consent. Use a
separate member-and-host credential for a service. A credential with retained
hosting consent cannot be promoted to administrator. Invitation expiry is an absolute Unix
time, within seven days. Membership initially shares this expiry. Transfer the
invitation file through an authenticated confidential channel. Its secret is
never printed or placed in an argument or URL.

The file is saved before issuance. If the command times out, repeat it with the
same arguments and output file. This retries the same invitation rather than
issuing a replacement. File creation alone does not confirm issuance.

The joining device redeems it and checks current membership:

```sh
HyperNetSuite --config Device/Profile.json redeem --invitation Invitation.json
HyperNetSuite --config Device/Profile.json status
```

Redemption retries by the same key are safe. A different device cannot use the
invitation. Delete the transferred invitation file after successful admission.
Revocation permanently disables the admitted key; subsequent joining requires a
new device identity. Current commands support these administrator operations:

```sh
HyperNetSuite --config Administrator/Profile.json status --device-key DEVICE_HEX
HyperNetSuite --config Administrator/Profile.json grant --device-key DEVICE_HEX --grants 1 --expires UNIX_SECONDS
HyperNetSuite --config Administrator/Profile.json revoke --device-key DEVICE_HEX
```

`grant` replaces a current grant. It cannot restore a revoked key. Removing the
last active administrator is refused. Every online operation requires current
quorum authority; loss of quorum produces a failure instead of a local decision.
There is no automatic key escrow or lost-key recovery. Retain an independently
secured administrator identity before relying on a network.

## Hosting consent

A host owner signs explicit resource limits. The specification has these fields:

```json
{
  "grants": 2,
  "expires": 1800000000,
  "memoryBytes": 268435456,
  "pids": 64,
  "cpuQuota": 100000,
  "cpuPeriod": 100000,
  "stateBytes": 16777216,
  "authorityEndpoint": "https://authority.example:8443",
  "authorityAddress": "192.0.2.10:8443"
}
```

Replace the example address and expiry. Expiry must be within seven days and
must not exceed membership expiry when consent is registered. The address pins
the remote destination, while the endpoint supplies the TLS server name.

```sh
HyperNetSuite --config Device/Profile.json host-consent --spec Specification.json --output Consent.json
```

This signs the exact local specification and reports its SHA-256 profile digest.
It does not start hosting. Version 1 also consents to a separate relay allowance: 128 MiB memory, half a CPU, 32 processes, 8 MiB temporary storage and an aggregate 1 MiB/s byte rate. The command reports the combined memory allowance. Register that digest and the SHA-256 fingerprint of
the host's DER client certificate with the authority:

```sh
openssl x509 -in HostCertificate.pem -outform DER | openssl dgst -sha256
HyperNetSuite --config Device/Profile.json consent --profile PROFILE_HEX \
  --grants 2 --expires UNIX_SECONDS --certificate CERTIFICATE_HEX
HyperNetSuite --config Device/Profile.json heartbeat --profile PROFILE_HEX
```

Install and start the independently packaged HyperNet host with this exact
consent document. Follow HyperNet's hosting instructions for its separate
container controls. Neither network grants nor a new remote consent record
can widen the already signed local resource specification.

For emergency withdrawal, stop the local host first. This is immediate and does
not require a reachable authority. Then record withdrawal when reachable:

```sh
HyperNetSuite --config Device/Profile.json withdraw
```

A successful heartbeat reports a short lease, not permission for future work
without revalidation. Stale, expired, revoked or unavailable authority is denied.
Administrative commands return JSON on success and a nonzero exit status on failure. The client
escapes terminal control characters in displayed JSON, errors and file paths.
See [Pages](Pages.md) for author, moderator, reader and version 2 hosting workflows.
Mail, transfers and shell services are not yet provided.

## Private mail

`HyperNetSuite --config Profile.json mail --help` lists address, device, delivery,
placement and archive commands. Follow [PrivateMail](PrivateMail.md) for invited
member setup, explicit first-contact verification and recovery.
