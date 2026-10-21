# Upgrade and recovery

[Documentation](ReadMe.md) | [Project README](../ReadMe.md)

Software and private user data have separate lifecycles. Keep all profiles,
identity files, mail vaults, recovery files and downloads outside an installed
software prefix. Package removal never revokes network grants or deletes those
external files.

## Side-by-side upgrade

1. Record the currently selected binary path and verify its signed inventory.
2. Back up private data through a separately protected storage process.
3. Verify the new archive with an independently pinned publisher key and obtain
   its signed, unexpired update policy.
4. Install it into a new private prefix and run its native qualification command.
5. Stop active client operations before selecting the new binary path.
6. Check the selected binary's version and use an existing profile for the intended
   network operation.
7. Retain the previous verified software until the new operation is confirmed.

The current release supports one contract. Retired page, consent and authority
state formats are rejected. Create a fresh isolated installation when replacing
an incompatible contract; no automatic migration is provided.
Package installation does not migrate private data or undo committed messages,
reviews, transfers or grants. Restore only a verified current-contract executable
when recovering a damaged installation. Do not roll back monotonic protocol state
or reuse obsolete consent merely to make an earlier executable accept it.

An update does not automatically select or activate a binary. A software rollback
is not a way to reverse network permissions or restore old protocol state.

## Offline update trust

Use an independently authenticated copy of both `Tools/Bundle.py` and its adjacent
`Tools/PackageTrust.py`. The finite offline update profile uses OpenSSH signatures;
it is not TUF and has no download service or automatic key discovery. Archive
signatures and update signatures use separate namespaces. The locally accepted
root is separate from the signed target; this profile uses its one pinned
Ed25519 key for both signatures, without delegated online signing roles.

Initialise one private persistent trust directory for this product and native
architecture. Keep it outside all installation prefixes and user-data profiles.
Authenticate the complete root pin and root generation independently. `KeyPin`
only computes a pin; possession of a downloaded key does not authenticate it.
The pin is lowercase SHA256 of the canonical `ssh-ed25519 BASE64` line, including
its final newline. It is not OpenSSH's displayed base64 fingerprint.

```sh
python3 Tools/Bundle.py KeyPin --public-key /Trust/Publisher.pub
python3 Tools/Bundle.py TrustInit --trust-directory /Private/SuitePackageTrust \
  --public-key /Trust/Publisher.pub --root-pin <independently-authenticated-sha256> \
  --root-generation 1 --version-floor 0.8.0 --state-contract HyperNet080Client1
```

The state contract is fixed by this product; an arbitrary operator-supplied label
cannot mark incompatible state as compatible. Core uses a different contract and
trust directory. The Linux release is version 0.8.0. Signed update sequences identify exact
builds and cannot move backwards. Earlier development packages do not become
release packages when a version label changes. Use independently accepted release
trust and the signed target for the new package; retain existing state and floors.

After creating a signed archive, the publisher authorises its exact target:

```sh
python3 Tools/Bundle.py Authorise --archive HyperNetSuite.tar \
  --signature HyperNetSuite.tar.sig --public-key /Trust/Publisher.pub \
  --signing-key /Offline/Publisher --output Target.json \
  --root-generation 1 --sequence <next-sequence> --version-floor 0.8.0 \
  --state-contract HyperNet080Client1 \
  --not-before <unix-seconds> --expires <unix-seconds>
```

Authorise first verifies the archive and its complete inventory. Its detached
`Target.json.sig` signature uses `HyperNetSuiteUpdate1`. The canonical policy
binds product, native architecture, version and minimum version, state contract,
root generation and pin, sequence, validity interval, archive size and SHA256,
and the exact manifest SHA256. The signing key must match the supplied public key.
Policy and signature files are bounded. Install verifies their signature before
parsing the policy. It has no fallback when the policy or retained trust is absent.

```sh
python3 Tools/Bundle.py Install --archive HyperNetSuite.tar \
  --signature HyperNetSuite.tar.sig --public-key /Trust/Publisher.pub \
  --trust-directory /Private/SuitePackageTrust \
  --policy Target.json --policy-signature Target.json.sig \
  --prefix /Private/HyperNetSuiteNext
python3 Tools/Bundle.py TrustInspect --trust-directory /Private/SuitePackageTrust
```

Install holds the exclusive trust lock while checking and publishing the package.
The target must meet the retained version floor, current root and exact state
contract. A larger sequence advances the floor; an equal sequence is allowed only
for the identical complete target policy and archive. Changing an expiry or root
generation requires a new sequence. The retained minimum version also advances to
the installed target's version. The sequence, target digest and time/version
floors are synchronised to disk before the new prefix is published. Expiry is
checked again immediately before publication. Existing prefixes are never replaced.

The local wall clock must be correct. A clock earlier than the retained observation
refuses installation. This does not provide authenticated time or prove that a
publisher has not withheld a newer target. Expiry bounds acceptance of old target
metadata; offline operation cannot discover the latest available release.

## Root rotation and interrupted installation

Obtain the new root pin and generation through an independent authenticated
channel. Inspect the current trust digest, then perform an explicit comparison:

```sh
python3 Tools/Bundle.py TrustInspect --trust-directory /Private/SuitePackageTrust
python3 Tools/Bundle.py TrustRotate --trust-directory /Private/SuitePackageTrust \
  --expected-trust-digest <inspected-trust-digest> \
  --public-key /Trust/NewPublisher.pub --root-pin <independently-authenticated-new-pin> \
  --root-generation <current-generation-plus-one>
```

Rotation refuses a changed trust snapshot or unchanged key. It advances exactly
one root generation and preserves sequence, target and version floors. The next
install needs a newly signed target with a larger sequence under the new root.
A package cannot rotate its own root, and an old-key signature cannot adopt a new
key. Keep old public keys only for verifying retained historical installations.

An interruption after the floor is committed leaves that floor in force. Retry
the exact same still-valid policy and archive into the same unused prefix or a
different new prefix. If the prefix was already published, verify that installation
instead of overwriting it. If the policy has expired, obtain a fresh target at a
larger sequence. Never delete or restore older trust state to make a retry pass.
An interrupted staged directory may remain; remove only that known incomplete
scratch directory after confirming no package operation is active.

Back up the complete trust directory independently and retain its latest digest,
sequence, target and root generation. Owner-only files, locking and atomic writes
cannot detect rollback of the entire disk together with its floors. Corrupt or
missing trust state refuses installation; recovery requires independently retained
current state. Old installations and external application state remain untouched.

## Integrity failure and reinstall

If verification fails, stop using that prefix. Keep private user data protected.
Use a trusted verifier and the independently pinned key to install an authenticated
archive into another new prefix. Do not execute tools from the suspect prefix to
repair it. Compare the expected inventory before deciding whether any unexpected
file is disposable. There is no force-remove option that silently discards it.

A package retains its signed archive under `Package/`. The retained copy supports
integrity checking; it is not an independent backup of user data. A replacement
archive must pass the same signature, inventory and current update policy checks
as an initial install. `Verify`, `VerifyInstalled` and `Remove` check historical
integrity only; they do not assert update freshness or lower the retained floor.

## Service metadata

After a service update, domain operations reconcile obsolete deployment metadata
with the retained certified successor. The successor must match the current quorum
floor and its signed manifest and consent. Missing or altered evidence refuses
resumption. Existing transfer progress and requester journals remain intact.

## Removal

From an independently trusted copy of the verifier:

```sh
python3 Tools/Bundle.py Remove --prefix /Chosen/HyperNetSuiteCurrent \
  --public-key Publisher.pub
```

Removal reauthenticates the retained archive, verifies the complete installed
inventory and refuses changed, missing, linked or unexpected entries. It removes
only that verified software prefix. Keep the account otherwise idle during
verification and removal. External private data and other installed versions
remain untouched. Revoke device memberships through the authority when retiring
an identity; deleting a client installation does not perform revocation.
