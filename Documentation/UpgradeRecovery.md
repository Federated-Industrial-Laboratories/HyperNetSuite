# Upgrade and recovery

Software and private user data have separate lifecycles. Keep all profiles,
identity files, mail vaults, recovery files and downloads outside an installed
software prefix. Package removal never revokes network grants or deletes those
external files.

## Side-by-side upgrade

1. Record the currently selected binary path and verify its signed inventory.
2. Back up private data through a separately protected storage process.
3. Verify the new archive with an independently pinned publisher key.
4. Install it into a new private prefix and run its native qualification command.
5. Stop active client operations before selecting the new binary path.
6. Check the selected binary's version and use an existing profile for the intended
   network operation.
7. Retain the previous verified software until the new operation is confirmed.

Version 0.7.0 preserves the 0.6.0 profile, identity and encrypted-vault formats.
Package installation does not migrate them. An older client can be selected again
only while its data and protocol contracts remain compatible. Restoring an older
binary does not undo messages, reviews, transfers or grants already committed to
authorities. Do not roll back monotonic protocol state or reuse old credentials
merely to make a previous binary accept them.

Changes to publisher keys require an independently authenticated new pin. A
signature by an unrecognised key must not be accepted as an automatic rotation.
Package signatures authenticate bytes and publisher identity; they do not prove
that an older version is safe. Select versions through the network's maintenance
policy and retain the expected version outside the package.

## Integrity failure and reinstall

If verification fails, stop using that prefix. Keep private user data protected.
Use a trusted verifier and the independently pinned key to install an authenticated
archive into another new prefix. Do not execute tools from the suspect prefix to
repair it. Compare the expected inventory before deciding whether any unexpected
file is disposable. There is no force-remove option that silently discards it.

A package retains its signed archive under `Package/`. The retained copy supports
integrity checking; it is not an independent backup of user data. A replacement
archive must pass the same signature and inventory checks as an initial install.

## Removal

From an independently trusted copy of the verifier:

```sh
python3 Tools/Bundle.py Remove --prefix /Chosen/HyperNetSuite070 \
  --public-key Publisher.pub
```

Removal reauthenticates the retained archive, verifies the complete installed
inventory and refuses changed, missing, linked or unexpected entries. It removes
only that verified software prefix. Keep the account otherwise idle during
verification and removal. External private data and other installed versions
remain untouched. Revoke device memberships through the authority when retiring
an identity; deleting a client installation does not perform revocation.
