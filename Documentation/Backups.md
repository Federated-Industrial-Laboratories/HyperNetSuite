# Named content backups

Cold backups preserve an exact approved Page and its associated canonical bitmap
or vector assets. A sealed Page backup contains its original ciphertext, including
its encrypted assets. The complete cold package receives a separate age X25519
encryption layer. Backup decryption keys stay with the selected recovery owners;
the storage destination does not need them.

Mail queues, transfer queues, authority journals, recipient vaults, daemon state
and search indexes are not part of this content archive. Replication does not
create a backup. An archive does not replace offline identity or network recovery
material.

## Prepare a destination

An installed service volume must have explicitly consented storage capacity above
its service state allocation. Native backup commands use only that surplus. They
bind the current installed host, volume and prepared filesystem, and retain a
private destination device/inode binding. An arbitrary directory cannot stand in
for an installed volume. Existing profiles with no surplus require a new explicit
storage provision with spare capacity.

Create an offline encryption identity in the Suite:

```text
HyperNetSuite authority-inspection backup key-generate --output BackupIdentity.txt
```

Retain the returned recipient identifier, and store the identity separately from
the cold destination. The destination specification is a JSON object:

```json
{
  "id": "<32-byte destination ID in hexadecimal>",
  "name": "BooksColdStorage",
  "host": "<installed host ID>",
  "volume": "<installed volume ID>",
  "bytes": 67108864,
  "objects": 128,
  "retentionMs": 2592000000,
  "recipients": ["<archive recipient identifier>"],
  "owners": ["<permitted content owner's Ed25519 key>"],
  "opaque": false
}
```

The storage operator uses the Core executable to initialise and sign the exact
consent. The output is public signed metadata; the private destination remains
inside the installed volume's `Backups` directory.

```text
HyperNet backup destination initialise --runtime-directory <installed-service> --spec BackupDestination.json --operator-key <operator-key> --output BackupDestination.cbor
```

Register this consent through the ordinary authority request path:

```text
HyperNetSuite authority-inspection backup register <online-options> --grant <hosting-grant> --profile BackupDestination.cbor
HyperNetSuite authority-inspection backup destination <online-options> --destination <destination-id>
```

`<online-options>` means the existing independently accepted bootstrap, requester
directory, signing key, authority socket and clock options. Registration requires
a current hosting capability covering the destination ID. The operator signature
and the registering manager's capability are checked separately. A destination's
identity and consent are immutable; withdrawal permanently ends new placement.

For sealed Pages, set `opaque` to true, retain the reviewer's consent in the
installed manifest, and include the destination ID in both the author's object
policy and the approved outer publication's `placement.backups`. Network or
administrator defaults cannot widen either list.

## Create and store

Bind explicit source and media routes with `pages content route`. The same route
registry accepts exact content and media host IDs. The current owner then creates
an archive using a `placement` reference formatted as `ID:generation:digest`:

```text
HyperNetSuite authority-inspection backup create <online-options> --grant <owner-grant> --placement <exact-placement> --destination <destination-id> --retention-ms 2592000000 --output BookArchive.cbor
```

The command checks current publication and destination consent, fetches the source
and every associated canonical asset, encrypts them for the exact destination
recipients, and commits the owner-signed archive manifest. The output is retained
before commitment so an interrupted command can resume with the same arguments.
Ordinary source fetching requires its current read permission; archive placement
and restore require the owner's current submit permission. Sealed publishers may
read and repair only their exact currently published ciphertext with submit
permission. This does not grant a plaintext key, recipient membership or approval
for changed content.

Import the encrypted package at its named destination using the Core command.
Copying a package to an inbox is not an acknowledged cold copy.

```text
HyperNet backup destination import --runtime-directory <installed-service> --host <host-id> --volume <volume-id> --destination <destination-id> --input BookArchive.cbor
HyperNet backup destination list --runtime-directory <installed-service> --host <host-id> --volume <volume-id> --destination <destination-id>
```

Import verifies owner consent, exact ciphertext digest, expiry and physical quota
before acknowledging durable storage. Metadata, retained packages and interrupted
imports are charged. Aggregate destination quotas cannot exceed the consented
volume surplus. A repeated exact import is idempotent. An archive identifier cannot
be replaced with different bytes.

The Suite's `backup get` and `backup list` inspect committed archive metadata;
the Core's `destination list` reports actual local custody. These are distinct
facts. `list` and `destinations` accept `--after` continuation identifiers.

## Restore and expire

Export from cold storage without decrypting it:

```text
HyperNet backup destination export --runtime-directory <installed-service> --host <host-id> --volume <volume-id> --destination <destination-id> --archive <archive-id> --output BookArchive.cbor
HyperNetSuite authority-inspection backup restore <online-options> --grant <owner-grant> --package BookArchive.cbor --identity BackupIdentity.txt --staging-directory <private-persistent-directory>
```

Restore first checks the exact committed archive against fresh authority, current
publication, source and asset placement, owner capabilities, destination consent
and withdrawal state. Decrypted bytes enter private, explicitly non-serving
staging. Source and media repairs then obtain fresh authority for each chunk.
Restoring an old package cannot resurrect a withdrawn Page, an old recipient
roster, a removed permission, a different host or a searchable stale catalogue.
A network or policy failure leaves staging non-serving. Repeating the exact
command resumes interrupted source and media jobs. When a previous repair is
complete, another restore starts fresh authorised host exchanges, including when
the same staging directory is reused. A retained copy receipt does not establish
that the host still has its bytes after another storage loss. A pending policy
discovery is reconciled on restart before the original backup workflow resumes;
an unrelated pending ordinary request is never replaced.

No search index is imported. Use the normal authorised local search workflow to
build a new index after successful reconciliation.

Withdraw an archive through `backup withdraw --archive ID:generation:digest`, or
a destination through `backup withdraw-destination --destination
ID:generation:digest`. Withdrawal ends restore or new placement; it does not
claim to erase an offline physical copy. The destination enforces the archive's
fixed retention and permits explicit early local deletion:

```text
HyperNet backup destination purge --runtime-directory <installed-service> --host <host-id> --volume <volume-id> --destination <destination-id>
HyperNet backup destination purge --runtime-directory <installed-service> --host <host-id> --volume <volume-id> --destination <destination-id> --archive <archive-id>
```

Every import, export and listing also applies expired-archive removal. Schedule
the native purge command when storage remains online without other activity.
Powered-off media cannot be erased until it is available. Cleanup remains
available after deployment expiry or withdrawal. Copies retained by an authorised
owner cannot be remotely revoked.
