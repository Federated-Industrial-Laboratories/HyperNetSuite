# Private mail

Private mail requires a current HyperNet membership, a pinned mail authority
signing key and at least one consented MailStore. MailStore is a separate,
confined HyperNet service. The authority stores public address, device and prekey
metadata; it does not receive letter plaintext, ciphertext or mailbox contents.
The Suite sends encrypted letters directly to the exact stores selected in the
address owner's signed manifest. An administrator cannot widen this placement.

The examples below abbreviate the common command prefix as `Mail`:

```sh
HyperNetSuite --config Profile.json mail --vault MailVault --key MailIdentity
```

`Profile.json` is an existing admitted member profile. Create its identity and
join through the ordinary invite commands described in Usage.md. The member's
registration link stays in the authority's private state; each address has a
separate public owner key, request key and MLS signing key. Reusing a membership
profile does not publish that link. Addresses, selected store addresses, device
rosters, message sizes and timing remain visible to the authority or selected
stores. This is not an anonymity network.

## Create and verify addresses

```sh
Mail init --authority-key AUTHORITY_PUBLIC_KEY
Mail hosts
Mail address-create --mailbox Personal --host HOST_PUBLIC_KEY --copies 1 \
  --expires UNIX_SECONDS --retention 86400
Mail address-show --mailbox Personal
Mail refill --mailbox Personal --count 8
Mail contact-verify --address CONTACT_ADDRESS --owner-fingerprint OWNER_PUBLIC_KEY
```

Replace `Mail` with the prefix above. The first command creates a mode 0700
vault directory and a separate mode 0600 native age identity. It reports the age
public recipient needed for encrypted exports. Keep the identity private; the
same operating-system account can read this key and decrypt its vault.

Exchange the full owner fingerprint through an independently trusted channel.
The address is derived from that owner key and the network identifier. A fetched
key is not automatically considered verified. Both sender and recipient verify
their contact before sending or first reading, respectively. A changed owner
requires a different address and a new explicit verification. Saved manifest
versions reject rollbacks or conflicting versions for that contact.

Use another mailbox label to create another independent address. Names are local
labels, not network aliases. Creation saves all private keys before registering
with the authority. If the response is lost, `address-register --mailbox Personal`
retries that exact registration and verifies its resulting manifest.

Address and device consent lasts at most seven days. Renew the address before
its devices: `address-renew --mailbox Personal --expires UNIX_SECONDS`, then
`device-renew --mailbox Personal --device-id DEVICE_ID --expires UNIX_SECONDS`.
Renewal changes the manifest generation and needs fresh public prekeys on every
receiving device. An owner can renew an expired address while its registering
member remains admitted. A deleted address cannot be reactivated.

## Send, retry and receive

Create subject and body files owned by the current user with no group or other
permissions. Subjects are limited to 512 UTF-8 bytes; bodies to 32768 bytes.

```sh
Mail send --mailbox Personal --to CONTACT_ADDRESS \
  --subject-file Subject.txt --body Letter.txt
Mail outbox
Mail retry --message-id MESSAGE_ID
Mail inbox --mailbox Personal
Mail read --mailbox Personal --host HOST_PUBLIC_KEY --message-id MESSAGE_ID
Mail read --mailbox Personal --local --message-id MESSAGE_ID
```

The draft and claim ID are encrypted and synced before requesting one-use
KeyPackages. The exact encrypted envelope is synced before the first upload.
Retries use those same bytes. `Queued`, `Partial` and `Stored` report placement
progress; `durable` is true only after the manifest's required number of signed
store receipts. `Stored` means all selected stores accepted the letter; it does
not mean the recipient read it. Inspect this structured result even when the
command succeeds. Preparation failures retain a queued draft with an error.

A letter includes every current Read device. An offline device with published
prekeys still receives it. Missing prekeys block the whole letter; devices are
never silently omitted. The receiver must periodically run `refill`. Each call
publishes at most eight packages. Thirty-two public packages per device are
allowed. After owner roster or placement changes, each retained receiving device
must refresh and refill for the new manifest generation. Old private packages
remain available for letters already admitted under the old generation.

Retry first asks each unresolved selected store for its signed receipt, using the
exact retained message ID, ciphertext digest and route. A matching receipt confirms
an earlier accepted letter even after sender or recipient renewal. Current sender
permission and recipient placement remain required. If a receipt query fails, that
host stays unresolved and no upload is attempted there. A confirmed absent receipt
permits a new upload only while both signed manifests still match the retained
ciphertext and its lifetime remains valid. Otherwise retry reports the failed host
explicitly; retain its receipt information and send a new letter only by an explicit
new action. Do not assume a timeout means no store accepted it. There is no atomic
transaction across stores and no silent replacement of an accepted envelope. `cancel --message-id MESSAGE_ID` removes only the local outbox
copy; it cannot recall previously stored letters.

A combined Read+Send device cannot send to its own address: MLS forbids duplicate
signature keys in a group. Use another address or a separate Send-only device
for this case. Different addresses in one vault work normally.

Read verifies the original sender operation, the authority's signed admission at
its recorded time, the store receipt and the complete owner-signed MLS leaf set.
The current roster does not retroactively authenticate an old letter. The
archive and destruction of the used private prekey are committed in one encrypted
snapshot before acknowledgement or output. Repeated reads do not consume a second
prekey. Output escapes terminal controls in subjects, bodies and server errors.

## Placement and scoped devices

```sh
Mail placement --mailbox Personal --host FIRST_HOST --host SECOND_HOST --copies 2
Mail device-create --mailbox Reader --address ADDRESS --expires UNIX_SECONDS \
  --permission Read --output ReaderBinding.json
Mail device-enrol --mailbox Personal --binding ReaderBinding.json
Mail device-revoke --mailbox Personal --device-id DEVICE_ID
```

Run `device-create` in the application's own vault and give the owner only its
public binding file. The owner reviews and signs that binding. Available scopes
are `Read`, `Send` and `Delete`; repeat `--permission` for multiple scopes. The
child gets no general membership, host or administrator rights. Use
`contact-verify --mailbox Reader` and `hosts --mailbox Reader` to select its
scoped identity for public directory access; no general member key is needed.
`device-export --mailbox Reader --output ReaderBinding.json` re-exports a saved
public binding if its original file was lost or could not be written. Keep application
vaults and age identities separate; sharing the owner's vault grants access to
all keys in that vault, regardless of the public child's advertised scope.

Placement names every allowed store; there is no fallback to administrator-selected
storage. Removing a store prevents future access through this manifest and asks
stores to remove no-longer-authorised data through policy synchronisation. Existing remote letters are not migrated automatically; read and export
needed history before changing placement. A malicious store can retain
ciphertext it already held. Revoking a device prevents
fresh operations and excludes it from future letters; it cannot erase that
device's existing plaintext or keys. New devices obtain future mail after refill;
historical mail requires explicit archive transfer.

`delete --mailbox Personal --host HOST --message-id ID --digest DIGEST` deletes a
remote letter through a Delete-scoped device and returns a signed receipt. Obtain
the digest from `inbox`. Delete each selected copy separately. Use
`archive-delete --mailbox Personal --message-id ID` to remove local retained
history. `address-delete --mailbox Personal` signs an address tombstone. Neither
operation promises erasure of previously copied plaintext or external backups.

## History and recovery

```sh
Mail archive-export --mailbox Personal --recipient AGE_PUBLIC_RECIPIENT \
  --output History.age
Mail archive-import --input History.age --expected-address ADDRESS
Mail archive-list --address ADDRESS
Mail archive-read --address ADDRESS --message-id MESSAGE_ID
```

Import into the vault whose age identity matches the explicit export recipient.
It is usable without an active mailbox. History is authenticated as the exporting
owner's or authorised device's retained copy and labelled `ImportedArchive`; it
is not reinterpreted as a newly received message. The export contains no active
MLS signer, request key, unspent prekey or outbox retry state. Import does not
restore any of those keys or change contact verification. A letter removed from
the active vault remains in any previously exported archive.

An owner may explicitly add `--include-owner-recovery` during export. Keep this
archive offline with its separate recipient identity. Then use:

```sh
Mail owner-recover --mailbox Recovered --input Recovery.age --expected-address ADDRESS
```

This restores the address owner, creates fresh request and MLS signing keys, and
registers a new device with the current authority. It requires a still-admitted
registering member. If the eight-device roster is full or the address expired,
it saves the recovered owner and fresh device locally, reports
`freshDeviceEnrolled:false`, and leaves activation pending. Renew the address or
revoke an old device, then use `device-export` and owner `device-enrol` to activate
the saved fresh binding. It does not restore old
prekeys, old active groups, contact verification or history; import history
separately. If the registration response is lost, `address-show` reconciles it
using the saved owner identity. Revoke lost devices with the recovered owner.

The encrypted vault holds active keys, drafts and retained plaintext history.
Keep the current vault and age identity safe, but do not copy an old vault back
into active service: that rolls back consumed-prekey and deduplication state.
Use history export and explicit owner recovery instead. No software check can
detect replacement of every local key, snapshot and rollback floor by someone
with full access to the account.

## Cryptographic profile and limits

Each letter uses a fresh RFC 9420 MLS group with
X25519/AES-128-GCM/SHA-256/Ed25519 and OpenMLS 0.9.1. The sender authenticates every
KeyPackage against the owner's device roster, exact credential, lifetime and
canonical MLS reference. No draft MLS extension, custom cipher or executable
mail body is enabled. Local snapshots and exports use the standard age X25519
recipient format through age 0.11.5, without plugins, SSH recipients or armor.

Deleting a consumed prekey and the temporary group removes those active secrets
from the live vault. Old snapshots, filesystem copies and device compromise can
preserve them. Retained history is deliberately decryptable with the archive key
and has no forward secrecy against that key's compromise. This per-letter profile
does not claim continuous conversation post-compromise recovery. It also does not
provide recipient anonymity, post-quantum protection or denial-of-service immunity.

TLS 1.3 validates the configured CA and service name, then checks the exact
consented leaf-certificate digest before HTTP upload. Proxy settings and redirects
are disabled and connection addresses are fixed by host consent. Host, device,
manifest and mailbox limits are enforced independently by HyperNet. The local
vault is limited to 32 MiB, 64 local mailboxes, 128 outbox entries and 1024 retained
history entries. Export/delete history and cancel unneeded drafts before reaching
these limits.

## MailStore consent

Host commands use the dedicated host's existing admitted profile and do not need
a vault. `mail host-consent --spec Host.json --output Consent.json` signs the
MailHostConsent documented by HyperNet; `mail host-register --consent Consent.json`
registers it. The host's admission grants must be MEMBER|HOST (3), with no page,
bridge or administrator role. Consent fixes resource limits, persistent-state
quota, TLS certificate digest, exact CA PEM digest, listener and authority
addresses, authority signer and expiry. Use HyperNet's MailStore launcher for
process confinement and separate persistent storage. `mail host-withdraw
--expected-generation N` withdraws that host consent.

The consented `memoryBytes`, `pids`, `cpuQuota` and `cpuPeriod` limit the MailStore
worker. The separate Gate additionally consumes up to 128 MiB of memory, 32 PIDs,
0.5 CPU (50000/100000) and 8 MiB of volatile state. `host-consent` reports both
sets of limits. `stateBytes` sizes the sole preallocated persistent mailbox file;
the Gate does not receive a second persistent mailbox database.
