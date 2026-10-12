# Private mail

The Mail client uses a fully accepted, independently pinned bootstrap, retained
quorum floors, an age-encrypted vault and explicitly selected Mail services.
The authority certifies public metadata and one-use package claims. It does not
receive plaintext or ciphertext. A selected store holds only encrypted letters.
There is no separate mail authority signing key and no direct TCP reader route.

## Prepare identities

An admitted manager needs SendMail15 and ReadMail16 capabilities to publish an
owner-signed mailbox. Store registration additionally requires StoreMail14 and
ManageService26. The deployment's registrar and operator consent remain separate
requirements. Mail owner keys, device request keys and MLS signing keys are
created separately inside the vault; device keys must not be admitted as members.

Each command takes an explicit location. These shell arrays abbreviate examples;
replace the paths, pins, IDs and expiry values with independently verified inputs:

```sh
Location=(--bootstrap /Private/Bootstrap.cbor --bootstrap-digest BOOTSTRAP_SHA256 \
  --clock-witness /Private/Clock/ClockHealth.cbor \
  --clock-monitor-key MONITOR_PUBLIC_KEY --host-kernel-boot CURRENT_BOOT_ID)
Vault=(--vault /Private/MailVault --age-key /Private/MailAge.key)
Manager=("${Location[@]}" --directory /Private/ManagerFloor \
  --key /Private/Manager.json --socket /Private/Authority/Control.sock)
```

The manager floor is initialized through `authority-inspection initialise` and
has its own ordinary requester stream. `mail init` creates a private vault and
separate age identity. It never overwrites existing state:

```sh
HyperNetSuite mail init "${Location[@]}" --directory /Private/ManagerFloor "${Vault[@]}"
HyperNetSuite mail address-create "${Location[@]}" --directory /Private/ManagerFloor \
  "${Vault[@]}" --mailbox Personal --host MAIL_SERVICE_KEY --private \
  --expires UNIX_SECONDS --retention 86400
HyperNetSuite mail publish "${Manager[@]}" "${Vault[@]}" --mailbox Personal \
  --grant MANAGER_GRANT_ID
HyperNetSuite mail device-initialise "${Location[@]}" \
  --directory /Private/PersonalFloor "${Vault[@]}" --mailbox Personal
```

Use `--grant-record` when an exact delegated grant is not already retained.
Address creation returns the address, owner public key and public device
binding; no private key is printed. Publication atomically admits the device's
request stream without granting membership or administrative authority.
`device-initialise` derives its requester from the vault and creates a separate
floor. Never reuse the manager directory for a device.

A private mailbox selects exactly one host and one copy. Omit `--private` only
when deliberately choosing another policy. Use repeated `--host` and `--copies`
for up to four explicitly selected stores. Administrators cannot expand this
owner-signed placement. No network-default fallback is used.

## Send and read

Use the device's floor and private authority socket for device commands:

```sh
Device=("${Location[@]}" --directory /Private/PersonalFloor "${Vault[@]}" \
  --mailbox Personal --socket /Private/Authority/Control.sock)
Store=(--service MAIL_SERVICE_KEY --service-directory /Private/MailService \
  --core /Installed/HyperNet)
HyperNetSuite mail sync "${Device[@]}"
HyperNetSuite mail refill "${Device[@]}" --count 4
HyperNetSuite mail contact-verify "${Device[@]}" \
  --address RECIPIENT_ADDRESS --owner-key INDEPENDENTLY_VERIFIED_OWNER_KEY
HyperNetSuite mail compose "${Location[@]}" --directory /Private/PersonalFloor \
  "${Vault[@]}" --mailbox Personal --recipient RECIPIENT_ADDRESS \
  --subject 'A private letter' --body-file /Private/Body.txt --expires UNIX_SECONDS
HyperNetSuite mail send "${Device[@]}" "${Store[@]}" --message MESSAGE_ID
HyperNetSuite mail inbox "${Device[@]}" "${Store[@]}"
HyperNetSuite mail read "${Device[@]}" "${Store[@]}" --message MESSAGE_ID
```

The body input is an owned private UTF-8 file. The initial recipient owner must
be verified independently, not merely copied from an unauthenticated directory.
Later contact refreshes preserve owner identity and reject rollback or forks.
Each Read device publishes one-use packages. Missing packages prevent the entire
claim. A caller can publish one through eight per refill; interrupted publication
resumes retained packages instead of regenerating their secrets.

`compose` retains the draft and returns its32-byte message ID. `send` claims an
exact complete package set, encrypts one MLS letter, and permanently binds its
ciphertext digest before upload. Rerun the same command after interruption.
The pending request, package selection and ciphertext remain unchanged.
Changing either mailbox revision before completion can refuse further delivery;
retain existing receipts and compose a new letter explicitly when appropriate.

`send` addresses one selected service per invocation. Repeat it for other
selected stores when the manifest requires several copies. The result reports
`confirmedCopies`, `requiredCopies` and `delivered`. Successful command execution
does not imply all required copies exist. `delivered` records verified storage
receipts, not that the recipient read the letter.

The example uses the installed service's bounded local exchange command. An
existing same-UID private socket can instead be selected with `--service-socket`.
These choices are mutually exclusive. They do not expose or discover a public
reader route. The supplied service key must match the exact selected Mail role.

Inbox pages contain up to16 sorted entries. Pass `--after` using the returned
`next` ID to continue. An empty final page is valid. Read independently verifies
the quorum result, service receipt, immutable ciphertext, original signed
manifests and actual MLS membership. It commits the decrypted archive and removes
the consumed private package in one encrypted snapshot before output. Repeating
a read returns that archive without consuming another package. Output is JSON,
which escapes terminal control characters in message text.

A combined Read/Send device cannot send to itself at the same address because
MLS does not admit duplicate signature keys. Use another address or a distinct
Send-only device. Separate addresses in one vault are supported.

## Owner changes and application devices

Owner commands create a local signed revision. Publish each revision before
creating another one so its exact predecessor remains the committed mailbox:

```sh
HyperNetSuite mail placement "${Location[@]}" --directory /Private/ManagerFloor \
  "${Vault[@]}" --mailbox Personal --host MAIL_SERVICE_KEY --private
HyperNetSuite mail publish "${Manager[@]}" "${Vault[@]}" --mailbox Personal \
  --grant MANAGER_GRANT_ID
```

Use `address-renew --expires UNIX_SECONDS` to extend a mailbox, publish that
revision, then use `device-renew --device DEVICE_ID --expires UNIX_SECONDS` and
publish again when its child expiry also needs extension. Both local commands
use the same location, vault and mailbox arguments as `placement`.
Device expiry must not exceed its mailbox expiry. After a publication changes,
retained Read devices sync and refill for that new generation. Old private
packages remain available for already accepted letters until their expiry.
New devices receive future letters; adding a device does not decrypt history.

Create an application's device in its own vault with `device-create --mailbox
Reader --address ADDRESS --expires UNIX_SECONDS --permission Read --output
/Private/ReaderBinding.json`, plus that vault's location arguments. Repeat
`--permission` for Send or Delete when needed. Give only the public binding to
the owner, who uses `device-enrol --mailbox Personal --binding FILE`, then
publishes the new revision. The application initializes its own device floor.
`device-export --mailbox Reader --output FILE` safely re-exports a retained
binding if the original output was lost; it never regenerates private keys.

`device-revoke --device DEVICE_ID` removes that device in the next owner-signed
revision. `address-delete` produces a permanent address tombstone. Publish both
through the manager. Removed identities stay reserved; neither operation can
revoke plaintext or keys already retained by another party. Placement changes
do not migrate existing letters or prove deletion from former stores.

## Deletion, history and recovery

`mail delete` uses a current Delete-scoped device and the same explicit store
arguments to delete one remote copy. The store retains a tombstone through claim
expiry; retry cannot resurrect it. Delete each required copy separately.
`archive-read --message ID` reads the retained local plaintext archive;
`archive-delete --message ID` removes only that local entry. Both use the vault
and location arguments and do not contact a service. `addresses` and `outbox`
show public summaries without exposing private keys or letter bodies.

For explicit onward release of one already archived letter, use `archive-disclose`
with its exact address/message, named recipient, purpose, expiry and
`--consent-disclosure`. The command writes signed metadata before private
no-overwrite plaintext output and makes no provider call. See
[Adapters](Adapters.md) for the complete selected-disclosure contract.

Keep the age identity separate from the encrypted vault and protect both. The
vault retains active private keys, unconsumed packages, pending drafts, receipts
and deliberately readable local history. Its admission bound is32MiB. Delete
unneeded local archives before reaching that bound. A compromised age identity
can expose retained plaintext history; this is not continuous conversation
post-compromise recovery.

Do not replace a live vault or floor with an older snapshot. Doing so can restore
consumed private packages or discard acknowledged effects. No check can detect
replacement of every local witness and private key by someone controlling the
account. Lost private packages cannot be reconstructed from public inventory.
There is no implicit owner recovery or automatic archive import in this client.

A healthy authority replacement preserves the bootstrap pin and explicitly
adopts a certified epoch chain in each manager/device floor. A freshly initialized
device floor begins at the accepted bootstrap and must adopt that chain before
contacting a later committee. Service requester and recipient journals must
likewise advance together. Exceptional recovery establishes a new network
identity requiring independent acceptance; it does not inherit mail secrets or
silently move this vault to another network.

## Cryptography and limits

Each letter uses RFC9420 MLS with X25519, AES-128-GCM, SHA-256 and Ed25519 through
the existing OpenMLS implementation. Local snapshots use age X25519 recipients,
without plugins or shell execution. Public packages are independently checked
against the owner-signed credential, exact native reference and lifetime.

Subjects are at most512bytes and bodies at most32768bytes. Ciphertext is at
most128KiB. A mailbox has at most eight devices and four selected stores.
Profile, grant, global authority state and store resource limits also apply.
Failure preserves committed history; limits never evict one-use safety records
silently. Authorities and selected stores can observe routing metadata, message
size and timing. This profile does not claim anonymity or post-quantum security.
