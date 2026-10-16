# Sealed recipient identities

Sealed Pages use separate user roots, device signing keys and X25519 encryption
keys. Network membership does not silently create or replace them. A network
administrator admits devices within explicit capabilities; the reader's accepted
root continuity determines which device keys can receive confidential content.

Use `authority-inspection recipients --help` for the command tree. Local commands
use an independently accepted bootstrap and `--bootstrap-digest`. Online commands
also need the private requester directory, current clock witness, explicit control
socket, identity and scoped capability described in [AuthorityInspection](AuthorityInspection.md).
All expiry arguments are absolute Unix milliseconds.

## Create and admit a device

1. Run `recipients init` with a new private `--vault` and `--age-key` path.
   The age identity encrypts the separate recipient vault. Keep it private and
   persistent; it is not an authority signer, mail key or network credential.
2. Run `root-create --member ID --threshold N --recovery-key CUSTODIAN:KEY
   --output Custody.cbor`, repeating the recovery key for each selected custodian.
   Supported custody is one key or two of three distinct keys. Protect custody
   keys independently. The custody commitment cannot be changed by network admission.
3. Run `root-register` using the member's explicit acceptance, local root vault,
   `--custody Custody.cbor`, independent `--trust-context` and admission authority.
   A new request refreshes that member's scoped directory and capability evidence
   before signing. An unresolved registration resumes its exact retained request.
   An interrupted directory page resumes its exact member, cursor and capability.
   Retain the exact exported root record and verify its digest independently.
4. On the device, run `device-create` to generate separate signing/encryption keys
   and export its public key request. Run `device-bind` at the accepted root with
   the exact root, request, validity and intended purposes. Reading is the default;
   `--enrol-devices` explicitly enables the separate delegation purpose.
5. At the admission endpoint, `challenge` checks the exact binding and creates a
   short-lived encrypted challenge in its private persistent challenge directory.
   On the device, `respond` pins the endpoint key, decrypts that challenge and
   signs the exact possession evidence. At the endpoint, `admit` consumes that
   response once, under the selected scope and validity.
6. Use `floor-initialise --role device` for the device's own requester floor.
   Keep this floor separate from the member's or administrator's ordinary stream.

A delegate uses its exact current `--delegate-binding` and `--delegate-admission`.
Both its enrolment purpose and current admission are checked. Withdrawal stops
future delegated enrolment. Duplicate or expired challenges and changed bindings
refuse; possessing only one of the device's two keys is insufficient.

The supported encryption keys have canonical X25519 encodings and pass a
contributory key check before encryption. Plugin recipients, passphrase recipients,
SSH recipients and external executable decryptors are not enabled.

## Pin contacts and freeze an audience

Use `contact-accept` after independently authenticating the contact's root digest
and trust context. Directory results alone cannot establish that first contact.
A changed root requires accepted continuous rotation or explicit recovery evidence.
A network administrator cannot replace the pinned root by returning another key.

`audience-set` signs the exact allowed members and optional excluded devices from
accepted contacts. It may use a separate `--read-grant` for current recipient
metadata. The sharing grant does not imply broad directory access.
`freeze` binds one publication, revision and encryption generation to the complete
current root/device/admission roster. A changed audience or removed recipient
requires a new finalisation with fresh encryption. Public anonymous sealed
rosters are not supported.

`directory --member ID` retrieves the exact current records for one authorised
member using bounded pages. Incomplete discovery never becomes a complete roster.
`context` retrieves an explicitly selected record. Both operations retain current
certified versions and refuse rollback below known restrictions. Member directory
and root/device context responses include the selected member's current membership
evidence. Admission independently checks that membership is active.

## Rotation and withdrawal

For ordinary root rotation, keep the old and new root vaults distinct.
`root-prepare` creates the exact successor proposal under current admission
context. `root-sign` uses both root keys plus explicit member acceptance; it
verifies the existing custody commitment. `root-submit` commits those exact
signed bytes. An edited proposal or a substituted successor refuses.

`root-revoke` uses the root's own requester floor to revoke an exact owned root
or device. Network admission withdrawal uses `revoke` with its explicit admission
capability. These are different authorities. Revocation records are immutable and
permanent key-role reservations prevent reuse under another cryptographic role.

Known revocation stops fresh content access. Previously retained ciphertext keys
or plaintext cannot be recalled. A key rotation cannot erase prior disclosure.
Use the lost-root recovery workflow below when the previous root is unavailable.

See [SealedPages](SealedPages.md) for private authoring, manual finalisation,
placement and reader verification.

## Lost-root recovery

Recipient recovery works without the previous root secret. It uses the custody
policy already committed by that recipient's accepted root. Network recovery
keys and an administrator's directory edit cannot replace this approval.

Create the replacement root in a separate recipient vault using the same member
and custody commitment. `recipients recovery-prepare` takes normal online and
capability inputs plus `--member`, `--new-root-key`, `--custody` and `--output`.
It fetches the exact current root and freezes the recipient, capability and
membership dependencies. The printed proposal digest covers the replacement key,
old root, accepted custody and complete state snapshot.

Each custodian inspects the exact replacement and custody with `recipients
recovery-inspect`, then independently runs `recipients recovery-sign` with normal location
inputs, `--proposal`, `--proposal-digest`, their private `--custody-key` identity
file and `--output`. Use separately protected keys; no old root secret is required.

`recipients recovery-assemble` takes the replacement vault's normal local inputs,
`--proposal`, `--proposal-digest`, `--share` files, `--member-key`, an independently
verified `--trust-context`, `--output` and `--recovery-output`. It checks distinct
accepted custody signatures, signs replacement-root possession and binds the
member's acceptance to the same recovery declaration. Unknown signers, repeated
shares, mixed proposals and insufficient thresholds refuse.

Submit the resulting submission with the existing `root-submit` command. Keep the
original requester floor unchanged between preparation and submission; a changed
snapshot or recipient record requires a fresh proposal and signatures. Each contact
then uses `contact-accept` with the exact previous and replacement digests, recovery
envelope and accepted custody file. Publication audiences do not change implicitly.
Previously encrypted content remains unavailable if its decryption keys were lost.
