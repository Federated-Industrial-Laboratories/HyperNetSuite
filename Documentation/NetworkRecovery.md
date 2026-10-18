# Offline network recovery

[Documentation](ReadMe.md) | [Project README](../ReadMe.md)

`HyperNetSuite network recovery` prepares and accepts a new network identity after
authority loss. It does not restore the old network or activate a connection.
The successor needs a new network ID, a new incarnation ID and its own complete,
accepted bootstrap. Prepare that bootstrap with the normal `network` commands.

Keep the predecessor profile, trust floor, journal and private data intact.
Recovery imports no grants, invitations, host consents, rosters, treaties or
private content. A historical inventory digest records an intended inventory;
it does not import that inventory or authorize a publication.

The predecessor recovery policy determines the permitted offline keys and
threshold. OwnerSingle requires its one key. OwnerThreshold requires two of its
three keys. SharedThreshold requires two distinct enrolled principals and their
keys. Software verifies signatures and declared principal identities; it cannot
prove that different people control them. An owner-only override is unavailable.

## Prepare the declaration

All input fingerprints are verified through an independent channel. Inspect a
bootstrap with `network inspect-bootstrap`. The commands below use its complete
bootstrap fingerprint, rather than the descriptor digest.

```sh
HyperNetSuite network recovery draft \
  --predecessor-bootstrap /Private/Predecessor.cbor \
  --predecessor-directory /Private/AuthorityFloor \
  --predecessor-fingerprint OLD_BOOTSTRAP_FINGERPRINT \
  --successor-bootstrap /Private/Successor.cbor \
  --output /Private/RecoveryDraft.cbor

HyperNetSuite network recovery inspect \
  --predecessor-bootstrap /Private/Predecessor.cbor \
  --predecessor-directory /Private/AuthorityFloor \
  --predecessor-fingerprint OLD_BOOTSTRAP_FINGERPRINT \
  --declaration /Private/RecoveryDraft.cbor --unsigned
```

The predecessor directory is the existing requester profile with its durable
certified floor, epoch archive and current policy cache. Fetch current policy with
`authority-inspection policy discover` while authority is healthy; administrative
inspection capability is not required. Recovery uses the exact retained current
kind114 generation, including committed custody changes.
It never resets that generation to the bootstrap policy. Keep this directory
available throughout recovery; missing bytes for a retained policy generation,
a changed custody floor or damaged floor refuse the operation. A locally retained
floor cannot prove that no unseen later change exists after total authority loss.
Independent successor acceptance
remains mandatory, and grants are never restored from that historical view.

Each custodian independently inspects the declaration digest and signs identical
bytes with their own offline identity file. The identity file uses the normal
private `secretKey`/`publicKey` representation and must have mode0600.

```sh
HyperNetSuite network recovery sign \
  --predecessor-bootstrap /Private/Predecessor.cbor \
  --predecessor-directory /Private/AuthorityFloor \
  --predecessor-fingerprint OLD_BOOTSTRAP_FINGERPRINT \
  --draft /Private/RecoveryDraft.cbor \
  --declaration-digest INSPECTED_DECLARATION_DIGEST \
  --identity /Private/Custodian.json --output /Private/Share.cbor

HyperNetSuite network recovery assemble \
  --predecessor-bootstrap /Private/Predecessor.cbor \
  --predecessor-directory /Private/AuthorityFloor \
  --predecessor-fingerprint OLD_BOOTSTRAP_FINGERPRINT \
  --draft /Private/RecoveryDraft.cbor \
  --share /Private/ShareA.cbor /Private/ShareB.cbor \
  --output /Private/RecoveryDeclaration.cbor
```

A valid threshold returns `AwaitingIndependentAcceptance`. It does not establish
a unique successor. For example, A+B and A+C can authorize different declarations
if A equivocates. A timestamp or larger signature set cannot resolve that conflict.

## Observe and accept new trust

Create a private ledger for the existing client profile. The directory must not
already exist. Its parent and the output profile directory must be private.

```sh
HyperNetSuite network recovery initialise \
  --previous-profile /Private/Predecessor.json --directory /Private/Recovery \
  --predecessor-directory /Private/AuthorityFloor

HyperNetSuite network recovery observe \
  --directory /Private/Recovery --declaration /Private/RecoveryDeclaration.cbor

HyperNetSuite network recovery accept \
  --previous-profile /Private/Predecessor.json --directory /Private/Recovery \
  --declaration /Private/RecoveryDeclaration.cbor \
  --successor-bootstrap /Private/Successor.cbor \
  --successor-fingerprint INDEPENDENTLY_VERIFIED_SUCCESSOR_FINGERPRINT \
  --output-profile /Private/Successor.json \
  --output-acceptance /Private/RecoveryAcceptance.cbor
```

Acceptance signs the exact declaration and the independently verified complete
successor bootstrap fingerprint with the predecessor client's device key. The
new profile has fresh device and relay identities. It retains the client's
minimum route privacy, required publication modes and network-search preference.
An incompatible successor refuses. The accepted successor route is part of the
new explicit trust decision; operator independence still requires verification.

The ledger saves the exact acceptance, new keys and output paths before publishing
the receipt and profile. After interruption, repeat the same command. It resumes
those exact bytes and refuses changed destinations or pre-existing different
output bytes. The predecessor profile is never overwritten.

`network recovery status --directory /Private/Recovery` reports observed
statements and conflicts without displaying private keys. Different valid
statements are retained before the command reports `RecoveryConflict`, including
statements with a different historical checkpoint. Reordered signature subsets
on identical declaration bytes are the same statement. A conflict remains after
restart and prevents acceptance. A recovered profile is bound to its ledger;
`network inspect` also refuses it after a later conflicting observation. Retain
the ledger for as long as its recovered profile is used. Missing or damaged state
fails closed. A full sixteen-statement ledger retains a restrictive saturation
flag and stops further acceptance.

Independent acceptance cannot prove that no unseen conflicting declaration
exists. Network recovery cannot recover private decryption keys or erase plaintext
that a previous authorized participant retained. Online joining still requires
the separate approved privacy connector and fresh membership; recovery supplies
neither permission.
