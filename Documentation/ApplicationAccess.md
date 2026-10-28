# Application access

[Documentation](ReadMe.md) | [Project README](../ReadMe.md)

`HyperNetSuite applications` manages exact consent between an ordinary owner and
a separate application identity. The owner needs DelegateGrant through its parent
grant; InspectAudit is not required. The application receives only the accepted
child grant, its own identity and its own protected authority floor.

## Independent setup

Generate a fresh application key in a private directory:

```sh
mkdir -m 700 Application
HyperNetSuite keygen --output Application/Identity.json
```

Authenticate the complete bootstrap digest and owner's public key independently.
Never take either pin from an untrusted offer. Initialise the application floor
with the `authority-inspection initialise` workflow in
[AuthorityInspection](AuthorityInspection.md), using the application's public
key as `--requester`. The owner has a separate floor for its own public key.
Obtain a current host clock observation through the same documented workflow.

Online commands accept these common arguments:

| Argument | Purpose |
| --- | --- |
| `--bootstrap` and `--bootstrap-digest` | Exact independently accepted network bootstrap |
| `--directory` | This signer's private retained floor directory |
| `--clock-witness` | Current locally trusted clock observation |
| `--clock-monitor-key` and `--host-kernel-boot` | Independently pinned monitor and host boot, when using signed observations |
| `--key` | This signer's private identity file |
| `--socket` | Explicit local authority control socket |

The socket is the local operator interface. It provides no public listener or
implicit route. A command does not start, discover or configure a remote service.

## Delegate and agree

Run `applications context` as the owner with `--parent PARENT_GRANT_ID` and
`--tier TIER_ID`. It returns only the exact authorised dependency closure. Its
private cache is separate from the complete audit context. A refused or stale
context cannot be reused to sign a broader grant.

Run `applications delegate` with the same parent and tier, plus:

| Argument | Value |
| --- | --- |
| `--id` | Fresh child grant ID |
| `--subject` | Application public key |
| `--actions` | Sorted numeric action codes separated by commas; default0 is ReadPage |
| `--scopes` | Sorted `kind:identifier` pairs separated by commas; default is the network |
| `--not-before-ms` and `--expires-ms` | Absolute Unix milliseconds within the parent's validity |
| `--limits` | Four space-separated limits, for example `5 5 1 1` |

Every action, scope and limit must attenuate the parent and selected tier.
Application grants have zero further delegation depth and cannot include action11
(DelegateGrant). The child is inert before registration.

Refresh `applications context` with `--child CHILD_GRANT_ID`. Prepare the exact
offer using `applications offer`, the owner's common arguments except `--socket`,
and `--parent`, `--tier`, `--grant CHILD_GRANT_ID`, `--not-before-ms`,
`--expires-ms`, and `--output Exchange/Offer.cbor`. The application's validity
must lie inside the grant and span at most seven days. Optional `--acceptance-ms`
bounds the consent window; its default is one hour and maximum is24hours.

Deliver only this offer to the application. Inspect and accept it offline:

```sh
HyperNetSuite applications inspect-offer \
  --bootstrap Bootstrap.cbor --bootstrap-digest BOOTSTRAP_SHA256 \
  --owner-key OWNER_PUBLIC_KEY --offer Exchange/Offer.cbor
HyperNetSuite applications accept \
  --bootstrap Bootstrap.cbor --bootstrap-digest BOOTSTRAP_SHA256 \
  --owner-key OWNER_PUBLIC_KEY --key Application/Identity.json \
  --offer Exchange/Offer.cbor --output Exchange/Acceptance.cbor
```

The independent owner pin is required unless the owner is a recognised genesis
administrator. Inspect the exact keys, grant, actions, scopes and validity before
acceptance. Neither command needs a clock, socket or owner's floor. Acceptance
contains the two signatures over identical bytes; it does not contain a mutable
request sequence or current authority Snapshot.

## Register and inspect

Return the acceptance to the owner. Run `applications register` with the owner's
online arguments, `--parent`, `--tier`, `--accepted Exchange/Acceptance.cbor` and
`--receipt Exchange/Receipt.cbor`. It refreshes the mutable context and commits
registration only while the exact consent and full delegation chain are current.

Deliver the receipt to the application and verify it offline:

```sh
HyperNetSuite applications confirm \
  --bootstrap Bootstrap.cbor --bootstrap-digest BOOTSTRAP_SHA256 \
  --accepted Exchange/Acceptance.cbor --receipt Exchange/Receipt.cbor
```

`HistoricalApplicationRegistration` reports a certified height and
`currentPermission: false`. It verifies the original registration; it does not
import the owner's floor or grant a current domain permission.

For a receipt issued after an authority replacement, supply `--prior-epochs`
with the exported epoch archive. Confirmation verifies the complete chain from
the independently accepted initial bootstrap, then selects the exact historical
committee that signed the receipt. Receipt contents cannot install a new trust
pin. Online commands use the current epoch retained by that requester's floor.

Use `authority-inspection stream-status` with the application's own floor and
key. Then run `applications get --application-key APPLICATION_PUBLIC_KEY` with
that profile's online arguments. The owner may use the same Get operation through
its separate floor. Get returns the exact admission, accepted grant and optional
withdrawal. `applications list` lists only the calling owner's complete set as
sorted metadata. Neither operation requires InspectAudit or live delegation
permission. Lifecycle output always has `currentPermission: false`.

These commands do not execute Pages, review, media, mail, transfer or SSH actions.
Those consumers must independently verify the current accepted grant and their
domain's restrictions. Legacy application profiles are refused by domain clients
that cannot establish that proof.

## Withdraw and recover

Either party can run `applications withdraw --application-key APPLICATION_PUBLIC_KEY`
with its own online arguments. This remains available after grant or ordinary
owner admission expiry or revocation. Inspect Get afterward to confirm the exact
withdrawal. Withdrawal is permanent; changed rights require a fresh application
key. It cannot recall content already disclosed.

Keep each floor, journal and pending request together. Rerun the same command
and arguments after an uncertain reply; the client resumes its retained request.
It cannot substitute a different operation or silently fence away an unknown
outcome. After a refused response, the client queries certified own-stream status
before choosing another operation. Only a confirmed original refusal releases
the pending request. A refusal to disclose an earlier success does not discard
that success or acknowledge its local effect.

An exact registration retry preserves a subsequently fenced application
stream and any withdrawal. The acceptance's original expiry does not erase an
already completed registration or make its receipt current authority.

The authority has256 permanent requester slots across root subjects, members and
applications. Expiry and withdrawal do not reclaim slots. Owner listing returns
complete bounded metadata without pagination; capacity failures never admit a
partial application. Never copy another signer's floor or reset retained state
to evade a capacity, continuity or uncertain-outcome refusal.

## Same-rights renewal

Renewal preserves the application key, owner, immutable grant, actions, scopes,
limits, tier and exact parent. It replaces the admission's finite validity and
increments its generation. The first explicit renewal migrates a version 1
admission to version 2. Old registration bytes retain their original meaning.

Fresh owner and application signatures approve each new validity interval of at
most seven days. The owner must still have DelegateGrant through the same exact
parent, and every current ancestor, tier, admission and revocation check applies.
An expired application can renew while its parent remains valid. A version 2
admission supplies its exact leaf grant's effective validity; it never extends
another grant or changes the grant's rights. Withdrawal and revocation cannot
be undone by renewal. A compromised application requires replacement, not renewal.

The operation replaces one admission and its current consent evidence. It does
not create another child grant or requester slot. Requester generations, sequence
floors and unresolved requests remain intact. Retry the exact pending renewal
before starting another owner operation. No unattended renewal permission is
implied by a prior acceptance.

Use the existing independent owner and application profiles:

1. Run `applications get --application-key APPLICATION_PUBLIC_KEY` as the owner
   to retain the current admission in the owner's authenticated cache.
2. Run `applications renewal-offer` with the owner's common profile arguments
   except `--socket`, plus `--application-key`, `--not-before-ms`, `--expires-ms`,
   `--acceptance-ms` and `--output Renewal.cbor`.
3. Run `applications accept-renewal` offline as the application with `--bootstrap`,
   `--bootstrap-digest`, `--owner-key`, `--key`, `--offer Renewal.cbor` and
   `--output AcceptedRenewal.cbor`. Independently authenticate the owner key.
4. Run `applications renew` as the owner with its common online arguments,
   `--parent`, `--tier` and `--accepted AcceptedRenewal.cbor`. This refreshes the
   delegation closure and preserves exact retry state.
5. Fetch the admission from the application's own profile to observe its new
   generation. Continue to use the application's existing floor and private key.

The published [renewal vector](ApplicationRenewalVector.json) binds the same
predecessor, grant and parties in the independent Core and Suite validators.

Authority history retains all committed prefixes in bounded disk segments.
Clients retain the existing compact checkpoint and Merkle proofs; an older floor
can catch up without discarding it. The replica's physical history quota remains
finite and requires operator monitoring. Renewal does not remove the independent
capacity bounds on legacy Mail objects or permanent identities.
