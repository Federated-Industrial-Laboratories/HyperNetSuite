# Applications and review adapters

[Documentation](ReadMe.md) | [Project README](../ReadMe.md)

Review adapters exchange explicitly selected inert data with a provider chosen
by the operator. HyperNetSuite does not start a provider, follow Page links or
give a provider credentials, a shell, plugins or tools. Provider output is an
untrusted recommendation, never a command.

## Native review authority

Use [ApplicationAccess](ApplicationAccess.md) for application admission and
[Pages](Pages.md) for its native Page policy. A reviewer needs the current exact
102 capability for action 3. An application also needs its current 127
registration and dual-signed 148 policy, with ReviewInspect and ReviewDecide
permissions for the selected namespace and Page. Withdrawn, expired or replaced
rights refuse. Application registration alone does not grant review access.

Ordinary reviewers and Manual application policies require the human's explicit
Approve or Reject decision. Automatic application policy uses mode 1 with an
exact policy digest; applying a recommendation still requires `--automatic`.
A human can instead supply an explicit decision under that same policy. Media
inspection is a separate permission and does not itself approve a Page.

All online commands use the independently accepted bootstrap, local requester
floor, signing key, clock observation, private authority socket and exact grant
arguments described in Pages. There is no direct reader route or legacy profile
fallback. Offline import uses the location and key arguments only; it neither
opens a requester floor nor makes a network request.

The examples use these Bash arrays; substitute independently verified pins and
the reviewer's existing private requester directory:

```sh
Location=(--bootstrap /Private/Bootstrap.cbor --bootstrap-digest BOOTSTRAP_SHA256 \
  --directory /Private/ReviewerFloor --clock-witness /Private/Clock/ClockHealth.cbor \
  --clock-monitor-key MONITOR_PUBLIC_KEY --host-kernel-boot CURRENT_BOOT_ID)
Online=("${Location[@]}" --key /Private/Reviewer.key \
  --socket /Private/Authority/Control.sock)
Capability=(--grant REVIEW_GRANT_ID)
```

Add `--grant-record /Private/ReviewGrant.cbor` to `Capability` when the exact
delegated grant is not already retained. The reviewer key used by offline import
must match the identity that signed the disclosure.

## Text disclosure

Create a private exchange directory and export one current pending source:

```sh
mkdir -m 700 /Private/ReviewExchange
HyperNetSuite adapters review-export "${Online[@]}" "${Capability[@]}" \
  --page-id PAGE_ID --recipient LocalClassifier \
  --purpose 'Review this Books submission' --policy-digest POLICY_SHA256 \
  --expires UNIX_SECONDS --consent-disclosure \
  --output /Private/ReviewExchange/Job.json \
  --receipt /Private/ReviewExchange/Disclosure.cbor
```

The expiry must be in the next 300 seconds and cannot exceed application consent.
The current quorum-certified inspection supplies the exact pending 141 revision
and immutable source. The signed private receipt binds network and incarnation,
requester, exact 102 grant, optional 148 policy and 127 registration, review mode,
140 ledger, 141 revision, canonical 203 source reference, author statement,
namespace, recipient label, purpose, policy digest, expiry and exact source.
The receipt is durable before the selected plaintext is exported.

The JSON export is `{ "job": JOB, "jobDigest": SHA256 }`. The job contains:

```text
version, kind, network, incarnation, jobId, requester, grant, application,
applicationRegistration, reviewMode, recipient, purpose, policyDigest,
issuedAt, expires, consentDisclosure, pageId, ledger, revision, source,
author, authorStatement, namespace, body
```

`version` is 1 and `kind` is `NativePageReview`. Ordinary reviewers have null
application, applicationRegistration and reviewMode fields. References are hex
encodings of canonical native records or object references. Providers copy the
opaque supplied bindings; they do not need to serialise or sign the job.
`jobDigest` hashes the compact UTF-8 JSON job in the field order above.

Arrange provider processing separately. Its result must be a private regular
JSON file of at most 8192 bytes with exactly these fields:

```json
{
  "version": 1,
  "jobId": "COPY_FROM_JOB",
  "network": "COPY_FROM_JOB",
  "incarnation": "COPY_FROM_JOB",
  "pageId": "COPY_FROM_JOB",
  "source": "COPY_FROM_JOB",
  "policyDigest": "COPY_FROM_JOB",
  "jobDigest": "COPY_FROM_EXPORT",
  "decision": "Abstain",
  "rationale": "No decision."
}
```

Decisions are case-sensitive Approve, Reject or Abstain. Rationale is at
most 2048 UTF-8 bytes and JSON output escapes terminal controls. Unknown or duplicate
fields, prose wrappers, additional objects, tool fields, wrong bindings and
oversized results refuse. Tool-shaped text inside the rationale remains text.
No provider identity signature is implied: protect the result file and any
separate provider transport. These restrictions contain effects, not mistakes
in a provider's judgement.

## Inspection and exact apply

```sh
HyperNetSuite adapters review-import "${Location[@]}" --key /Private/Reviewer.key \
  --receipt /Private/ReviewExchange/Disclosure.cbor \
  --result /Private/ReviewExchange/Result.json
HyperNetSuite adapters review-apply "${Online[@]}" "${Capability[@]}" \
  --receipt /Private/ReviewExchange/Disclosure.cbor \
  --result /Private/ReviewExchange/Result.json --decision reject \
  --decision-output /Private/ReviewExchange/Apply.cbor
```

Import validates the disclosure signature and exact recommendation and reports
`applied:false` and `authorityChecked:false`. Manual apply requires the human's
own decision, which can differ from the recommendation. Abstain cannot publish
or reject. An explicitly authorised Automatic application replaces `--decision`
with `--automatic`; the current exact mode 1 policy must match the disclosed
policy digest. Neither a Manual policy nor an ordinary reviewer can do that.

Before constructing a new decision, apply rechecks the pending ledger, revision,
source and exact application policy. It saves an immutable signed apply receipt
binding the recommendation, explicit choice and exact native PageReviewStatement,
source and optional approved bundle. Only then does it submit the decision.
If interrupted, repeat the same command, result and decision-output path. The
saved statement is reused without new randomness or silent substitution. A
changed choice or recommendation requires a new review; it cannot overwrite the
retained attempt. The authority and requester verifier still require current
rights, source, media evidence, expiry and exact application policy on retry.
The receipt is historical local provenance, not reusable permission.

Do not start another operation while this exact apply is pending. After known
completion, a second publication request is unnecessary. Expiry cannot recall
an already committed decision or plaintext previously disclosed. Expired or
replaced jobs require a fresh export before any new effect.

## Selected media disclosure

Text export includes inert asset declarations but never fetches their payloads.
Disclose one selected asset only with separate media consent and an explicit
local store route:

```sh
HyperNetSuite adapters media-export "${Online[@]}" "${Capability[@]}" \
  --receipt /Private/ReviewExchange/Disclosure.cbor --asset Diagram \
  --host HOST_ID --service-socket /Private/Media/Service.sock \
  --progress-directory /Private/ReviewExchange/DiagramProgress \
  --consent-media-disclosure --output /Private/ReviewExchange/Diagram.json \
  --media-receipt /Private/ReviewExchange/DiagramDisclosure.cbor
```

For an installed store use `--service-directory` and optional `--core` in place
of `--service-socket`. The reviewer needs current MediaInspect permission.
The client chooses only a 144 asset belonging to the exact disclosed 141 revision,
fetches the entire canonical object through finite authenticated store requests,
verifies its bytes and persists resumable progress, then records current 145
inspection evidence. It rechecks the pending Page again before disclosure.

A separate signed receipt is saved before plaintext release. Metadata binds the
original job, recipient, purpose, policy, expiry, source and revision, exact 144
asset and 145 inspection; the JSON `payload` is standard padded base64. The output
bound follows the existing canonical media byte ceiling plus base64 expansion
and bounded metadata. It is not an independent smaller asset quota. Canonical
bitmap and inert vector validation, host consent and current copy requirements
continue to apply. Page approval independently requires all required current
copies and reviewer inspections. An inspection records byte verification, not
human examination or classifier accuracy.

Exchange destinations have user-owned 0700 parents and 0600 files. Reads reject
symbolic-link traversal and writes never replace a destination. A failed export
can leave its private signed receipt; choose new output paths for a new disclosure.
All files have actual encoded size bounds. Retain or remove plaintext according
to the chosen disclosure policy; expiry does not erase released copies.

## One-letter mail disclosure

Mail applications use the separate Read, Send and Delete device permissions
in [PrivateMail](PrivateMail.md). Application registration never becomes a
mailbox credential. An owner signs each explicit device binding and publishes
the exact roster. Keep application vaults separate from owner vaults and keep
provider processing separate from devices with Send or Delete rights.

An owner of a local encrypted vault can explicitly disclose one archived letter.
A Read grant does not itself consent to onward disclosure. Use the location and
vault arguments described in PrivateMail, plus the exact mailbox, address and
32-byte message ID:

```sh
HyperNetSuite mail archive-disclose "${Location[@]}" \
  --directory /Private/PersonalFloor "${Vault[@]}" --mailbox Personal \
  --address ADDRESS_ID --message MESSAGE_ID --recipient LocalClassifier \
  --purpose 'Classify this selected letter' --expires UNIX_SECONDS \
  --consent-disclosure --output /Private/ReviewExchange/Letter.json \
  --receipt /Private/ReviewExchange/LetterReceipt.json
```

The output contains `disclosure` metadata and exactly one `letter`. Metadata
binds network, incarnation, bootstrap pin, selected address/message, recipient,
purpose, creation/expiry, consent, local archive origin and plaintext digest.
Expiry is at most 300 seconds. The content digest is SHA256 of the compact JSON
letter encoding. A purpose-bound signature by the local device request key
attests to this disclosure; it is not fresh online authority or a new sender
signature. The signed receipt contains metadata and its digest, never another
plaintext copy, keys, unconsumed packages or recovery material.

Both destinations must be absent in owned private directories. Their paths are
checked before the receipt is persisted and plaintext is released. Neither file
replaces existing data. If a later output error leaves only the receipt, preserve
it and use new output/receipt names for a deliberate retry. A receipt does not
claim that a provider received or processed the export.

The operation makes no authority or provider call and cannot send, delete,
classify or act on a letter. Device revocation prevents new online access but
cannot recall history already decrypted. Protect and remove released plaintext
separately; expiry cannot recall a recipient's retained copy.
