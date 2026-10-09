# Applications and review adapters

HyperNetSuite exposes native Pages to separate application identities. It also
exchanges inert review data with a provider chosen by the operator. It neither
starts a provider nor gives it a credential, shell, plugin, network client or
HyperNet tool. A model response is untrusted data. The operator is responsible
for any separately arranged disclosure and provider retention policy.

## Dedicated application access

Create a new key and profile in a private directory. Obtain the network identity,
endpoint and CA through the same authenticated process as other clients:

```sh
mkdir -m 700 Application
HyperNetSuite keygen --output Application/Identity.json
HyperNetSuite configure --network NETWORK_HEX --endpoint https://authority.example:8443 \
  --ca NetworkCa.pem --identity Application/Identity.json --application \
  --output Application/Profile.json
HyperNetSuite --config Application/Profile.json applications consent \
  --owner-key OWNER_PUBLIC_KEY --expires UNIX_SECONDS --namespace News \
  --permission PagesRead --output Application/Consent.json
HyperNetSuite --config Owner/Profile.json applications grant --consent Application/Consent.json
HyperNetSuite --config Application/Profile.json applications get --application-key APPLICATION_PUBLIC_KEY
HyperNetSuite --config Application/Profile.json pages list --namespace News
HyperNetSuite --config Application/Profile.json pages read --page-id PAGE_ID
```

The `application` profile flag selects client checks. The authority independently
enforces all rights, including when this flag is absent or incorrect. No owner
secret appears in the application profile. A key with another network role,
including a pending invitation, cannot become an application key. Applications
cannot invite, grant, host, federate, request replica tickets, transfer files,
use SSH or access mail through their Pages permission.

Repeat `--namespace` for up to eight exact namespaces. Repeat `--page-id` to
restrict access to at most sixteen exact page IDs. Omitting page IDs selects all
pages in the listed namespaces. Lists are sorted and deduplicated before signing;
there are no wildcards. `pages list` and `pages queue` require an explicit
`--namespace` with an application profile. Permissions are intersections of the
namespace, page allowlist and action:

| Permission | Operations |
| --- | --- |
| PagesRead | List and read currently published native pages |
| PagesSubmit | Submit and withdraw this application's own pages |
| ReviewInspect | Queue and inspect pending pages |
| ReviewDecide | Approve or reject exact pending content; requires ReviewInspect |

Review permissions require an administrator owner. ReviewDecide also requires
`--review-policy-digest POLICY_SHA256` and `--review-mode manual` or `automatic`
when creating consent. Digest the exact policy bytes through a trusted local
process. Deliver that policy to the chosen provider separately; the export
contains the digest, not policy text. In Suite, Manual requires an operator-supplied
decision. The authority checks the signed mode and scope; it does not prove that a
human acted. Other clients holding a Manual credential must enforce their own
human-confirmation policy. Automatic permits the separate `review-apply --automatic`
operation under that exact policy. Neither mode starts a provider or automatically
watches a queue.

Application consent uses the existing signed request envelope with command
`ApplicationConsent`. Its fields are `ownerKey`, `expires`, `namespaces`,
`pageIds` (null or exact list), `permissions`, `reviewPolicyDigest` and `reviewMode`
(the last two null without ReviewDecide). The owner signs
`ApplicationGrantCreate { consent: ENVELOPE }`. The inner application signature
proves possession; the outer owner signature approves exact scope. The ordinary
request freshness window applies to both signatures, so issue the grant promptly.
The grant is immutable. Generate a fresh application key for changed scope.
Expiry is at most seven days and cannot exceed the owner's current membership.

```sh
HyperNetSuite --config Owner/Profile.json applications list
HyperNetSuite --config Owner/Profile.json applications list --after APPLICATION_PUBLIC_KEY
HyperNetSuite --config Owner/Profile.json applications revoke --application-key APPLICATION_PUBLIC_KEY
```

Get and revoke are available to the owner or application; an owner lists only
its own records. A successful grant response is required to establish access.
After an uncertain creation response, get the application key before retrying.
Owner rights, application expiry, revocation and scope are rechecked on each
action. Changes also affect publication availability within the existing
five-second authority freshness bound. Retained archive signatures alone do not
grant continuing access. There are initially eight retained grants per owner and
64 per network. Referenced grants remain reserved; they cannot be reclaimed by
churning credentials.

## Independent wire clients

Applications send HTTPS `POST /V1/Command` with TLS 1.3 and the explicitly pinned
network CA. The JSON envelope has `network`, `publicKey`, `payload` and
`signature`. Network and public key are canonical lowercase 32-byte hex;
signature is 64-byte lowercase hex. Payload is unpadded base64url of the exact
UTF-8 JSON request bytes. Requests contain `version: 1`, `requestId` (16-byte hex),
`issuedAt` (Unix seconds) and `command`. Ed25519 signs the concatenation of
`HyperNet/Request/1` followed by NUL, decoded network, decoded public key, and
exact payload bytes. Do not reserialise a received signed payload before verifying
it. The authority accepts the existing 60-second request freshness window. The
same envelope construction signs the nested ApplicationConsent.

Get and create return `result.application`; list returns `result.entries` and
`result.next`; revoke returns `result.applicationKey` and `result.revoked`.
An application record has `ownerKey`, `applicationKey`, `grant`, `grantDigest`,
`expires`, `namespaces`, `pageIds`, `permissions`, `reviewPolicyDigest`,
`reviewMode` and `revoked`. `grant` preserves the owner envelope and nested consent;
`grantDigest` is SHA256 of the exact signed owner message, including its domain
and identities. Suite verifies these signatures and the duplicated scope fields.
Fresh authenticated authority responses establish current grant status; archived
signatures establish provenance only. Commands use the Core protocol's normal
`ok`, `code`, `epoch` and `result` response fields.

App-signed PageReview includes `applicationPolicyDigest` and
`applicationReviewMode`, exactly matching the current grant. Human PageReview omits
both. Application reviews also require `reviewExpires`, an absolute Unix deadline
within 300 seconds. Adapter apply supplies its job expiry for either identity
kind; ordinary human `pages review` omits the optional deadline. Submission and approval proofs keep their actual application signer keys;
the owner never impersonates the application. See HyperNet's application and
Pages protocol documentation for complete server bounds and error behaviour.

## Explicit review exchange

Create a private exchange directory. Use a human administrator profile or a
separate ReviewInspect application profile. Every export selects one current,
verified, signed pending submission:

```sh
mkdir -m 700 ReviewExchange
HyperNetSuite --config Reviewer/Profile.json adapters review-export \
  --page-id PAGE_ID --recipient LocalClassifier --purpose 'Review for the News policy' \
  --policy-digest POLICY_SHA256 --expires UNIX_SECONDS --consent-disclosure \
  --output ReviewExchange/Job.json --receipt ReviewExchange/Receipt.json
```

Expiry must be within 300 seconds, and must fit any application grant. An
application's bound review policy must match. The receipt is signed by the
configured reviewer. It privately retains the exact job and signed source. The
export contains `{ "job": JOB, "jobDigest": SHA256 }`. `JOB` has these fields:

```text
version, kind, network, jobId, requester, applicationGrantDigest, reviewMode,
recipient, purpose, policyDigest, issuedAt, expires, consentDisclosure, pageId,
expectedVersion, revision, author, namespace, audience, profile, digest,
submissionDigest, body
```

`version` is 1 and `kind` is `PageReview`. Human exports have null
`applicationGrantDigest` and `reviewMode`. The opaque `jobDigest` binds the compact
UTF-8 JSON encoding of `JOB` in the field order above. Providers echo the supplied
digest; they do not need to serialise or sign the job. Only public identifiers,
selected content and disclosure metadata are exported. Page links remain text;
no link is fetched. Pages and provider rationale cannot select another operation,
identity, endpoint, file, tool or policy.

Arrange any provider processing separately. The result must be an owner-only
regular JSON file, no larger than 8192 bytes, containing exactly:

```json
{
  "version": 1,
  "jobId": "COPY_FROM_JOB",
  "network": "COPY_FROM_JOB",
  "pageId": "COPY_FROM_JOB",
  "digest": "COPY_FROM_JOB",
  "submissionDigest": "COPY_FROM_JOB",
  "policyDigest": "COPY_FROM_JOB",
  "jobDigest": "COPY_FROM_EXPORT",
  "decision": "Abstain",
  "rationale": "No decision."
}
```

Decisions are case-sensitive `Approve`, `Reject` or `Abstain`. Rationale is at
most 2048 UTF-8 bytes and is displayed with terminal controls escaped. Unknown
or duplicate fields, prose wrappers, multiple JSON objects, tool calls, wrong
bindings and oversized results fail. Prompt instructions inside content remain
content; this containment does not establish classifier accuracy or prevent a
provider from making a bad recommendation. Results carry no provider identity
signature. Anyone able to write the result file can supply a recommendation;
protect the local exchange and any separate provider transport accordingly.

```sh
HyperNetSuite --config Reviewer/Profile.json adapters review-import \
  --receipt ReviewExchange/Receipt.json --result ReviewExchange/Result.json
HyperNetSuite --config Reviewer/Profile.json adapters review-apply \
  --receipt ReviewExchange/Receipt.json --result ReviewExchange/Result.json --decision reject
```

Import validates and displays a recommendation only. It makes no network request
and does not check current authority. Manual apply requires the human's own
`--decision approve` or `reject`; it can differ from the recommendation. An
application must hold a current Manual ReviewDecide grant. Ordinary `pages review`
with a Manual application profile also verifies and supplies the current policy.
An explicit Automatic grant uses this separate operation:

```sh
HyperNetSuite --config AutomaticReviewer/Profile.json adapters review-apply \
  --receipt ReviewExchange/Receipt.json --result ReviewExchange/Result.json --automatic
```

Automatic apply requires the same application grant, mode and policy as export.
Automatic Abstain cannot change publication. A separate human decision can differ
from any recommendation. Both modes recheck the exact current pending
source, version and signer before sending a signed PageReview. The authority then
rechecks current rights, the exact object and the signed review expiry before
committing the decision. A response can arrive after its deadline; a result already
committed cannot be recalled through expiry. A stale, replaced,
expired or revoked job must be exported anew; failures never silently publish.
Do not retry a successful apply: the changed page version makes old results stale.

All exchange destinations require a user-owned mode 0700 parent. Files are mode 0600,
bounded, opened through directory descriptors without symbolic-link traversal,
and published without replacing an existing file. The receipt is saved before
plaintext export. If export fails, inspect the retained private receipt and select
new paths for another export. Expiry controls apply permission; it cannot erase
copies already released. Delete plaintext exports according to the chosen policy.

## One-letter mail disclosure

Mail applications use the existing separate device permissions Read, Send and
Delete described in [PrivateMail](PrivateMail.md). A Pages application grant never
becomes a mailbox credential. Keep provider file processing separate from a mail
device, particularly one with Send or Delete rights.

An owner of a local encrypted vault can explicitly disclose one already archived
letter. Select its exact mailbox, 32-byte address ID and native 16-byte message ID
(both canonical lowercase hexadecimal):

```sh
HyperNetSuite --config Mail/Profile.json mail --vault Mail/Vault --key Mail/VaultKey \
  archive-disclose --mailbox Personal --address ADDRESS_ID --message-id MESSAGE_ID \
  --recipient LocalClassifier --purpose 'Classify this selected letter' \
  --expires UNIX_SECONDS --consent-disclosure \
  --output ReviewExchange/Letter.json --receipt ReviewExchange/LetterReceipt.json
```

The output contains `disclosure` metadata and exactly one `letter`. The metadata
binds network, address, message, recipient, purpose, creation/expiry, consent,
origin and the letter digest. Expiry is at most 300 seconds. The digest is SHA256
of the compact serde JSON letter encoding; the signed receipt contains only this
metadata and its digest, never another plaintext copy, keys, prekeys, vault state
or owner recovery material. Its signature identifies the local mailbox request
key and attests to disclosure; it is not a fresh online authorisation or a new
sender signature. `origin` distinguishes retained local and imported archive
records. Conflicting copies with the same selected message ID are refused.

This operation works on local history, makes no authority or provider call, and
cannot send, delete, classify or act on a letter. A device revocation prevents new
online access but cannot recall history it already decrypted. Protect and remove
exported plaintext separately. The general encrypted archive/recovery commands
remain separate, explicit workflows.
