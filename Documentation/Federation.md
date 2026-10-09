# Federated Pages

Federation imports explicitly shared native Pages into a separately reviewed
destination namespace. Each direction needs its own agreement. The source author,
source administrator, destination administrator and bridge operator each provide
separate permission. Imported pages cannot be exported through another agreement.

## Establish an agreement

Exchange the network identities and dedicated authority signing public keys
through an authenticated channel. These signing keys are separate from TLS keys
and must never be admitted as members. Create two distinct bridge device identities
with `keygen`, invite each into its own network with grant 9, and redeem each
invitation. Obtain a separate client transport certificate for each network.
Keep ordinary author, reader and administrator credentials out of the bridge.

Prepare the same public treaty file for both administrators:

```json
{
  "version": 1,
  "agreementId": "REPLACE_WITH_16_RANDOM_BYTES_AS_LOWERCASE_HEX",
  "sourceNetwork": "SOURCE_NETWORK_HEX",
  "destinationNetwork": "DESTINATION_NETWORK_HEX",
  "sourceAuthorityKey": "SOURCE_SIGNING_PUBLIC_KEY_HEX",
  "destinationAuthorityKey": "DESTINATION_SIGNING_PUBLIC_KEY_HEX",
  "sourceBridgeKey": "SOURCE_BRIDGE_PUBLIC_KEY_HEX",
  "destinationBridgeKey": "DESTINATION_BRIDGE_PUBLIC_KEY_HEX",
  "sourceNamespace": "News",
  "destinationNamespace": "PartnerNews",
  "service": "Pages",
  "profile": "HyperNetPage/2",
  "expires": 1800000000
}
```

Replace all identity placeholders and the absolute Unix expiry. Each public key
and network identity is 32 bytes of lowercase hexadecimal. All four keys must
be distinct. Namespace names contain ASCII letters and digits, begin with a
letter, and contain at most 32 characters. Validate and compare the treaty digest
before both administrators accept it:

```sh
HyperNetSuite federation treaty Treaty.json
HyperNetSuite --config SourceAdministrator.json federation accept --treaty Treaty.json
HyperNetSuite --config DestinationAdministrator.json federation accept --treaty Treaty.json
HyperNetSuite --config DestinationAdministrator.json federation agreements
```

The identifier binds immutable terms. Withdrawn agreements cannot be restored;
renegotiation requires a new identifier. There is no discovery or implicit trust.
The authority signing key configured at each broker must match its treaty key.

## Consent to a bridge

Follow HyperNet's Bridge guide to create `Specification.json` with the exact
agreement digest, two TLS endpoints, literal destination addresses, hashes of
the exact CA files and bounded resources. The operator signs it offline with
both bridge identities:

```sh
HyperNetSuite federation sign-consent --spec Specification.json --treaty Treaty.json \
  --source-identity SourceIdentity.json --destination-identity DestinationIdentity.json \
  --output Consent.json
HyperNetSuite --config SourceBridge.json federation register --consent Consent.json \
  --certificate SOURCE_CLIENT_CERTIFICATE_DER_SHA256
HyperNetSuite --config DestinationBridge.json federation register --consent Consent.json \
  --certificate DESTINATION_CLIENT_CERTIFICATE_DER_SHA256
```

Register the exact same consent file on both sides. Use `openssl x509 -in
Client.pem -outform DER | openssl dgst -sha256` for a client certificate hash.
The command reports the profile digest and combined memory allowance, including
two fixed relays. Signing and registration do not start a bridge. Install and
start it with HyperNet's independent container tools. Its two TLS clients use
separate roots and credentials; its network permits only the consented endpoints.

## Share, review and read

The source author first submits a native page and obtains its normal source
approval. Membership-only publication does not authorise cross-network sharing.
The same author then opts the exact publication into an accepted agreement:

```sh
HyperNetSuite --config SourceAuthor.json federation share --agreement AGREEMENT_ID --page-id PAGE_ID
HyperNetSuite --config DestinationAdministrator.json federation queue --agreement AGREEMENT_ID
HyperNetSuite --config DestinationAdministrator.json federation inspect --agreement AGREEMENT_ID \
  --page-id PAGE_ID --output Review.json --tui
HyperNetSuite --config DestinationAdministrator.json federation review --input Review.json --decision approve
HyperNetSuite --config DestinationReader.json federation list --agreement AGREEMENT_ID
HyperNetSuite --config DestinationReader.json federation read --agreement AGREEMENT_ID --page-id PAGE_ID --tui
```

The bridge imports into quarantine. Only the destination administrator can inspect
and approve that exact descriptor. `--decision reject` suppresses it. Changed
source publications need fresh author sharing and fresh destination review.
Repeated bridge refreshes do not change publication versions or undo a rejection.

The independent reader verifies native author/source-review signatures, author
sharing, destination approval and short signed evidence from both authorities.
It displays the origin network, author and namespace separately from the local
namespace and reviewer. TUI controls match Pages: `r` revalidates, `b` returns,
and `q` exits. `--ascii` and plain redirected output remain available.
Native and foreign pages share one history of at most 16 retained pages. Links
back into the configured local network read native publications; links to foreign
origins require an explicit active local agreement for the exact network and
namespace. The reader rechecks agreement activity when following a foreign link.
It retains the current foreign agreement for links within that origin namespace.
Otherwise, if several agreements match, select one explicitly with `federation
read`. A withdrawn selected agreement cannot silently switch to another one.
Every followed link checks the verified publication's network, author, namespace
and page identity. Refresh uses the current page's native or bilateral proof
checks, and Back preserves the retained display across both kinds of page. Back
at the first page keeps it open; `q` exits the whole reader.
External HTTPS links remain display-only. Selecting a native replica keeps that
replica for native navigation and rejects foreign routes.

## Stop sharing or access

```sh
HyperNetSuite --config SourceAuthor.json federation share --agreement AGREEMENT_ID --page-id PAGE_ID --withdraw
HyperNetSuite --config DestinationAdministrator.json federation withdraw-page --agreement AGREEMENT_ID \
  --page-id PAGE_ID --expected-version CURRENT_VERSION
HyperNetSuite --config Administrator.json federation withdraw --agreement AGREEMENT_ID --expected-version CURRENT_VERSION
HyperNetSuite --config Bridge.json federation withdraw-consent
```

Stop the local bridge before withdrawing its online consent. Local container
withdrawal works during an outage. Agreement or membership withdrawal blocks new
local operations immediately. Source-side changes can remain usable at the
destination only until the already signed lease expires, at most five seconds.
Loss of either quorum or transport path prevents lease renewal. Both clocks must
agree closely; future-dated evidence fails closed. Restarting cannot make expired
evidence current.

Author withdrawal does not require readable content or current reviewer approval.
It still requires the author's current valid membership. The authority checks
immutable ownership and the exact network, agreement and page scope. A committed
withdrawal remains effective after reviewer restoration or broker restart.
Re-sharing requires a fresh explicit command against the current generation.

Before contacting the authority, the client saves a signed intent in a private
`Withdrawals` directory beside the configured identity file. The directory is
mode 0700; pending files are mode 0600 and contain no private key. Keep this
identity directory under the user's control. Sharing operations use a per-page
lock and refuse a new opt-in while a local withdrawal remains pending. Keep using
the same identity directory across profiles to preserve this local coordination.

The withdrawal command reports `Confirmed` only after an authority commit.
It reports `Pending` and exits unsuccessfully if it cannot confirm the change.
A pending request is retained across process restarts; it is not a background
service and does not retry automatically. Use:

```sh
HyperNetSuite --config SourceAuthor.json federation retry-withdrawal \
  --agreement AGREEMENT_ID --page-id PAGE_ID
HyperNetSuite --config SourceAuthor.json federation share-status \
  --agreement AGREEMENT_ID --page-id PAGE_ID
```

If the original request could not observe a generation before the outage, retry
shows `GenerationConfirmationRequired` and the current sharing status. Review
that state, then explicitly target the displayed generation:

```sh
HyperNetSuite --config SourceAuthor.json federation retry-withdrawal \
  --agreement AGREEMENT_ID --page-id PAGE_ID --expected-generation GENERATION
```

This confirmation also resolves a conflict with concurrent new consent if the
original withdrawal never committed. A pending command already bound to a
generation retries that generation by default. If the withdrawal committed and
another device subsequently re-shared, retry reports `Confirmed` with
`SupersededByLaterConsent`; it does not cancel the newer consent. Pending files
are removed only after confirmation. To withdraw a newer grant after such a
retry, run a new `share --withdraw` command. Deleting a pending file is not withdrawal.

The five-second remote permission bound starts after committed withdrawal, not
when an offline user creates an intent. An authority that has not received the
request may still renew sharing. Already displayed or exported bytes cannot be
recalled. Retained screen content is marked as approval at fetch; refresh requires
current permission. Manual approval is the default. Model adapters, mail, file
transfer and shell services are separate future features.
