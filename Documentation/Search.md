# Catalogue and search

Search has two explicit scopes. `search network` sends literal terms to the
selected network's consenting content services. `search local` searches only
publications explicitly retained in an encrypted local corpus. Entering a local
query never connects, refreshes authority, falls back to network search, or forwards
missing terms. `--historical` is an explicit local option with no claim that
current membership, withdrawal or revocation has been checked.

Every result derives from an exact approved HyperPage. Search includes the title,
headings, inert text, image alternative text, component labels and `@Tags` values.
Forms, field values and schemas are excluded. Terms are literal, Unicode
lowercase comparisons; there are no regular expressions, executable expressions or
remote ranking scripts. Repeated `--term` arguments require every term unless
`--any` is given. An empty term list lists the authorised catalogue. Snippets are
bounded safe text. The client recomputes matching, ranking and snippets from the
verified source; an index cannot invent an approved result. Missing results and
search completeness are not certified.

## Network search

Enable network-search disclosure when preparing the selected network profile with
`network prepare --permit-network-search`. This authorises explicit network search;
it does not change the default local scope or provide confidentiality from the
final service receiving the terms. A relay protects the route according to its
configured guarantees, not from the selected search service itself.

```sh
HyperNetSuite network connect --profile Network.json -- \
  search network --namespace Books --term botanical --limit 20
```

The current capability must include `ReadPage` and `SearchCatalogue`. Applications
also require explicit `PagesRead` and `PagesSearch` permissions. Native hosts must
have signed content consent containing `search: true` and current `IndexPages`
authority. Configure exact host routes with `pages content route`. Search uses the
selected Content service and its existing encrypted transport. Authority requests
contain only publication, placement and permission scope; neither terms nor a
query-derived digest is placed in the authority journal.

The native catalogue supplies complete certified publication, placement and host
contexts, so the first still-current item does not repeat PageRead and ContentGet.
If earlier content exchanges consume that catalogue result's original validity,
or the retained authority floor advances, the next item obtains a fresh PageView
before query preparation. A catalogue context is reused only at its exact retained
prefix. This does not extend a proof or reuse an operation permission.
Fresh policy discovery still precedes catalogue or Page selection. Its complete
result can supply the accepted policy for the first content request at that exact
floor and original expiry, with no pending recovery and explicit search consent
from the selected host. Otherwise normal discovery runs before query disclosure.
The content service still checks current exact authorisation, including indexing
capability. Its verified receipt establishes the exact requester completion when
it connects the retained floor; uncertain continuity requires StreamStatus.
Receipt and progress validation still precede final acknowledgement.
Before displaying matches, the client obtains a fresh batched LocalSearchLease for
the exact returned publications and any continuation item. Catalogue context never
replaces this final revocation and application-permission check.

Imports are selected explicitly with repeated `--bridge AGREEMENT=ROUTE` arguments.
Each route identifies the importing network's Bridge protocol6 endpoint. Its
signed profile must opt in with `federation bridge profile --search` and retain
current `IndexPages` authority. The destination searches its retained approved
import, with current bilateral evidence, original provenance and local review.
Search terms never travel to the source network. An import does not grant access
to other networks or merge their catalogues. Native namespaces and imported
agreements remain within the one explicitly selected network.

A new recipient first obtains a verified source inventory and hydrates each
candidate's local publication context without sending query terms. An authenticated
`FederationPageContext` refusal with code3 omits an absent, unpublished or
inaccessible import. StaleSnapshot code12, transport errors and invalid proofs
stop discovery; they are never treated as empty search results. The client obtains
fresh query-free bilateral evidence after hydration, then signs the exact current
listing dependencies. Concurrent publication or permission changes can still
refuse that listing. Titles, snippets and continuation metadata are exposed only
after local approval and current search authority have been verified.

`--local-diagnostics` permits explicitly supplied local operator service sockets.
It makes no reader-address privacy claim and is rejected inside `network connect`.
Normal connections require retained approved relay endpoints and never select a
direct fallback. Before connecting or constructing query frames, the client checks
the loaded endpoint's network, incarnation, protocol and explicitly retained
application subject. That subject must match the certified content host or
destination Bridge. The opaque route identifier is separate from this application
identity. The retained mapping pins the complete canonical route profile, including
TLS identities and voucher; a valid route for another service cannot receive terms.

Failures identify the catalogue, Page context, content placement, stream preparation,
content exchange or completion phase. These fixed diagnostic labels contain no
query terms or publication identifiers. Route timeout errors separately identify
the operation, total-connection or idle deadline. These errors do not trigger a
retry or extend a deadline.
Domain request preparation obtains a fresh clock observation after persisting the
exact request and before issuing its challenge. An unavailable observation refuses
issuance while preserving the pending request for exact recovery.

If an authority request's own deadline expires before local acceptance, the client
can recover once on a newly prepared connection with a fresh challenge for the
same signed intent. Current permission is required again; the previous challenge,
operation expiry and stream lifetime are not extended. A second expiry stops the
command with its request retained. See
[expired domain requests](AuthorityInspection.md#expired-domain-requests).

If checkpoint compaction overtakes a returned authority result, selected read-only
Page queries can request a fresh evaluation of the same signed intent. This applies
only to Page context, read, catalogue, local-search lease and content-placement
queries. It uses the same connection and only the time remaining before the
original five-second deadline. The overtaken result grants no permission and
advances no retained floor. Invalid proofs, other failures, mutations and serving
authorisations never trigger this recovery.

## Retained local search

Initialise an explicit corpus and a separate private age identity. The network
wrapper supplies the selected bootstrap and requester defaults without constructing
a search connector for `init`, `local` or `forget`.

```sh
HyperNetSuite network connect --profile Network.json -- \
  search init --corpus RetainedPages --corpus-key RetainedPages.key
HyperNetSuite network connect --profile Network.json -- \
  search retain native --page-id PAGE_ID \
  --corpus RetainedPages --corpus-key RetainedPages.key
HyperNetSuite network connect --profile Network.json -- \
  search sync --corpus RetainedPages --corpus-key RetainedPages.key
HyperNetSuite network connect --profile Network.json -- \
  search local --corpus RetainedPages --corpus-key RetainedPages.key \
  --namespace Books --term botanical
```

`retain` and `sync` accept publication identities, never query terms. Retention
uses ordinary read consent; a host need not permit network indexing for an
authorised reader to derive a local result. `retain imported` requires
`--agreement`, `--page-id` and `--bridge ROUTE`. Subsequent imported sync requires
`--bridge AGREEMENT=ROUTE`. It refreshes bilateral evidence without forwarding
queries. `retain sealed` requires `--object`, `--namespace`, `--device`,
`--recipient-vault` and `--recipient-age-key`. A device can retain both ordinary
and sealed pages under its member's current read/search grant. A different member
or device cannot silently inherit that retained corpus.

Native and imported bundles are encrypted in `RetainedSearch.age`; no plaintext
search index is written. Sealed publications remain ciphertext inside that corpus.
Local sealed matching additionally requires the authorised recipient vault and its
separate age key, and reconstructs plaintext only in memory. The corpus is bound
to its bootstrap, network, incarnation and requester. Protect the separate corpus
key like other private identities. `search forget --item ITEM_ID` removes one
retained item from the current encrypted corpus; it does not erase independently
retained backups or plaintext previously disclosed to an authorised reader.

Current local search independently verifies the retained original quorum receipt
and its exact query-free publication, grant and device scope. A requester-signed
local attestation binds that receipt to its original kernel boot and monotonic
deadline; corpus decryption-key possession alone cannot rewrite Current authority.
The original short-lived deadline is at most five seconds and is never extended. Native and sealed entries are refreshed by
one query-free batch so they can share a current window. Expired leases, changed
known dependencies, rebooted systems or unavailable clock health yield
`StaleLocked` or explicit partial coverage without exposing locked titles and
snippets. Imports additionally require live bilateral evidence. Run another
explicit sync when current authority expires. For durable offline reading, choose
`search local --historical`; its response labels the absence of current revocation
checks. It still verifies the retained exact publication and requires recipient
keys for sealed content.

A direct `search local` invocation can supply the usual `--bootstrap`,
`--bootstrap-digest`, `--directory` and `--clock-witness` paths without using the
network wrapper at all. Neither authority nor content sockets need to be mounted.

## Results and capacity

JSON results identify `scope`, `queryLeavesDevice`, `retainedView`, exact result
identity, namespace, provenance, score, tags, safe snippet and `nextCursor`.
Network coverage reports only the returned count, explicit selected scopes and
whether one continuation item was verified. It does not disclose a whole-corpus
match count or examined count from expired candidate proofs. Local coverage reports
available and locked retained items separately. `sync` reports
`currentItems`, `refreshedItems` and explicit `locked` reasons. A result cursor is
bound to the selected query, scope, corpus generation, requester and known policy
and publication versions. A changed view requires a fresh first page.

The existing protocol bounds apply: at most sixteen terms, 1,024 total term bytes,
64 selected namespaces and 100 requested results. A local lease batch holds at
most 64 exact publications and must also fit the existing 64-reference authority
proof budget, including complete permission and publication dependencies. An
oversized closure is refused, never truncated into an apparently complete lease.
A network response refreshes only the selected result page and one continuation
item; that selection must also fit the complete proof budget. Lower `--limit` if
its dependency closure exceeds the budget. Having more matches elsewhere does not
consume that page's fresh proof budget. Use repeated `sync --item` arguments to
select an explicit smaller local group when needed. A retained corpus holds at most 2,048 items and 32MiB of encoded encrypted
archive plaintext, including exact provenance and JSON byte-array representation;
large collections can use additional explicit corpora. These are decoder and
proof admission bounds, not per-second traffic limits.
