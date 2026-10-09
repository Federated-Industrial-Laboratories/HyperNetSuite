# Pages

Pages contain inert HyperNetPage/2 components. The client never executes a page,
interprets HTML, or fetches external links. Images require exact manifests and
explicit reveal; [Media](Media.md) describes authoring and separate storage consent.
Keep reader, author, administrator and hosting identities separate. A credential
with hosting consent cannot use ordinary Pages commands, even after its hosting
grant is removed. Use a separately invited member identity for reading.

The [HyperPage specification](HyperPage.md) defines responsive components, colours,
local actions and the strict authoring limits.

## Author and moderator

Write a UTF-8 draft with a final LF, for example:

```text
HyperNetPage/2
# Welcome
: This paragraph is information.
## Notices
- A list item
=> https://example.com/ External reference
```

Use `pages preview Draft.txt --tui` to inspect local text. Preview is explicitly
unapproved. Omit `--tui` for plain output. `--ascii` escapes non-ASCII characters.
The source limit is 16 KiB, 512 lines, and 1024 bytes per line. Controls and unknown
markup are rejected. See HyperNet's Pages specification for the full grammar.

With the author's configuration:

```sh
HyperNetSuite --config Author.json pages submit --file Draft.txt --namespace News --output Submission.json
HyperNetSuite --config Author.json pages queue
```

The private retry file is written before transmission and contains the exact
signed submission and its generated page ID. Retry the same command with the
same file after an uncertain response. The request freshness window is 60 seconds.
After that window, inspect the retained page ID to determine the current version;
do not assume that a timed-out request failed. Keep retry and review files private.
For an update, pass `--page-id ID --expected-version VERSION` from inspection.
A pending replacement leaves the previous approved publication visible.

With a separate administrator configuration:

```sh
HyperNetSuite --config Administrator.json pages queue
HyperNetSuite --config Administrator.json pages inspect --page-id ID --output Review.json --tui
HyperNetSuite --config Administrator.json pages review --input Review.json --decision approve
```

Use `--decision reject` to discard the pending revision. Review binds the saved
exact source, author, namespace, audience, profile, digest and version. Concurrent
changes make an old decision fail; inspect again before deciding. Unapproved
content can be offensive. Inspect only in a suitable environment. [Adapters](Adapters.md) provides separate
review application grants and explicit optional model data exchange. Manual review
remains the default.

An author or administrator withdraws both pending and published content with
`pages withdraw --page-id ID --expected-version VERSION`. Historical signed
records and copies already viewed cannot be recalled or securely erased.

## Reader

Use the [Browser](Browser.md) for catalogue and address navigation with retained
page focus and scrolling. Existing TUI read commands use that same browser.

```sh
HyperNetSuite --config Reader.json pages list --namespace News
HyperNetSuite --config Reader.json pages read --page-id ID --tui
HyperNetSuite --config Reader.json pages read --page-id ID --replica HOST_PUBLIC_KEY
```

A replica request requires the named consenting host to supply its verified cache
bytes through the broker. It does not silently fall back to origin content.
Delivery tickets expire after 15 seconds; individual network calls time out after
10 seconds. Client polling has a 20-second deadline checked between calls.

The client independently verifies the author's and reviewer's signatures, source
hash and exact approval bindings. Current publication permission comes from a
fresh authenticated authority response. The screen identifies approval at fetch;
retained text does not imply continuing permission. Press `r` to revalidate.
Outages, withdrawals or revocations prevent new authorised fetches, but cannot
retract bytes already received. Administrators remain trusted for authorisation.

[TerminalLayout](TerminalLayout.md) describes responsive rows, panels, independent
scrollboxes, Unicode clipping, logical colours and the complete keyboard controls.
Tab and Shift-Tab select controls; Enter activates a button. Arrow and page keys
scroll the selected viewport. `p` selects whole-page scrolling, `m` toggles
monochrome and `i` displays trusted metadata and the full selected destination.
Plain output contains every component's content, including offscreen text.

Internal links retain the network, author and namespace checks. Native and foreign
pages use one navigation history. Foreign links require an active local agreement
for their exact origin network and namespace; trust is never added automatically.
A selected native replica remains required for native links and prevents following
foreign links. External HTTPS references are displayed only. `b` returns through
at most 16 retained pages; `r` refreshes the current native or federated publication
with its corresponding proof checks. Back at the first page keeps that page open.
`q`, Escape or Ctrl-C exits the reader. Approval does not guarantee that a page's
statements are accurate or harmless.

## Hosting consent

Every host registration requires the exact signed version 3 consent document.
The specification explicitly includes services, namespaces and both cache limits:

```json
{"services":["Pages"],"namespaces":["News"],"pageCacheBytes":1048576,"pageMediaCacheBytes":0}
```

Namespace labels are case-sensitive ASCII identifiers. A Pages cache is at least
64 KiB and fits inside the consented state allowance after its 256 KiB reserve.
Page text hosting does not grant media storage; its media cache allowance must
be zero. Media uses the separate PageMedia consent and store. Heartbeat-only
consent uses empty services/namespaces and both caches zero. Omitting these fields
or using a retired consent format is rejected.

Register with `consent --document Consent.json` and the matching profile,
certificate, grants and expiry. Possessing a profile hash alone grants no hosting
rights. The infrastructure independently verifies the signed document and scope.
See [Usage](Usage.md) for the complete signed hosting procedure.
