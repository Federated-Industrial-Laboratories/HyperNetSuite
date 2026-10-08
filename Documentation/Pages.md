# Pages

Pages contain inert HyperNetPage/1 text. The client never executes a page, imports
assets, interprets HTML, or fetches external links. This profile has no images.
Keep reader, author, administrator and hosting identities separate. A credential
with hosting consent cannot use ordinary Pages commands, even after its hosting
grant is removed. Use a separately invited member identity for reading.

## Author and moderator

Write a UTF-8 draft with a final LF, for example:

```text
HyperNetPage/1
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
content can be offensive. Inspect only in a suitable environment. A model adapter
is not included; decisions require a designated administrator.

An author or administrator withdraws both pending and published content with
`pages withdraw --page-id ID --expected-version VERSION`. Historical signed
records and copies already viewed cannot be recalled or securely erased.

## Reader

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

Arrow keys or `j`/`k` scroll; Page Up/Down and Home/End move further. Tab and Shift
Tab select a link. Enter follows an internal link after checking its network,
author and namespace. Cross-network trust is never added automatically. External
HTTPS references are displayed only. `b` returns through at most 16 retained pages;
`q`, Escape or Ctrl-C exits. A small terminal requests resizing. Pipes and TERM=dumb
use plain output without terminal controls. Unicode width varies by terminal;
use `--ascii` when necessary.

Normal exit and handled interrupt, termination and hangup signals restore terminal
attributes and the alternate screen. Forced process termination, a process abort
or terminal failure cannot guarantee restoration; `stty sane` and `reset` recover
a shell terminal. Page content is visually separated from authority information;
approval is not a guarantee that its statements are accurate or harmless.

## Hosting consent

Add all of the following to the resource specification used by `host-consent`:

```json
{"services":["Pages"],"namespaces":["News"],"pageCacheBytes":1048576}
```

These fields select version 2 consent. Namespace labels are case-sensitive ASCII
letters and digits, start with a letter, and contain at most 32 characters. The
cache needs at least 64 KiB and must leave 256 KiB of the state budget unused.
The service and namespace lists are exact allowlists. Version 1 remains
heartbeat-only. Register version 2 with `consent --document Consent.json` alongside
its profile hash, grants, expiry and client-certificate fingerprint. The authority
verifies the exact signed consent file before accepting its scope. Follow the
HyperNet Hosting guide to initialise and run the confined host.
