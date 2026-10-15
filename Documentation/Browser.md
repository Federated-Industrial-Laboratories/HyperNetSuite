# Browser

The browser uses an independently accepted bootstrap, a retained requester floor,
an explicitly selected authority endpoint and a scoped Page capability.
Use [PrivateRoutes](PrivateRoutes.md) for a relay-only client connection; the
`network connect` wrapper supplies its retained trust and endpoint. It does not
discover networks or open external applications. Every fetched Page carries
current quorum evidence and its exact signed author, reviewer and source bundle.
Pages remain inert HyperPage documents.

```sh
HyperNetSuite browse [online options] --grant GRANT --namespace News
HyperNetSuite browse [online options] --grant GRANT hypernet://NETWORK/AUTHOR/News/PAGE
HyperNetSuite browse [online options] --grant GRANT --namespace News --after CURSOR
```

Online options select the bootstrap file and its independently verified file
SHA256, private requester directory, signing key, authority socket and trusted
clock witness. See [Pages](Pages.md). The signing identity may be a member or an
explicitly scoped application; registration alone does not confer Page access.

NETWORK and AUTHOR are complete64-character lowercase hexadecimal identities;
PAGE is a complete32-character identity. CURSOR is the exact64-character record
cursor returned by the catalogue, rather than a raw Page identity. It cannot be
combined with a Page address. `--namespace` selects the native catalogue.

## Catalogue and addresses

Without an address, `browse` fetches a catalogue from the configured authority.
Each bounded batch carries certified publication records and an explicit continuation cursor. Entries show identities
and publication information, not titles extracted from unfetched page bodies.
Select an entry and press Enter to fetch and verify its content. Catalogue access
does not approve a draft or confer access to another namespace or network.

The catalogue does not prefetch another batch or a page body. Press `n` for the
next batch and `p` for the preceding retained batch. The next cursor comes from
the authority response. A retained batch is a previous observation; refresh it
to obtain current availability. Opening an entry always checks the publication.

Press `o` to enter an address. The editor accepts at most 512 ASCII characters.
Ctrl-U clears the entry; Enter submits it and Escape cancels. Ctrl-C exits the
browser. Other ordinary input and bracketed paste cannot become browser shortcuts
while the editor is active.
Invalid or oversized pasted values are rejected as a whole. Pasted text never
submits itself. Terminal input decoding and pending escape sequences are bounded.

A native address must identify the exact network, author, namespace and page.
The fetched publication must match all four values. The native browser refuses another network; use the explicit Federation workflow.
An address cannot select a different endpoint, certificate or identity.
HTTPS references are displayed as external references and are not fetched or
passed to a browser, shell or other program.

## Keys and retained state

| Key | Operation |
| --- | --- |
| o | Open address entry |
| c | Open the configured native catalogue |
| ? | Show or hide browser help |
| b | Return to the previous retained view |
| r | Refresh the current catalogue or verify the current page again |
| q / Escape / Ctrl-C | Exit; address entry uses Ctrl-C to exit and Escape to cancel |
| Arrows / Tab | Select catalogue entries; page controls follow the layout manual |
| Enter | Open the selected catalogue entry or activate the selected page button |
| n / p | Next or previous catalogue batch |
| i | Show the page's trusted publication details and full selected destination |
| m | Toggle publisher colours and monochrome |
| a | Start or pause the page's bounded local motion |

See [TerminalLayout](TerminalLayout.md) for page scrolling, nested focus, wrapping
and colour controls. The browser keeps at most 16 prior views in memory. Back
restores that view's page offset, selected control and scrollbox offsets. It does
not fetch or claim current permission for previously received content. There is
no persistent browsing history or automatic background refresh.

Refreshing an unchanged exact publication preserves its view. A changed
publication resets document-specific state. The monochrome setting remains a
reader preference across navigation; a nonempty `NO_COLOR` variable forces it.
Resizing recomputes layout within the existing bounds and reveals selected controls.

## Errors, waiting and plain output

Status and help are browser-owned content outside the page rectangle. A failed
load leaves the previous verified page visible, with a bounded sanitised error.
A failed refresh does not promote that retained display to a current publication.
A page whose layout exceeds the cell budget is refused before replacing the
current view. If resizing makes a retained page too large to lay out, trusted
chrome reports `Layout unavailable` and keeps navigation and help available.
Shrinking the terminal retries layout without refetching the page.

Withdrawal, revocation or an unavailable authority can prevent new reads without
erasing bytes already received. The publication details distinguish retained
display from permission checked at fetch.

Only one explicitly requested network operation is pending at a time. The browser
remains responsive to quit and termination signals while that operation waits.
Leaving the browser restores terminal attributes, cursor and alternate screen;
it does not revoke a request already sent to the authority. Confirmed form mail
may already be queued or delivered; inspect the encrypted outbox before retrying.
Transport calls
remain bounded by the existing connection and request deadlines.

Pipes and `TERM=dumb` produce complete plain output and exit. With an address,
the output contains the verified page and all offscreen component text. Without
one, it contains one catalogue batch and its next cursor. Use `--after` to request
another batch explicitly. `--ascii` escapes non-ASCII display text. Plain output
has no terminal styling, automatic navigation or page actions.

`pages read --tui` shares this browser session and recoverable navigation. Local preview and moderation remain explicitly
unapproved; they do not gain network navigation from page content.

Native forms support local field editing and a separate trusted send review.
See [Forms](Forms.md) for explicit mailbox selection, keyboard controls,
confirmation and recovery. Pages cannot choose local credentials, autofill
values or submit automatically.
The sender must independently verify the destination owner with
`mail contact-verify` and publish its scoped Send device before using Submit.
The recipient separately accepts the exact approved form before typed intake.

Images remain labelled placeholders until the reader activates an explicit
Reveal control. Each fetch rechecks the exact page and consented media route.
Select a graphics protocol explicitly; unsupported terminal contexts retain
alt text. Animation uses local clocks and cached pixels, with no network frame
stream or background fetch. See [Media](Media.md) for commands and
[MediaViewer](MediaViewer.md) for supported graphics, isolation and limits.

## Explicit media and form access

Pass `--media-route HOST=/Private/MediaControl.sock`, or
`--media-service HOST=/Private/InstalledService` with `--media-core /Path/HyperNet`.
Each host must already occur in the exact approved asset manifest. Repeat these
options for distinct hosts. No endpoint comes from Page text. Select an existing
private persistent `--media-directory /Private/BrowserMedia`; exact asset/host jobs
survive interruption. Retrieval resumes its retained operation before new work,
then checks the current publication again before revealing pixels. Local
inspection can instead bind `--media AssetId=/Explicit/CanonicalFile`.

Enable form submissions with `--form-directory`, `--form-vault`, `--form-age-key`,
`--form-mailbox` and `--form-service`. The Mail directory belongs to a separately
scoped requester, in the same network and incarnation. Choose either an explicit
`--form-socket` or `--form-service-directory` and optional `--form-core`.
`--form-retention-seconds` defaults to3600; the recipient's current policy must
permit the requested duration. Choose a shorter duration when its policy requires
it. This setting never extends mailbox or device expiry.

Submitting first prepares an encrypted draft and opens a separate trusted review.
Read all values, identities and placement details before typing SEND. Confirmation
rechecks the exact displayed publication and Mail versions, then durably records
the immutable outbox entry before sending. Changed content or placement requires
new review. Cancellation sends nothing and retains the draft for the Forms CLI.
A failed send reports the exact message identity to resume with `forms send`;
closing the terminal does not cancel an already confirmed transmission.

## Catalogue discovery

Use [Search](Search.md) to find verified native or approved imported publications,
or to query an encrypted explicitly retained local corpus. Local and Network are
explicit command scopes; a failed local query never becomes a network request.
Search results include provenance and native Page URIs suitable for subsequent
explicit navigation. Search does not submit forms or activate media effects.
