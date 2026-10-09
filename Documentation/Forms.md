# Forms

HyperNet forms declare data fields and an explicit encrypted-mail destination.
They do not contain executable code, URLs, local paths, hidden values, file
inputs or automatic actions. The supported action is `HyperNetFormMail/1` within
one network. Federated pages can display forms but cannot submit them.

A form supports bounded text, multiline text, signed integers, booleans and
choices. See [HyperPage](HyperPage.md) for the source grammar and field limits.
A form-bearing signed page bundle is limited to 20 KiB, serialized values to
8 KiB and envelope metadata to 2 KiB. The complete mail body must fit 32 KiB.
The reader checks the proof bound before accepting field input.

## Credentials and contacts

Provision sender and receiver mailboxes through [Private mail](PrivateMail.md).
Each sender needs a current Send device. Each receiver needs a current Read
device and published one-use KeyPackages. Both parties independently verify the
other address owner's fingerprint. A fingerprint declared by a page does not
create a verified contact.

A Pages application credential does not grant mail rights. An application can
use a separate PagesRead profile for publication checks and a separately enrolled
mail device in its own encrypted vault. `--config` supplies the authority endpoint,
network and pinned CA; mail operations use the explicitly selected vault device.
`--reader-config` selects the separate Pages credential for `accept`, `prepare`
and `submit`. Omitting it explicitly uses the main configured Pages credential.
Both profiles must identify the same network. No credential comes from page data.

The current private mail vault format is version 2. Older snapshots are rejected;
there is no compatibility reader or automatic conversion. Existing installed
binaries and their separate vaults are not changed by creating a new vault.

## Browser input and confirmation

Select the sending mailbox explicitly when opening the browser:

```sh
HyperNetSuite --config Reader/Profile.json browse --namespace News \
  --vault Sender/MailVault --key Sender/MailIdentity --mailbox Personal \
  --mail-config Sender/Profile.json
```

`--config` supplies the Pages credential. `--mail-config` selects the mail
authority profile; omitting it uses the Pages profile's network and endpoint.
The profiles must identify the same network. The three vault, key and mailbox
options are required together. Pages cannot select these paths or credentials.

Tab selects a field; Enter opens its local editor. Enter saves a valid value,
Escape cancels the edit and Ctrl-C exits. Ctrl-U clears the input. Ctrl-N inserts
a newline in a multiline field; Ctrl-D omits an optional field. Page Up and
Page Down scroll long input. Integers use decimal notation, booleans use `true`
or `false`, and choices use the exact published option. Bracketed paste inserts
bounded text only; it never activates shortcuts or submits a value.
Saving also checks the current layout budget. If a value would exceed it, the
editor retains the input and previous saved view so the value can be shortened
or the terminal resized before another save.

Values remain in the current browser's memory until submission preparation.
There is no autofill or background save. Back retains values with the exact page;
an unchanged refresh preserves them, while a changed publication clears them.
Draft previews and foreign pages cannot edit or submit forms. Plain output
displays the form contract without accepting input.

Activate Submit to prepare a review. The separate trusted screen shows every
value, the actual sender and recipient, the publication, expiry and storage
policy. Scroll to the end, then directly type `SEND` and press Enter. Pasted
confirmation text is ignored. Escape or `q` discards the review without sending.
Confirmation rechecks current authority before committing to the outbox.

If the browser closes or a delivery result is lost, inspect `forms reviews` and
`mail outbox`. A retained unconfirmed review can be inspected or discarded.
An already queued message uses the retry command below and its original ID.
Quitting cannot recall a confirmed delivery. The ordinary browser and
`pages read --tui` can display forms without mail credentials; use the explicit
`browse` invocation above to submit them.

## Accept an exact publication

The receiver first reads the approved page with its own Pages credential. It
accepts only a form addressed to its own mailbox and owner fingerprint:

```sh
HyperNetSuite --config Consumer/Profile.json forms \
  --vault Consumer/MailVault --key Consumer/MailIdentity \
  --reader-config Reader/Profile.json accept \
  --mailbox Intake --page-id PAGE_ID --form-id Contact
```

This operation verifies the signed bundle and current authority response. It
retains the exact descriptor, form ID, schema digest and bundle digest in the
receiver's encrypted vault. Every changed page publication needs a fresh accept
operation. `forms accepted` lists the retained records. Mail rights alone cannot
create acceptance without a successful independent Pages read. Self-signed page
proofs supplied by a sender do not establish publication authority.

## Prepare, review and send

Save typed JSON values in a file owned by the current user with mode 0600.
For example, `{"Name":"Ada","Count":2,"Reply":true,"Topic":"Support"}`.
Unknown fields, incorrect types, missing required values and values outside the
published bounds are rejected.

```sh
HyperNetSuite --config Sender/Profile.json forms \
  --vault Sender/MailVault --key Sender/MailIdentity \
  --reader-config Reader/Profile.json prepare \
  --mailbox Personal --page-id PAGE_ID --form-id Contact --values Values.json
```

Preparation fetches the current approved page, checks the pinned contact and
recipient manifest, then stores an immutable encrypted review. It sends no mail.
The returned review contains the actual sender, recipient, page/version, form,
all values, exact expiry, recipient manifest digest, selected storage hosts,
required copies and retention policy. `--expires UNIX_SECONDS` can request a
shorter lifetime. The default also respects every current receiving Read device's
expiry, the sending device and both address lifetimes.

Read every review field before confirming. A retained review can be shown again
with `forms review --review-id REVIEW_ID` or removed with
`forms discard --review-id REVIEW_ID`. `forms reviews` lists retained identifiers
without values, including reviews saved before an interrupted response.
Confirmation is a separate operation:

```sh
HyperNetSuite --config Sender/Profile.json forms \
  --vault Sender/MailVault --key Sender/MailIdentity \
  --reader-config Reader/Profile.json submit \
  --mailbox Personal --review-id REVIEW_ID --confirm
```

Confirmation rechecks the exact page and both mailbox manifests. Any change
requires a new prepare and review. It commits the exact submission ID, body and
reviewed destination policy to the encrypted outbox before delivery. The
submission ID equals the mail message ID. The review is consumed in that same
commit; confirming it again cannot create another message.

`Queued`, `Partial`, `Stored` and `durable` have the normal mail meanings.
A successful command can report a queued item and an error; inspect its result.
These receipts describe encrypted storage, not successful business processing.
If a retry fails before reconciliation completes, the result preserves known
receipt-derived durability and lists its stored hosts. `retryConfirmed: false`
and `error` describe the failed new attempt; they do not undo earlier receipts.

```sh
HyperNetSuite --config Sender/Profile.json forms \
  --vault Sender/MailVault --key Sender/MailIdentity retry \
  --mailbox Personal --message-id MESSAGE_ID
```

Retry never creates a replacement submission. Before encryption, changed sender
or recipient policy blocks the original queued record. After encryption, receipt
reconciliation runs before considering another upload, retaining the same
ciphertext and message ID. A lost response does not authorise another ID.
`mail outbox` lists queued records; `mail cancel` removes only a local queued copy.
Withdrawal or cancellation cannot recall data already delivered.

## Receive typed data

```sh
HyperNetSuite --config Consumer/Profile.json forms \
  --vault Consumer/MailVault --key Consumer/MailIdentity receive \
  --mailbox Intake --host HOST_PUBLIC_KEY --message-id MESSAGE_ID
```

The receiver authenticates the mail delivery and checks the strict
`HyperNetFormSubmission/1` body against the authenticated route, message ID,
network, sender/device, recipient, recipient manifest and expiry. It verifies the
exact signed page bundle and the schema digest over the original Form block.
Only an exact independently accepted publication can produce `status: Accepted`
and typed values. Unknown profiles or unaccepted publications return
`Unrecognised`; they remain ordinary mail data. Malformed known submissions fail.
No referenced images are fetched and no business action is performed. Accepted
input proves the authenticated sender, accepted publication and field constraints;
it does not prove truthful answers or use of this particular interface. An accepted
historical publication can remain usable after withdrawal for data already queued.

After authenticated delivery has been saved, `receive --local` processes that
same receiving device's local archive without another network read. Imported or
self-authored archive records cannot become authenticated intake through this
option. A durable ledger binds each accepted submission ID to its exact received
body and route. The same payload returns `duplicate: true`; conflicting reuse is
rejected. The vault retains at most 64 unsubmitted reviews, 128 accepted form
publications and 1024 ledger entries. Exhaustion fails without evicting replay
history. The whole encrypted vault also retains its existing 32 MiB bound.

`Tools/FormsConsumer.py` is a minimal independent consumer. It uses a dedicated
mail device and emits validated JSON data. Run the separate receiver acceptance
operation above using a PagesRead profile first. The example never accepts a
page, sends mail or invokes a business action. Applications must use the supplied
submission ID to deduplicate downstream effects in their own transactions;
transport retries do not guarantee exactly-once business processing.
