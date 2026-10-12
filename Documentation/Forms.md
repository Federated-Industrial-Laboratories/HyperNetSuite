# Forms

HyperNet forms declare fields and an explicit encrypted Mail destination. They
contain no executable validation, hidden values, file inputs, local paths,
automatic submissions or destination URLs. The `HyperNetFormMail/1` action uses
an approved native Page and a separately authorised Mail device in the same
network and incarnation. Page approval does not confer Mail permissions.
Imported foreign Pages cannot submit through this native Mail action.

Text, multiline text, integers, booleans and choices use the inert schema in
[HyperPage](HyperPage.md). A form-bearing canonical Page bundle is at most20KiB;
encoded values are at most8KiB. The complete JSON submission, including its
base64 bundle and publication references, must fit the32KiB Mail body. These
bounds apply together; their individual maxima cannot always be combined.

## Identity and placement

Provision the sender and recipient using [PrivateMail](PrivateMail.md). The
sender uses a current Send device; the recipient uses a current Read device and
published one-use encryption packages. Verify the recipient owner independently
with `mail contact-verify` before preparing a form. A fingerprint declared by a
Page never creates a verified contact.

Pages and Mail use separate requester identities and durable floors. Both use
the independently accepted bootstrap and explicit private authority socket.
The Page reader may be a member or a scoped application. Its credential never
substitutes for the selected Mail device. Current mailbox137 authority includes
its manager's SendMail15 capability and the device's specific permission.

A review shows the exact Page ledger140, revision141, approval142 and immutable
bundle, every entered value, sender device, recipient owner, mailbox versions,
expiry, selected stores, required copies, retention and private placement.
Private placement remains the recipient owner's exact selection; no default
store is added. Confirmation refuses changed Page or mailbox metadata. The
immutable outbox also refuses a changed mailbox version at package claim time,
including private placement and device or signed-manifest revisions.

## Prepare and confirm

These commands use normal `--bootstrap`, `--bootstrap-digest`, `--directory`,
`--clock-witness` and optional monitor pins. Page operations also take `--key`,
`--socket` and `--grant` (and `--grant-record` for an uncached delegated grant).
For them, `--directory` is the Page floor, and `--mail-directory` selects the
separate Mail device floor. `--vault`, `--age-key` and `--mailbox` select local
Mail state.

1. Write typed values to a private mode0600 JSON file, for example
   `{"Name":"Ada","Reply":true}`. Unknown fields, missing required values and
   values outside the schema fail before a draft is stored.
2. Run `forms prepare` with the Page and Mail options above, `--page PAGE_ID`,
   `--form FORM_ID`, `--values Values.json` and `--expires UNIX_SECONDS`.
   Preparation performs authorised metadata reads and saves an encrypted review;
   it neither claims an encryption package nor sends a message.
3. Inspect the returned review or use `forms review --review REVIEW_ID` with
   the local trust and Mail options. `forms reviews` lists unconfirmed drafts.
4. Run `forms confirm --review REVIEW_ID --confirm-submission` with the same
   Page and Mail options. This checks the current publication and mailbox state,
   then atomically moves the draft into an immutable encrypted outbox. It returns
   a message ID without sending it. A repeated confirmation returns that same
   confirmed message.
5. Run `forms send --message MESSAGE_ID` using the ordinary Mail device options
   (`--directory` is now the Mail floor), and `--service SERVICE_KEY` plus either
   `--service-socket PATH` or `--service-directory PATH --core HyperNet`.
   Repeat the same command and message ID after interruption. Multiple explicitly
   selected stores require their own send; the result reports confirmed copies.

`forms cancel --review REVIEW_ID` removes only an unconfirmed draft. Confirmed
messages remain in `mail outbox`; cancellation cannot recall a delivered message.
Retries preserve the original message, package claim, ciphertext and receipts.
If current policy no longer matches the confirmed consent, prepare and confirm
a new submission. No command silently edits the existing message to fit it.

The browser uses these same operations while borrowing its existing Page
connection. Its trusted confirmation must display every value and the actual
recipient and storage policy before explicit approval. Pages cannot choose
credentials, local files, service sockets or the user's confirmation.

## Terminal editing

In a native Page, select a form field with Tab and press Enter to edit it. Enter
validates and saves the local value; Escape discards that edit. Ctrl-U clears the
editor, and Ctrl-D omits an optional field. Ctrl-N inserts a newline only in a
multiline field. PageUp and PageDown scroll a long edit. Boolean fields accept
`true` or `false`; choice fields require one of the declared values. Pasted text
is bounded input and never submits or invokes a browser command. Ctrl-C exits
the browser.

Activate the form's Submit control to prepare its separate encrypted review.
Scroll to the end of the trusted review, then type `SEND` and press Enter to
confirm. This review includes every entered value and the actual identities and
placement. Escape cancels sending and leaves the draft available through
`forms reviews`. The CLI's `--confirm-submission` is the corresponding explicit
approval; inspect `forms review` before supplying it.

## Receive typed submissions

Run `forms accept --page PAGE_ID --form FORM_ID` with the receiver's Page options
and separate receiving Mail device. This independently reads the currently
approved bundle and requires the form to target that mailbox and its owner.
The encrypted vault retains the exact accepted publication and schema.
`forms accepted` lists these records. A new approved revision requires its own
acceptance; merely receiving signed content does not establish that acceptance.

`forms receive --message MESSAGE_ID` uses the receiving Mail device and explicit
store transport. It performs the current authenticated Mail fetch, verifies and
decrypts the MLS letter, then checks the complete route, exact Page bundle,
schema and values against the receiver's independently accepted publication.
`forms receive-local --message MESSAGE_ID` performs only the latter checks on a
letter already authenticated for the selected local device. Plaintext disclosure
files and arbitrary JSON are not intake sources.

Before returning `Accepted`, intake durably records a digest of the exact body
and authenticated route under the submission ID. An identical repeated message
returns `duplicate: true`; a conflicting reuse fails. Unrecognised mail or an
unaccepted publication produces `Unrecognised`. These results never execute
business actions: a consumer must handle its own application transaction.

Drafts, outbox consent, accepted publications and the permanent replay ledger
share the existing age-encrypted32MiB vault budget. There are no separate small
lifetime counts. Admission refuses when the actual snapshot no longer fits;
replay entries are not evicted. Removing a local archived letter does not remove
its replay identity. Normal network effects continue to use current quorum,
clock, device, one-use claim and serving-receipt checks.

This workflow uses explicit local control and installed service exchange.
Scope-safe remote reader routes are a separate requirement; no direct reader
network fallback is supplied here.
