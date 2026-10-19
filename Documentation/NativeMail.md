# Native Mail

[Documentation](ReadMe.md) | [Project README](../ReadMe.md)

HyperNet Mail is a native desktop client for existing HyperNet mailboxes. It uses
the same encrypted vault, verified contacts, retained request state and selected
network routes as the command-line client.

Build or install HyperNetSuite with its `gui` feature. Enrol the mailbox and
initialise its device requester with the [Mail commands](PrivateMail.md) first.

```sh
HyperNetSuite mail gui \
  --profile /Private/Network.json \
  --vault /Private/MailVault \
  --age-key /Private/MailAge.key \
  --mailbox Personal
```

The profile must retain successful network membership and a Mail route for each
selected store. The application does not fall back to direct connections or SSH.
The vault and age identity remain private local files. Account creation,
enrolment, placement changes and device administration remain CLI operations.

## Read mail

Choose a mailbox and store, then select **Refresh** in **Inbox**. The list contains
encrypted message identifiers and sizes. **Open** retrieves and decrypts one
message, then saves it in the local encrypted archive. **Archive** opens retained
letters without contacting the storage host. Message bodies are inert text;
opening a message does not fetch embedded resources.

Inbox pages contain up to 16 identifiers. **Next page** requests the next page.
**Receive keys** publishes four one-use keys for subsequent messages.

## Verify contacts and send

1. Obtain the recipient's address and owner public key through an independent
   authenticated channel.
2. Open **Contacts**, enter both values, acknowledge independent verification and
   select **Verify contact**. A network directory alone is not verification.
3. Use **Compose** to enter the recipient, subject, message and expiry. **Save
   draft** stores the letter locally; it does not send it.
4. In **Outbox**, choose the recipient's store and select **Review / retry**.
5. Inspect the full recipient address, verified owner, mailbox revision, selected
   store, expiry and message. **Send to selected store** confirms that exact item.

The confirmation binds the content and recipient revision. A mailbox change
between review and claiming is refused. The selected store must belong to the
recipient's placement. For multiple required copies, review and send the same
message to each selected store. Stored-copy acknowledgements do not mean that the
recipient has opened the message.

The subject is limited to 512 UTF-8 bytes and the body to 32,768 UTF-8 bytes.
Expiry can be 1 through 168 hours; current mailbox and service limits can require
a shorter lifetime. Drafts are immutable after saving. Compose another draft to
change an unsent letter.

## Recover an interruption

**Retry exact operation** repeats the retained command after a transient error.
For a send interrupted before closing the application, reopen **Outbox**, select
the same message and store, then review and send again. The existing request and
ciphertext are resumed. A new message is not a substitute for resolving an
uncertain send.

An unfinished command-line or Page-form send retains its original workflow; the
Mail window does not replace that confirmation or discard its pending operation.

## Delete copies

**Delete stored copy** deletes only the selected storage copy. The confirmation
shows the exact message and store. The local archive remains available.
**Delete local copy** permanently removes this device's readable archive entry.
The one-use decryption key was erased when the letter was first archived, so
fetching its stored ciphertext cannot restore it. An unfinished fetch must be
completed before deleting the archive. Other stores and recipients can retain
their copies.

## Controls and settings

Tab and Shift+Tab move between controls. Enter activates a focused button. Focus
a scroll region to use Up/Down, PageUp/PageDown and Home/End. **Settings** and
**Help** have dedicated windows; Ctrl+, and F1 open them. Text size uses the same
persistent setting as the browser.
Ctrl+C copies selected text; Ctrl+V pastes into an editable field.

Closing the application cancels further network work. An operation whose remote
outcome is uncertain remains recorded for exact recovery.
