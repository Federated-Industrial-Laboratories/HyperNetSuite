# Native Transfers

[Documentation](ReadMe.md) | [Project README](../ReadMe.md)

HyperNet Transfers provides encrypted file exchange through the accepted routes
of one retained network profile. It uses the same offers, recipient acceptance,
requester state, encrypted vault and private transport as the transfer CLI.

## Open the application

```sh
HyperNetSuite transfers gui --profile Network.json \
  --vault TransferVault --age-key TransferIdentity.key \
  --sender-grant SENDER_GRANT_ID --recipient-grant RECIPIENT_GRANT_ID
```

The profile must have an admitted membership, authenticated clock witness and
approved authority and transfer routes. Capability 18 permits sending; capability
19 permits receiving. Supply either or both grants for the intended operations.
When a grant is not already retained, add its authenticated record with
`--sender-grant-record` or `--recipient-grant-record`.

The application opens an existing private transfer vault. If no vault exists,
select **Create vault** and confirm creation at the supplied paths. Parent
directories must already exist. Existing state and keys are never replaced.

**Local outbox → My transfer identity** shows the participant identifier and the
separate public age encryption key. Authenticate both independently with the
sender. Never share the private age identity file. The encrypted vault is bound
to the accepted network and participant.

## Send a file

1. Select **New transfer** and **Choose file**.
2. Enter the recipient participant key and independently verified public age key.
3. Enter a public label and a duration in minutes, hours or days (up to seven days).
4. Select **Prepare offer**. This encrypts and retains the exact file locally.
5. Review the recipient, encryption key, ciphertext digest, size and expiry.
   Confirm verification of the keys, then select **Publish**.
6. Refresh the agreement after the recipient accepts a store.
7. Select **Upload / resume** and confirm the accepted store.

Changing the source file after preparation does not change the retained offer.
An unpublished offer remains in **Local outbox**; **Review publication** resumes
its exact publication. Ciphertext, including encryption overhead, cannot exceed
8 MiB. The vault retains at most its existing 64 MiB encrypted snapshot limit.

## Receive a file

1. Select **Received offers**, or enter a transfer identifier and select **Inspect**.
2. Select **Find stores**. Choose a consenting store with an approved route.
3. Enter a destination label. Acceptance lasts until the offer expires, limited
   by the selected store's displayed lifetime. Select **Shorter duration** if needed.
4. Select **Review acceptance**, verify the offer and store, then select **Accept**.
5. After upload, select **Choose output** and select a new output path.
6. Select **Download / resume**, review the output path and confirm.

Expiry displays show remaining time; hover for the exact UTC timestamp and Unix
milliseconds. Preparation and acceptance review retain a fixed absolute expiry,
so confirmation and retry do not extend it.

The destination label belongs to the agreement; it is not a filesystem path.
The output path remains local. Downloads authenticate the complete ciphertext,
recipient key, encrypted file context and plaintext digest before creating a
private file. Existing files and symbolic paths are refused. Content is never
executed or extracted. The sender's embedded filename does not choose the path.

## Progress and recovery

Network operations run in a serialized background worker. **Pause** finishes the
current request and retains acknowledged chunks. Upload and download resume from
this retained progress. Closing the application retains uncertain operations;
reopening never starts a replacement request or fences a stream automatically.

After an error, **Retry exact operation** repeats the reviewed request. On restart,
**Local outbox** displays a retained operation with **Review recovery**. This
reconciles the exact retained intent. A retained download also requires a new
output path. If another application owns the pending request, recover it there.
After recovery, refresh the list or reopen the local vault view.

Lists expose explicit **Next page** and **More stores** controls. No automatic
route substitution occurs when a selected store is unavailable.

## Remove data

**Store status** obtains a fresh report. **Delete stored data** removes the
recipient's ciphertext at the accepted store. **Cancel transfer** prevents future
store operations; delete first when both actions are needed. **Forget local data**
removes only this participant's retained ciphertext and partial download. Each
operation requires an explicit review. None erases previously disclosed copies,
backups or physical media remnants.

Settings and Help open separate windows. Appearance settings are shared with the
native Browser and Mail applications. `Ctrl+,` opens Settings; `F1` opens Help.
Use `Ctrl+C` and `Ctrl+V` to copy selected text and paste into fields.
The graphical application uses the standard GUI build. Terminal-only builds keep
all transfer CLI commands and omit `transfers gui`.
