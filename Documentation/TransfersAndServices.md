# Transfers and services

HyperNetSuite 0.5 provides independent Linux clients for encrypted file transfer
and separately consented SSH services. These commands use the documented HTTPS
interfaces; they do not read server databases or require a HyperNet source tree.
They operate within one network. Federation does not grant access automatically.

## Trust and local state

Configure each member as described in [Usage](Usage.md). Verify the network root
and the separate service authority signing fingerprint through a trusted channel.
The authority and store must support HyperNet 0.5 or newer. Member credentials,
mail device keys, transfer encryption identities and native SSH keys have separate
roles. A mail-only device cannot transfer files or request SSH access.

Create a transfer vault for each member and network. Parent directories must
already exist. The command creates a new mode 0700 directory and mode 0600 key:

```sh
HyperNetSuite --config Member.json transfers --vault TransferVault --key TransferIdentity.txt init --authority-key SERVICE_AUTHORITY_KEY
```

Save the printed `ageRecipient` and exchange it with senders through an
authenticated channel. The native age X25519 identity encrypts both this vault and
received files. It is not an authority signing credential. Keep the private key
separate from backups of the encrypted vault. Losing the key loses recovery.
Compromise of this static key permits decryption of retained ciphertext; this
profile does not claim forward secrecy. There is no hidden decryption service.

Local state uses a locked, authenticated encrypted snapshot. It preserves the
exact offer, immutable ciphertext and partial receive progress across restarts.
The vault permits 64 outgoing and 64 incoming entries, within a 64 MiB snapshot.
Keep a protected backup before replacing the device or moving the vault. Restore
into a private directory with the matching key; never run two copies concurrently.
There is no automatic rollback recovery for a restored older snapshot.

## Offer, accept and send

The sender encrypts one regular file before submitting any offer. An offer
contains sender and recipient member keys, recipient age public key, ciphertext
size and SHA256, plaintext byte count, expiry and an opaque label. The filename
and plaintext hash exist only inside the encrypted file. Use a non-sensitive
label of 1-64 ASCII letters, digits, hyphens or underscores. By default the random
transfer ID is the label. Maximum ciphertext size is 8 MiB, including encryption
and metadata overhead; plaintext must be slightly smaller. Empty files work.

```sh
HyperNetSuite --config Sender.json transfers --vault SenderTransfers --key SenderAge.txt offer --recipient RECIPIENT_MEMBER_KEY --recipient-age age1RECIPIENT --file Report.bin --expires UNIX_TIME
HyperNetSuite --config Recipient.json transfers list
HyperNetSuite --config Recipient.json transfers inspect --transfer-id TRANSFER_ID
HyperNetSuite --config Recipient.json transfers hosts
HyperNetSuite --config Recipient.json transfers --vault RecipientTransfers --key RecipientAge.txt accept --transfer-id TRANSFER_ID --host SELECTED_HOST_KEY --destination Inbox
HyperNetSuite --config Sender.json transfers --vault SenderTransfers --key SenderAge.txt send --transfer-id TRANSFER_ID
```

The recipient must explicitly accept the immutable offer and select a live
consenting store. Acceptance checks that the offer names the recipient's actual
local age identity. `--destination` is an opaque recipient label, not a filesystem
path. Acceptance expires no later than the offer and selected host consent; an
optional `--expires UNIX_TIME` can shorten it. Authority reserves capacity before
upload. There is no fallback to another store and no automatic acceptance.

`send` uploads 64 KiB chunks and commits only after full ciphertext size and digest
verification. `resume` is an alias. `--max-chunks 1` intentionally stops after one
chunk, allowing bounded progress. The final JSON field `complete` is the delivery
result; command success alone does not mean all bytes have been uploaded.

A failed connection preserves the exact encrypted job. Repeat `send` to query
signed store status and resume at the durable prefix. Exact chunk retries are
idempotent. A lost final response is reconciled against the same stored object.
A failed initial registration prints the saved ID; `register --transfer-id ID`
retries that offer. `outbox` lists local saved IDs, including unregistered jobs.
`status --transfer-id ID` verifies current policy and the selected store receipt.
These commands take the same `--vault` and `--key` arguments as `send`.

## Receive and delete

Create a private output directory first, then select the new filename explicitly:

```sh
mkdir -m 700 Received
HyperNetSuite --config Recipient.json transfers --vault RecipientTransfers --key RecipientAge.txt receive --transfer-id TRANSFER_ID --destination Inbox --output Received/Report.bin
```

Receive verifies the signed offer, recipient acceptance, selected TLS store and
signed complete receipt. Each chunk is bounded and the complete ciphertext must
match its signed SHA256 and byte count. age authenticates the plaintext; its
internal context, size and hash must match the offer. Current authority and store
permission are checked again after decryption. Only then does an atomic
no-replacement rename expose a mode 0600 file. Existing files, destination races,
parent traversal, symlink components and device inputs are refused. An interrupted
download resumes from encrypted local state; an output is never partially exposed.
The sender's filename is informational only. There is no archive extraction or
execution. Existing files are never overwritten, including on a repeated receive.

```sh
HyperNetSuite --config Recipient.json transfers --vault RecipientTransfers --key RecipientAge.txt delete --transfer-id TRANSFER_ID
HyperNetSuite --config Sender.json transfers cancel --transfer-id TRANSFER_ID
HyperNetSuite --config Sender.json transfers --vault SenderTransfers --key SenderAge.txt forget --transfer-id TRANSFER_ID
```

Only the recipient can delete selected-store ciphertext. Either participant can
cancel at authority. Cancellation, expiry, revocation and withdrawn host consent
deny further operations; the store prunes under current authority policy. A
cancelled offer cannot be revived. `forget` removes local saved transfer state
only after cancellation, expiry or verified store deletion. Expired local jobs
remain removable after authority history has expired, without network access.
The initial authority permits 32 unexpired offers per sender and 256 across
the network; expiry releases that directory capacity. Store deletion does
not erase recipient copies, backups or physical media remnants. Ciphertext,
participant identities, sizes, timings and destination labels are visible to
selected infrastructure; filesystem paths and file names are not.

## Transfer store operators

Use a separate host identity with hosting rights and the Core transfer store
runtime. Supply a complete `TransferHost` JSON specification with version 1,
network and host key, generation, services `["Transfer"]`, endpoint and pinned
literal address, CA file SHA256 and certificate DER SHA256, authority endpoint,
authority address and service signer, memory/PID/CPU/state limits and expiry.
State allowance is 8-64 MiB. The signed worker limits also require a fixed gate
allowance of 128 MiB memory, 32 PIDs, 0.5 CPU and 8 MiB volatile state.

```sh
HyperNetSuite --config TransferHost.json transfers host-consent --spec HostSpec.json --output Consent.json
HyperNetSuite --config TransferHost.json transfers host-register --consent Consent.json
HyperNetSuite --config TransferHost.json transfers host-withdraw --expected-generation 1
```

The host specification is signed locally before registration. Consent is exact;
changing a resource, address or certificate requires a new generation. Follow the
Core `TransferStore` operator instructions for isolation, persistent state and
lifecycle commands. Stop the local runtime for immediate local withdrawal.

## Discover and approve an SSH service

Services are separately signed offers for one endpoint, pinned Ed25519 SSH host
key, account `HyperNetService`, purpose, forced-command image and command digest,
resources and expiry. A general network invitation never grants SSH access.
Only a service operator can register or withdraw that consent. The initial profile
permits one active accepted grant per service and lasts at most 300 seconds.

```sh
HyperNetSuite --config Member.json services list
HyperNetSuite --config Member.json services inspect --service-key SERVICE_KEY
HyperNetSuite --config Member.json services request --service-key SERVICE_KEY --authority-key SERVICE_AUTHORITY_KEY --ssh-public-key ServiceKey.pub --ssh-binary /opt/OpenSSH/Bin/ssh --identity ServiceKey --purpose ExactPurpose --expires UNIX_TIME --output GrantRequest.json
HyperNetSuite --config ServiceOperator.json services status --grant-id GRANT_ID
HyperNetSuite --config ServiceOperator.json services accept --grant-id GRANT_ID
```

Generate a dedicated native Ed25519 OpenSSH key with maintained `ssh-keygen`.
The private key must work in OpenSSH batch mode; interactive passphrase prompts
and agent unlocking are not supported. Public key files may have a comment; the signed request uses canonical key bytes
without options or comments. Reusing a membership or mail key for SSH is refused.
The request proves native key possession with a standard OpenSSH SSHSIG signature
in namespace `HyperNetSshKey1`. Its message binds the network, requesting member
and native public key. The selected OpenSSH client must have its matching
`ssh-keygen` executable beside it; both must be owned and inaccessible to group
or other writes. Signing uses a private temporary key copy, an empty environment
and an explicitly empty passphrase. Encrypted keys fail without prompting.
A public key alone cannot reserve an SSH identity. Permanent key reservation
occurs only when the operator accepts a proved grant.

The request binds the exact service consent generation, member, native public key,
account, purpose and expiry. The operator inspects and explicitly accepts it using
its own matching mutual TLS credential. `GrantRequest.json` is saved before the
request, including its exact possession proof. Repeat the same command and
absolute expiry to recover a lost response; the saved proof is verified and
reused without opening the private key again.

Both member and operator can run `services revoke --grant-id GRANT_ID`. The
operator can withdraw the entire service with `services withdraw
--expected-generation N`. Revoked grants remain terminal. Renewed service consent
requires a new explicit grant; an existing session cannot silently inherit it.

## Invoke the constrained service

```sh
HyperNetSuite --config Member.json services connect --grant-id GRANT_ID --authority-key SERVICE_AUTHORITY_KEY --ssh-binary /opt/OpenSSH/Bin/ssh --identity ServiceKey --ssh-public-key ServiceKey.pub
```

The client requires an explicit owned native OpenSSH executable, version 10.6 or
newer. Version 10.6p1 is the qualified baseline; later updates require operator
maintenance and compatibility checks. No SSH implementation is embedded in the
Suite. The binary, dedicated private key and native public key are selected
locally. The key must be mode 0600 and have one link. Private key contents never
enter command-line arguments or authority requests.

Each invocation verifies current grant and signed service consent. It creates a
private temporary known-hosts file with the exact consented SSH host key. OpenSSH
uses an empty configuration and environment, only the selected identity, strict
host-key checking, no agent, password, X11, TCP forwarding, tunnel, proxy,
multiplexing or PTY. The actual endpoint is the consented literal IP and port.
The server executes only the fixed service program in its isolated image. Remote
command strings and full shells are outside this profile.

Standard input is closed unless `--input PrivateRequest.bin` explicitly supplies
a private regular file, at most 8 MiB. Standard output and error are each bounded
to 8 MiB and displayed only as escaped terminal text. Use `--output
PrivateResponses/Response.bin` for binary output in a new file inside an owned
mode 0700 directory. Failed or expired invocations do not publish an output file.
A nonzero remote status is a command failure. The JSON result follows terminal
text; applications should use `--output` when they need byte-exact response data.

Core independently supervises a live authority lease of at most five seconds and
terminates the complete service container on withdrawal, revocation or lost
quorum. An independent runtime timeout enforces absolute grant expiry. Client
expiry enforcement is additional; it is not a substitute for server supervision.

Operators use `services consent --spec ServiceSpec.json --output Consent.json`
and `services register --consent Consent.json` with their dedicated host profile.
The full specification and supervised server lifecycle are documented by Core.
Consent includes the fixed program/image digests, not an arbitrary shell command.
Only explicitly mounted service data is accessible to that service account.

## Independent application interfaces

Third-party clients use signed `POST /V1/Command` requests and purpose-separated
signed transfer/service objects. The Suite defines its wire types independently.
Transfer stores accept `POST /V1/Transfer` with a signed operation and optional
base64url ciphertext chunk. Operations are `Status`, `Put`, `Commit`, `Fetch` and
`Delete`. Resumption uses the same immutable offer and fresh per-operation policy.
`TransferOfferList` uses an optional `after` cursor and returns at most 16 records
with a `next` cursor. The CLI follows the bounded directory until complete.
A complete receipt is a host-signed storage acknowledgement, not proof of physical
media erasure. APIs never accept an output filesystem path or execute file content.

SSH grant APIs expose discovery, request, operator acceptance, revocation and fresh
supervisor authorisation. They do not issue general shell access or share private
SSH keys. Independent applications can wrap the documented CLI using JSON files,
explicit private request/response files and ordinary exit status. They receive no
special rights. Read the Core versioned protocol contract before implementing a
separate client. This profile is not an independent security certification or a
qualified production Internet deployment.
