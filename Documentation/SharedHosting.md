# Host a shared server

[Documentation](ReadMe.md) | [Join a server](SimpleJoining.md) | [Native administration](Administration.md)

Open **Create / manage a server** from the join window. Select **Invite only**,
**Password** or **Public**, the ordinary participant capacity, access lifetime
and hosting lifetime. Invite only is selected for a new server. Public admission
is an explicit choice. Enable external Agents only when wanted; their operators
must approve separate identities, rooms and permissions.

```sh
HyperNetSuite join host-desktop
```

RelayChat opens the same window with its verified installed executable, enabling
chat and its separate owner account. Suite alone can host read-only Pages. The
existing manual native deployment and HRC network commands remain available.

## Review and start

The coordinated package installer verifies the native dependencies before use.
Choose an address assigned to the server and review its relay and joining ports.
Authority listeners use private container addresses and local-only bindings; they
are not public ports to forward. The server needs the normal native Linux hosting prerequisites,
including rootless Podman, subordinate identities, delegated cgroup controllers
and slirp4netns. The wizard shows per-role memory, storage and CPU budgets.

A single host may run several authority replicas, but all belong to one
organisation and one failure domain. The wizard requires acknowledging that
arrangement. It does not describe the deployment as independent operators.

The default participant preset allows approved Page reading and, with chat,
ordinary participation in the welcome room. It does not allow room creation,
moderation, publishing, hosting or arbitrary delegation. The owner has a
separate account and native profile. Participant capacity includes that owner;
the public registrar subtracts the reserved owner place. Native policy permits
up to 64 participants. The initial shared HRC room supports 32 including its
owner, so the chat preset uses that lower bound.

Choose **Access until removed** for persistent membership, or a finite expiry.
Choose **Run until stopped or withdrawn** for persistent hosting, or finite
hosting consent. These are separate native policy choices. Neither silently
extends an existing finite authority or operational consent. Finite transport
proofs and current authority checks remain active in all modes.

Review the exact requirements and choose **Create and start server**. A failed or
cancelled setup retains its journal and keys. Select the unfinished server to
resume the same reviewed configuration. Do not delete its private state or create
replacement keys to retry it.

Ready means the native services and the authenticated joining endpoint passed
checks from this host. Verify the shared link from another connection before
inviting others. A local check cannot prove Internet firewall forwarding, router
configuration or CGNAT reachability. The wizard does not open arbitrary firewall
ports or bypass network restrictions.

## Link and certificate options

**Native links** uses a retained private TLS authority. The app verifies the
identity and TLS pins carried by the link. QR codes use the native join scheme;
no public certificate authority is contacted. This option works with LAN
addresses and requires no certificate service account.

**Public HTTPS with automatic certificates** uses Certbot5.10 or newer and
Let's Encrypt. Review the linked subscriber terms, supply a contact email and
accept the certificate disclosure before starting. The authority receives that
email and server address; issued certificates are public. IP-address
certificates use the shortlived profile. The host checks renewal every six hours
and retries failed checks after five minutes. This certificate lifetime does not
limit membership or hosting consent.

Public TCP80 must reach the selected unprivileged challenge port, initially8080,
on this computer for initial issuance and later renewals. Configure that rule in
the router or firewall. The application does not modify those rules. The temporary
HTTP listener has its own rootless container and read-only mount of validation
tokens. It receives no certificate account, TLS private key, registrar or owner
state. The joining HTTPS port remains separate.

**Use certificates managed by another tool** reads a certificate-chain PEM file
and a private-key PEM file owned privately by the current account. The external
manager must renew those files. The host checks them every minute. Both public
certificate options deliver one atomic certificate/key bundle to the isolated
HTTPS listener, which reloads it without restarting chat. Failed refreshes appear
in the dashboard; clients continue to enforce hostname, chain and expiry checks.
The host never bypasses certificate checks to recover a failed renewal.

## Share and control access

The dashboard can create private invitations with a use count and expiry, show
and export a QR image, or copy a short connection message. One use and seven days
are the initial invitation choices. A reusable invitation is optional. Invitation
expiry affects new claims; it does not shorten already granted membership.

For password joining, set the password and select Password mode. Share the
password separately from the public link. Rotating it changes future password
joins and leaves existing memberships intact. Disabling an invitation also
leaves its already admitted members intact. **Accept new joins** pauses future
admission without deleting active members or their exact pending operations.

The initial private-CA link pins both native identity and TLS authority. Open it
in the application, or import its QR there. A general web browser requires a
publicly trusted server certificate for an ordinary HTTPS landing page without
a certificate warning. Never teach recipients to bypass certificate checks.

Removing a participant closes the corresponding Home admission and native slot.
Removing a person also closes their scoped Agents. A large cascade is retained
and resumed through **Continue removal**. The host keeps bounded terminal
receipts until authenticated acknowledgement; it does not erase historical
outcomes or reset authority floors to make room. New admission can therefore
pause when retained evidence reaches its safety bound. Moderation and device
controls use the owner's separate HRC account.

## Stop, withdraw and recover

**Stop hosting** preserves the state for an ordinary restart. It disables the
public joining user service and stops the native host through its supported
lifecycle command. An authority's idle private bridge remains for the next
explicit restart. **Withdraw hosting consent** permanently withdraws this host
profile and releases its verified owned bridges. Hosting again requires a
separately reviewed host. Neither action deletes user history or private recovery
material. Unresolved cleanup remains visible and can be retried.

An interrupted activation retains its exact request until the native completion
is verified and reported. Completed request and receipt exports are bounded to
the current and previous activations; native requester floors remain intact.

For operation after logout and reboot, enable unattended user services from the
dashboard. The desktop may request administrator authentication for this local
system setting. The host supervisor uses service restart with backoff, without a
service lifetime timer. A stopped host stays stopped until explicitly resumed.

Export **redacted diagnosis** to inspect native phase, joining readiness and
unattended startup status. It omits private invitations, passwords, key bytes and
member histories. Keep owner recovery files separately backed up and stop the
host before changing its software or moving private state.

For a Suite controller update, stop hosting and use **Install or update signed
hosting software**. Install the coordinated packages, open the verified installed
hosting application, select the saved server and choose **Review controller
update**. Apply the exact review, then use **Start / resume** separately. The
controller update requires the same Core package and image, HRC executable,
publisher and state contract. It changes the stopped controller and its exact
service commands; it does not change permissions or replace identities.

An interrupted controller update stays offline. Review and apply its retained
update again. Do not delete the update plan or restore an older journal to retry.
Core software changes use the native stopped deployment successor workflow and
its separate software consent; a controller update cannot authorise them.

## Isolation and administration boundary

The public HTTPS listener runs in the admitted Core image with a separate mapped
rootless user, read-only root filesystem, dropped capabilities, no new privileges,
and explicit memory, CPU, PID and descriptor bounds. It receives only its TLS
state, the installed Suite executable and a read-only mount of the admission
socket directory. TLS state writes run inside that identity's container; the
host does not follow listener-controlled paths through a privileged copier.

The listener has its own network namespace. Source-preserving slirp4netns port
forwarding exposes only the reviewed joining port and disables host loopback
access. The registrar runs in a second mapped identity with no network access. It
receives only its admission state, descriptor key, scoped native operator
artifacts, current public clock evidence and authenticated control sockets.
Governance, service-owner and recovery keys are not mounted. The Home extension
bridge admits only signed admission actions; its ordinary admin socket remains
private. The registrar authenticates Unix peer identities and accepts owner
controls only from its separate owner UID. Ordinary participants
cannot select helper programs, paths, native grants or owner credentials.

Native policy bounds constrain the registrar even if its public-facing input is
hostile. Each slot has fixed purpose, selected roles, quotas and no delegation
rights. Password rotation and invitation changes do not create new native
policies. Immutable policy rotation has a retained native policy limit; it must
not discard withdrawal evidence to bypass that limit.
