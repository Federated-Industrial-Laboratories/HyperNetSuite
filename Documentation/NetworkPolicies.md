# Network policy and recovery custody

[Documentation](ReadMe.md) | [Project README](../ReadMe.md)

`HyperNetSuite authority-inspection policy` changes the current network policy
through the ordinary ordered authority stream. It preserves the network identity,
requester floors, grants and publication history. Policy changes do not disclose
existing content, grant capabilities or replace recipient identities.

The online commands take the same `--bootstrap`, `--bootstrap-digest`,
`--directory`, clock-witness and monitor pins as other authority commands, plus
`--key`, `--socket` and the exact administration `--grant`. The requester needs
AdministerPolicy on the network. Applications cannot administer network policy.

Run `policy get` to fetch certified current policy. Run `policy prepare --spec
Policy.json --output Proposal.cbor` to prepare an exact successor. The JSON fields
are `enrolment`, `publicReading`, `minimumRoute`, `allowedRelayDomains`,
`allowedPublicationModes`, `defaultPublicationMode`, `limits`,
`manualReviewDefault`, `policyAuthority` and optional `recovery`. Values follow
[PolicyContract](PolicyContract.md). IDs and keys use 64-character hexadecimal;
sets must be sorted and distinct. Omitting `recovery` preserves exact custody.
Manual review remains required; unscoped automated approval is refused.

The optional recovery object contains `custody` (0 owner single, 1 owner
threshold, 2 shared threshold), `principals`, `keys` as `[principal,key]` pairs,
`immutableShared` and `acceptedBy` as SHA-256 fingerprints of the exact new keys
that will sign. Thresholds are fixed at one of one or two of three. Shared custody
requires three declared principals. Software verifies declarations and signatures;
it cannot establish whether different people control the keys.

Inspect the proposal using `policy inspect --proposal Proposal.cbor`. Its digest
binds the complete proposal, including exact previous policy and recovery records,
current capability dependencies and resulting settings. When custody is unchanged,
submit it with `policy apply --proposal Proposal.cbor --proposal-digest DIGEST`.

For a custody change, each old custodian runs `policy sign --proposal Proposal.cbor
--proposal-digest DIGEST --identity OldCustodian.json --output OldShare.cbor`.
Each selected new custodian uses the same command with `--new-custody` and their
own identity. Each sign command also takes the standard bootstrap/location inputs.
The normal private identity format contains `secretKey` and `publicKey`; never
combine independent custodians' secrets on an administrator's system.

Run `policy assemble --proposal Proposal.cbor --old-share OldA.cbor OldB.cbor
--new-share NewA.cbor NewB.cbor --output SignedProposal.cbor`. Old authorization
and new acceptance are verified separately over exactly the proposed kind114
record. Inspect the assembled proposal and apply its newly printed exact digest.
The authority compares every predecessor at committed order and changes kind100
and kind114 atomically. A stale proposal refuses; prepare and review a new one.
Repeat an interrupted apply with identical bytes to resolve its durable request.

A shared-to-owner change or threshold reduction requires each affected client to
accept the weaker trust contract. `policy get` prints the current `trustDigest`;
`policy accept --trust-digest DIGEST` records the exact inspected contract in that
requester's private directory. Until acceptance, ordinary use refuses TrustChanged.
Acceptance does not change separate client route, publication or placement minima.
Immutable shared custody cannot weaken in the same network identity.

Current policy bytes are cached only against exact retained certified generations.
Keep these bytes and the requester floor together for [offline network
recovery](NetworkRecovery.md). A recovery ceremony cannot silently revive keys
removed by a retained custody change.

Ordinary participants use `HyperNetSuite authority-inspection policy discover` with their bootstrap,
requester key, retained directory, clock witness and authority socket. This
fetches only the network policy and its exact recovery custody. It does not
require administrative inspection capability or include Page IDs, search terms,
mail addresses or file identifiers. The printed trust digest can then be used
with `policy accept` after independent inspection.

Normal private requests discover this contract before sending their content or
resource selection and bind its exact policy generation. A concurrent replacement
refuses the effect instead of applying it under different trust. A weaker learned
contract is retained for inspection before normal work stops. An interrupted
request retains its original policy pin and must be reconciled or explicitly
fenced; it is never silently rewritten. Revocation, withdrawal and local deletion
do not require acceptance of an expanded trust contract.

Before local acceptance, discovery can recover once from its own request deadline
expiry using a new connection and challenge for the exact retained intent. The
original policy pin and each challenge's deadline remain unchanged. Refusal,
invalid proof and errors during or after publication remain visible. See
[expired domain requests](AuthorityInspection.md#expired-domain-requests).

Recovery `acceptedBy` values are the lowercase hexadecimal SHA256 fingerprints
of the public keys, matching the bootstrap custody format. They are not the
protocol's domain-separated record digests.

Existing owner-only application metadata and intrinsic deployment ownership or
withdrawal paths remain available under their own authority checks. Such queries
do not grant administrative inspection, new service authority or confidential
content access.

The same applies to an owner's cold archive catalogue, hosting profiles, transfer
agreements, SSH grants and mailbox metadata. Sending mail, fetching content,
restoring an archive or accepting a new service still requires the current policy.
Recipient and sealed publication records are signed after context discovery;
submission preserves that exact pre-state and policy dependency.
