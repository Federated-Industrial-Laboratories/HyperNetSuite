# Tier and grant administration

Tier rank controls display order. Authority comes from explicit actions, scopes,
validity, limits and delegation chains. A tier edit does not rewrite a grant or
restore a revoked grant. Current restrictions apply to existing grants pinned to
the authenticated history of that tier. Surviving actions remain available only
within the intersection of the grant and current tier scopes, limits and depth.

Administration uses independently accepted bootstrap trust, a durable requester
floor, a healthy clock and a current grant. Supply the usual `--bootstrap`,
`--bootstrap-digest`, `--directory`, `--clock-witness`, `--key` and `--socket`
options. The socket can name a retained authority relay endpoint. Explicit local
operator sockets provide no reader-address privacy guarantee.

## Tiers

`authority-inspection tiers list --grant POLICY_GRANT` lists current tiers.
`tiers get --tier TIER_ID --grant POLICY_GRANT` inspects one exact tier.
Listing requires network-scoped `AdministerPolicy`. An edit requires that action
in every old and proposed scope. Applications cannot administer tiers.

Prepare a private JSON specification with these required fields:

```json
{
  "id": "TIER_ID",
  "rank": 20,
  "label": "Catalogue Readers",
  "actions": [0, 1],
  "scopes": [{"kind": 0, "id": "NETWORK_ID"}],
  "delegationDepth": 0,
  "limits": [16777216, 4096, 16, 16]
}
```

Replace identifiers with canonical 32-byte lowercase hexadecimal values. Actions
and scope pairs must be sorted and distinct. Limits retain their protocol meaning;
the example is not a universal capacity recommendation. Rank ranges from0 to65535
and does not imply read, hosting, voting or administrative authority.

With the common connection options above, run:

```sh
HyperNetSuite authority-inspection tiers preview --grant "$PolicyGrant" \
  --spec Tier.json --create --output TierPreview.cbor
HyperNetSuite authority-inspection tiers apply --grant "$PolicyGrant" \
  --preview TierPreview.cbor --preview-digest "$PreviewDigest"
```

Omit `--create` when editing an existing tier. Creation requires an absent ID;
editing binds the exact current predecessor. Preview prints `TierPreviewComplete`,
the full affected-subject list and `previewDigest`. Inspect that result before
using its digest with apply. Apply prints `TierApplied` with the exact new record.
Subsequent commands reconcile older cached tier records with that exact certified
successor. A conflicting or uncertified replacement cannot repair a cache.

## Delegation and revocation

The `authority-inspection grants` commands use a separate `--context-grant` with
`InspectAudit` to discover complete current governance. That discovery grant does
not confer delegation or revocation rights. The selected parent must permit
delegation; the revoking grant must permit revocation.

A delegation specification contains `id`, `subject`, `tier`, `actions`, `scopes`,
`notBeforeMs`, `expiresMs`, `delegationDepth` and four `limits`. `tier` is an exact
tier ID or null to select the parent's current tier. Scope objects use the same
`kind` and `id` fields as tier specifications. The child must attenuate its parent
and current tier, including validity, quotas and remaining delegation depth.

```sh
HyperNetSuite authority-inspection grants delegate-preview \
  --context-grant "$AuditGrant" --parent "$ParentGrant" \
  --spec ChildGrant.json --output GrantPreview.cbor
HyperNetSuite authority-inspection grants apply --context-grant "$AuditGrant" \
  --preview GrantPreview.cbor --preview-digest "$PreviewDigest"
HyperNetSuite authority-inspection grants revoke-preview \
  --context-grant "$AuditGrant" --grant "$RevokingGrant" \
  --target "$TargetGrant" --output RevocationPreview.cbor
```

Use the same `grants apply` command with the reviewed revocation file and its
printed digest. Preview returns `GrantPreviewComplete`; apply returns
`GrantApplied`. Delegation does not admit the subject as a network member.
Revocation writes a permanent tombstone and also disables descendant grant chains.
Existing low-level mutation APIs remain available to explicit programmatic clients.

## Complete review and concurrent changes

Preview is read-only. It creates no grant, membership, reservation or policy edit.
The client collects consecutive certified pages, checks unique affected subjects
and verifies the complete count and digest before saving a review file. Partial,
changed or oversized previews cannot be applied. Impact entries conservatively
identify dependencies requiring review; they do not claim that every affected
subject loses permission.

The impact list includes dependencies in validated recipient and sealed records,
native author and reviewer statements, and signed application consent. Opaque
content and foreign metadata do not supply local authority dependencies.

The review file binds the network, requester, exact proposal and dependencies.
Apply checks the selected file digest, obtains fresh authority and atomically
compares the reviewed governance and domain view at commit. Changed dependencies
refuse with `StaleSnapshot12`; fetch and inspect a new preview. Ordinary read-only
stream progress does not invalidate an otherwise unchanged view. Cursor mismatch
returns `CursorScope32`, and an oversized impact closure returns `PreviewLimit33`.
The original mutation and its signed audit evidence commit together.

Keep review files private. An expired or revoked administrator grant cannot be
revived by an old review file. These workflows do not reverse earlier disclosure
of plaintext to an authorised reader or host.
