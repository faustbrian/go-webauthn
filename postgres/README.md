# PostgreSQL WebAuthn adapter

This optional module implements the root WebAuthn store using the public
identity coordinator, existing protocol migrations and native audit/outbox
contributors. The caller owns pool lifetime and migration installation.

Native passkey owners can borrow protocol persistence inside their existing
Work through [registration participation](../docs/registration-participation.md)
and [identified assertion participation](../docs/assertion-participation.md).
These explicit opaque participants do not independently commit, authenticate
an identity or replace the parent's current authority and session workflow.
Standalone store APIs retain their existing behavior.

The parent must preserve original-command binding, final precommit checks,
acknowledged-result ordering and original recovery. Unknown outcomes and
replays return no new challenge or verification. Install the identity,
audit, outbox and complete protocol histories before selecting composition;
the participants add no migration.

`Store.CredentialRemoval(RemovalRequest)` lends the exact self-user native
`identity.passkey.delete` command a serial-use protocol participant. Append its
`Fields` to the original command, invoke `Validate` during plan admission, and
invoke `Apply` and final `Check` with the actual registered parent and sole
Work. The parent owns authorization, explicit fresh proof, passkey metadata,
credential/reference and authority version changes, and affected sessions;
this seam alone is not an authenticated deletion workflow. Its canonical
lifecycle is `identity.passkey.remove_credential`; the parent reference version
and the request's optimistic protocol version are independent.
Every participant error must propagate and abort the complete parent Work.

Removal increments the protocol version and erases the stored public key,
retaining the credential row and RP-wide credential/handle reservations. This
terminal record is not returned as a usable credential. Old verifier queries
also receive no usable key, and their existing version/record comparisons fence
previously loaded assertions. Current identified/discoverable lookups additionally
deny retained assertion snapshots after removal. Authenticators may retain
their local passkey; server removal does not erase an authenticator.

Restart recovery uses `Store.RecoverRemoval` inside the original parent's
`RecoveryWork`, alongside every other owner. The existing command-linked
protocol effect is atomic with removal and must be retained for at least the
kernel journal's lifetime. No marker proves only this original command did not
remove; a marker beside a pending journal remains unknown. Only an actual
committed kernel receipt establishes historical success, never today's row.
Recovery does not renew proof or authorize reexecution. No migration is added;
installed migration history remains unchanged.
