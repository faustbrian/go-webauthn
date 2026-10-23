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
