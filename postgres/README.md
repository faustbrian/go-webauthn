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
audit, outbox and complete protocol histories before selecting composition.
This adapter revision requires forward migration 4 before use, including
retained enrollment/discovery; older binaries remain compatible with the
populated forward schema.

`Store.SignupRegistrationCreation(creation, originalFlowID)` and
`Store.SignupRegistrationFinalization(transition, originalFlowID)` lend the
existing registration participant types to the exact anonymous
`identity.passkey.register-options.signup-v1` and
`identity.passkey.register-verify.signup-v1` parents. The root protocol context
keeps a trusted preallocated prospective user ID, configured service actor and
empty anonymous-flow field. The parent instead has empty `UserID`, the original
anonymous flow, service-account actor, and a text `registration.user` field
equal to that prospective ID. Append the participant's `Fields` as well; its
domain-separated digest fixes the original flow and complete opaque protocol
input. This is not authentication or permission to create an account.

Options retain only the bounded protocol ceremony and parent effects, without
creating an identity, stable user handle, credential or session. For verified
registration, the native parent must create the actual active identity in the
same Work before participant `Apply`. The participant consumes only the exact
stored original flow/prospective ID and immutable root ceremony, promotes its
pending association once to the existing FK-backed user association, and binds
the RP-wide stable handle and credential. Final `Check` repeats the stored-flow,
consumption, current-active-user and original-expiry fences. Any error must abort
the complete Work. Parent risk, pre-auth consumption, identity/MFA/authorization
initialization, session issuance, remember policy and signup authorization remain
required; the protocol participant supplies none of those effects.

`RecoverRegistration` accepts either the retained exact self-user enrollment or
the exact anonymous signup parent inside its original recovery invocation.
Unknown outcomes and historical committed recovery do not reveal a challenge,
reissue verification or authenticate a user. Existing `RegistrationCreation` /
`RegistrationFinalization` methods continue to select only `.native-v1` self-user
enrollment.

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
