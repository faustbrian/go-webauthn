# Native identified assertion participation

The PostgreSQL assertion participant stages protocol persistence inside the
native passkey owner's existing identity coordinator Work. It does not add a
coordinator, callback workflow, ceremony store, credential authority or journal.
The root verifier and the existing registration participant remain unchanged.

## Selected contract

The parent contributor is `passkey/postgres`, contract `identity.passkey`,
version 1. Its operations are `identity.passkey.signin-options` and
`identity.passkey.signin-verify`, each with schema `<operation>.native-v1`,
schema version 1, a required command record and a 0-to-1 command-record
lifecycle. The protocol credential retains its independent monotonic version
and counter transition; those are not the command-record lifecycle.

Only identified existing-account assertions are selected: `get`, a 32-byte
stable handle, an explicit allowed-credential list and ES256. The root service
always requires UP and UV and uses `none` attestation for enrollment. The
parent must admit its actual resident-required enrollment profile and mapping;
assertion input does not itself prove residency or fresh attestation.
Discoverable signin, signup, credential management, shared-RP tenancy and
other algorithms remain unsupported by this participant.

`Store.AssertionCreation` accepts only the root service's opaque
`CeremonyCreation`; `Store.AssertionFinalization` accepts only its opaque
cryptographically verified `AssertionTransition`. Mutable credential/mutation
projections, matching descriptors, fields and boolean authorization cannot
construct either input or confer identity authentication.

## One original command and one Work

1. Add the participant's owned `Fields()` to the parent's original command and
   invoke `Validate` from its pure command validator. The digest binds the
   complete original protocol input, including command/tenant/user/actor,
   correlation, RP/version, origin, handle, algorithms and allowed credentials;
   finalization also binds the exact verified response and before/after state.
2. Reserve through the actual parent coordinator. For a newly acknowledged
   reservation only, call creation `Generate` with the original primary database
   clock sample before Work opens. Defer `Discard` for every abandonment,
   cancellation, failure and panic. Copies share serial-use generation/reveal
   custody and must not be used concurrently. Replays/recovery generate nothing.
3. Call `Apply` only inside the registered parent's genuine `ApplyFeature`
   invocation using its actual instance, unchanged command and supplied Work.
   Existing protocol helpers enforce current active user, RP/handle bindings,
   ceremony expiry/one-use and exact credential version/state CAS. Native
   `webauthn.effects` records the original parent purpose and fingerprint.
4. In that same Work, the parent owns real preauthentication/risk admission,
   current identity/factor/passkey authority, enrolled-profile mapping, metadata,
   session creation and required audit/lifecycle effects. Propagate every error
   so all effects roll back. In the final precommit invocation call `Check` and
   repeat all parent admission checks without renewing original validity.
5. Only after the actual final coordinator commit is acknowledged, call
   `Result` with its receipt. Creation transfers challenge custody once;
   finalization returns protocol credential state to the real root verifier.
   The participant trusts the native parent to supply its actual receipt and
   preserve this ordering; it does not authenticate arbitrary caller-created
   receipts. Failure, unknown and replay never return new protocol verification
   or challenges, and old aliases cannot be used to reveal a later result.

Use the same primary authority and install the complete identity, audit,
outbox, protocol and parent migration histories before activating composition.
This additive seam requires no protocol schema change. The application owns
pool lifetime; the participant never reserves, opens, commits or retains Work.

## Original-command recovery and evidence limits

The native parent's authorized recovery invocation calls `RecoverAssertion`
and combines its result with the parent's metadata and other owned effects.
Missing protocol effects provide noncommit evidence; any protocol effect with
a pending original journal remains unknown, never reconstructed authentication.
Committed terminal history comes from the sole original coordinator. Recovery
does not consume another proof, change counters, reissue a session, recreate
options or restore challenge custody.

The [public native-coordinator fixture](../postgres/assertion_participant_integration_test.go)
uses real PostgreSQL and a genuinely registered ES256 credential to exercise
shared rollback, final checks, one-use/CAS races and lost server COMMIT recovery.
Its parent-only metadata is not the actual passkey workflow, current factor/risk
admission or session issuer. Full authenticated passkey workflow, public
consumer composition and release qualification remain the owning platform's
separate evidence boundaries.
