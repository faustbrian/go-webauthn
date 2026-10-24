# Native assertion participation

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

The identified selectors accept `get`, a 32-byte
stable handle, an explicit allowed-credential list and an ES256/Ed25519 profile.
Nil preserves ES256-only selection; explicit profiles retain their exact ordered
unique allowlist. The verified before/after credential must retain its selected
algorithm through finalization and recovery. The root service
always requires UP and UV and uses `none` attestation for enrollment. The
parent must admit its actual resident-required enrollment profile and mapping;
assertion input does not itself prove residency or fresh attestation.
Signup, credential management, shared-RP tenancy and RS256 remain
unsupported by these participants. Resident discovery uses the explicit
anonymous selectors below, not an identified request with omitted checks.
Protocol support does not automatically enable a new algorithm in the owning
native passkey workflow or its HTTP composition.

`Store.AssertionCreation` accepts only the root service's opaque
`CeremonyCreation`; `Store.AssertionFinalization` accepts only its opaque
cryptographically verified `AssertionTransition`. Mutable credential/mutation
projections, matching descriptors, fields and boolean authorization cannot
construct either input or confer identity authentication.

The existing constructors select self-user parents throughout. Public
unauthenticated identified signin instead explicitly selects
`Store.PreauthAssertionCreation` and `Store.PreauthAssertionFinalization`.
Creation requires the original trusted `SubjectServiceAccount` actor, distinct
from the identified user. Root `VerifyAssertion` must retain that exact service
actor: replacing it with the user before signature verification denies. Only
the genuine opaque verified transition permits finalization to bind the final
parent to `SubjectUser` with actor equal to the verified target. The protocol
ceremony, mutation and complete intent digest retain the original service
actor; this bridge changes parent attribution, not protocol evidence.

The parent separately validates the actual ingress caller, original browser,
risk evidence and current identity/passkey/session owners. An identified user
or service actor in a request is not authentication. Neither participant can
construct verifier custody from a decoded mutation or issue a session itself.

## Account-independent resident discovery

`Store.DiscoverableAssertionCreation` selects the root service's genuine
`get-discoverable` creation: no user, handle or allowlist, the original trusted
service actor and a nonempty original anonymous session flow. The native
signin-options operation retains the same ID/schema/version but explicitly
sets `SubjectRequirement: identity.FeatureSubjectAnonymousFlow`. Its parent
binding has empty `UserID` and the exact protocol `AnonymousFlowID`. Creation
does not query account status or manufacture a decoy identity or credential.

`Store.DiscoverableAssertionFinalization` accepts only the genuine opaque root
assertion transition. `Before.UserID` supplies the cryptographically resolved
target; the exact signin-verify parent is self-human with that user and an empty
parent anonymous flow. Protocol context, service actor and original flow remain
unchanged in the transition, ceremony and complete digest. The shared native
helpers consume the original anonymous ceremony and retain current user,
RP/handle mapping locks and exact credential CAS through final commit.

The parent must select the matching operation in its contributor registry and
separately bind original browser/identifier/risk/remember policy and current
identity/passkey/session authority. Resident discovery does not establish that
the verified credential matches a requested identifier; that comparison occurs
only inside the owning passkey finalization. These protocol participants do not
claim signin or session issuance by themselves. Existing identified constructors
and standalone discoverable storage retain their selected contracts.

Apply forward migration **3** before selecting native discovery options. It
admits only `identity.passkey.signin-options` as an additional anonymous effect
purpose, retaining the user/flow exclusivity constraint. Existing migrations 1
and 2 and their populated identified/anonymous protocol rows remain unchanged;
old binaries keep their existing query and standalone effect shapes.

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

Recovery admits service-attributed creation only for the exact signin-options
operation, including its explicitly anonymous subject profile; signin-verify
still requires the original self-human parent. An
exact service-context verification retry can read its original credential
snapshot only under that command's native signin-verify effect, verified
target, ceremony/RP and retained original service actor. The bounded retained
ceremony must match that scope and identified assertion profile. Standalone
assertion history retains its existing actor-equality rule. This snapshot lets
the existing coordinator classify replay; it does not recreate authentication.

Resident-discovery retries similarly retain exact original command, tenant,
ceremony/RP, service actor and anonymous flow. Native history is selected only
from its self-human signin-verify effect and a bounded complete retained
discoverable ceremony matching that scope and the verified credential owner.
Recovery neither changes that anonymous protocol attribution nor remints
options, challenges, proof, counter transitions or sessions.

The [public native-coordinator fixture](../postgres/assertion_participant_integration_test.go)
uses real PostgreSQL and genuinely registered ES256/Ed25519 credentials to exercise
shared rollback, final checks, one-use/CAS races and lost server COMMIT recovery.
The [algorithm-profile cases](../postgres/participant_algorithms_integration_test.go)
exercise selected membership and changed/reordered profile denial with genuine
root-verified responses.
Its parent-only metadata is not the actual passkey workflow, current factor/risk
admission or session issuer. Full authenticated passkey workflow, public
consumer composition and release qualification remain the owning platform's
separate evidence boundaries.
