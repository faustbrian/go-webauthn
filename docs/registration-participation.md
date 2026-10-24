# Native registration participation

The optional PostgreSQL participant composes protocol persistence inside the
selected native passkey owner's **existing** identity coordinator transaction.
It is not a second coordinator, a workflow callback or an application-authored
domain store. The root protocol service remains adapter-neutral and unchanged.

## Selected contract

Only self-service existing-account enrollment is selected: tenant-bound,
resident-required creation, mandatory UV, `none` attestation and an explicit
ES256/Ed25519 algorithm profile. Nil retains the original ES256-only default;
explicit profiles contain one or both supported algorithms without duplicates.
Their original order and exact verified credential membership remain bound
through finalization and recovery. RS256 is not selected by this participant.
The parent contributor descriptor is `passkey/postgres`, contract
`identity.passkey`, version 1. Operations are
`identity.passkey.register-options` and `identity.passkey.register-verify`, each
with schema `<operation>.native-v1`, schema version 1 and required record ID.
Each primary record has a 0-to-1 creation lifecycle. Signup, assertion/signin,
management, HTTP and shared-RP tenancy remain unsupported by
this seam. Standalone WebAuthn services retain their broader selected profiles.
Downstream native passkey owners must independently select and prove a compatible
profile; protocol support does not automatically enable Ed25519 in those owners.

The parent's concrete passkey adapter implements the root `Store` contract.
It borrows the actual native protocol store for lookup and participation; it
does not copy protocol SQL or maintain another ceremony/credential authority.
Construct `RegistrationCreation` only from the real root service's opaque
`CeremonyCreation`. Construct `RegistrationFinalization` only from its opaque
verified `RegistrationTransition`. Public mutable projections cannot construct
either input. No participant returns `VerifiedRegistration` or grants identity
authentication.

## Original command and one Work

1. Include the participant's owned `Fields()` in the parent's original command.
   This digest binds all original protocol input, including RP/version, origin,
   selection, handle/exclusions, and verified response identity. `Validate`
   belongs in the registered parent's pure command validator. Fields, matching
   descriptors or a structural command alone confer no authorization.
2. Reserve through the sole existing coordinator. Only after an acknowledged
   new reservation, before opening Work, call creation `Generate` with the
   original primary database clock sample. Generation is once per invocation;
   replay/recovery never generate entropy. Defer `Discard` for abandonment,
   cancellation, failure and panic paths. Copies share generation/reveal state
   and are serial-use, not concurrent handles.
3. During the exact parent's `ApplyFeature` invocation, call `Apply` using its
   actual contributor instance and unchanged command. Protocol current-user,
   RP-wide uniqueness, ceremony expiry/consumption and credential insertion
   use that supplied Work and existing schema. Protocol evidence records the
   actual parent command/purpose/fingerprint in `webauthn.effects`; there is no
   second receipt or replay journal.
4. In the same Work, the parent owns and must enforce original authenticated
   session/CSRF possession, fresh operation-bound proof consumption, current
   credential/directory/authorization/factor/risk admission, stable identity
   mapping, identity credential reference and required audit/lifecycle effects.
   Recheck participant `Check` and all parent admission at final precommit.
   Every error must propagate to abort the whole Work. No independent commit
   before or after this transaction can satisfy these atomic requirements.
5. Call `Result` only with the actual acknowledged coordinator receipt for
   this new invocation, after Work has committed. Creation transfers challenge
   custody once; finalization returns a credential only for the real root
   verifier. `Result` does not prove an arbitrary caller-supplied receipt was
   committed; the native parent is trusted to preserve this ordering. Failure,
   unknown and replay provide no challenge or new verification, and cannot be
   retried through an old participant alias.

Parent and protocol stores must use the same primary authority. The caller
owns pool lifetime and migration installation. Existing native protocol
migrations are unchanged; install the complete kernel/audit/outbox/protocol
histories and all parent-owned prerequisites before activating composition.

## Recovery and limits of evidence

Recovery is the original parent coordinator's authorized scoped query, not
`Store.Recover` for a separate standalone `webauthn.*` command. The parent's
recovery contributor calls `RecoverRegistration` in its genuine recovery
invocation and combines it with its own proof/mapping/effect evidence. Missing
protocol effects are noncommit evidence; any effect while the command journal
remains pending is unknown, never reconstructed authentication. Committed
terminal history is returned through the original coordinator. Recovery cannot
create options, re-reveal a challenge, consume proof again or renew authority.

The [native consumer test](../postgres/registration_participant_integration_test.go)
exercises protocol participation using real PostgreSQL, genuine ES256/Ed25519 responses,
the public coordinator and parent-only test metadata. That fixture is not the
actual fresh-authenticated passkey workflow and cannot qualify that milestone.
The [algorithm-profile cases](../postgres/participant_algorithms_integration_test.go)
also cover exact mixed-profile selection, unselected algorithms and unchanged
original-profile retry/recovery.
Complete passkey identity/factor/risk/session composition remains its owner's
responsibility; no boolean authorization or stub unlocks it.
