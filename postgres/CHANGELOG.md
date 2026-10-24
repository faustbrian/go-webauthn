# Changelog

## Unreleased

- Add explicit self-user removal-assertion options and atomic verified assertion
  consumption plus credential removal in the native parent's sole Work. Both
  authenticating-key and distinct-key removal retain independent optimistic
  versions, original assertion expiry and exact final successor fences. Install
  additive migration 6 before selecting this profile; it retains source and target
  snapshots without changing existing history or password-proof deletion.
  Session, remaining usable key, policy and identity effects remain parent-owned.
  A same-Work remaining-credential fence verifies live protocol state against
  retained original resident-registration provenance without treating historical
  ceremony expiry as credential expiry. Unknown outcomes release no verification
  and recover only the original command.

- Add explicitly selected session-bound additional enrollment: original UV
  assertion options, atomic assertion consumption plus registration options,
  and matching registration finalization share the native parent's Work.
  Compound effects retain exact source/creation identities and enforce the
  original assertion expiry through registration precommit; a later ceremony
  cannot renew enrollment authority. Legacy enrollment/signup finalization
  cannot consume a session-bound ceremony. Install additive migration 5 before
  using this adapter revision. Existing migration history and participant
  profiles remain unchanged; current session, risk and metadata authority stay
  parent-owned, and retries/recovery never reissue challenge or verification.

- Add explicitly selected self-human assertion participation for native passkey
  rename. Protected update-action options and finalization schemas cannot substitute
  for sign-in; finalization and original recovery retain the parent's exact
  metadata N-to-N+1 lifecycle independently of protocol counter versions.
  Original-session/action binding, current authority, risk and metadata changes
  remain parent-owned. Existing sign-in APIs and installed schema are unchanged.

- Add explicit anonymous-flow registration participation for the passkey
  `.signup-v1` parent using real root-issued resident-required UV/ES256
  transitions. Pending options create no identity, stable user handle or
  credential. Verification binds the original stored flow and prospective
  user, promotes its ceremony association once, and inserts the handle and
  credential in the parent's sole transaction after parent-owned identity
  creation. Risk, signup authority, MFA and sessions stay parent-owned;
  existing self-user enrollment is unchanged. Install forward migration 4
  before using this adapter revision, including retained enrollment/discovery;
  populated history and old-binary schema access remain compatible.

- Add native self-user credential removal participation in the existing
  passkey delete parent's sole transaction. Exact optimistic protocol state is
  replaced by a key-erased, versioned terminal row; RP-wide credential and
  handle reservations remain, so registration cannot resurrect the old ID.
  Current lookups and retained assertion snapshots deny removed credentials,
  while old verifier queries fail closed without a schema migration. Parent
  fresh-proof, passkey authority and session effects remain parent-owned;
  retained protocol effects support original-command recovery, not new
  authentication or authenticator-local erasure.

- Add explicit native resident-discovery assertion participation with anonymous
  service/flow-attributed options and opaque verified-target finalization under
  the self-human parent. Original anonymous ceremony consumption, current
  mapping locks, exact retry history and original-command recovery remain in
  the parent's sole Work. Identified participants and standalone discovery are
  unchanged; passkey identifier/risk/session admission stays parent-owned.
  Apply forward migration 3 before enabling native discovery options; it adds
  only that anonymous parent purpose and preserves user/flow exclusivity and
  all existing populated protocol rows.

- Add explicitly selected identified preauthentication assertion participation:
  options retain their trusted ingress service actor through signature
  verification, and only the opaque verified transition binds the final native
  parent to the verified self-user. Original protocol attribution and exact
  retry/recovery identity remain retained; existing self-user and registration
  APIs are unchanged. This seam does not itself authenticate or issue sessions.

- Add opaque identified ES256 assertion participation for native passkey
  signin options and verification. Ceremony creation and one-use credential
  counter/version updates can share the parent's existing identity-coordinator
  Work and metadata, with current-user/final-expiry fences and original-command
  recovery. Unknown and replayed commits release no challenge or verification.
  Standalone APIs, registration participants and migrations remain unchanged;
  this protocol seam alone is not a complete authenticated passkey workflow.

- Add opt-in resident-required ES256 registration participation for the native
  passkey enrollment owner. Ceremony creation and verified credential insertion
  can share the parent's existing identity-coordinator Work, proof use and
  mapping instead of committing separately. Parent-bound native effects retain
  original-command recovery; failure, replay and unknown acknowledgement do
  not release challenges or new verification. Existing standalone APIs and
  installed migration history are unchanged. This is a protocol composition
  prerequisite, not a complete passkey enrollment or authentication workflow.

- Support the root verifier's opt-in Ed25519 profile through existing atomic
  identified/discoverable credential storage and original-command recovery.
  Algorithm policy is retained in ceremony JSON; existing schema and legacy
  ES256 row bytes require no additional migration.

- Add anonymous discoverable ceremony resolution, active-subject fencing and
  atomic challenge/counter/backup updates through the existing coordinator.
  Apply forward migration 2 before new binaries; existing identified records
  and historical recovery remain compatible.

- Add a forward-only PostgreSQL ceremony/credential participant candidate using
  the public identity coordinator with atomic consumption, credential CAS,
  RP-wide uniqueness, native evidence and original-command recovery. Install
  the identity, audit and outbox prerequisites before this adapter's migration.
  This first profile rejects shared-RP tenancy and remains unqualified.
- Preserve the original typed unknown outcome when a noncommit recovery's
  acknowledgement is lost, so subsequent same-scope recovery can reconcile
  history without retrying effects or recreating challenge custody.
