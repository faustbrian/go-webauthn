# Changelog

## Unreleased

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
