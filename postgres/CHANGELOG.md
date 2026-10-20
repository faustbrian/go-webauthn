# Changelog

## Unreleased

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
