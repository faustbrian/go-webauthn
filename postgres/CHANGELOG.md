# Changelog

## Unreleased

- Add a forward-only PostgreSQL ceremony/credential participant candidate using
  the public identity coordinator with atomic consumption, credential CAS,
  RP-wide uniqueness, native evidence and original-command recovery. Install
  the identity, audit and outbox prerequisites before this adapter's migration.
  This first profile rejects shared-RP tenancy and remains unqualified.
- Preserve the original typed unknown outcome when a noncommit recovery's
  acknowledgement is lost, so subsequent same-scope recovery can reconcile
  history without retrying effects or recreating challenge custody.
