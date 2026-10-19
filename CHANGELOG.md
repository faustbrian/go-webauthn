# Changelog

## Unreleased

- Add optional resident-required registration and usernameless assertions for
  existing active users, with mandatory RP-wide credential/handle matching,
  original pre-auth flow binding and atomic credential finalization. Existing
  identified APIs remain supported; this does not provide signup or sessions.

- Add an unqualified, identified-user WebAuthn none/ES256 ceremony candidate
  with exact tenant/RP/origin policy, opaque reveal-once challenge custody,
  selected typed extensions and durable PostgreSQL credential transitions.
  It does not issue sessions or provide passkey orchestration; full protocol,
  interoperability and release qualification remain incomplete.
- Keep extension inputs creation-only and preserve their original registration
  authority across assertions. Configuration requires canonical serialized
  origins; default-port and empty-port spellings are rejected, not normalized.
