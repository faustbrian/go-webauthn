# Changelog

## Unreleased

- Add explicitly selected RS256 none-attestation registration and identified/
  discoverable assertions with COSE RSA exponent 65537, a bounded 2048..8192-bit
  modulus and PKCS#1 v1.5/SHA-256 signatures. Preserve existing nil/default
  ES256 bytes and exact ordered ceremony policy. RSA authenticator/browser
  interoperability and whole-unit qualification remain unverified.

- Add explicit Ed25519 algorithm selection for none-attestation registration
  and identified/discoverable assertions. Ordered algorithm policy is copied,
  exactly advertised and frozen into ceremony authority; changing it rejects
  in-flight ceremonies. Nil configuration, existing ES256 records and challenge
  fingerprints remain unchanged. Ed25519 browser interoperability and whole-unit
  release qualification remain unverified.

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
