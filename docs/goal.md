# Goal: planned go-webauthn boundary

Status: planned

The coordination plan identifies `github.com/faustbrian/go-webauthn` as the
future owner of WebAuthn registration and authentication ceremonies,
relying-party, origin and challenge policy, attestation and assertion
verification, authenticator metadata, counters, and security-key profiles.

The source planning record is
`.ai/identity-platform/goals/webauthn.md` in the Golib coordination tree, with
SHA-256
`5f63350a261382d79471c1e2c3fee95af14fb78e324fcba52f065866841e586f`.
That record contains proposed contracts; it is not implementation evidence.

## Current planning acceptance

- Keep this repository visibly planned and absent from installable consumer
  catalogs.
- Record the frozen Protocols and Descriptions family, WebAuthn capabilities,
  ownership, and delivery lifecycle in schema-v2 engineering metadata.
- Validate the metadata locally and in hosted CI with immutable,
  checksum-verified `go-library-tools` v1.4.0 tooling.
- Keep the module non-releasable and release blocked until implementation and
  executable evidence address the [versioned WebAuthn threat model](security/threat-model-v1.md).
- Publish a [private vulnerability reporting process](../SECURITY.md).
- Do not claim a public package identifier, installation path, runtime API,
  compatibility promise, protocol conformance, or released behavior.

## Deferred implementation

Source packages, nested modules, dependencies, protocol and API contracts,
behavior, hardening evidence, compatibility commitments, tags, and releases
remain outside this planning-only goal. They require separately authorized
work and their own executable acceptance evidence. The threat model records
unresolved implementation risks, not accepted runtime risk or implemented
controls.
