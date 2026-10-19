# go-webauthn

**Unqualified implementation candidate; not a released or complete M15 profile.**

The root module owns WebAuthn protocol verification. The independent
[`postgres`](postgres) module owns real durable ceremony and credential storage
through the existing identity coordinator. Neither owns identity enrollment
authorization, sessions, passkey workflows, browser UI or HTTP routes.

The candidate selects identified-user ES256, `none` attestation, exact tenant/
RP/origin binding, mandatory UP/UV, 32-byte opaque user handles, five-minute
single-use challenges, typed `credProps`/`credProtect`, backup flags and counter
policy. Unsupported variants fail closed. Source identity, precise bounds and
authority distinctions are in [protocol sources](docs/protocol-sources.md).

## Public flow

1. An existing trusted identity workflow authorizes enrollment/use and selects
   tenant before looking up RP configuration. `CeremonyContext` is correlation,
   not authentication or authorization proof.
2. Construct the concrete native store with the primary pool and public
   coordinator policy, then construct `webauthn.New` with that store, fixed
   tenant/RP/version/origins, explicit timeout and an opaque
   `NewChallengeDigestKey` value. The service copies mutable configuration.
3. `BeginRegistration` commits a digest-only ceremony before returning browser
   options. `TransferJSON` reveals the challenge once to a synchronous delivery
   callback outside SQL. A retry returns original safe ceremony metadata but
   cannot re-reveal its challenge.
4. `VerifyRegistration` accepts bounded browser JSON, verifies the selected
   protocol, then atomically consumes the ceremony and inserts one credential.
   Only successful finalization produces an opaque `VerifiedRegistration`.
5. `BeginAssertion` selects the identified subject and nonempty credential
   allowlist. `VerifyAssertion` verifies exact client-data bytes and signature,
   then atomically consumes the ceremony and updates counter/backup/version
   before returning an opaque `VerifiedAssertion`.

Every operation uses its own random `identity.NewCommandID`. Preserve that ID
and complete original input across retries. An unknown acknowledgement returns
no challenge or verified evidence; `Recover` uses that original command and
scope. A committed replay returns typed `Replay`, not renewed authentication.
Recovery reports only historical outcome and cannot recreate challenge bytes.

The concrete public-path walkthrough is
[the PostgreSQL consumer test](postgres/ceremony_integration_test.go). It is not
evidence of signup, sessions, HTTP integration or complete browser conformance.

## Ownership and operations

The caller owns pool lifetime, migration execution, bounded authorization policy,
the challenge-digest key and any explicit copies made during delivery. The
library owns no background goroutine or global user authority. Never log or
snapshot challenge-bearing browser options, raw responses, handles or credentials.
`Challenge.Discard` invalidates every unrevealed alias; ordinary diagnostics
cannot inspect its closure-backed custody, including enclosing wrappers.

Install the public identity kernel, audit and outbox histories, then
`postgres.MigrationSource` through the existing migration owner. The native
adapter never opens a private domain transaction. Current active-subject,
expiry and optimistic checks remain under the sole coordinator transaction,
including its final check after audit/lifecycle persistence.
A reserved command that is denied or rolled back can retain its separate
original no-change failure audit; it cannot retain a partial success mutation
or lifecycle effect.

Current exclusions include discoverable/usernameless flows, shared RP tenancy,
Ed25519/RSA, trusted attestation/metadata, credential management, key rotation,
passkeys, sessions and reference/HTTP composition. They remain requirements of
the complete retained goals, not silently removed obligations.

## Verification and release

Consumer fixtures cover the selected real-PostgreSQL ceremony, failure,
concurrency and recovery paths, including actual Chromium output checked by
pinned WPT helpers and WebCrypto. This is not the full WPT suite. The candidate
still requires independent final review and clean-consumer/public-pin proof.
Whole-unit qualification additionally retains the full original goal's coverage,
mutation, security, compatibility, lifecycle and release obligations. A local
test or source pin is not a release, full M15 acceptance or production claim.

See [SECURITY.md](SECURITY.md) and the
[versioned threat model](docs/security/threat-model-v1.md). MIT applies to owned
code; the embedded unmodified PSL retains its MPL 2.0 notice.
