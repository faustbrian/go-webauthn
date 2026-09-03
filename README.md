# go-webauthn

> **Status: planned.** This repository does not currently provide an
> installable package, a released version, or a runtime API.

`go-webauthn` reserves the planned Golib boundary for WebAuthn registration
and authentication ceremonies, relying-party and origin policy, challenge
policy, attestation and assertion verification, authenticator metadata,
counters, and security-key profiles. The plan keeps those concepts separate
from identity orchestration, passkey experiences, persistence adapters,
browser interfaces, and sessions.

## Planned responsibility

The future root package is intended to own WebAuthn ceremony and verification
contracts, bounded browser-protocol parsing, relying-party policy,
authenticator state transitions, and caller-supplied storage coordination. Its
contracts remain proposals until they are implemented, reviewed, verified,
and released.

## Non-goals

The planned root boundary does not own:

- identity signup, sign-in, account, or session orchestration;
- passkey user experiences or browser JavaScript;
- database clients, migrations, transactions, or persistence adapters; or
- application authorization policy, caches, or background workers.

Those concerns may become separate modules or compose existing Golib packages.
Their presence in planning material does not make them available here.

## Lifecycle and ownership

Implementation, hardening, and release have not started. The current module
declaration exists only so repository tooling can validate the planned module
identity, family, ownership, and lifecycle metadata.

The plan requires caller-owned configuration and runtime resources, copied
mutable inputs, context-bounded external operations, and no package-owned
background work. These are design constraints, not claims about released
behavior.

## Planning and verification

The [repository goal](docs/goal.md) and `modules.json` record the planning scope
and schema-v2 engineering inventory. Planned lifecycle state excludes this
module from installable and released consumer catalogs. The local
`make cohesion` target validates that boundary with the exact checksum-pinned
`go-library-tools` v1.4.0 release declared in `.golib.yaml`.

Passing repository checks proves only that the planning scaffold and metadata
are internally consistent. It does not prove WebAuthn behavior, protocol
conformance, or an API.

See the versioned [Golib ecosystem index](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/README.md)
and [package-family guidance](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/design-language.md#package-families-and-selection)
for the shared design language.

## License

MIT. See [LICENSE](LICENSE).
