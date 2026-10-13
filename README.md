# go-webauthn

> **Status: planned.** This repository does not currently provide an
> installable package, a released version, or a runtime API. The module is
> non-releasable; release is blocked pending implementation and executable
> security evidence.

`go-webauthn` reserves the planned Golib boundary for WebAuthn registration
and authentication ceremonies, relying-party and origin policy, challenge
policy, attestation and assertion verification, authenticator metadata,
counters, and security-key profiles. The plan keeps those concepts separate
from identity orchestration, passkey experiences, persistence adapters,
browser interfaces, and sessions.

## Planning documentation

This repository remains planned and non-releasable. The
[documentation map](docs/index.md) links its proposed contracts and security
boundaries; it is not an installation or runtime guide.

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

The versioned [WebAuthn threat model](docs/security/threat-model-v1.md)
identifies the trust boundaries and security evidence required before release.
See [SECURITY.md](SECURITY.md) to report a suspected vulnerability privately.
Neither document establishes a runtime security control.

## Planning and verification

The [repository goal](docs/goal.md) and `modules.json` record the planning scope
and schema-v2 engineering inventory. Planned lifecycle state excludes this
module from installable and released consumer catalogs. The local
`make cohesion` target validates that boundary with the exact checksum-pinned
`go-library-tools` v2.1.2 release declared in `.golib.yaml`.

Passing repository checks proves only that the planning scaffold and metadata
are internally consistent. It does not prove WebAuthn behavior, protocol
conformance, security, or an API. Release requires a separately authorized
implementation and focused executable evidence for the threat-model boundaries.

Use the checksum-verified public `golib` v2.1.2 release declared in
`.golib.yaml`, with Go 1.27.2 as the verification producer. The planned module's
minimum remains Go 1.27.0; no runtime package or release is introduced.
An ordinary standalone checkout is sufficient, without sibling repositories,
goal ledgers or building Tools from source:

```sh
make check
make ci
```

Both routes, and the `make fast-check` alias, check configuration, repository
structure, cohesion, offline specification decisions, local documentation links
and unconditional whole-tree secrets. They run no application tests, mutation
campaigns or release checks. Hosted Required applies the same structural checks
and scans committed changed content against the exact validated PR base or push
before commit, without a fallback base or a duplicate full-history scan.
Missing or invalid change identities and failed checks remain failures.

`make check-full` optionally preserves the previous full manifest-selected
contract, including broad spelling and external-link documentation assurance.
It is not an ordinary CI prerequisite and does not establish runtime or release
qualification for this planned module.

`make check-online` explicitly adds authoritative specification refresh to the
local contract. Scheduled and manual CI also refresh those authorities online
and run whole-tree secrets. Passing any of these planning routes is not runtime
security or release qualification.

See the versioned [Golib ecosystem index](https://github.com/faustbrian/go-library-tools/blob/v1.8.4/docs/ecosystem/README.md)
and [package-family guidance](https://github.com/faustbrian/go-library-tools/blob/v1.8.4/docs/ecosystem/design-language.md#package-families-and-selection)
for the shared design language.

## License

MIT. See [LICENSE](LICENSE).
