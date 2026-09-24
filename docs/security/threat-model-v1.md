# WebAuthn threat model, version 1

Status: planning baseline, 2026-09-24. Scope: the proposed root module of
`github.com/faustbrian/go-webauthn`. There is no source package, supported
version, or runtime security control. This model must be revised when concrete
API, protocol profile, storage boundary, or implementation evidence exists.

## Assets, actors, and boundaries

The assets are authentication decisions, challenge and ceremony state,
credential public keys and identifiers, opaque user handles, relying-party
identity, origin and top-origin policy, attestation trust decisions,
authenticator counters and backup flags, and sensitive operational metadata.
Credential private keys must not cross into the proposed verifier; their
device or synced-provider lifecycle is outside this module. Any service
credential used to fetch metadata belongs to the caller or an explicit future
adapter.

An attacker can control browser-supplied JSON and binary credential responses,
client and authenticator extension values, credential identifiers, replayed or
reordered ceremonies, malformed transport framing, and requests racing for the
same account or challenge. A compromised or malicious authenticator, browser,
origin, proxy, metadata source, dependency, build action, or maintainer is a
separate trust scenario. The application, storage provider, trusted clock,
configured relying-party policy, and transport are not assumed correct merely
because a verifier accepts a response.

| Boundary | Planned owner and required decision |
| --- | --- |
| Browser or transport to parser | Module must bound bytes, nesting, collection counts, decoding, and allocation before parsing; reject ambiguous, malformed, and trailing data. Caller owns request body limits and HTTPS/proxy policy. |
| Parsed client and authenticator data to verifier | Module must bind ceremony type, challenge, origin and top origin where applicable, relying-party ID hash, user-presence and user-verification policy, credential ID, algorithm, signature, and extension semantics. Every required check must fail closed. |
| Verifier to ceremony and credential store | Caller owns durable state, tenant/account binding, expiry, atomic single-use challenge consumption, credential uniqueness, and transactional counter/backup-state updates. An eventual callback contract must make those obligations explicit. |
| Attestation and metadata | Module must make attestation policy and trust anchors explicit. Optional remote metadata acquisition must be caller-controlled and bounded for URL, DNS, redirects, proxy, response size, freshness, and timeouts; no implicit network access. |
| Verification result to application | Caller owns account lookup, authorization, session issuance, recovery, fallback, and rate limits. A successful WebAuthn assertion alone cannot authorize an application action. |
| Diagnostics and release pipeline | Module must avoid sensitive data in errors, logs, traces, metrics, panics, fixtures, and CI artifacts. Maintainers own dependency, action, artifact, and release integrity. |

The planned core has no filesystem, database, queue, cache, process,
environment, plugin, or background-worker access. If a future design adds one,
this model and its ownership and abuse cases must be revised before release.

## Unresolved risks and release evidence

No runtime risk is accepted: no runtime exists. Every row is a release blocker,
not a claim that a mitigation has been implemented. The module maintainer owns
the proposed verifier and parser contracts; the adopting application owns the
caller-side responsibilities. A risk can be accepted only in a later, explicit
record naming its owner, rationale, mitigation, and review condition.

| Risk and attacker outcome | Required mitigation and executable evidence | Owner / review condition |
| --- | --- | --- |
| Origin, relying-party, cross-origin, or ceremony confusion authenticates the wrong site or operation | Pin a documented WebAuthn specification profile; fail closed on origin/top-origin and RP ID hash mismatch, ceremony type, challenge mismatch, and policy-required flags; exercise malformed and cross-site vectors plus independent conformance fixtures. | Module maintainer; review at API design and each protocol-profile change. Caller must configure trusted RP/origin policy. |
| Replayed, expired, duplicated, reordered, or concurrently consumed challenges authenticate twice | Define unpredictable challenge generation and caller-owned storage with tenant/account binding, deadline, atomic consumption, and race semantics; test replay, expiry, cross-account use, concurrent assertions, and partial store failure. | Caller for persistence, module maintainer for contract; review before integration and on store changes. |
| Signature, algorithm, key, attestation, or extension confusion bypasses verification | Require standard maintained cryptographic primitives, strict COSE algorithm/key matching, signature coverage, attestation format and trust-policy decisions, and rejection of unsupported critical extensions; test negative vectors and interoperable positive fixtures. | Module maintainer; review on algorithm, attestation, or extension additions. |
| Unbounded JSON, CBOR, base64url, certificate chains, metadata, or nested references exhaust resources or create parser differentials | Set explicit limits for input bytes, depth, count, decoded size, chain length, concurrency, and time; reject duplicate or ambiguous fields; seed hostile-input tests and bounded fuzzing from the selected specification. | Module maintainer, caller for HTTP body limit; review whenever parser or format support changes. |
| Counter rollback, backup flags, discoverable credentials, or user-handle confusion hides cloning or crosses accounts | Define per-credential state transition policy, counter limitations, account binding, backup-state interpretation, and atomic persistence; test rollback, zero/unsupported counters, backup transitions, and concurrent updates. | Caller for state and account mapping, module maintainer for verification result; review on credential-state changes. |
| Sensitive material leaks through diagnostics or fixtures | Redact challenges, credential and user identifiers, attestation, signatures, keys, and account context by default; test errors, formatting, callbacks, panic paths, and emitted diagnostics with synthetic secrets. | Module maintainer and caller for upstream logs; review on observability changes. |
| Remote metadata or trust-anchor retrieval enables SSRF, stale trust, or availability failure | Keep network access opt-in and caller-controlled; bound DNS/redirect/proxy policy, response size, timeout, retry, cache freshness, and cancellation; test redirect, internal-address, outage, and stale-data decisions if retrieval is implemented. | Caller or explicit adapter owner; review before any network-capable adapter ships. |
| Dependency, CI action, artifact, or maintainer compromise distributes unsafe code | Pin and review dependencies and actions; run relevant vulnerability, secret, license, and workflow checks; verify release provenance and independent consumer behavior at release. Scanners supplement manual security review. | Maintainers; review for dependency/action changes and every release. |

## Release disposition

Release is blocked. Implementation must first define the supported protocol
profile and ownership contracts, then produce focused hostile-input,
fail-closed, replay/concurrency, redaction, cancellation, and conformance
evidence for the actually implemented boundaries. Relevant static, dependency,
secret, and release-integrity checks are required at the corresponding
implementation or release boundary. Planning metadata checks cannot satisfy
those security gates. The public README, manifest, and security policy must
continue to reflect the absence of a usable verifier until that evidence is
reviewed.
