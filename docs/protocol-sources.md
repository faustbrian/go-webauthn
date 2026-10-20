# Selected protocol and source identity

These are finite **selected ceremony profiles**, not whole-unit
conformance or a release. The supported algorithm/attestation combinations are ES256 or
explicitly selected Ed25519 with `none`; unsupported profiles fail closed. RSA, trusted attestation,
metadata, sessions, passkey orchestration and reference/HTTP
composition remain later scope under the complete retained goals.
The discoverable profile is a native prerequisite for later passkey integration,
not closure of M16's signup, session and management journeys.

| Source | Immutable identity | SHA-256 |
| --- | --- | --- |
| [WebAuthn Level 3](https://www.w3.org/TR/2026/CR-webauthn-3-20260526/) | W3C Candidate Recommendation, 26 May 2026 | `cd9be6587c6560ffe6f2b7175324d0bc4cd33963cf752ad414160affd7f8e163` |
| [FIDO CTAP 2.1](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html) | Proposed Standard, 15 June 2021; credential protection §12.1 | `d834d83c3bd317fffc31bd24b9a3c09a7e27d9934f84282963c37f8d60882c03` |
| [Public Suffix List](https://raw.githubusercontent.com/publicsuffix/list/e1b8015c3b2f0f4f8c18659c2480fc1a22c07b20/public_suffix_list.dat) | `e1b8015c3b2f0f4f8c18659c2480fc1a22c07b20` | `fe6adc7fb8014f57d28d69b18d0aa3e581efb432544922e12131a5d4a87bd954` |
| [Web Platform Tests](https://codeload.github.com/web-platform-tests/wpt/tar.gz/9bc6e2404bff5349e48d7962b0a495582bc5ade8) | `9bc6e2404bff5349e48d7962b0a495582bc5ade8` | `559c6d1edbff75dfbacb10a3466a36da8897dc3f586da1866a7b718f928a837a` |
| [EdDSA](https://www.rfc-editor.org/rfc/rfc8032.txt) | RFC 8032, January 2017; §7.1 TEST 1 public key/signature | `ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3` |
| [COSE algorithms](https://www.rfc-editor.org/rfc/rfc9053.txt) | RFC 9053, August 2022; EdDSA and OKP key parameters | `3d470615875620375f8453ba25b8dce7e4d0271e76b0b79a46df34ccb2d56ab0` |

The complete PSL is embedded unchanged from `docs/public_suffix_list.dat`.
It is Mozilla Public License 2.0; its upstream license notice is retained in
the file. Update by downloading that exact upstream path, checking its digest,
and changing the immutable pin and affected origin tests together. Unicode
PSL rules are converted with the fixed Unicode 15.1 IDNA contract from
`go-identifier/v2` revision `9892f17723c0`; Go toolchain Unicode tables never
silently replace that policy.

CBOR/COSE semantics additionally follow [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949),
[RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) and
[RFC 9053](https://www.rfc-editor.org/rfc/rfc9053). This profile accepts bounded
definite-length CBOR with duplicate scalar map keys rejected; tags, floating
point, indefinite lengths and private/alternate COSE key profiles are unsupported.
Client data is hashed byte-for-byte, not reserialized.
The optional EdDSA profile is pinned to Ed25519 (`alg=-8`, `kty=1`, `crv=6`),
not all curves historically assigned to EdDSA. RFC 8032's published public key
and signature are retained as an official crypto oracle; no RFC private key
is retained. An additional fixed WebAuthn-format signature was generated on
2026-10-20 by OpenSSL 3.5.9 (`pkeyutl -sign -rawin`) over
`authenticatorData || SHA256(clientDataJSON)` using a disposable generated
Ed25519 key. Its public key/signature and exact client data are retained in
`algorithm_test.go`; the private key is discarded. This is independent crypto
verification, not an independent authenticator/browser ceremony claim.
Configured origins follow [RFC6454 §6.2](https://www.rfc-editor.org/rfc/rfc6454#section-6.2)
serialization: default ports and an empty trailing port delimiter are rejected,
not silently normalized into a different exact-origin policy.

The preserved planning `PUBLIC_CONTRACTS.json` still mentions an unavailable
`identity.UnitOfWork` and omits ceremony creation/read persistence. The selected
transaction contract explicitly supersedes that adapter-shaped proposal:
the core `Store` owns narrow storage-neutral creation/load/finalization/recovery
operations; only the PostgreSQL adapter imports the sole identity coordinator.
The adapter uses committed `go-identity` source `46d7a68f6b96`, including open
feature execution, exact command custody, audit/lifecycle and native recovery.
No private transaction or substitute command authority is introduced.

## Fixed bounds and authority

- Challenges are 32 cryptographically random bytes, expire in five minutes,
  and are stored only as scoped keyed digests. The digest key is opaque and
  must remain available for original-command retention/recovery as well as
  all active ceremonies. Key rotation/retirement is not selected in this profile.
- Client data: 16 KiB; attestation: 64 KiB; authenticator data: 4 KiB;
  credential ID: 1 KiB; reference opaque user handle: exactly 32 bytes.
  CBOR/JSON nesting is limited to 16 and aggregate structural items to 256.
- Tenant is trusted input selected before configured RP lookup. Credential
  IDs and user handles have RP-wide database uniqueness. This profile rejects
  sharing one RP across tenants rather than inventing a cross-tenant mapping.
- The exact configured origin, RP/configuration version, purpose and subject
  (or explicit pre-auth flow for usernameless assertions)
  are frozen into the ceremony. `crossOrigin=true` and any `topOrigin` member
  deny. Only the explicit exact `http://localhost:<port>` development exception
  is supported; production configuration keeps it disabled.
- Explicit algorithm selection is copied, advertised in exact order, stored
  with ceremony authority and included in the existing keyed challenge digest.
  Absent selection preserves legacy ES256 bytes and fingerprints. Changing the
  profile rejects in-flight ceremonies even without a version bump; version
  configuration must still advance. Native credential JSON stores the exact
  COSE bytes/algorithm and requires no new schema or installed-history rewrite.
- Resident-required registration and assertions without an allowlist follow
  the same pinned WebAuthn §5.4.4/§7.2 profile. The returned 32-byte handle must
  resolve the exact credential/subject mapping; signature verification and
  current active-subject checks precede committed verification. Unsigned
  `credProps` and `none` attestation do not prove physical key residency.
- UP and UV are mandatory. BE is immutable and BS without BE denies.
  Backup-eligible counters retain the maximum and expose bounded counter risk
  for zero/equal/decreasing values. A positive non-backup counter that fails
  to increase denies and requires a separately verified factor/recovery workflow;
  this protocol module does not manufacture that recovery authority.
- Only selected creation `credProps` and `credProtect` outputs survive.
  WebAuthn §10.4 and CTAP2.1 §12.1 make both creation-only: assertion options
  omit these inputs and unsolicited assertion outputs cannot refresh their
  retained registration metadata. `credProps` is an unsigned browser claim,
  never authorization evidence. `credProtect` is an authenticator-data claim;
  none attestation does not establish device provenance. Unknown/unselected
  extension values are discarded and never persisted or advertised.

Official source pins alone do not prove conformance. Independent browser/
authenticator results, the selected real-PostgreSQL failure/concurrency paths,
clean-consumer adoption, independent final review and remaining whole-unit
gates must be completed before their respective acceptance claims.

The selected unmodified WPT browser resources are retained under
`postgres/testdata/wpt` with the upstream license:

| File | SHA-256 |
| --- | --- |
| `utils.js` | `5963e22ce5d27c010030c94e81527771a0d5dd9bca80e502747678f017c04292` |
| `common-inputs.js` | `fb44c680f4f8458f1b34ed0afef2f066e9510e76bc48e39b2807deaace3cfbe8` |
| `LICENSE.md` | `5fac07febb0e2a97fb0d7b0def149ec08b642e1ba4b9c345283ab1cbd2af6570` |

Their test helper consumption is not the full upstream conformance suite.

## Independent browser boundary

The selected consumer runs actual Chromium `navigator.credentials.create/get`
through an isolated loopback CDP virtual CTAP2.1 authenticator. It uses UP/UV,
resident-key capability and `hasCredBlob=true`: [Chromium source
`0e66b94549a8bd85f03fbdf189b752d6e7b63c32`](https://chromium.googlesource.com/chromium/src/+/0e66b94549a8bd85f03fbdf189b752d6e7b63c32/content/browser/webauth/virtual_authenticator.cc)
ties credProtect capability to that CDP flag. The fixture requests no credBlob
input and the verifier retains no credBlob output.

The exercised runtime is Chrome `155.0.8059.85` at that source revision, driven
by Node `26.10.0`, with PostgreSQL `18.6`. The unmodified pinned WPT helpers
independently parse actual browser COSE/UP/UV output and convert its DER signature
for WebCrypto verification before the separate Go verifier and durable Store
accept it. Raw browser responses and challenges remain in memory-only pipes,
never logs or recorded browser traces. This proves only the selected ceremony
profile, not UI behavior, all browsers/authenticators or the complete WPT suite.
This retained browser profile is ES256-only. No Ed25519 browser/authenticator
evidence is claimed; that interoperability obligation remains open, as do the
whole-unit coverage, mutation, release and broader qualification gates.
