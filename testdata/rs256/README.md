# RS256 public verification fixtures

`rs256_test.go` uses the public modulus and exponent from RFC 7515 Appendix
A.2.1. The original RFC text's SHA-256 is
`ecbf84674118e62526511c1237e1deaa86aada86d25b247623a2a7e04ae62e40`.
Only its public parameters are retained; no RFC private components are copied.
Source: <https://www.rfc-editor.org/rfc/rfc7515.txt>, May 2015.

`openssl.json` was generated on 2026-11-13 by `generate.mjs` using OpenSSL 3.5.9.
Its SHA-256 is
`f1c191e3b76c766cda8ec0d041abdb514c12e77cdea956f243d42eac67741363`.
The fixture records the exact executable checksum and public RSA parameters,
client-data bytes, authenticator data and PKCS#1 v1.5/SHA-256 signature over
`authenticatorData || SHA256(clientDataJSON)`. The generated private key is
task-temporary and deleted in the generator's `finally` block. No key is reused
for an application or retained in this repository. This oracle is independent
crypto verification, not an independent authenticator or browser ceremony.

Regenerate from the repository root with an explicitly selected OpenSSL:

```sh
RS256_OPENSSL=/absolute/path/to/openssl node testdata/rs256/generate.mjs
shasum -a 256 testdata/rs256/openssl.json
```

Generation intentionally uses a fresh 3072-bit key, so bytes change. Review the
new public-only fixture, update its checksum here, and run the root RS256 tests
and affected native consumers. Keep the documented OpenSSL revision/checksum
with the result; do not substitute Go's test signer for this independent oracle.

The generated fixture and generator use this repository's MIT license.
The extracted RFC public parameters follow the IETF Trust Legal Provisions:
<https://trustee.ietf.org/license-info/>. RFC 7515 is copyright 2015 IETF Trust
and the persons identified as its authors; code components are provided under
the Simplified BSD License without warranty.
