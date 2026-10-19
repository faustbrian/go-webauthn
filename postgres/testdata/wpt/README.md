# Pinned official Web Platform Tests resources

These files are unmodified Web Platform Tests resources at
`9bc6e2404bff5349e48d7962b0a495582bc5ade8`, the exact preserved WebAuthn fixture
pin. The source archive SHA-256 is
`559c6d1edbff75dfbacb10a3466a36da8897dc3f586da1866a7b718f928a837a`.

The browser interoperability test uses the official ES256 selection and CBOR/
COSE assertion helpers against actual Chromium virtual-authenticator output;
the production verifier does not import or execute this browser fixture code.
The official sample challenge is not used for a real ceremony: the public
service supplies its own newly generated challenge.

Update from the same immutable paths in `web-platform-tests/wpt`, verify file
digests in `docs/protocol-sources.md`, preserve LICENSE.md and run the affected
browser/PostgreSQL consumer before changing the pinned version. A helper fixture
alone is not the full upstream Web Platform Tests conformance suite.
