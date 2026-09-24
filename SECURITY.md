# Security policy

## Supported versions

There are no supported versions. This repository contains planning metadata,
not an importable package, runtime implementation, tag, or release. Its module
is non-releasable and release is blocked until implementation and executable
security evidence satisfy the [versioned threat model](docs/security/threat-model-v1.md).

## Private reporting

Do not open a public issue for a suspected vulnerability. Use
[GitHub private vulnerability reporting for `faustbrian/go-webauthn`](https://github.com/faustbrian/go-webauthn/security/advisories/new).
Identify the affected commit or planning record, realistic impact, and a
minimal reproduction using synthetic data when possible. Report suspected
vulnerabilities in this repository even while it has no supported version;
the maintainer will determine whether the report affects planning material,
future implementation, or another module.

Do not include live challenges, credential IDs, user handles, attestation
objects, authenticator data, signatures, private keys, session tokens, or
unredacted service output. Redact relying-party, origin, account, device, and
transport identifiers.

## Response and disclosure

The maintainer will privately acknowledge and triage reports, aiming to
acknowledge within five business days. Triage assesses severity from exploit
prerequisites, affected versions, confidentiality or integrity impact, and
availability impact. The maintainer will agree on a remediation and disclosure
plan with the reporter, keep exploit details and reporter identity private
during an embargo, and coordinate affected-module fixes before publication.
Confirmed vulnerabilities in released versions require a private fix,
regression evidence, affected-version assessment, a GitHub advisory, release
notes, and upgrade guidance before public disclosure. This process does not
promise a fix or release date, and it does not imply any version is supported
today.

## Current security boundary

No WebAuthn verifier or runtime control exists here. The planned package would
own bounded protocol parsing, ceremony verification, relying-party and origin
policy, challenge binding, attestation and assertion validation, and
authenticator-state transitions. The caller would own HTTPS deployment,
application identity and authorization, challenge storage and atomic
consumption, credential persistence, rate limits, and incident response.
Those responsibilities are proposed boundaries, not implemented safeguards.

The [threat model](docs/security/threat-model-v1.md) records unresolved risks
and release evidence. Do not use this repository as an authentication
dependency while it remains planning-only.
