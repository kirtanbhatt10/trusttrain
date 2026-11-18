# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Include:

- the affected component (backend, dashboard, SDK/CLI, workflow) and version or commit;
- steps to reproduce or a proof of concept;
- the impact you expect.

If private reporting is not available, contact the maintainer ([@kirtanbhatt10](https://github.com/kirtanbhatt10)) through the contact details on their GitHub profile and ask for a private channel, without disclosing details publicly.

You should receive an acknowledgement within 7 days. Fixes are released as soon as practical, and reporters are credited unless they prefer otherwise.

## Scope

In scope: authentication and authorization bypass, injection, path traversal, unsafe deserialization, code execution through datasets or models, provenance or signature forgery, secret exposure, and denial of service that bypasses the configured limits.

Out of scope: evasion of the poisoning detectors by a crafted dataset. Detection is heuristic and its limits are documented in [docs/DETECTION_METHODOLOGY.md](docs/DETECTION_METHODOLOGY.md). Improvements are welcome as regular issues or pull requests.

## Hardening checklist for operators

- Run with `TRUSTTRAIN_ENVIRONMENT=production` (enforces a strong JWT secret, an explicit signing key and no wildcard CORS).
- Serve behind TLS; keep the API and database off the public internet where possible.
- Protect the Ed25519 signing key (`0600`, separate backups) and rotate it if exposed.
- Remove the bootstrap admin variables after creating real accounts.
- Keep `TRUSTTRAIN_MAX_UPLOAD_BYTES`, `TRUSTTRAIN_MAX_ROWS` and `TRUSTTRAIN_MAX_TEXT_CHARS_PER_CELL` as low as your datasets allow.
- Enforce rate limits at the gateway when running more than one backend replica.

The full threat model and the results of the latest security review are in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
