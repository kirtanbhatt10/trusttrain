# Threat model

This document covers two things: the threats TrustTrain helps *detect* in ML supply chains, and the threats *to TrustTrain itself* together with the controls that address them. It ends with the results of the application security review.

## 1. Scope and assets

| Asset | Why it matters |
| --- | --- |
| Uploaded datasets | May be proprietary or contain personal data; also the evidence base for incidents |
| Fingerprint and provenance manifests | Integrity anchors; forging one would hide tampering |
| Ed25519 signing key | Whoever holds it can mint "trusted" provenance |
| JWT secret | Whoever holds it can forge any role |
| Lineage, findings, incidents | Drive quarantine and retraining decisions |
| User accounts | Role-based access to all of the above |

## 2. Threats TrustTrain addresses in the ML supply chain

| Threat | Example | TrustTrain control | Residual risk |
| --- | --- | --- | --- |
| Silent dataset modification | Rows edited between review and training | Whole-file, chunk and row fingerprints; `verify`, `compare`, CI policy | Only detects changes relative to a recorded manifest |
| Forged or stale provenance | Manifest edited to match a tampered file | Ed25519 signatures over canonical JSON; trust requires valid signature **and** matching hash | Compromise of the signing key |
| Label flipping | Targeted mislabeled rows | `label_inconsistency`, conflicting-label duplicates | Clean-label attacks are not detected |
| Backdoor triggers | Rare token forcing a target label | `trigger_token_association`; Backdoor Discovery Lab | Multi-token, syntactic or style triggers |
| Duplicate flooding | Crafted example repeated many times | `duplicate_detection` | Paraphrased floods below the similarity threshold |
| Instruction injection | "Ignore previous instructions…" in fine-tuning data | `suspicious_instruction_pattern` | Paraphrased or translated injections |
| Implanted fixed outputs | Same response attached to unrelated prompts | `semantic_inconsistency` (forced responses) | Varied wording of the implanted output |
| Unrelated responses | Responses that do not answer the prompt | `semantic_inconsistency` (relevance rank) | Subtly wrong but on-topic answers |
| Distribution manipulation | Skewed class balance or vocabulary | `distribution_shift` against a trusted reference | Needs a trusted reference version |
| Unknown blast radius | Bad dataset already used in production | Lineage graph and downstream trace; incidents | Only relationships that were recorded |

## 3. Threats to TrustTrain itself (STRIDE)

| Category | Threat | Control |
| --- | --- | --- |
| **Spoofing** | Credential stuffing on login | Separate login rate limit (default 20/min per IP); scrypt hashing; generic error for unknown user and wrong password |
| | Forged tokens | HS256 with a ≥ 32-character secret enforced in production; `sub`, `exp` and `role` required; algorithm pinned |
| **Tampering** | Modifying stored datasets or manifests on disk | Integrity verification re-hashes stored files; provenance becomes untrusted on any mismatch |
| | Path traversal through filenames | Server-generated UUID storage names; `resolve_inside()` refuses paths that escape the storage directory |
| | Archive tricks (zip-slip, zip bombs) | Archives rejected by magic bytes; nothing is ever extracted |
| **Repudiation** | Denying a quarantine or approval | Every state change writes an `AuditEvent`; incidents keep an append-only event history with actor |
| **Information disclosure** | Leaking stack traces | Global exception handler returns a generic 500 and logs details server-side |
| | Cross-origin reads | CORS restricted to configured origins; wildcard refused in production; credentials not allowed |
| | Secrets in the repository or CI logs | `.env*` and keys git-ignored; only `.env.example` with placeholders; workflow passes secrets via env and never echoes them |
| | Signing key readable by others | Generated with mode `0600` (tested) |
| **Denial of service** | Oversized uploads | Streaming size limit (`TRUSTTRAIN_MAX_UPLOAD_BYTES`), 413 on excess; nginx `client_max_body_size` |
| | Huge row counts or giant cells | `TRUSTTRAIN_MAX_ROWS` and a per-cell character limit before detectors run; near-duplicate search capped at 30,000 rows |
| | Request floods | Sliding-window rate limit (default 240/min per IP) |
| **Elevation of privilege** | Viewer performing writes | Role dependency on every route (`viewer < analyst < admin`), with tests for forbidden paths |
| | Executing dataset content | Data is only parsed by pandas or PyArrow; detectors match text with regular expressions and never evaluate it |
| | Unsafe deserialization | No pickle anywhere; lab models use `.npz` with `allow_pickle=False`; registered external models are metadata only and never loaded |
| | Command injection | No `subprocess`, `os.system` or shell invocation in the backend or SDK |

## 4. Application security review

Reviewed against the checklist in the project brief. "Test" names refer to automated tests in `backend/tests/`.

| Area | Result | Evidence |
| --- | --- | --- |
| Authentication | JWT bearer tokens, scrypt password hashes, bootstrap admin from environment only | `test_login_success_and_me`, `test_login_failure`, `test_unknown_user_login_rejected`, `test_forged_token_rejected`, `test_requires_authentication` |
| Authorization | Role checks on every non-public route | `test_viewer_cannot_upload`, `test_only_admin_manages_users`, `test_viewer_sdk_cannot_upload` |
| Input validation | Pydantic schemas with length limits; strict enums for states, roles, severities | `test_finding_validation`, 422 responses |
| File upload restrictions | Extension allow-list, content parsing, archive magic-byte rejection, size limit | `test_invalid_files_rejected`, `test_oversized_upload_rejected`, `test_unsupported_types` |
| Path traversal | Client filenames never used as paths | `test_path_traversal_filename_is_neutralised` |
| Unsafe file handling | Temporary upload files via `mkstemp` in the storage directory, atomic rename, cleanup on failure | `core/files.py` |
| SQL injection | SQLAlchemy parameter binding only; no string-built SQL | `test_sql_injection_in_filters_is_inert` |
| XSS | React escapes all output; no `dangerouslySetInnerHTML`; CSP in nginx (`default-src 'self'`); Markdown reports are shown as plain text in the dashboard | Code review, `pages/Reports.tsx` |
| CSRF | Not applicable: no cookies or ambient credentials; tokens are sent explicitly in the `Authorization` header | Design |
| CORS | Allow-list; methods and headers restricted; wildcard refused in production | `test_cors_only_allows_configured_origin`, `test_production_requires_secure_config` |
| Rate limiting | General and login limits | `test_rate_limit` |
| Dependency vulnerabilities | `pip-audit`: none found. `npm audit --omit=dev`: none. Dev-only advisory below | See [TESTING.md](TESTING.md) |
| Secret exposure | No secrets committed; production refuses weak or missing secrets | `test_production_requires_secure_config`, `.gitignore` |
| Insecure temporary files | `mkstemp` and `TemporaryDirectory` only | bandit clean |
| ZIP/archive extraction | Never extracted; rejected | `test_invalid_files_rejected` |
| Resource exhaustion | Size, row and cell limits | `test_row_limit_enforced`, `test_oversized_upload_rejected` |
| Unsafe deserialization | No pickle; `allow_pickle=False` | `test_save_load_without_pickle`, `test_external_model_cannot_be_executed` |
| Command injection | No shell execution paths | bandit clean, code review |

### Findings fixed during the review

- **Rate limiting behind the bundled nginx proxy.** uvicorn only trusts `X-Forwarded-For` from `127.0.0.1` by default, so in the Docker deployment every request appeared to come from the nginx container and all users shared one rate-limit bucket. `docker-compose.yml` now pins the nginx container's address and sets `FORWARDED_ALLOW_IPS` to it.

### Known limitations and accepted risks

- **In-memory rate limiter:** per process; not shared across replicas or restarts. Use a gateway or Redis-backed limiter when scaling out.
- **Synchronous inspection:** a request holds a worker for the duration of the inspection (bounded by the limits above).
- **File-based signing key:** adequate for a single instance. Use KMS or HSM-backed keys for higher assurance.
- **Single signing key:** manifests signed by a previous key are reported as untrusted ("unknown key") after rotation. Re-sign with `POST /api/datasets/{id}/provenance`.
- **Token revocation:** JWTs are valid until expiry (default 60 minutes); there is no server-side revocation list.
- **Dev-only npm advisory:** `picomatch` (GHSA-fc5q-39xc-vjpf, ReDoS) reaches the project only through Vite and Vitest during development and build; no patched release exists at the time of writing, and it is not part of the shipped bundle.
- **Downloaded Markdown reports:** user-supplied text (titles, notes, descriptions) is escaped only for table syntax, not for HTML. Open downloaded reports in a viewer that does not render raw HTML.
- **Detection evasion:** an attacker who knows the detectors can craft poisons that evade them (see [DETECTION_METHODOLOGY.md](DETECTION_METHODOLOGY.md)).
