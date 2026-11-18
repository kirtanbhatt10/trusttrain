# Testing

## How to run

```bash
# Backend: unit, API, security, integration, attack-lab and SDK-against-API tests
cd backend
pip install --index-url https://download.pytorch.org/whl/cpu torch==2.15.0
pip install -r requirements-dev.txt && pip install -e ../sdk
pytest --cov=app

# Same suite against PostgreSQL (tables are dropped before each test, so use a scratch database)
TRUSTTRAIN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/trusttrain_test pytest

# SDK and CLI
cd sdk && pip install -e ".[dev]" && pytest --cov=trusttrain

# Frontend
cd frontend && npm install && npm run lint && npm test && npm run build

# Static analysis and security
ruff check backend sdk scripts examples && ruff format --check backend sdk scripts examples
(cd backend && mypy app) && (cd sdk && mypy trusttrain)
bandit -r backend/app sdk/trusttrain scripts examples -c backend/pyproject.toml
pip-audit -r backend/requirements.txt
(cd frontend && npm audit --omit=dev)
python -m compileall -q backend/app sdk/trusttrain scripts examples

# Migrations match the models
cd backend && TRUSTTRAIN_DATABASE_URL=sqlite:////tmp/m.db alembic upgrade head && alembic check
```

The `CI` workflow (`.github/workflows/ci.yml`) runs these on every push and pull request.

## Test inventory

| Suite | File | Covers |
| --- | --- | --- |
| Backend | `test_api_core.py` | Health, login, `/me`, forged and missing tokens, role enforcement, user management, invalid files, oversized uploads, path traversal, row and cell limits, rate limiting, CORS, production config validation, SQL injection inertness, 404s |
| | `test_fingerprint.py` | All five formats, cross-format row hashes, chunk localisation, version comparison, reordering, Merkle properties, manifest verification, upload of every format through the API, tampering detection, candidate-copy comparison, cell-length limit |
| | `test_provenance.py` | Ed25519 round trip, key file permissions, refusal without key in production, provenance on upload, tampered manifest, unknown key, modified file, approval re-signing, derived dataset parents |
| | `test_detectors.py` | Each of the eight detectors on positive and negative cases, column-role inference, rule disabling, risk scoring, engine method status and error isolation |
| | `test_evaluation.py` | Deterministic toy model, pickle-free save and load, trigger candidates, clean model has no trigger, poisoned lab model confirmed, undeclared trigger discovered but not "confirmed", evaluation API, external models never executed |
| | `test_lineage_incidents.py` | Graph contains only recorded edges, downstream trace, incident lifecycle and invalid transitions, associations, quarantine, reports, dashboard summary, empty dashboard, findings API |
| | `test_attack_lab.py` | Reproducibility, ground-truth integrity, every attack type surfaced, precision and recall floors, clean datasets stay low risk, distribution shift |
| | `test_integration_workflow.py` | The full brief workflow (below) |
| | `test_sdk_integration.py` | Real SDK and CLI against the real API, with FastAPI's TestClient as the HTTP transport |
| SDK and CLI | `sdk/tests/test_client.py` | Every public client method, auth flows, directory inspection, error wrapping, context manager |
| | `sdk/tests/test_cli.py` | `init`, `fingerprint`, `verify`, `inspect`, `lineage`, `report`, `ci` (offline and API policies), env overrides |
| | `sdk/tests/test_local.py` | Offline fingerprinting and verification |
| Frontend | `src/test/app.test.tsx` | Login and session expiry, rendering every page from the sidebar, API-driven metrics, loading, empty and error (with retry) states, running an inspection, filtering and triaging findings, incident creation, transitions and notes, lineage highlighting |
| | `src/services/api.test.ts` | Bearer token, query strings, error and validation mapping, 401 handling, network failures, Markdown reports |

### Integration workflow (`test_full_supply_chain_workflow`)

1. Upload a clean dataset
2. Generate its fingerprint
3. Generate signed provenance
4. Inspect the dataset
5. Create a training run
6. Associate a model artifact
7. Modify a copy of the dataset
8. Detect the integrity mismatch
9. Trace affected downstream artifacts
10. Create an incident
11. Generate an investigation report

## Results of the latest full run

Environment: Linux x86_64, Python 3.13.18, Node.js 22.23.4, PostgreSQL 16 (Ubuntu package), run on 2026-11-18.

| Check | Result |
| --- | --- |
| Backend tests (SQLite) | **110 passed**, line coverage 94% |
| Backend tests (PostgreSQL 16) | **110 passed** |
| SDK and CLI tests | **38 passed**, line coverage 96% |
| Frontend tests (Vitest) | **20 passed** (2 files) |
| Frontend type-check (`tsc --noEmit`) | Passed |
| Frontend production build | Passed |
| ruff (lint and format) | No issues |
| mypy (backend `app`, SDK) | No issues |
| bandit | No issues |
| `python -m compileall` | Passed |
| Alembic `upgrade head` + `check` (SQLite and PostgreSQL) | In sync |
| pip-audit (`requirements.txt`, `requirements-dev.txt`) | No known vulnerabilities |
| `npm audit --omit=dev` (shipped dependencies) | 0 vulnerabilities |
| `npm audit` (including dev tooling) | 1 high: `picomatch` ReDoS (GHSA-fc5q-39xc-vjpf) via Vite and Vitest; no patched version published; build-time only |
| Manual smoke test | Production-mode server on PostgreSQL; CLI `init`, `fingerprint`, `verify`, `inspect`; `examples/quickstart.py` end to end |

### Not run in this environment

- **Docker images and `docker compose up`.** The build environment could not pull base images from Docker Hub. `docker compose config` validates the compose file, and the backend was exercised directly with the same settings the image uses (production mode, PostgreSQL, file-based signing key, Alembic migrations).
- **Python 3.11 and 3.12.** Tests ran on 3.13. CI covers 3.11 (SDK) and 3.12 (backend).
- **Browser end-to-end tests.** Frontend behavior is covered by component tests with a mocked API; there is no Playwright or Cypress suite yet.

## Adversarial tests and detection effectiveness

The attack lab and benchmark are described in [RESEARCH_AND_BENCHMARKS.md](RESEARCH_AND_BENCHMARKS.md). `test_attack_lab.py` enforces regression floors so a change that weakens detection fails CI. Each attack type must be surfaced on at least 70% of its rows. Actionable precision and recall must stay at or above 0.8, with a false-positive rate at or below 3%, on both datasets. Clean datasets must stay at low risk or below.
