# TrustTrain

**AI training supply chain security platform: dataset integrity, poisoning detection, model behavior analysis, provenance and ML artifact lineage.**

TrustTrain helps ML teams answer a simple question before and after they train: *can we trust the data that went into this model, and if not, what is affected?*

---

## Table of contents

1. [Overview](#overview)
2. [Problem statement](#problem-statement)
3. [Why TrustTrain](#why-trusttrain)
4. [Features](#features)
5. [Architecture](#architecture)
6. [Technology stack](#technology-stack)
7. [Installation](#installation)
8. [Backend setup](#backend-setup)
9. [Frontend setup](#frontend-setup)
10. [Database setup](#database-setup)
11. [Docker setup](#docker-setup)
12. [CLI usage](#cli-usage)
13. [SDK usage](#sdk-usage)
14. [API documentation](#api-documentation)
15. [Testing](#testing)
16. [Synthetic attack lab](#synthetic-attack-lab)
17. [Security limitations](#security-limitations)
18. [Roadmap](#roadmap)
19. [Contributing](#contributing)
20. [License](#license)

---

## Overview

TrustTrain is a self-hosted platform made of:

- a **FastAPI backend** that fingerprints datasets, signs provenance manifests, runs poisoning detectors, evaluates models for trigger behavior, records lineage and manages security incidents;
- a **React dashboard** for inventory, findings, lineage graphs, incidents and reports;
- a **Python SDK and CLI** (`trusttrain`) for scripts, notebooks and CI;
- a **reusable GitHub Actions workflow** that verifies datasets against committed manifests and enforces a configurable policy.

Every number shown in the dashboard is computed from data stored by the backend. Findings are presented as **evidence for investigation**, with confidence, methodology and limitations. They are not verdicts of malicious intent.

## Problem statement

Modern models are trained on data assembled from many sources: scraped corpora, vendor datasets, user feedback, synthetic data and earlier model outputs. Each hop is an opportunity for:

- **silent modification**: a dataset changes between review and training, and nobody notices;
- **data poisoning**: label flips, duplicated crafted examples, injected instructions or trigger phrases that implant a backdoor;
- **lost lineage**: when a dataset is found to be bad, nobody can say which training runs, checkpoints and deployments consumed it.

Code supply chains have signing, SBOMs and dependency graphs. Training data usually has none of these.

## Why TrustTrain

| Question | How TrustTrain answers it |
| --- | --- |
| Has this dataset been modified? | SHA-256 whole-file, chunk-level and row-level fingerprints with version comparison |
| Can I trust this manifest? | Ed25519-signed provenance manifests; unsigned or unverifiable manifests are never shown as trusted |
| Does it contain suspicious examples? | Eight explainable detectors with configurable thresholds |
| Does a model react to a trigger? | Backdoor Discovery Lab with baseline, trigger probing and clean-vs-suspect comparison |
| What is affected if this dataset is bad? | NetworkX lineage graph built only from recorded relationships |
| What do we do now? | Incident workflow with explicit quarantine, notes, remediation history and reports |

## Features

### Dataset DNA (fingerprinting)
- Whole-file SHA-256, 1 MiB chunk hashes and per-row SHA-256 fingerprints with a Merkle root
- CSV, JSON, JSONL, Parquet and TXT
- Metadata extraction (rows, columns, dtypes, encoding), exact duplicate detection
- Manifest generation, integrity verification and row-level diff (added and removed rows)
- Source files are opened read-only and never modified

### Provenance
- Name, version, source, import time, hashes, processing operations, parent/derived datasets, approval and integrity status
- Ed25519-signed, canonical-JSON manifests with public-key fingerprints; verification on read

### Poisoning detection
| Detector | Method |
| --- | --- |
| `statistical_anomaly` | Robust z-score (median/MAD) per numeric column and text length; Isolation Forest across numeric features |
| `duplicate_detection` | Exact and near-duplicates (TF-IDF cosine), including duplicates with conflicting labels |
| `label_inconsistency` | Out-of-fold logistic regression; rows whose label gets very low probability (simplified confident learning) |
| `trigger_token_association` | Rare tokens that co-occur with one label while the rest of the text points to another |
| `embedding_outlier` | Local Outlier Factor in an LSA embedding space (optional local sentence-transformers model) |
| `suspicious_instruction_pattern` | Prompt-injection phrasing, hidden Unicode, encoded blobs, code-execution primitives, exfiltration links |
| `semantic_inconsistency` | Prompt/response relevance rank and "forced response" detection for instruction datasets |
| `distribution_shift` | Chi-square (labels), Kolmogorov–Smirnov (numeric/text length), Jensen–Shannon (vocabulary) against a reference version |

Each finding carries an ID, severity, method, evidence row references, confidence, explanation and suggested investigation steps. See [docs/DETECTION_METHODOLOGY.md](docs/DETECTION_METHODOLOGY.md).

### Backdoor Discovery Lab
- Trains small, deterministic PyTorch bag-of-words classifiers on lab datasets (isolated artifacts, stored as `.npz` without pickle)
- Baseline accuracy, trigger test generation, per-token flip rates against a probe population, clean-vs-suspect comparison and behavior regression
- Distinguishes `confirmed_experimental_trigger`, `suspicious_behavior_detected`, `unverified_potential_backdoor` and `no_trigger_behavior_detected`

### Lineage
- Datasets → processing operations → derived datasets → training runs → models → fine-tuned models → deployments
- Downstream impact tracing from any dataset; interactive graph in the dashboard

### Incident response
- States: `open`, `under_investigation`, `quarantined`, `remediation_required`, `resolved`
- Associate datasets, compute affected downstream artifacts, investigation notes, explicit admin-only quarantine, remediation history, JSON and Markdown reports
- Nothing is ever deleted automatically

### Developer interfaces
- Python SDK (`from trusttrain import TrustTrain`) with typed results and error handling
- CLI: `init`, `fingerprint`, `verify`, `inspect`, `lineage`, `report`, `ci`
- Reusable GitHub Actions workflow with policy-based enforcement

## Architecture

```mermaid
flowchart LR
    subgraph Clients
        UI[React dashboard]
        SDK[Python SDK]
        CLI[trusttrain CLI]
        GHA[GitHub Actions workflow]
    end

    subgraph API[FastAPI backend]
        AUTH[Auth + RBAC<br/>JWT, rate limiting]
        DS[Dataset service<br/>safe uploads]
        FP[Dataset DNA<br/>fingerprints]
        PROV[Provenance<br/>Ed25519 signing]
        DET[Detection engine<br/>8 detectors]
        EVAL[Backdoor Discovery Lab<br/>PyTorch toy models]
        LIN[Lineage<br/>NetworkX]
        INC[Incidents + reports]
    end

    DB[(PostgreSQL<br/>SQLAlchemy + Alembic)]
    FS[(Artifact store<br/>uploads, manifests, lab models)]

    UI --> AUTH
    SDK --> AUTH
    CLI --> SDK
    GHA --> CLI
    AUTH --> DS --> FP
    DS --> PROV
    DS --> DET
    EVAL --> FS
    LIN --> DB
    INC --> LIN
    DS --> DB
    DS --> FS
    DET --> DB
    PROV --> FS
```

More detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Technology stack

| Layer | Technology |
| --- | --- |
| API | Python 3.11+, FastAPI, Pydantic v2, Uvicorn |
| Persistence | PostgreSQL 16 (SQLite for local development and tests), SQLAlchemy 2, Alembic |
| Data | pandas, PyArrow, NumPy, SciPy |
| ML | scikit-learn, PyTorch (CPU), optional local sentence-transformers |
| Graph | NetworkX |
| Crypto | `cryptography` (Ed25519), PyJWT (HS256), scrypt password hashing |
| Frontend | React 19, TypeScript, Vite, Tailwind CSS 4, React Router |
| Tooling | pytest, Vitest, Testing Library, ruff, mypy, bandit, pip-audit, npm audit |
| Packaging | Docker, docker compose, nginx |

All versions are pinned in `backend/requirements*.txt`, `sdk/pyproject.toml` and `frontend/package.json`.

**About Hugging Face Transformers:** the default embedding backend is TF-IDF + truncated SVD, so the platform runs fully offline with no model download. If `sentence-transformers` is installed and `TRUSTTRAIN_EMBEDDING_MODEL` points to a local model directory, that model is used instead. No paid API is required.

## Installation

Prerequisites: Python 3.11+, Node.js 20+ (22 recommended), and optionally Docker and PostgreSQL.

```bash
git clone https://github.com/kirtanbhatt10/trusttrain.git
cd trusttrain
cp .env.example .env    # then replace every placeholder
```

## Backend setup

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
# CPU-only PyTorch first, to avoid pulling CUDA wheels
pip install --index-url https://download.pytorch.org/whl/cpu torch==2.15.0
pip install -r requirements-dev.txt

export TRUSTTRAIN_BOOTSTRAP_ADMIN_EMAIL=admin@example.com
export TRUSTTRAIN_BOOTSTRAP_ADMIN_PASSWORD='choose-a-long-password'
uvicorn app.main:app --reload --port 8000
```

In `development` mode (the default) the backend uses SQLite under `./trusttrain-data`, creates tables automatically, generates a local Ed25519 signing key and, if `TRUSTTRAIN_JWT_SECRET` is unset, uses an ephemeral secret. **Production mode refuses to start** without a strong JWT secret, a provided signing key and non-wildcard CORS origins.

## Frontend setup

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173, proxies /api to http://localhost:8000
npm run build      # production bundle in dist/
```

## Database setup

PostgreSQL is the production database. Schemas are managed with Alembic:

```bash
createdb trusttrain
export TRUSTTRAIN_DATABASE_URL=postgresql+psycopg://USER:PASSWORD@localhost:5432/trusttrain
cd backend && alembic upgrade head
```

The Docker backend image runs `alembic upgrade head` on start-up.

## Docker setup

```bash
cp .env.example .env     # set POSTGRES_PASSWORD, TRUSTTRAIN_JWT_SECRET, admin bootstrap values
docker compose up --build
```

- Dashboard: <http://localhost:8080>
- API and OpenAPI docs: <http://localhost:8000/docs>

Ports bind to `127.0.0.1` only. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for production guidance.

## CLI usage

```bash
pip install ./sdk
export TRUSTTRAIN_API_URL=http://localhost:8000
export TRUSTTRAIN_EMAIL=admin@example.com TRUSTTRAIN_PASSWORD='...'   # or TRUSTTRAIN_TOKEN

trusttrain init --dataset data/train.csv          # writes .trusttrain/config.json
trusttrain fingerprint data/train.csv              # offline: writes a manifest
trusttrain verify data/train.csv                   # offline: exit 1 on mismatch, with row diff
trusttrain inspect data/train.csv --fail-on high   # upload + run detectors
trusttrain lineage --dataset DATASET_ID            # downstream artifacts
trusttrain report --incident INCIDENT_ID           # Markdown incident report
trusttrain ci --output trusttrain-report.json      # policy checks for CI
```

`fingerprint` and `verify` run locally and need no server.

## SDK usage

```python
from trusttrain import TrustTrain

security = TrustTrain(api_url="http://localhost:8000")   # credentials from env vars

report = security.inspect_dataset("./training-data")    # a file or a directory
print(report.risk_level)                                 # highest level across files
for finding in report.findings:
    print(finding.severity, finding.method, finding.title)

single = security.inspect_dataset("./training-data/train.csv")
run = security.record_training_run("sentiment-v3", dataset_ids=[single.dataset_id])
security.register_model("sentiment-v3", training_run_id=run["id"])
print(security.lineage(single.dataset_id))
```

See [sdk/README.md](sdk/README.md) and [examples/](examples/).

## API documentation

The running server publishes interactive OpenAPI docs at `/docs` and `/redoc`. A full endpoint reference with roles and examples is in [docs/API_REFERENCE.md](docs/API_REFERENCE.md).

Authentication: `POST /api/auth/login` returns a bearer token. Roles are `viewer` (read), `analyst` (upload, inspect, evaluate, manage incidents) and `admin` (quarantine, approvals, users).

## Testing

```bash
cd backend && pytest                    # backend unit, API, integration and attack-lab tests
cd sdk && pytest                        # SDK and CLI
cd frontend && npm test && npm run build
```

Run the backend suite against PostgreSQL by setting `TRUSTTRAIN_TEST_DATABASE_URL`. Results of the last full run, and how to reproduce them, are in [docs/TESTING.md](docs/TESTING.md).

## Synthetic attack lab

```bash
python scripts/generate_attack_lab.py   # writes datasets/synthetic/ (seeded, reproducible)
python scripts/run_benchmark.py --output docs/benchmark-results.json
```

The lab generates clean and poisoned sentiment and instruction datasets with label flips, trigger-token backdoors, conflicting duplicates, injected instructions, out-of-range values, unrelated and forced responses, and hidden-character injections. Ground truth is written to `ground_truth.json`. Everything comes from templates; no real or private data is used and no executable payloads are produced. See [datasets/synthetic/README.md](datasets/synthetic/README.md) and [docs/RESEARCH_AND_BENCHMARKS.md](docs/RESEARCH_AND_BENCHMARKS.md).

Measured on the lab (actionable findings, severity medium or above):

| Dataset | Rows | Poisoned rows | Precision | Recall | F1 | FPR |
| --- | --- | --- | --- | --- | --- | --- |
| Sentiment | 1,282 | 126 | 0.858 | 0.865 | 0.862 | 0.016 |
| Instruction | 600 | 45 | 1.000 | 0.978 | 0.989 | 0.000 |

These are results on synthetic data that the detectors were developed against. They do **not** predict performance on real-world poisoning.

## Security limitations

- Detection is heuristic and statistical. A clean report does not prove a dataset is unpoisoned, and a finding does not prove malicious intent.
- Adaptive attackers who know the detectors can craft poisons that evade them (for example clean-label attacks, or triggers that are not rare tokens).
- The Backdoor Discovery Lab evaluates TrustTrain's own toy classifiers. It does not load arbitrary third-party model formats.
- The rate limiter is in-memory and per process. Put a shared limiter or reverse proxy in front of multi-replica deployments.
- Datasets are capped by `TRUSTTRAIN_MAX_UPLOAD_BYTES` (default 50 MiB) and `TRUSTTRAIN_MAX_ROWS` (default 200,000). Inspection runs synchronously in the request.
- Signing keys are file-based. Use a KMS or HSM-backed key in serious deployments.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and [SECURITY.md](SECURITY.md).

## Roadmap

- Background job queue for large inspections
- Streaming fingerprints for datasets larger than memory
- Model-format adapters (safetensors, ONNX) for behavioral evaluation of external models
- Sigstore/KMS signing backends and in-toto attestations
- Image and audio dataset support
- Clean-label and gradient-based poisoning detectors (e.g. spectral signatures, activation clustering)
- SSO/OIDC authentication

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
