# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-18

First public release.

### Added
- **Dataset DNA:** whole-file, 1 MiB chunk and row-level SHA-256 fingerprints with a Merkle root for CSV, JSON, JSONL, Parquet and TXT; metadata extraction; duplicate detection; manifest generation; integrity verification and version comparison (rows added and removed, schema and dtype changes).
- **Provenance:** Ed25519-signed provenance manifests covering source, version, hashes, processing operations, parent and derived datasets, approval and integrity status; trust requires a valid signature and a matching file hash.
- **Poisoning detection:** eight explainable detectors (statistical anomaly, duplicates with conflicting labels, label inconsistency, trigger-token association, embedding outliers, suspicious instruction patterns, semantic input-output inconsistency, distribution shift) with configurable thresholds and risk aggregation.
- **Backdoor Discovery Lab:** deterministic PyTorch toy classifiers, baseline evaluation, trigger probing, clean-vs-suspect comparison and behavior regression, with four distinct verdicts.
- **Lineage:** NetworkX graph of datasets, processing operations, training runs, models, fine-tunes and deployments, built only from recorded relationships; downstream impact tracing.
- **Incident response:** state machine, dataset association with impact analysis, notes, explicit admin-only quarantine and release, remediation history, JSON and Markdown reports.
- **API:** FastAPI with JWT authentication, viewer, analyst and admin roles, rate limiting, CORS allow-list, security headers and upload, row and cell limits.
- **Dashboard:** React, TypeScript, Vite and Tailwind CSS: overview, dataset inventory and inspection, findings triage, model evaluation, interactive supply-chain graph, training runs, incidents, reports and settings.
- **Python SDK and `trusttrain` CLI:** `init`, `fingerprint`, `verify`, `inspect`, `lineage`, `report`, `ci`.
- **GitHub Actions:** CI workflow and a reusable dataset-check workflow with policy-based enforcement.
- **Synthetic attack lab:** reproducible poisoned datasets with ground truth, a detection benchmark and regression floors.
- PostgreSQL support with Alembic migrations; Docker images and Compose file.
- Documentation: README, architecture, threat model, detection methodology, API reference, testing, deployment, research and benchmarks.
