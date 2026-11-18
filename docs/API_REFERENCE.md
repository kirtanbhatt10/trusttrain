# API reference

The backend exposes a JSON REST API under `/api`. A running server also serves interactive OpenAPI documentation at `/docs` (Swagger UI) and `/redoc`, and the raw schema at `/openapi.json`. Those are generated from the code and are always authoritative.

## Authentication

```http
POST /api/auth/login
Content-Type: application/json

{"email": "admin@example.com", "password": "..."}
```

Response:

```json
{"access_token": "<JWT>", "token_type": "bearer", "expires_in": 3600, "role": "admin"}
```

Send the token on every other request:

```http
Authorization: Bearer <JWT>
```

Tokens are HS256 JWTs with `sub`, `role`, `iat` and `exp` claims. Lifetime is `TRUSTTRAIN_JWT_TTL_MINUTES` (default 60). Login is rate limited separately (`TRUSTTRAIN_AUTH_RATE_LIMIT_PER_MINUTE`, default 20 per client IP).

### Roles

Roles are hierarchical: `admin` ⊃ `analyst` ⊃ `viewer`.

| Role | Can |
| --- | --- |
| `viewer` | Read everything: datasets, findings, lineage, incidents, reports |
| `analyst` | Upload datasets, run inspections and evaluations, record training runs, models and deployments, manage incidents and findings |
| `admin` | Everything above plus: sign provenance, change approval status, quarantine or release artifacts, manage users |

## Errors

Errors use FastAPI's standard shape:

```json
{"detail": "Dataset not found"}
```

| Status | Meaning |
| --- | --- |
| 401 | Missing, invalid or expired token; wrong credentials |
| 403 | Authenticated but role too low |
| 404 | Unknown ID |
| 409 | Conflict: invalid incident state transition, approving a quarantined dataset |
| 413 | Upload exceeds `TRUSTTRAIN_MAX_UPLOAD_BYTES` |
| 422 | Request validation failed, or the upload is an unsupported, malformed or archive file |
| 429 | Rate limit exceeded (`Retry-After` header set) |
| 500 | Unexpected error; details are logged server-side, never returned |

## Endpoints

| Method | Path | Minimum role | Description |
| --- | --- | --- | --- |
| `GET` | `/api/health` | public | Liveness and version |
| `POST` | `/api/auth/login` | public | Exchange credentials for a token |
| `GET` | `/api/auth/me` | viewer | Current user |
| `GET` | `/api/users` | admin | List users |
| `POST` | `/api/users` | admin | Create user (`email`, `password` ≥ 12 chars, `role`) |
| `GET` | `/api/dashboard/summary` | viewer | Aggregated counts and distributions for the overview page |
| `GET` | `/api/activity` | viewer | Recent audit events |
| `GET` | `/api/reports/datasets/{dataset_id}` | viewer | Dataset security report (JSON) |
| `GET` | `/api/settings` | viewer | Effective, non-secret settings (limits, thresholds) |
| `GET` | `/api/datasets` | viewer | List datasets (filters: `risk_level`, `integrity_status`) |
| `POST` | `/api/datasets` | analyst | Upload a dataset (multipart) |
| `GET` | `/api/datasets/{dataset_id}` | viewer | Dataset details |
| `PATCH` | `/api/datasets/{dataset_id}` | analyst | Update `description`; changing `approval_status` requires admin |
| `GET` | `/api/datasets/{dataset_id}/manifest` | viewer | Fingerprint manifest recorded at import |
| `POST` | `/api/datasets/{dataset_id}/verify` | analyst | Re-hash the stored file and compare with the manifest |
| `POST` | `/api/datasets/{dataset_id}/compare` | analyst | Compare an uploaded candidate copy with the import fingerprint (not stored) |
| `GET` | `/api/datasets/{dataset_id}/provenance` | viewer | Latest provenance manifest with signature verification result |
| `POST` | `/api/datasets/{dataset_id}/provenance` | admin | Create and sign a new provenance manifest |
| `POST` | `/api/datasets/derivations` | analyst | Record a processing operation from parent to child dataset |
| `POST` | `/api/datasets/{dataset_id}/inspect` | analyst | Run poisoning detectors |
| `GET` | `/api/datasets/{dataset_id}/inspections` | viewer | Inspection history |
| `GET` | `/api/datasets/{dataset_id}/findings` | viewer | Findings for a dataset |
| `GET` | `/api/findings` | viewer | All findings (filters: `severity`, `method`, `status`, `dataset_id`, `limit` ≤ 1000) |
| `GET` | `/api/findings/{finding_id}` | viewer | One finding with full evidence |
| `PATCH` | `/api/findings/{finding_id}` | analyst | Triage: `open`, `acknowledged`, `dismissed` |
| `GET` | `/api/inspections/{inspection_id}` | viewer | One inspection with per-method status |
| `GET` | `/api/training-runs` | viewer | List training runs |
| `POST` | `/api/training-runs` | analyst | Record a training run and its input datasets |
| `GET` | `/api/training-runs/{run_id}` | viewer | Training run details |
| `GET` | `/api/models` | viewer | List model artifacts |
| `POST` | `/api/models` | analyst | Register a model artifact (metadata only) |
| `POST` | `/api/models/lab` | analyst | Train an isolated experimental classifier on a registered dataset |
| `GET` | `/api/models/{model_id}` | viewer | Model details |
| `GET` | `/api/deployments` | viewer | List deployments |
| `POST` | `/api/deployments` | analyst | Record a deployment of a model |
| `GET` | `/api/evaluations` | viewer | List behavioral evaluations |
| `POST` | `/api/evaluations` | analyst | Run the Backdoor Discovery Lab on a lab model |
| `GET` | `/api/evaluations/{evaluation_id}` | viewer | Evaluation results |
| `GET` | `/api/lineage/graph` | viewer | Full lineage graph (nodes and edges) |
| `GET` | `/api/lineage/datasets/{dataset_id}/downstream` | viewer | Recorded downstream artifacts of a dataset |
| `GET` | `/api/incidents` | viewer | List incidents |
| `POST` | `/api/incidents` | analyst | Create an incident |
| `GET` | `/api/incidents/{incident_id}` | viewer | Incident with events and affected artifacts |
| `POST` | `/api/incidents/{incident_id}/datasets/{dataset_id}` | analyst | Associate a dataset |
| `POST` | `/api/incidents/{incident_id}/transition` | analyst | Change state |
| `POST` | `/api/incidents/{incident_id}/notes` | analyst | Add an investigation note |
| `POST` | `/api/incidents/{incident_id}/quarantine` | admin | Quarantine or release a dataset or model (nothing is deleted) |
| `POST` | `/api/incidents/{incident_id}/remediations` | analyst | Record a remediation action |
| `GET` | `/api/incidents/{incident_id}/report` | viewer | Incident report; `?format=markdown` for Markdown |

## Selected request bodies

### Upload a dataset

```bash
curl -H "Authorization: Bearer $TOKEN" \
  -F file=@train.csv -F name=reviews -F version=2 -F source="vendor-x export" \
  -F parent_id=<optional parent dataset id> -F operation="dedupe" \
  http://localhost:8000/api/datasets
```

Accepted extensions: `.csv`, `.json`, `.jsonl`, `.parquet`, `.txt`. Archives (zip, gzip, 7z, rar, bzip2) are rejected by magic bytes, whatever their extension.

### Run an inspection

```json
POST /api/datasets/{id}/inspect
{
  "reference_dataset_id": "trusted earlier version for distribution_shift; defaults to the parent dataset if one is recorded",
  "methods": ["duplicate_detection", "label_inconsistency"],
  "text_column": "text",
  "label_column": "label",
  "input_column": null,
  "output_column": null,
  "thresholds": {"near_duplicate_threshold": 0.95}
}
```

All fields are optional. Columns are auto-detected by name when omitted. The response includes `risk_level`, `risk_score`, the per-method status (`ran`, `skipped` with reason, or `error`) and all findings.

### Finding object

```json
{
  "id": "…",
  "severity": "high",
  "method": "trigger_token_association",
  "title": "Token 'cf' behaves like a backdoor trigger for label 'positive'",
  "confidence": 0.9,
  "explanation": "…",
  "evidence": {"rows": [12, 57, …], "token": "cf", "…": "…"},
  "investigation_steps": ["…"],
  "limitations": "…",
  "status": "open"
}
```

`evidence.rows` are 0-based row indices into the dataset as loaded (at most 50 are listed; counts are always complete).

### Run a behavioral evaluation

```json
POST /api/evaluations
{
  "model_id": "lab model id",
  "dataset_id": "clean evaluation dataset id",
  "comparison_model_id": "optional clean reference model id",
  "declared_triggers": ["cf"],
  "flip_threshold": 0.5
}
```

Only models created with `POST /api/models/lab` can be evaluated; registered external models are metadata-only.

### Quarantine

```json
POST /api/incidents/{id}/quarantine
{"target_type": "dataset", "target_id": "…", "action": "quarantine", "reason": "Trigger rows confirmed"}
```

### Incident states

| From | Allowed next states |
| --- | --- |
| `open` | `under_investigation`, `resolved` |
| `under_investigation` | `quarantined`, `remediation_required`, `resolved` |
| `quarantined` | `under_investigation`, `remediation_required`, `resolved` |
| `remediation_required` | `under_investigation`, `quarantined`, `resolved` |
| `resolved` | `under_investigation` (reopen) |

Two further rules apply: moving to `quarantined` requires at least one prior quarantine action on the incident, and moving to `resolved` requires a non-empty `comment`. Invalid transitions return 409. The rules live in `backend/app/services/incidents.py`.
