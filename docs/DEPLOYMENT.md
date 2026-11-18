# Deployment

## Modes

| `TRUSTTRAIN_ENVIRONMENT` | Behavior |
| --- | --- |
| `development` (default) | SQLite allowed; tables auto-created; signing key generated under the data directory if missing; ephemeral JWT secret if unset (logged as a warning) |
| `test` | As development; used by the test suite |
| `production` | Start-up fails unless `TRUSTTRAIN_JWT_SECRET` has at least 32 characters, `TRUSTTRAIN_SIGNING_KEY_PATH` points to an existing key, and CORS has no wildcard. Schema is managed only by Alembic; the signing key is never auto-generated |

## Docker Compose (single host)

```bash
cp .env.example .env
# Edit .env:
#   POSTGRES_PASSWORD            long random value
#   TRUSTTRAIN_ENVIRONMENT       production
#   TRUSTTRAIN_JWT_SECRET        python -c "import secrets; print(secrets.token_urlsafe(48))"
#   TRUSTTRAIN_BOOTSTRAP_ADMIN_* first admin (remove after first login)
#   TRUSTTRAIN_CORS_ORIGINS      the dashboard origin(s)
```

Create the provenance signing key in the data volume **before** the first production start:

```bash
docker compose run --rm --no-deps --entrypoint python backend -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as s
import os
k = Ed25519PrivateKey.generate().private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption())
fd = os.open('/data/signing-key.pem', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.write(fd, k); os.close(fd)"
```

Then:

```bash
docker compose up -d --build
```

| Service | Image | Port (host loopback only) |
| --- | --- | --- |
| `db` | `postgres:16-alpine` | not published |
| `backend` | `docker/backend.Dockerfile` (Python 3.12 slim, CPU PyTorch, non-root user) | `127.0.0.1:8000` |
| `frontend` | `docker/frontend.Dockerfile` (static build served by nginx, proxies `/api`) | `127.0.0.1:8080` |

The backend container runs `alembic upgrade head` before starting uvicorn, and has a health check on `/api/health`. Uvicorn trusts `X-Forwarded-For` only from the nginx container (`FORWARDED_ALLOW_IPS`), so rate limits apply per real client IP.

> The compose file was validated with `docker compose config`. Images could not be built in the environment where this release was prepared (no access to Docker Hub), so build and run them in your own environment before relying on them.

## Exposing it

Put a TLS-terminating reverse proxy or load balancer in front of the `frontend` service (or of both services if clients call the API directly):

- Terminate TLS and redirect HTTP to HTTPS; add HSTS.
- Keep `client_max_body_size` (nginx) at or above `TRUSTTRAIN_MAX_UPLOAD_BYTES`.
- If you add another proxy hop, set `FORWARDED_ALLOW_IPS` to that proxy's address too, or the rate limiter will see a single client.
- Restrict `/docs` and `/openapi.json` at the proxy if you do not want them public.

## Configuration reference

| Variable | Default | Notes |
| --- | --- | --- |
| `TRUSTTRAIN_ENVIRONMENT` | `development` | `development`, `test`, `production` |
| `TRUSTTRAIN_DATABASE_URL` | `sqlite:///./trusttrain-data/trusttrain.db` | e.g. `postgresql+psycopg://user:pass@host:5432/trusttrain` |
| `TRUSTTRAIN_DATA_DIR` | `./trusttrain-data` | Uploads, manifests and lab models. Back it up together with the database |
| `TRUSTTRAIN_JWT_SECRET` | — | Required (≥ 32 chars) in production |
| `TRUSTTRAIN_JWT_TTL_MINUTES` | `60` | Token lifetime |
| `TRUSTTRAIN_BOOTSTRAP_ADMIN_EMAIL` / `_PASSWORD` | — | Creates the first admin if it does not exist |
| `TRUSTTRAIN_SIGNING_KEY_PATH` | `<data dir>/signing-key.pem` in development | Ed25519 PKCS8 PEM; required in production |
| `TRUSTTRAIN_CORS_ORIGINS` | `http://localhost:5173` | Comma-separated list |
| `TRUSTTRAIN_RATE_LIMIT_PER_MINUTE` | `240` | Per client IP, all routes |
| `TRUSTTRAIN_AUTH_RATE_LIMIT_PER_MINUTE` | `20` | Per client IP, login |
| `TRUSTTRAIN_MAX_UPLOAD_BYTES` | `52428800` (50 MiB) | Enforced while streaming |
| `TRUSTTRAIN_MAX_ROWS` | `200000` | Per dataset |
| `TRUSTTRAIN_MAX_TEXT_CHARS_PER_CELL` | `20000` | Longer text cells are rejected |
| `TRUSTTRAIN_ZSCORE_THRESHOLD`, `TRUSTTRAIN_NEAR_DUPLICATE_THRESHOLD`, `TRUSTTRAIN_LABEL_NOISE_THRESHOLD`, `TRUSTTRAIN_LOF_THRESHOLD`, `TRUSTTRAIN_SEMANTIC_RANK_THRESHOLD`, `TRUSTTRAIN_DISTRIBUTION_PVALUE` | see `backend/app/config.py` | Default detector thresholds |
| `TRUSTTRAIN_EMBEDDING_MODEL` | — | Optional local sentence-transformers model directory |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` | uvicorn: proxies whose forwarding headers are trusted |

## Operations

- **Migrations:** `cd backend && alembic upgrade head`. After changing models: `alembic revision --autogenerate -m "…"`, review the generated file, and commit it. CI runs `alembic check`.
- **Backups:** PostgreSQL (`pg_dump`) and the data volume must be backed up together; manifests and provenance records refer to each other. Keep the signing key backup separate and access-controlled.
- **Key rotation:** replace the key file and restart. Existing provenance records become "unknown key" (untrusted) until an admin re-signs them with `POST /api/datasets/{id}/provenance`.
- **Users:** create further users with `POST /api/users` (admin), then remove the bootstrap variables.
- **Scaling:** the rate limiter is per process. With several replicas, enforce limits at the gateway. Inspections run synchronously, so size workers for the largest dataset you allow.
- **Logs:** the application logs to stdout. Secrets, tokens and dataset contents are not logged.
