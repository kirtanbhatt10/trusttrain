"""Offline dataset fingerprinting and verification.

Produces manifests in the ``trusttrain.manifest/v1`` format, identical to the
server's (``backend/app/core/fingerprint.py``), so a manifest committed to a
repository can be verified locally or in CI without contacting the API.
Source files are opened read-only.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

MANIFEST_SCHEMA = "trusttrain.manifest/v1"
CHUNK_SIZE = 1024 * 1024
SUPPORTED_SUFFIXES = {".csv": "csv", ".json": "json", ".jsonl": "jsonl", ".ndjson": "jsonl", ".parquet": "parquet", ".txt": "txt"}


class LocalDatasetError(ValueError):
    """Raised when a local file cannot be fingerprinted."""


def detect_format(path: Path) -> str:
    fmt = SUPPORTED_SUFFIXES.get(path.suffix.lower())
    if fmt is None:
        raise LocalDatasetError(f"Unsupported dataset type: {path.suffix or '(none)'}")
    return fmt


def load_frame(path: Path, fmt: str | None = None) -> pd.DataFrame:
    fmt = fmt or detect_format(path)
    try:
        if fmt == "csv":
            df = pd.read_csv(path, dtype_backend="numpy_nullable", encoding="utf-8-sig")
        elif fmt == "txt":
            df = pd.DataFrame({"text": [ln for ln in path.read_text(encoding="utf-8-sig").splitlines() if ln.strip()]})
        elif fmt == "json":
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            if isinstance(data, dict):
                lists = [v for v in data.values() if isinstance(v, list)]
                if len(lists) != 1:
                    raise LocalDatasetError("JSON object must contain exactly one list of records")
                data = lists[0]
            if not isinstance(data, list) or not all(isinstance(r, dict) for r in data):
                raise LocalDatasetError("JSON dataset must be a list of objects")
            df = pd.DataFrame.from_records(data)
        elif fmt == "jsonl":
            records = [json.loads(ln) for ln in path.read_text(encoding="utf-8-sig").splitlines() if ln.strip()]
            if not all(isinstance(r, dict) for r in records):
                raise LocalDatasetError("Every JSONL line must be an object")
            df = pd.DataFrame.from_records(records)
        else:
            import pyarrow.parquet as pq

            df = pq.read_table(path).to_pandas()
    except LocalDatasetError:
        raise
    except Exception as exc:
        raise LocalDatasetError(f"Could not parse {path.name} as {fmt}: {type(exc).__name__}") from exc
    df.columns = [str(c) for c in df.columns]
    return df


def sha256_file(path: Path) -> tuple[str, list[str], int]:
    whole = hashlib.sha256()
    chunks: list[str] = []
    size = 0
    with path.open("rb") as fh:
        while block := fh.read(CHUNK_SIZE):
            whole.update(block)
            chunks.append(hashlib.sha256(block).hexdigest())
            size += len(block)
    return whole.hexdigest(), chunks, size


def _normalise(value: Any) -> Any:
    if value is None or value is pd.NA or value is pd.NaT:
        return None
    if isinstance(value, float) and math.isnan(value):
        return None
    if isinstance(value, np.generic):
        return _normalise(value.item())
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, (list, tuple, np.ndarray)):
        return [_normalise(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _normalise(v) for k, v in value.items()}
    if isinstance(value, (int, bool, str)):
        return value
    return str(value)


def row_hashes(df: pd.DataFrame) -> list[str]:
    out = []
    for rec in df.to_dict(orient="records"):
        canon = json.dumps({str(k): _normalise(v) for k, v in rec.items()}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        out.append(hashlib.sha256(canon.encode()).hexdigest())
    return out


def merkle_root(hashes: list[str]) -> str:
    level = [bytes.fromhex(h) for h in hashes]
    if not level:
        return hashlib.sha256(b"").hexdigest()
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


def fingerprint(path: str | Path) -> dict[str, Any]:
    """Compute a ``trusttrain.manifest/v1`` manifest for a local dataset file."""
    path = Path(path)
    if not path.is_file():
        raise LocalDatasetError(f"Not a file: {path}")
    fmt = detect_format(path)
    df = load_frame(path, fmt)
    file_hash, chunks, size = sha256_file(path)
    hashes = row_hashes(df)
    positions: dict[str, list[int]] = defaultdict(list)
    for i, h in enumerate(hashes):
        positions[h].append(i)
    groups = [p for p in positions.values() if len(p) > 1]
    return {
        "schema": MANIFEST_SCHEMA,
        "file": {"name": path.name, "format": fmt, "size_bytes": size, "sha256": file_hash},
        "chunks": {"size": CHUNK_SIZE, "hashes": chunks},
        "rows": {
            "count": len(df),
            "columns": list(df.columns),
            "dtypes": {str(c): str(t) for c, t in df.dtypes.items()},
            "row_hashes": hashes,
            "merkle_root": merkle_root(hashes),
        },
        "duplicates": {"exact_duplicate_rows": sum(len(g) - 1 for g in groups), "groups": groups[:100]},
        "generated_at": datetime.now(UTC).isoformat(),
    }


def verify(path: str | Path, manifest: dict[str, Any]) -> dict[str, Any]:
    """Compare a file against a trusted manifest. ``status`` is ``verified`` or ``modified``."""
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise LocalDatasetError("Manifest schema not recognised")
    current = fingerprint(path)
    old_rows, new_rows = manifest["rows"]["row_hashes"], current["rows"]["row_hashes"]
    old_count: dict[str, int] = defaultdict(int)
    new_count: dict[str, int] = defaultdict(int)
    for h in old_rows:
        old_count[h] += 1
    for h in new_rows:
        new_count[h] += 1
    added = sum(max(0, c - old_count.get(h, 0)) for h, c in new_count.items())
    removed = sum(max(0, c - new_count.get(h, 0)) for h, c in old_count.items())
    old_chunks, new_chunks = manifest["chunks"]["hashes"], current["chunks"]["hashes"]
    changed_chunks = [
        i for i in range(max(len(old_chunks), len(new_chunks))) if i >= len(old_chunks) or i >= len(new_chunks) or old_chunks[i] != new_chunks[i]
    ]
    identical = manifest["file"]["sha256"] == current["file"]["sha256"]
    return {
        "status": "verified" if identical else "modified",
        "expected_sha256": manifest["file"]["sha256"],
        "actual_sha256": current["file"]["sha256"],
        "rows_added": added,
        "rows_removed": removed,
        "changed_chunks": changed_chunks,
        "content_equivalent": manifest["rows"]["merkle_root"] == current["rows"]["merkle_root"],
        "columns_added": [c for c in current["rows"]["columns"] if c not in manifest["rows"]["columns"]],
        "columns_removed": [c for c in manifest["rows"]["columns"] if c not in current["rows"]["columns"]],
    }
