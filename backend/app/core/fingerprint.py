"""Dataset DNA: whole-file, chunk-level and row-level fingerprints.

Inputs are opened read-only; source files are never modified.

Manifest format ``trusttrain.manifest/v1`` is shared with the Python SDK
(``sdk/trusttrain/local.py``); both implementations are tested for agreement.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

MANIFEST_SCHEMA = "trusttrain.manifest/v1"
CHUNK_SIZE = 1024 * 1024
MAX_DUPLICATE_GROUPS = 100


def sha256_file(path: Path, chunk_size: int = CHUNK_SIZE) -> tuple[str, list[str], int]:
    """Return (whole-file SHA-256, per-chunk SHA-256 list, size in bytes)."""
    whole = hashlib.sha256()
    chunks: list[str] = []
    size = 0
    with path.open("rb") as fh:
        while block := fh.read(chunk_size):
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


def canonical_row(record: dict[str, Any]) -> str:
    return json.dumps({str(k): _normalise(v) for k, v in record.items()}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def row_hashes(df: pd.DataFrame) -> list[str]:
    return [hashlib.sha256(canonical_row(rec).encode()).hexdigest() for rec in df.to_dict(orient="records")]


def merkle_root(hashes: Iterable[str]) -> str:
    level = [bytes.fromhex(h) for h in hashes]
    if not level:
        return hashlib.sha256(b"").hexdigest()
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


def duplicate_groups(hashes: list[str]) -> list[list[int]]:
    positions: dict[str, list[int]] = defaultdict(list)
    for idx, h in enumerate(hashes):
        positions[h].append(idx)
    return [p for p in positions.values() if len(p) > 1]


def build_manifest(path: Path, fmt: str, df: pd.DataFrame, display_name: str | None = None) -> dict[str, Any]:
    file_hash, chunk_hashes, size = sha256_file(path)
    hashes = row_hashes(df)
    groups = duplicate_groups(hashes)
    return {
        "schema": MANIFEST_SCHEMA,
        "file": {"name": display_name or path.name, "format": fmt, "size_bytes": size, "sha256": file_hash},
        "chunks": {"size": CHUNK_SIZE, "hashes": chunk_hashes},
        "rows": {
            "count": len(df),
            "columns": list(map(str, df.columns)),
            "dtypes": {str(c): str(t) for c, t in df.dtypes.items()},
            "row_hashes": hashes,
            "merkle_root": merkle_root(hashes),
        },
        "duplicates": {
            "exact_duplicate_rows": sum(len(g) - 1 for g in groups),
            "groups": groups[:MAX_DUPLICATE_GROUPS],
        },
        "generated_at": datetime.now(UTC).isoformat(),
    }


def compare_manifests(old: dict[str, Any], new: dict[str, Any], sample: int = 25) -> dict[str, Any]:
    """Describe differences between two manifests of (versions of) a dataset."""
    old_chunks, new_chunks = old["chunks"]["hashes"], new["chunks"]["hashes"]
    changed_chunks = [
        i for i in range(max(len(old_chunks), len(new_chunks))) if i >= len(old_chunks) or i >= len(new_chunks) or old_chunks[i] != new_chunks[i]
    ]
    old_rows, new_rows = old["rows"]["row_hashes"], new["rows"]["row_hashes"]
    old_counts: dict[str, int] = defaultdict(int)
    for h in old_rows:
        old_counts[h] += 1
    new_counts: dict[str, int] = defaultdict(int)
    for h in new_rows:
        new_counts[h] += 1
    added_idx = []
    seen: dict[str, int] = defaultdict(int)
    for i, h in enumerate(new_rows):
        seen[h] += 1
        if seen[h] > old_counts.get(h, 0):
            added_idx.append(i)
    removed_idx = []
    seen.clear()
    for i, h in enumerate(old_rows):
        seen[h] += 1
        if seen[h] > new_counts.get(h, 0):
            removed_idx.append(i)
    old_cols, new_cols = old["rows"]["columns"], new["rows"]["columns"]
    dtype_changes = {
        c: {"old": old["rows"]["dtypes"][c], "new": new["rows"]["dtypes"][c]}
        for c in set(old_cols) & set(new_cols)
        if old["rows"]["dtypes"].get(c) != new["rows"]["dtypes"].get(c)
    }
    identical = old["file"]["sha256"] == new["file"]["sha256"]
    return {
        "identical_file": identical,
        "content_equivalent": old["rows"]["merkle_root"] == new["rows"]["merkle_root"],
        "changed_chunks": changed_chunks,
        "rows_added": len(added_idx),
        "rows_removed": len(removed_idx),
        "added_row_indices_sample": added_idx[:sample],
        "removed_row_indices_sample": removed_idx[:sample],
        "columns_added": [c for c in new_cols if c not in old_cols],
        "columns_removed": [c for c in old_cols if c not in new_cols],
        "dtype_changes": dtype_changes,
    }


def verify_against_manifest(manifest: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare a freshly computed manifest against a trusted one."""
    diff = compare_manifests(manifest, current)
    status = "verified" if diff["identical_file"] else "modified"
    return {"status": status, "expected_sha256": manifest["file"]["sha256"], "actual_sha256": current["file"]["sha256"], "diff": diff}
