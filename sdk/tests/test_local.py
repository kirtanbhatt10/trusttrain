from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from trusttrain.local import LocalDatasetError, detect_format, fingerprint, merkle_root, verify

FRAME = pd.DataFrame({"text": ["a b", "c", "a b"], "label": ["x", "y", "x"], "score": [1.0, 2.5, 1.0]})


def write(tmp_path: Path, fmt: str) -> Path:
    path = tmp_path / f"d.{fmt}"
    if fmt == "csv":
        FRAME.to_csv(path, index=False)
    elif fmt == "json":
        path.write_text(json.dumps(FRAME.to_dict(orient="records")))
    elif fmt == "jsonl":
        path.write_text("\n".join(json.dumps(r) for r in FRAME.to_dict(orient="records")))
    elif fmt == "parquet":
        FRAME.to_parquet(path, index=False)
    else:
        path.write_text("\n".join(FRAME["text"]))
    return path


@pytest.mark.parametrize("fmt", ["csv", "json", "jsonl", "parquet", "txt"])
def test_fingerprint_formats(tmp_path: Path, fmt: str) -> None:
    path = write(tmp_path, fmt)
    before = path.read_bytes()
    m = fingerprint(path)
    assert m["schema"] == "trusttrain.manifest/v1"
    assert m["rows"]["count"] == 3
    assert m["duplicates"]["exact_duplicate_rows"] == 1
    assert path.read_bytes() == before


def test_merkle_root_matches_across_structured_formats(tmp_path: Path) -> None:
    roots = {fingerprint(write(tmp_path, f))["rows"]["merkle_root"] for f in ("csv", "json", "jsonl", "parquet")}
    assert len(roots) == 1


def test_verify_unchanged_and_modified(tmp_path: Path) -> None:
    path = write(tmp_path, "csv")
    manifest = fingerprint(path)
    assert verify(path, manifest)["status"] == "verified"
    path.write_text(path.read_text() + "evil,z,9.0\n")
    result = verify(path, manifest)
    assert result["status"] == "modified"
    assert result["rows_added"] == 1 and result["rows_removed"] == 0
    assert result["changed_chunks"] == [0]


def test_verify_detects_column_change(tmp_path: Path) -> None:
    path = write(tmp_path, "csv")
    manifest = fingerprint(path)
    FRAME.assign(extra=1).to_csv(path, index=False)
    assert verify(path, manifest)["columns_added"] == ["extra"]


def test_verify_rejects_unknown_manifest(tmp_path: Path) -> None:
    with pytest.raises(LocalDatasetError):
        verify(write(tmp_path, "csv"), {"schema": "other"})


@pytest.mark.parametrize("name", ["model.pkl", "noext"])
def test_unsupported_types(name: str) -> None:
    with pytest.raises(LocalDatasetError):
        detect_format(Path(name))


def test_invalid_json_and_missing_file(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2]")
    with pytest.raises(LocalDatasetError):
        fingerprint(bad)
    with pytest.raises(LocalDatasetError):
        fingerprint(tmp_path / "missing.csv")


def test_merkle_empty() -> None:
    assert len(merkle_root([])) == 64
