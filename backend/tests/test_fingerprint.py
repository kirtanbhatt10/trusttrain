"""Dataset DNA: format support, fingerprints, modifications and verification."""

from __future__ import annotations

import io
import json
import shutil
from pathlib import Path

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from app.core.fingerprint import build_manifest, compare_manifests, merkle_root, sha256_file, verify_against_manifest
from app.core.tabular import DatasetFormatError, detect_format, load_dataframe
from app.services.datasets import dataset_path
from tests.conftest import upload

FRAME = pd.DataFrame({"text": ["alpha beta", "gamma", "alpha beta", "delta"], "label": ["a", "b", "a", "b"], "score": [1.0, 2.5, 1.0, 3.0]})


def _write(tmp_path: Path, fmt: str) -> Path:
    path = tmp_path / f"data.{fmt}"
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
def test_each_format_loads_and_fingerprints(tmp_path: Path, fmt: str) -> None:
    path = _write(tmp_path, fmt)
    before = path.read_bytes()
    df = load_dataframe(path, detect_format(path.name), max_rows=100)
    assert len(df) == 4
    manifest = build_manifest(path, fmt, df)
    assert manifest["file"]["sha256"] == sha256_file(path)[0]
    assert len(manifest["rows"]["row_hashes"]) == 4
    assert manifest["duplicates"]["exact_duplicate_rows"] == 1  # rows 0 and 2 are identical
    assert path.read_bytes() == before  # source never modified


def test_row_hashes_agree_across_formats(tmp_path: Path) -> None:
    roots = set()
    for fmt in ("csv", "json", "jsonl", "parquet"):
        path = _write(tmp_path, fmt)
        roots.add(build_manifest(path, fmt, load_dataframe(path, fmt, 100))["rows"]["merkle_root"])
    assert len(roots) == 1


def test_json_wrapper_object(tmp_path: Path) -> None:
    path = tmp_path / "w.json"
    path.write_text(json.dumps({"data": [{"a": 1}, {"a": 2}]}))
    assert len(load_dataframe(path, "json", 10)) == 2


def test_unsupported_extension() -> None:
    with pytest.raises(DatasetFormatError):
        detect_format("model.pkl")


def test_chunk_hashes_localise_changes(tmp_path: Path) -> None:
    path = tmp_path / "big.txt"
    lines = [f"line {i} " + "x" * 50 for i in range(60_000)]
    path.write_text("\n".join(lines))
    m1 = build_manifest(path, "txt", load_dataframe(path, "txt", 100_000))
    lines[-1] = "tampered line"
    path.write_text("\n".join(lines))
    m2 = build_manifest(path, "txt", load_dataframe(path, "txt", 100_000))
    diff = compare_manifests(m1, m2)
    assert len(m1["chunks"]["hashes"]) > 1
    assert diff["changed_chunks"] == [len(m1["chunks"]["hashes"]) - 1]
    assert diff["rows_added"] == 1 and diff["rows_removed"] == 1


def test_compare_detects_added_removed_and_schema(tmp_path: Path) -> None:
    a = tmp_path / "a.csv"
    b = tmp_path / "b.csv"
    FRAME.to_csv(a, index=False)
    changed = pd.concat([FRAME.iloc[1:], pd.DataFrame([{"text": "new", "label": "a", "score": 9.0}])]).assign(extra=1)
    changed.to_csv(b, index=False)
    diff = compare_manifests(build_manifest(a, "csv", load_dataframe(a, "csv", 10)), build_manifest(b, "csv", load_dataframe(b, "csv", 10)))
    assert diff["columns_added"] == ["extra"]
    assert not diff["identical_file"]


def test_reordering_changes_file_hash_but_not_row_multiset(tmp_path: Path) -> None:
    a, b = tmp_path / "a.csv", tmp_path / "b.csv"
    FRAME.to_csv(a, index=False)
    FRAME.iloc[::-1].to_csv(b, index=False)
    diff = compare_manifests(build_manifest(a, "csv", load_dataframe(a, "csv", 10)), build_manifest(b, "csv", load_dataframe(b, "csv", 10)))
    assert not diff["identical_file"]
    assert diff["rows_added"] == 0 and diff["rows_removed"] == 0


def test_merkle_root_properties() -> None:
    assert merkle_root(["00" * 32]) == "00" * 32
    assert merkle_root(["00" * 32, "11" * 32]) != merkle_root(["11" * 32, "00" * 32])


def test_verify_against_manifest(tmp_path: Path) -> None:
    path = _write(tmp_path, "csv")
    trusted = build_manifest(path, "csv", load_dataframe(path, "csv", 10))
    assert verify_against_manifest(trusted, trusted)["status"] == "verified"
    path.write_text(path.read_text().replace("gamma", "GAMMA"))
    current = build_manifest(path, "csv", load_dataframe(path, "csv", 10))
    result = verify_against_manifest(trusted, current)
    assert result["status"] == "modified"
    assert result["diff"]["rows_added"] == 1


@pytest.mark.parametrize("fmt", ["csv", "json", "jsonl", "parquet", "txt"])
def test_upload_each_format_via_api(client: TestClient, analyst: dict[str, str], tmp_path: Path, fmt: str) -> None:
    path = _write(tmp_path, fmt)
    ds = upload(client, analyst, path.name, path.read_bytes())
    assert ds["file_format"] == fmt
    assert ds["row_count"] == 4
    assert ds["integrity_status"] == "verified"
    manifest = client.get(f"/api/datasets/{ds['id']}/manifest", headers=analyst).json()
    assert manifest["file"]["sha256"] == ds["sha256"]
    assert "row_hashes" not in manifest["rows"]


def test_api_verification_detects_tampering(client: TestClient, analyst: dict[str, str], settings, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    path = _write(tmp_path, "csv")
    ds = upload(client, analyst, "d.csv", path.read_bytes())
    assert client.post(f"/api/datasets/{ds['id']}/verify", headers=analyst).json()["status"] == "verified"
    from app.database import new_session
    from app.models import Dataset

    with new_session() as db:
        stored = dataset_path(settings, db.get(Dataset, ds["id"]))
    shutil.copy(stored, tmp_path / "backup.csv")
    stored.write_text(stored.read_text() + "injected,a,1.0\n")
    result = client.post(f"/api/datasets/{ds['id']}/verify", headers=analyst).json()
    assert result["status"] == "modified"
    assert result["diff"]["rows_added"] == 1
    assert client.get(f"/api/datasets/{ds['id']}", headers=analyst).json()["integrity_status"] == "modified"


def test_compare_candidate_copy(client: TestClient, analyst: dict[str, str], tmp_path: Path) -> None:
    path = _write(tmp_path, "csv")
    ds = upload(client, analyst, "d.csv", path.read_bytes())
    same = client.post(f"/api/datasets/{ds['id']}/compare", headers=analyst, files={"file": ("copy.csv", io.BytesIO(path.read_bytes()))})
    assert same.json()["status"] == "verified"
    altered = path.read_bytes().replace(b"delta", b"DELTA")
    diff = client.post(f"/api/datasets/{ds['id']}/compare", headers=analyst, files={"file": ("copy.csv", io.BytesIO(altered))})
    assert diff.json()["status"] == "modified"


def test_cell_length_limit(tmp_path: Path) -> None:
    path = tmp_path / "long.csv"
    path.write_text("text,label\nshort,a\n" + "x" * 500 + ",b\n")
    assert len(load_dataframe(path, "csv", 100, max_cell_chars=500)) == 2
    with pytest.raises(DatasetFormatError, match="per-cell limit is 100"):
        load_dataframe(path, "csv", 100, max_cell_chars=100)
    # Non-text columns are not affected.
    numbers = tmp_path / "numbers.csv"
    numbers.write_text("value\n" + "\n".join(str(10**12 + i) for i in range(5)) + "\n")
    assert len(load_dataframe(numbers, "csv", 100, max_cell_chars=3)) == 5
