"""Signed provenance manifests."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.database import new_session
from app.models import Dataset, ProvenanceRecord
from app.provenance.manifest import evaluate_record
from app.provenance.signing import ManifestSigner, verify_signature
from app.services.datasets import dataset_path
from tests.conftest import csv_bytes, upload


def test_sign_and_verify_roundtrip() -> None:
    signer = ManifestSigner(Ed25519PrivateKey.generate())
    manifest = {"b": 1, "a": {"nested": [1, 2]}}
    sig = signer.sign(manifest)
    assert verify_signature(manifest, sig, signer.public_key)
    assert not verify_signature({**manifest, "b": 2}, sig, signer.public_key)
    assert not verify_signature(manifest, "not base64!!", signer.public_key)
    other = ManifestSigner(Ed25519PrivateKey.generate())
    assert not verify_signature(manifest, sig, other.public_key)


def test_key_created_with_restrictive_permissions(tmp_path: Path) -> None:
    key = tmp_path / "k.pem"
    signer = ManifestSigner.load_or_create(key, allow_create=True)
    assert key.stat().st_mode & 0o777 == 0o600
    assert ManifestSigner.load_or_create(key, allow_create=False).fingerprint == signer.fingerprint


def test_missing_key_refused_without_create(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(RuntimeError):
        ManifestSigner.load_or_create(tmp_path / "missing.pem", allow_create=False)


def test_provenance_created_on_upload(client: TestClient, analyst: dict[str, str], small_reviews: pd.DataFrame) -> None:
    ds = upload(client, analyst, "r.csv", csv_bytes(small_reviews), source="synthetic-generator", version="3")
    prov = client.get(f"/api/datasets/{ds['id']}/provenance", headers=analyst).json()
    assert prov["verification"]["trusted"] is True
    m = prov["manifest"]
    assert m["dataset"]["source"] == "synthetic-generator"
    assert m["dataset"]["version"] == "3"
    assert m["integrity"]["sha256"] == ds["sha256"]
    assert m["approval_status"] == "pending"


def test_tampered_manifest_is_untrusted(client: TestClient, analyst: dict[str, str], small_reviews: pd.DataFrame) -> None:
    ds = upload(client, analyst, "r.csv", csv_bytes(small_reviews))
    with new_session() as db:
        rec = db.query(ProvenanceRecord).filter_by(dataset_id=ds["id"]).one()
        rec.manifest = {**rec.manifest, "approval_status": "approved"}
        db.commit()
    v = client.get(f"/api/datasets/{ds['id']}/provenance", headers=analyst).json()["verification"]
    assert v["trusted"] is False and v["signature_valid"] is False


def test_unknown_signing_key_is_untrusted(client: TestClient, analyst: dict[str, str], small_reviews: pd.DataFrame) -> None:
    ds = upload(client, analyst, "r.csv", csv_bytes(small_reviews))
    with new_session() as db:
        rec = db.query(ProvenanceRecord).filter_by(dataset_id=ds["id"]).one()
        foreign = ManifestSigner(Ed25519PrivateKey.generate())
        rec.signature = foreign.sign(rec.manifest)
        rec.public_key_fingerprint = foreign.fingerprint
        db.commit()
    v = client.get(f"/api/datasets/{ds['id']}/provenance", headers=analyst).json()["verification"]
    assert v["trusted"] is False
    assert "unknown key" in " ".join(v["reasons"])


def test_modified_file_makes_provenance_untrusted(
    client: TestClient, analyst: dict[str, str], admin: dict[str, str], settings, small_reviews: pd.DataFrame
) -> None:  # type: ignore[no-untyped-def]
    ds = upload(client, analyst, "r.csv", csv_bytes(small_reviews))
    with new_session() as db:
        path = dataset_path(settings, db.get(Dataset, ds["id"]))
    path.write_bytes(path.read_bytes() + b"999,evil,positive,5\n")
    v = client.get(f"/api/datasets/{ds['id']}/provenance", headers=analyst).json()["verification"]
    assert v["trusted"] is False and v["hash_matches"] is False
    # Re-signing a modified dataset is refused.
    assert client.post(f"/api/datasets/{ds['id']}/provenance", headers=admin).status_code == 409


def test_approval_reissues_signed_manifest(client: TestClient, analyst: dict[str, str], admin: dict[str, str], small_reviews: pd.DataFrame) -> None:
    ds = upload(client, analyst, "r.csv", csv_bytes(small_reviews))
    assert client.patch(f"/api/datasets/{ds['id']}", headers=analyst, json={"approval_status": "approved"}).status_code == 403
    assert client.patch(f"/api/datasets/{ds['id']}", headers=admin, json={"approval_status": "approved"}).status_code == 200
    prov = client.get(f"/api/datasets/{ds['id']}/provenance", headers=admin).json()
    assert prov["manifest"]["approval_status"] == "approved"
    assert prov["verification"]["trusted"] is True


def test_evaluate_record_without_current_hash() -> None:
    signer = ManifestSigner(Ed25519PrivateKey.generate())
    manifest = {"integrity": {"sha256": "ab" * 32}}
    rec = ProvenanceRecord(dataset_id="x", manifest=manifest, signature=signer.sign(manifest), public_key_fingerprint=signer.fingerprint)
    assert evaluate_record(rec, signer, None)["trusted"] is False
    assert evaluate_record(rec, signer, "ab" * 32)["trusted"] is True


def test_derived_dataset_provenance_records_parent(client: TestClient, analyst: dict[str, str], small_reviews: pd.DataFrame) -> None:
    parent = upload(client, analyst, "p.csv", csv_bytes(small_reviews))
    child = upload(client, analyst, "c.csv", csv_bytes(small_reviews.head(150)), parent_id=parent["id"], operation="filter:first-150")
    m = client.get(f"/api/datasets/{child['id']}/provenance", headers=analyst).json()["manifest"]
    assert m["lineage"]["parent_dataset_id"] == parent["id"]
