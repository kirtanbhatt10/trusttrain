"""Dataset ingestion, fingerprinting, verification and provenance."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd
from fastapi import UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.core.files import resolve_inside, store_upload
from app.core.fingerprint import build_manifest, verify_against_manifest
from app.core.tabular import load_dataframe
from app.models import Dataset, ProvenanceRecord, User
from app.provenance.manifest import create_record, evaluate_record
from app.provenance.signing import ManifestSigner
from app.services import audit


def dataset_path(settings: Settings, dataset: Dataset) -> Path:
    return resolve_inside(settings.uploads_dir, dataset.storage_name)


def manifest_path(settings: Settings, dataset: Dataset) -> Path:
    return resolve_inside(settings.manifests_dir, f"{dataset.id}.json")


def load_dataset_frame(settings: Settings, dataset: Dataset) -> pd.DataFrame:
    return load_dataframe(dataset_path(settings, dataset), dataset.file_format, settings.max_rows, settings.max_text_chars_per_cell)


def read_manifest(settings: Settings, dataset: Dataset) -> dict[str, Any]:
    return json.loads(manifest_path(settings, dataset).read_text())


async def ingest_upload(
    db: Session,
    settings: Settings,
    signer: ManifestSigner,
    user: User,
    upload: UploadFile,
    *,
    name: str,
    version: str,
    source: str,
    description: str,
    parent_id: str | None,
) -> Dataset:
    display, fmt, storage_name, path = await store_upload(upload, settings.uploads_dir, settings.max_upload_bytes)
    try:
        if parent_id is not None and db.get(Dataset, parent_id) is None:
            raise LookupError(f"Parent dataset {parent_id} not found")
        df = load_dataframe(path, fmt, settings.max_rows, settings.max_text_chars_per_cell)
        manifest = build_manifest(path, fmt, df, display_name=display)
        dataset = Dataset(
            name=name or Path(display).stem,
            version=version,
            source=source,
            description=description,
            file_format=fmt,
            original_filename=display,
            storage_name=storage_name,
            size_bytes=manifest["file"]["size_bytes"],
            sha256=manifest["file"]["sha256"],
            row_count=len(df),
            columns=list(map(str, df.columns)),
            parent_id=parent_id,
            integrity_status="verified",
            created_by=user.id,
        )
        db.add(dataset)
        db.flush()
        settings.manifests_dir.mkdir(parents=True, exist_ok=True)
        manifest_path(settings, dataset).write_text(json.dumps(manifest))
        create_record(db, signer, dataset, manifest)
        audit.record(db, user.email, "dataset.uploaded", "dataset", dataset.id, f"Uploaded {display} ({len(df)} rows) as {dataset.name} v{version}")
        db.commit()
    except BaseException:
        db.rollback()
        path.unlink(missing_ok=True)
        raise
    return dataset


def verify_dataset(db: Session, settings: Settings, dataset: Dataset, actor: str) -> dict[str, Any]:
    """Re-fingerprint the stored file and compare with the manifest captured at import."""
    trusted = read_manifest(settings, dataset)
    path = dataset_path(settings, dataset)
    try:
        df = load_dataset_frame(settings, dataset)
        current = build_manifest(path, dataset.file_format, df, display_name=dataset.original_filename)
    except Exception:  # noqa: BLE001 - unreadable content is itself an integrity failure
        from app.core.fingerprint import sha256_file

        sha, chunks, size = sha256_file(path)
        current = {
            "file": {"sha256": sha, "size_bytes": size},
            "chunks": {"hashes": chunks},
            "rows": {"row_hashes": [], "columns": [], "dtypes": {}, "merkle_root": ""},
        }
    result = verify_against_manifest(trusted, current)
    new_status = result["status"]
    if dataset.integrity_status != new_status:
        audit.record(db, actor, f"dataset.integrity_{new_status}", "dataset", dataset.id, f"Integrity check: {new_status}")
    dataset.integrity_status = new_status
    db.commit()
    return {"dataset_id": dataset.id, **result}


def compare_file_to_dataset(settings: Settings, dataset: Dataset, path: Path, fmt: str) -> dict[str, Any]:
    trusted = read_manifest(settings, dataset)
    df = load_dataframe(path, fmt, settings.max_rows, settings.max_text_chars_per_cell)
    current = build_manifest(path, fmt, df)
    return {"dataset_id": dataset.id, **verify_against_manifest(trusted, current)}


def latest_provenance(db: Session, dataset_id: str) -> ProvenanceRecord | None:
    return db.scalars(select(ProvenanceRecord).where(ProvenanceRecord.dataset_id == dataset_id).order_by(ProvenanceRecord.created_at.desc())).first()


def provenance_view(db: Session, settings: Settings, signer: ManifestSigner, dataset: Dataset) -> dict[str, Any] | None:
    record = latest_provenance(db, dataset.id)
    if record is None:
        return None
    from app.core.fingerprint import sha256_file

    current_sha, _, _ = sha256_file(dataset_path(settings, dataset))
    return {
        "record_id": record.id,
        "dataset_id": dataset.id,
        "manifest": record.manifest,
        "signature": record.signature,
        "public_key_fingerprint": record.public_key_fingerprint,
        "created_at": record.created_at,
        "verification": evaluate_record(record, signer, current_sha),
    }


def reissue_provenance(db: Session, settings: Settings, signer: ManifestSigner, dataset: Dataset, actor: str) -> ProvenanceRecord:
    """Sign a fresh manifest (e.g. after approval). Refused if the file no longer matches its import fingerprint."""
    if verify_dataset(db, settings, dataset, actor)["status"] != "verified":
        raise PermissionError("Dataset content no longer matches its import fingerprint; refusing to sign")
    record = create_record(db, signer, dataset, read_manifest(settings, dataset))
    audit.record(db, actor, "provenance.signed", "dataset", dataset.id, "Signed provenance manifest issued")
    db.commit()
    return record
