"""Provenance manifests: who/what/when/where-from for a dataset version.

A provenance record is only *trusted* when its Ed25519 signature verifies
against a key the server trusts **and** the dataset's current file hash
matches the hash recorded in the signed manifest.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Dataset, ProcessingOperation, ProvenanceRecord
from app.provenance.signing import ManifestSigner, verify_signature

PROVENANCE_SCHEMA = "trusttrain.provenance/v1"


def build_provenance_manifest(db: Session, dataset: Dataset, fingerprint: dict[str, Any]) -> dict[str, Any]:
    ops = db.scalars(select(ProcessingOperation).where(ProcessingOperation.output_dataset_id == dataset.id)).all()
    derived = db.scalars(select(ProcessingOperation).where(ProcessingOperation.input_dataset_id == dataset.id)).all()
    return {
        "schema": PROVENANCE_SCHEMA,
        "dataset": {
            "id": dataset.id,
            "name": dataset.name,
            "version": dataset.version,
            "source": dataset.source,
            "imported_at": dataset.created_at.isoformat() if dataset.created_at else None,
            "original_filename": dataset.original_filename,
            "format": dataset.file_format,
        },
        "integrity": {
            "sha256": fingerprint["file"]["sha256"],
            "size_bytes": fingerprint["file"]["size_bytes"],
            "chunk_hashes": fingerprint["chunks"]["hashes"],
            "row_count": fingerprint["rows"]["count"],
            "row_merkle_root": fingerprint["rows"]["merkle_root"],
            "status": dataset.integrity_status,
        },
        "lineage": {
            "parent_dataset_id": dataset.parent_id,
            "processing_operations": [
                {"id": o.id, "operation": o.operation, "input_dataset_id": o.input_dataset_id, "parameters": o.parameters} for o in ops
            ],
            "derived_dataset_ids": sorted({o.output_dataset_id for o in derived}),
        },
        "approval_status": dataset.approval_status,
        "issued_at": datetime.now(UTC).isoformat(),
    }


def create_record(db: Session, signer: ManifestSigner, dataset: Dataset, fingerprint: dict[str, Any]) -> ProvenanceRecord:
    manifest = build_provenance_manifest(db, dataset, fingerprint)
    record = ProvenanceRecord(
        dataset_id=dataset.id,
        manifest=manifest,
        signature=signer.sign(manifest),
        public_key_fingerprint=signer.fingerprint,
    )
    db.add(record)
    return record


def evaluate_record(record: ProvenanceRecord, signer: ManifestSigner, current_sha256: str | None) -> dict[str, Any]:
    """Return a trust verdict. Anything short of full verification is untrusted."""
    reasons: list[str] = []
    key_known = record.public_key_fingerprint == signer.fingerprint
    if not key_known:
        reasons.append("Manifest was signed by an unknown key")
    signature_valid = key_known and verify_signature(record.manifest, record.signature, signer.public_key)
    if key_known and not signature_valid:
        reasons.append("Signature does not match manifest contents")
    hash_matches = current_sha256 is not None and record.manifest.get("integrity", {}).get("sha256") == current_sha256
    if not hash_matches:
        reasons.append("Current file hash differs from the signed hash")
    trusted = signature_valid and hash_matches
    return {
        "record_id": record.id,
        "trusted": trusted,
        "signature_valid": signature_valid,
        "hash_matches": hash_matches,
        "signing_key_fingerprint": record.public_key_fingerprint,
        "reasons": reasons,
    }
