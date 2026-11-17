"""Dataset inventory, upload, fingerprint, verification, provenance and inspection."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, File, Form, HTTPException, UploadFile, status
from sqlalchemy import select

from app.api.deps import DB, Admin, Analyst, AppSettings, Signer, Viewer, get_or_404
from app.core.files import UploadTooLargeError, store_upload
from app.core.tabular import DatasetFormatError
from app.models import Dataset, Finding, InspectionRun, ProcessingOperation
from app.schemas.schemas import (
    DatasetOut,
    DatasetUpdate,
    DerivationCreate,
    InspectionOut,
    InspectionRequest,
    ProvenanceOut,
    VerificationOut,
)
from app.services import audit
from app.services.datasets import (
    compare_file_to_dataset,
    ingest_upload,
    provenance_view,
    read_manifest,
    reissue_provenance,
    verify_dataset,
)
from app.services.inspection import inspect_dataset

router = APIRouter(prefix="/api/datasets", tags=["datasets"])


def _bad_upload(exc: Exception) -> HTTPException:
    if isinstance(exc, UploadTooLargeError):
        return HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, str(exc))
    return HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc))


@router.get("", response_model=list[DatasetOut])
def list_datasets(db: DB, _: Viewer, risk_level: str | None = None, integrity_status: str | None = None) -> list[Dataset]:
    query = select(Dataset).order_by(Dataset.created_at.desc())
    if risk_level:
        query = query.where(Dataset.risk_level == risk_level)
    if integrity_status:
        query = query.where(Dataset.integrity_status == integrity_status)
    return list(db.scalars(query).all())


@router.post("", response_model=DatasetOut, status_code=201)
async def upload_dataset(
    db: DB,
    settings: AppSettings,
    signer: Signer,
    user: Analyst,
    file: Annotated[UploadFile, File()],
    name: Annotated[str, Form(max_length=200)] = "",
    version: Annotated[str, Form(max_length=64)] = "1",
    source: Annotated[str, Form(max_length=500)] = "",
    description: Annotated[str, Form(max_length=5000)] = "",
    parent_id: Annotated[str | None, Form()] = None,
    operation: Annotated[str | None, Form(max_length=120)] = None,
) -> Dataset:
    try:
        dataset = await ingest_upload(
            db,
            settings,
            signer,
            user,
            file,
            name=name,
            version=version,
            source=source,
            description=description,
            parent_id=parent_id or None,
        )
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except (DatasetFormatError, UploadTooLargeError) as exc:
        raise _bad_upload(exc) from exc
    if parent_id and operation:
        db.add(ProcessingOperation(input_dataset_id=parent_id, output_dataset_id=dataset.id, operation=operation))
        db.commit()
    return dataset


@router.get("/{dataset_id}", response_model=DatasetOut)
def get_dataset(dataset_id: str, db: DB, _: Viewer) -> Dataset:
    return get_or_404(db, Dataset, dataset_id, "Dataset")


@router.patch("/{dataset_id}", response_model=DatasetOut)
def update_dataset(dataset_id: str, body: DatasetUpdate, db: DB, settings: AppSettings, signer: Signer, user: Analyst) -> Dataset:
    dataset = get_or_404(db, Dataset, dataset_id, "Dataset")
    if body.approval_status is not None and body.approval_status != dataset.approval_status:
        if user.role != "admin":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Only admins can change approval status")
        if body.approval_status == "approved" and dataset.quarantined:
            raise HTTPException(status.HTTP_409_CONFLICT, "Quarantined datasets cannot be approved")
        dataset.approval_status = body.approval_status
        audit.record(db, user.email, f"dataset.{body.approval_status}", "dataset", dataset.id, f"Approval set to {body.approval_status}")
        db.commit()
        try:
            reissue_provenance(db, settings, signer, dataset, user.email)
        except PermissionError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    if body.description is not None:
        dataset.description = body.description
        db.commit()
    return dataset


@router.get("/{dataset_id}/manifest")
def get_manifest(dataset_id: str, db: DB, settings: AppSettings, _: Viewer, include_row_hashes: bool = False) -> dict[str, Any]:
    dataset = get_or_404(db, Dataset, dataset_id, "Dataset")
    manifest = read_manifest(settings, dataset)
    if not include_row_hashes:
        manifest["rows"] = {k: v for k, v in manifest["rows"].items() if k != "row_hashes"}
    return manifest


@router.post("/{dataset_id}/verify", response_model=VerificationOut)
def verify(dataset_id: str, db: DB, settings: AppSettings, user: Analyst) -> dict[str, Any]:
    return verify_dataset(db, settings, get_or_404(db, Dataset, dataset_id, "Dataset"), user.email)


@router.post("/{dataset_id}/compare", response_model=VerificationOut)
async def compare_with_file(dataset_id: str, db: DB, settings: AppSettings, _: Analyst, file: Annotated[UploadFile, File()]) -> dict[str, Any]:
    """Compare an uploaded candidate copy against the dataset's import fingerprint without storing it."""
    dataset = get_or_404(db, Dataset, dataset_id, "Dataset")
    with tempfile.TemporaryDirectory(prefix="trusttrain-cmp-") as tmp:
        try:
            _name, fmt, _storage, path = await store_upload(file, Path(tmp), settings.max_upload_bytes)
            return compare_file_to_dataset(settings, dataset, path, fmt)
        except (DatasetFormatError, UploadTooLargeError) as exc:
            raise _bad_upload(exc) from exc


@router.get("/{dataset_id}/provenance", response_model=ProvenanceOut)
def get_provenance(dataset_id: str, db: DB, settings: AppSettings, signer: Signer, _: Viewer) -> dict[str, Any]:
    view = provenance_view(db, settings, signer, get_or_404(db, Dataset, dataset_id, "Dataset"))
    if view is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No provenance record")
    return view


@router.post("/{dataset_id}/provenance", response_model=ProvenanceOut, status_code=201)
def sign_provenance(dataset_id: str, db: DB, settings: AppSettings, signer: Signer, user: Admin) -> dict[str, Any]:
    dataset = get_or_404(db, Dataset, dataset_id, "Dataset")
    try:
        reissue_provenance(db, settings, signer, dataset, user.email)
    except PermissionError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    view = provenance_view(db, settings, signer, dataset)
    if view is None:  # pragma: no cover - a record was just created
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Provenance record missing")
    return view


@router.post("/derivations", status_code=201)
def record_derivation(body: DerivationCreate, db: DB, user: Analyst) -> dict[str, str]:
    src = get_or_404(db, Dataset, body.input_dataset_id, "Input dataset")
    dst = get_or_404(db, Dataset, body.output_dataset_id, "Output dataset")
    if src.id == dst.id:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "A dataset cannot be derived from itself")
    op = ProcessingOperation(input_dataset_id=src.id, output_dataset_id=dst.id, operation=body.operation, parameters=body.parameters)
    db.add(op)
    if dst.parent_id is None:
        dst.parent_id = src.id
    db.flush()
    audit.record(db, user.email, "dataset.derivation_recorded", "dataset", dst.id, f"{src.name} → {dst.name} via {body.operation}")
    db.commit()
    return {"id": op.id}


@router.post("/{dataset_id}/inspect", response_model=InspectionOut, status_code=201)
def run_inspection(dataset_id: str, body: InspectionRequest, db: DB, settings: AppSettings, user: Analyst) -> InspectionRun:
    dataset = get_or_404(db, Dataset, dataset_id, "Dataset")
    try:
        return inspect_dataset(db, settings, dataset, user.email, body.model_dump())
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except (ValueError, DatasetFormatError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc


@router.get("/{dataset_id}/inspections", response_model=list[InspectionOut])
def list_inspections(dataset_id: str, db: DB, _: Viewer) -> list[InspectionRun]:
    get_or_404(db, Dataset, dataset_id, "Dataset")
    return list(db.scalars(select(InspectionRun).where(InspectionRun.dataset_id == dataset_id).order_by(InspectionRun.created_at.desc())).all())


@router.get("/{dataset_id}/findings")
def dataset_findings(dataset_id: str, db: DB, _: Viewer) -> list[dict[str, Any]]:
    get_or_404(db, Dataset, dataset_id, "Dataset")
    rows = db.scalars(select(Finding).where(Finding.dataset_id == dataset_id).order_by(Finding.created_at.desc())).all()
    return [{"id": f.id, "severity": f.severity, "method": f.method, "title": f.title, "status": f.status} for f in rows]
