"""Security findings and inspection runs."""

from __future__ import annotations

from fastapi import APIRouter, Query
from sqlalchemy import select

from app.api.deps import DB, Analyst, Viewer, get_or_404
from app.models import Finding, InspectionRun
from app.schemas.schemas import FindingOut, FindingUpdate, InspectionOut
from app.services import audit

router = APIRouter(prefix="/api", tags=["findings"])


@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    db: DB,
    _: Viewer,
    severity: str | None = None,
    method: str | None = None,
    status: str | None = None,
    dataset_id: str | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
) -> list[Finding]:
    query = select(Finding).order_by(Finding.created_at.desc()).limit(limit)
    if severity:
        query = query.where(Finding.severity == severity)
    if method:
        query = query.where(Finding.method == method)
    if status:
        query = query.where(Finding.status == status)
    if dataset_id:
        query = query.where(Finding.dataset_id == dataset_id)
    return list(db.scalars(query).all())


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: str, db: DB, _: Viewer) -> Finding:
    return get_or_404(db, Finding, finding_id, "Finding")


@router.patch("/findings/{finding_id}", response_model=FindingOut)
def update_finding(finding_id: str, body: FindingUpdate, db: DB, user: Analyst) -> Finding:
    finding = get_or_404(db, Finding, finding_id, "Finding")
    finding.status = body.status
    audit.record(db, user.email, f"finding.{body.status}", "finding", finding.id, finding.title)
    db.commit()
    return finding


@router.get("/inspections/{inspection_id}", response_model=InspectionOut)
def get_inspection(inspection_id: str, db: DB, _: Viewer) -> InspectionRun:
    return get_or_404(db, InspectionRun, inspection_id, "Inspection")
