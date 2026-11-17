"""Dashboard aggregates, reports and read-only settings. All values are computed from the database."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from app.api.deps import DB, AppSettings, Signer, Viewer, get_or_404
from app.detectors.engine import DETECTOR_NAMES
from app.models import AuditEvent, Dataset, Deployment, Evaluation, Finding, Incident, InspectionRun, ModelArtifact, TrainingRun
from app.provenance.signing import public_key_pem
from app.services.reports import dataset_report

router = APIRouter(prefix="/api", tags=["dashboard"])


def _counts(db: DB, column: Any) -> dict[str, int]:
    return {str(k): int(v) for k, v in db.execute(select(column, func.count()).group_by(column)).all()}


@router.get("/dashboard/summary")
def summary(db: DB, _: Viewer) -> dict[str, Any]:
    history: dict[str, Counter[str]] = defaultdict(Counter)
    for created, level in db.execute(select(InspectionRun.created_at, InspectionRun.risk_level)).all():
        history[created.date().isoformat()][level] += 1
    findings_by_day: Counter[str] = Counter()
    for (created,) in db.execute(select(Finding.created_at)).all():
        findings_by_day[created.date().isoformat()] += 1
    days = sorted(set(history) | set(findings_by_day))[-30:]
    recent = db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(15)).all()
    return {
        "totals": {
            "datasets": db.scalar(select(func.count()).select_from(Dataset)) or 0,
            "inspections": db.scalar(select(func.count()).select_from(InspectionRun)) or 0,
            "open_findings": db.scalar(select(func.count()).select_from(Finding).where(Finding.status == "open")) or 0,
            "training_runs": db.scalar(select(func.count()).select_from(TrainingRun)) or 0,
            "models": db.scalar(select(func.count()).select_from(ModelArtifact)) or 0,
            "deployments": db.scalar(select(func.count()).select_from(Deployment)) or 0,
            "evaluations": db.scalar(select(func.count()).select_from(Evaluation)) or 0,
            "quarantined_datasets": db.scalar(select(func.count()).select_from(Dataset).where(Dataset.quarantined.is_(True))) or 0,
            "quarantined_models": db.scalar(select(func.count()).select_from(ModelArtifact).where(ModelArtifact.status == "quarantined")) or 0,
        },
        "integrity_status": _counts(db, Dataset.integrity_status),
        "risk_distribution": _counts(db, Dataset.risk_level),
        "findings_by_severity": _counts(db, Finding.severity),
        "findings_by_method": _counts(db, Finding.method),
        "evaluation_verdicts": _counts(db, Evaluation.classification),
        "incidents_by_state": _counts(db, Incident.state),
        "detection_history": [
            {"date": d, "inspections": sum(history[d].values()), "findings": findings_by_day[d], "by_risk": dict(history[d])} for d in days
        ],
        "recent_activity": [
            {
                "id": e.id,
                "at": e.created_at.isoformat(),
                "actor": e.actor,
                "action": e.action,
                "target_type": e.target_type,
                "target_id": e.target_id,
                "summary": e.summary,
            }
            for e in recent
        ],
    }


@router.get("/activity")
def activity(db: DB, _: Viewer, limit: int = Query(default=100, ge=1, le=500)) -> list[dict[str, Any]]:
    events = db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)).all()
    return [
        {
            "id": e.id,
            "at": e.created_at.isoformat(),
            "actor": e.actor,
            "action": e.action,
            "target_type": e.target_type,
            "target_id": e.target_id,
            "summary": e.summary,
        }
        for e in events
    ]


@router.get("/reports/datasets/{dataset_id}")
def report_dataset(dataset_id: str, db: DB, settings: AppSettings, signer: Signer, _: Viewer) -> dict[str, Any]:
    return dataset_report(db, settings, signer, get_or_404(db, Dataset, dataset_id, "Dataset"))


@router.get("/settings")
def read_settings(settings: AppSettings, signer: Signer, _: Viewer) -> dict[str, Any]:
    return {
        "environment": settings.environment,
        "limits": {
            "max_upload_bytes": settings.max_upload_bytes,
            "max_rows": settings.max_rows,
            "max_text_chars_per_cell": settings.max_text_chars_per_cell,
        },
        "thresholds": {
            "zscore_threshold": settings.zscore_threshold,
            "near_duplicate_threshold": settings.near_duplicate_threshold,
            "label_noise_threshold": settings.label_noise_threshold,
            "lof_threshold": settings.lof_threshold,
            "semantic_rank_threshold": settings.semantic_rank_threshold,
            "distribution_pvalue": settings.distribution_pvalue,
        },
        "detectors": DETECTOR_NAMES,
        "supported_formats": ["csv", "json", "jsonl", "parquet", "txt"],
        "signing_key": {"algorithm": "Ed25519", "fingerprint": signer.fingerprint, "public_key_pem": public_key_pem(signer.public_key)},
        "rate_limit_per_minute": settings.rate_limit_per_minute,
    }
