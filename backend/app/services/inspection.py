"""Runs dataset inspections and persists findings."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.config import Settings
from app.detectors.engine import run_inspection
from app.models import Dataset, Finding, InspectionRun
from app.services import audit
from app.services.datasets import load_dataset_frame

_THRESHOLD_KEYS = {
    "zscore_threshold",
    "near_duplicate_threshold",
    "label_noise_threshold",
    "lof_threshold",
    "semantic_rank_threshold",
    "distribution_pvalue",
    "trigger_min_count",
    "trigger_max_doc_fraction",
    "trigger_contradiction",
    "forced_response_min_prompts",
    "forced_response_max_prompt_similarity",
    "vocabulary_jsd_threshold",
}


def build_config(settings: Settings, overrides: dict[str, Any]) -> dict[str, Any]:
    config: dict[str, Any] = {
        "zscore_threshold": settings.zscore_threshold,
        "near_duplicate_threshold": settings.near_duplicate_threshold,
        "label_noise_threshold": settings.label_noise_threshold,
        "lof_threshold": settings.lof_threshold,
        "semantic_rank_threshold": settings.semantic_rank_threshold,
        "distribution_pvalue": settings.distribution_pvalue,
    }
    thresholds = overrides.get("thresholds") or {}
    unknown = set(thresholds) - _THRESHOLD_KEYS
    if unknown:
        raise ValueError(f"Unknown thresholds: {sorted(unknown)}")
    config.update(thresholds)
    for key in ("text_column", "label_column", "input_column", "output_column"):
        if overrides.get(key):
            config[key] = overrides[key]
    return config


def inspect_dataset(db: Session, settings: Settings, dataset: Dataset, actor: str, request: dict[str, Any]) -> InspectionRun:
    df = load_dataset_frame(settings, dataset)
    reference_df = None
    reference_id = request.get("reference_dataset_id")
    if reference_id is None and dataset.parent_id:
        reference_id = dataset.parent_id
    if reference_id:
        reference = db.get(Dataset, reference_id)
        if reference is None:
            raise LookupError("Reference dataset not found")
        reference_df = load_dataset_frame(settings, reference)
    config = build_config(settings, request)
    result = run_inspection(df, config, reference=reference_df, methods=request.get("methods"))
    run = InspectionRun(
        dataset_id=dataset.id,
        reference_dataset_id=reference_id,
        risk_level=result.risk_level,
        risk_score=result.risk_score,
        config={**config, "column_roles": result.roles.as_dict()},
        methods=[
            {"method": o.method, "status": o.status, "reason": o.reason, "duration_ms": o.duration_ms, "findings": len(o.findings)}
            for o in result.outcomes
        ],
        duration_ms=result.duration_ms,
    )
    db.add(run)
    db.flush()
    for draft in result.findings:
        db.add(
            Finding(
                inspection_id=run.id,
                dataset_id=dataset.id,
                severity=draft.severity,
                method=draft.method,
                title=draft.title[:300],
                confidence=round(draft.confidence, 4),
                explanation=draft.explanation,
                evidence=_json_safe(draft.stored_evidence()),
                investigation_steps=draft.investigation_steps,
                limitations=draft.limitations,
            )
        )
    dataset.risk_level = result.risk_level
    audit.record(db, actor, "dataset.inspected", "dataset", dataset.id, f"Inspection found {len(result.findings)} findings; risk {result.risk_level}")
    db.commit()
    db.refresh(run)
    return run


def _json_safe(value: Any) -> Any:
    """Convert numpy scalars and other non-JSON values recursively."""
    import numpy as np

    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, float) and value != value:  # NaN
        return None
    return value
