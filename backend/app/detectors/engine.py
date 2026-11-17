"""Runs the configured detectors and aggregates a risk assessment.

The risk level summarises *how much evidence warrants investigation*; it is not
a probability that the dataset was maliciously poisoned.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import pandas as pd

from app.detectors.base import ColumnRoles, DetectionContext, Detector, FindingDraft, MethodOutcome, infer_roles
from app.detectors.distribution import DistributionShiftDetector
from app.detectors.duplicates import DuplicateDetector
from app.detectors.embeddings import EmbeddingOutlierDetector
from app.detectors.instructions import SuspiciousInstructionDetector
from app.detectors.labels import LabelInconsistencyDetector, TriggerTokenDetector
from app.detectors.semantic import SemanticInconsistencyDetector
from app.detectors.statistical import StatisticalAnomalyDetector

SEVERITY_WEIGHT = {"info": 0.0, "low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}


def all_detectors() -> list[Detector]:
    return [
        StatisticalAnomalyDetector(),
        DuplicateDetector(),
        LabelInconsistencyDetector(),
        EmbeddingOutlierDetector(),
        SuspiciousInstructionDetector(),
        TriggerTokenDetector(),
        SemanticInconsistencyDetector(),
        DistributionShiftDetector(),
    ]


DETECTOR_NAMES = [d.name for d in all_detectors()]


@dataclass
class InspectionResult:
    roles: ColumnRoles
    outcomes: list[MethodOutcome]
    risk_score: float
    risk_level: str
    duration_ms: int
    findings: list[FindingDraft] = field(default_factory=list)


def score_findings(findings: list[FindingDraft]) -> tuple[float, str]:
    if not findings:
        return 0.0, "none"
    weighted = sorted((SEVERITY_WEIGHT[f.severity] * f.confidence for f in findings), reverse=True)
    # Strongest signal dominates; corroborating signals add with diminishing weight.
    score = weighted[0] + sum(w * 0.5 ** (i + 1) for i, w in enumerate(weighted[1:])) * 0.5
    score = round(min(1.0, score), 4)
    if score >= 0.75:
        level = "critical"
    elif score >= 0.5:
        level = "high"
    elif score >= 0.25:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "none"
    return score, level


def run_inspection(
    df: pd.DataFrame,
    config: dict[str, Any],
    reference: pd.DataFrame | None = None,
    methods: list[str] | None = None,
) -> InspectionResult:
    start = time.perf_counter()
    roles = infer_roles(df, config)
    ctx = DetectionContext(df=df.reset_index(drop=True), roles=roles, config=config, reference=reference)
    outcomes: list[MethodOutcome] = []
    for detector in all_detectors():
        if methods and detector.name not in methods:
            outcomes.append(MethodOutcome(detector.name, "skipped", "not selected"))
            continue
        ok, reason = detector.applicable(ctx)
        if not ok:
            outcomes.append(MethodOutcome(detector.name, "skipped", reason))
            continue
        t0 = time.perf_counter()
        try:
            found = detector.run(ctx)
            outcomes.append(MethodOutcome(detector.name, "ran", "", int((time.perf_counter() - t0) * 1000), found))
        except Exception as exc:  # noqa: BLE001 - one failing detector must not hide the others
            outcomes.append(MethodOutcome(detector.name, "error", f"{type(exc).__name__}: {exc}"[:300], int((time.perf_counter() - t0) * 1000)))
    findings = [f for o in outcomes for f in o.findings]
    score, level = score_findings(findings)
    return InspectionResult(roles, outcomes, score, level, int((time.perf_counter() - start) * 1000), findings)
