"""Typed result objects returned by the SDK."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

RISK_ORDER = ["unknown", "none", "low", "medium", "high", "critical"]


class TrustTrainError(Exception):
    """Base error for SDK failures."""


class APIError(TrustTrainError):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(f"API error {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail


class AuthenticationError(APIError):
    pass


@dataclass(frozen=True)
class Finding:
    id: str
    severity: str
    method: str
    title: str
    confidence: float
    explanation: str
    evidence: dict[str, Any]
    investigation_steps: list[str]
    limitations: str

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> Finding:
        return cls(
            id=data["id"],
            severity=data["severity"],
            method=data["method"],
            title=data["title"],
            confidence=float(data["confidence"]),
            explanation=data.get("explanation", ""),
            evidence=data.get("evidence", {}),
            investigation_steps=list(data.get("investigation_steps", [])),
            limitations=data.get("limitations", ""),
        )


@dataclass(frozen=True)
class InspectionReport:
    dataset_id: str
    dataset_name: str
    inspection_id: str
    risk_level: str
    risk_score: float
    findings: list[Finding]
    methods: list[dict[str, Any]]
    sha256: str

    @classmethod
    def from_api(cls, dataset: dict[str, Any], inspection: dict[str, Any]) -> InspectionReport:
        return cls(
            dataset_id=dataset["id"],
            dataset_name=dataset["name"],
            inspection_id=inspection["id"],
            risk_level=inspection["risk_level"],
            risk_score=float(inspection["risk_score"]),
            findings=[Finding.from_api(f) for f in inspection.get("findings", [])],
            methods=list(inspection.get("methods", [])),
            sha256=dataset["sha256"],
        )


@dataclass(frozen=True)
class DirectoryReport:
    """Aggregate of per-file inspections; ``risk_level`` is the highest per-file level."""

    reports: list[InspectionReport] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    @property
    def risk_level(self) -> str:
        levels = [r.risk_level for r in self.reports] or ["unknown"]
        return max(levels, key=RISK_ORDER.index)

    @property
    def findings(self) -> list[Finding]:
        return [f for r in self.reports for f in r.findings]


def risk_at_least(level: str, threshold: str) -> bool:
    return RISK_ORDER.index(level) >= RISK_ORDER.index(threshold)
