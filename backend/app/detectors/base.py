"""Shared types for poisoning detectors.

A detector receives a :class:`DetectionContext` and returns zero or more
:class:`FindingDraft` objects. Findings are *signals for investigation*, never
proof of malicious intent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

import pandas as pd

SEVERITIES = ("info", "low", "medium", "high", "critical")

_TEXT_NAMES = ("text", "sentence", "content", "review", "document", "body", "message")
_INPUT_NAMES = ("prompt", "instruction", "input", "question", "query")
_OUTPUT_NAMES = ("response", "output", "completion", "answer", "target_text")
_LABEL_NAMES = ("label", "labels", "target", "class", "category", "sentiment", "y")
MAX_EVIDENCE_ROWS = 50


@dataclass
class ColumnRoles:
    text: str | None = None
    label: str | None = None
    input: str | None = None
    output: str | None = None
    numeric: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"text": self.text, "label": self.label, "input": self.input, "output": self.output, "numeric": self.numeric}


def _first_match(columns: list[str], names: tuple[str, ...]) -> str | None:
    lower = {c.lower(): c for c in columns}
    for name in names:
        if name in lower:
            return lower[name]
    return None


def is_identifier(series: pd.Series, name: str) -> bool:
    """Heuristic: unique integer keys named like identifiers are not features."""
    lowered = name.lower()
    named_like_id = lowered in ("id", "idx", "index", "row_id", "uid") or lowered.endswith("_id")
    return named_like_id and pd.api.types.is_integer_dtype(series) and series.is_unique


def infer_roles(df: pd.DataFrame, overrides: dict[str, Any] | None = None) -> ColumnRoles:
    overrides = overrides or {}
    cols = list(df.columns)
    roles = ColumnRoles(
        text=overrides.get("text_column") or _first_match(cols, _TEXT_NAMES),
        label=overrides.get("label_column") or _first_match(cols, _LABEL_NAMES),
        input=overrides.get("input_column") or _first_match(cols, _INPUT_NAMES),
        output=overrides.get("output_column") or _first_match(cols, _OUTPUT_NAMES),
    )
    for name in (roles.text, roles.label, roles.input, roles.output):
        if name is not None and name not in df.columns:
            raise ValueError(f"Column '{name}' not present in dataset")
    if roles.text is None:
        # Fall back to the string column with the longest average length.
        str_cols = [c for c in cols if df[c].dtype == object or str(df[c].dtype).startswith("string")]
        str_cols = [c for c in str_cols if c not in (roles.label, roles.input, roles.output)]
        if str_cols:
            roles.text = max(str_cols, key=lambda c: df[c].astype(str).str.len().mean())
    roles.numeric = [
        c
        for c in cols
        if c != roles.label and pd.api.types.is_numeric_dtype(df[c]) and not pd.api.types.is_bool_dtype(df[c]) and not is_identifier(df[c], c)
    ]
    return roles


@dataclass
class DetectionContext:
    df: pd.DataFrame
    roles: ColumnRoles
    config: dict[str, Any]
    reference: pd.DataFrame | None = None

    def text_series(self) -> pd.Series | None:
        if self.roles.input and self.roles.output:
            return self.df[self.roles.input].fillna("").astype(str) + " \n " + self.df[self.roles.output].fillna("").astype(str)
        if self.roles.text:
            return self.df[self.roles.text].fillna("").astype(str)
        return None


@dataclass
class FindingDraft:
    method: str
    severity: str
    title: str
    confidence: float
    explanation: str
    evidence: dict[str, Any]
    investigation_steps: list[str]
    limitations: str

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"Unknown severity {self.severity}")
        self.confidence = float(max(0.0, min(1.0, self.confidence)))

    @property
    def row_indices(self) -> list[int]:
        rows = self.evidence.get("row_indices", [])
        return [int(r) for r in rows] if isinstance(rows, list) else []

    def stored_evidence(self) -> dict[str, Any]:
        """Evidence with the row list capped for storage/transport."""
        evidence = dict(self.evidence)
        rows = self.row_indices
        evidence["row_indices_total"] = len(rows)
        evidence["row_indices"] = rows[:MAX_EVIDENCE_ROWS]
        return evidence


@dataclass
class MethodOutcome:
    method: str
    status: str  # ran | skipped | error
    reason: str = ""
    duration_ms: int = 0
    findings: list[FindingDraft] = field(default_factory=list)


class Detector(Protocol):
    name: str

    def applicable(self, ctx: DetectionContext) -> tuple[bool, str]: ...

    def run(self, ctx: DetectionContext) -> list[FindingDraft]: ...


def severity_for_fraction(fraction: float, low: float = 0.002, medium: float = 0.01, high: float = 0.05) -> str:
    if fraction >= high:
        return "high"
    if fraction >= medium:
        return "medium"
    if fraction >= low:
        return "low"
    return "info"


def snippet(value: Any, limit: int = 160) -> str:
    text = str(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"
