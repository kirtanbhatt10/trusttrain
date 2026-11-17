"""Statistical anomaly detection on numeric features and text lengths.

Uses the robust z-score (median / MAD) per column, plus an Isolation Forest
across all numeric features when there are at least two of them.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from app.detectors.base import DetectionContext, FindingDraft, severity_for_fraction

_MIN_ROWS = 30


def robust_z(values: np.ndarray) -> np.ndarray:
    median = np.nanmedian(values)
    mad = np.nanmedian(np.abs(values - median))
    if mad == 0 or np.isnan(mad):
        std = np.nanstd(values)
        if std == 0 or np.isnan(std):
            return np.zeros_like(values, dtype=float)
        return (values - np.nanmean(values)) / std
    return 0.6745 * (values - median) / mad


class StatisticalAnomalyDetector:
    name = "statistical_anomaly"

    def applicable(self, ctx: DetectionContext) -> tuple[bool, str]:
        if len(ctx.df) < _MIN_ROWS:
            return False, f"needs at least {_MIN_ROWS} rows"
        if not ctx.roles.numeric and ctx.text_series() is None:
            return False, "no numeric or text columns"
        return True, ""

    def run(self, ctx: DetectionContext) -> list[FindingDraft]:
        threshold = float(ctx.config.get("zscore_threshold", 4.0))
        findings: list[FindingDraft] = []
        n = len(ctx.df)
        columns: dict[str, np.ndarray] = {c: pd.to_numeric(ctx.df[c], errors="coerce").to_numpy(dtype=float) for c in ctx.roles.numeric}
        text = ctx.text_series()
        if text is not None:
            columns["__text_length__"] = np.log1p(text.str.len().to_numpy(dtype=float))
        for col, values in columns.items():
            z = robust_z(values)
            idx = np.where(np.abs(z) > threshold)[0]
            if len(idx) == 0:
                continue
            frac = len(idx) / n
            label = "log text length" if col == "__text_length__" else f"column '{col}'"
            findings.append(
                FindingDraft(
                    method=self.name,
                    severity=severity_for_fraction(frac, low=0.001, medium=0.02, high=0.1) if frac < 0.2 else "low",
                    title=f"{len(idx)} extreme values in {label}",
                    confidence=min(0.9, 0.4 + float(np.median(np.abs(z[idx]))) / (threshold * 4)),
                    explanation=(
                        f"{len(idx)} of {n} rows have a robust z-score above {threshold} for {label}. "
                        "Extreme values can indicate injected or corrupted records, but are often legitimate long-tail data."
                    ),
                    evidence={
                        "column": None if col == "__text_length__" else col,
                        "row_indices": [int(i) for i in idx[np.argsort(-np.abs(z[idx]))]],
                        "max_abs_z": round(float(np.max(np.abs(z[idx]))), 3),
                        "median": float(np.nanmedian(values)),
                    },
                    investigation_steps=[
                        "Review the flagged rows against the data source.",
                        "Check whether the values fall within physically or semantically valid ranges.",
                        "Compare with a trusted earlier version of the dataset.",
                    ],
                    limitations="Assumes the bulk of the column is roughly unimodal; heavy-tailed features produce false positives.",
                )
            )
        if len(ctx.roles.numeric) >= 2 and n >= 100:
            matrix = np.column_stack([np.nan_to_num(columns[c], nan=np.nanmedian(columns[c])) for c in ctx.roles.numeric])
            forest = IsolationForest(n_estimators=200, contamination="auto", random_state=0)
            scores = -forest.fit(matrix).score_samples(matrix)
            z = robust_z(scores)
            idx = np.where(z > threshold)[0]
            if len(idx):
                findings.append(
                    FindingDraft(
                        method=self.name,
                        severity=severity_for_fraction(len(idx) / n, low=0.001, medium=0.02, high=0.1),
                        title=f"{len(idx)} multivariate outliers (Isolation Forest)",
                        confidence=0.55,
                        explanation="These rows are unusually easy to isolate across the combined numeric features.",
                        evidence={"columns": ctx.roles.numeric, "row_indices": [int(i) for i in idx[np.argsort(-z[idx])]]},
                        investigation_steps=[
                            "Inspect the joint feature values of flagged rows.",
                            "Confirm their origin in the ingestion logs.",
                        ],
                        limitations="Isolation Forest scores are relative; small datasets give unstable results.",
                    )
                )
        return findings
