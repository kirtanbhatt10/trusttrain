"""Detection-effectiveness benchmark against the synthetic attack lab.

Row-level metrics are computed per detector and for the combined engine:

* positives  – rows injected or modified by an attack (ground truth)
* flagged    – rows referenced by any finding of the detector
* precision, recall, F1, false-positive rate (FP / clean rows)
* actionable = only findings with severity medium or above

Numbers are produced by running the real detectors; nothing is hard-coded.
"""

from __future__ import annotations

import time
from typing import Any

from app.detectors.engine import DETECTOR_NAMES, run_inspection
from app.evaluation.synthetic import generate_attack_lab

ACTIONABLE = {"medium", "high", "critical"}


def _metrics(flagged: set[int], positives: set[int], total: int) -> dict[str, float | int]:
    tp = len(flagged & positives)
    fp = len(flagged - positives)
    fn = len(positives - flagged)
    negatives = total - len(positives)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "flagged": len(flagged),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fp / negatives, 4) if negatives else 0.0,
    }


def run_benchmark(seed: int = 2024) -> dict[str, Any]:
    lab = generate_attack_lab(seed)
    cases = [
        ("sentiment", lab.sentiment_poisoned, lab.sentiment_clean, lab.ground_truth["sentiment_poisoned"], lab.sentiment_clean),
        ("instruct", lab.instruct_poisoned, lab.instruct_clean, lab.ground_truth["instruct_poisoned"], lab.instruct_clean),
    ]
    report: dict[str, Any] = {"seed": seed, "datasets": {}}
    for name, poisoned, reference, truth, clean in cases:
        positives = {r for attack in truth.values() for r in attack.get("rows", [])}
        t0 = time.perf_counter()
        result = run_inspection(poisoned, {}, reference=reference)
        elapsed = time.perf_counter() - t0
        clean_t0 = time.perf_counter()
        clean_result = run_inspection(clean, {})
        clean_elapsed = time.perf_counter() - clean_t0

        actionable = {r for f in result.findings if f.severity in ACTIONABLE for r in f.row_indices}
        clean_actionable = {r for f in clean_result.findings if f.severity in ACTIONABLE for r in f.row_indices}
        per_detector: dict[str, Any] = {}
        all_flagged: set[int] = set()
        for method in DETECTOR_NAMES:
            flagged = {r for f in result.findings if f.method == method for r in f.row_indices}
            all_flagged |= flagged
            expected = {r for a in truth.values() if a.get("expected_detector") == method for r in a.get("rows", [])}
            clean_flagged = {r for f in clean_result.findings if f.method == method for r in f.row_indices}
            outcome = next(o for o in result.outcomes if o.method == method)
            per_detector[method] = {
                "status": outcome.status,
                "duration_ms": outcome.duration_ms,
                "vs_all_poisoned_rows": _metrics(flagged, positives, len(poisoned)),
                "recall_on_targeted_attack": round(len(flagged & expected) / len(expected), 4) if expected else None,
                "rows_flagged_on_clean_dataset": len(clean_flagged),
                "clean_dataset_flag_rate": round(len(clean_flagged) / len(clean), 4),
            }
        per_attack = {
            attack: {
                "rows": len(info.get("rows", [])),
                "expected_detector": info.get("expected_detector"),
                "detected_by_engine": round(len(set(info.get("rows", [])) & all_flagged) / len(info["rows"]), 4) if info.get("rows") else None,
            }
            for attack, info in truth.items()
        }
        report["datasets"][name] = {
            "rows": len(poisoned),
            "poisoned_rows": len(positives),
            "risk_level": result.risk_level,
            "clean_dataset_risk_level": clean_result.risk_level,
            "combined_engine_all_findings": _metrics(all_flagged, positives, len(poisoned)),
            "combined_engine_actionable": _metrics(actionable, positives, len(poisoned)),
            "clean_dataset_actionable_rows": len(clean_actionable),
            "per_detector": per_detector,
            "per_attack": per_attack,
            "processing_seconds": round(elapsed, 3),
            "clean_processing_seconds": round(clean_elapsed, 3),
            "distribution_shift_findings": [f.title for f in result.findings if f.method == "distribution_shift"],
        }
    return report
