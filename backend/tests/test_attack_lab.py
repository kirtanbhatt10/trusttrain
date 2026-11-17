"""Adversarial evaluation against the synthetic attack lab.

These are regression floors measured from the current detectors (see
docs/RESEARCH_AND_BENCHMARKS.md for the full numbers). They guard against
silent degradation; they are not claims of real-world performance.
"""

from __future__ import annotations

import pytest

from app.evaluation.benchmark import run_benchmark
from app.evaluation.synthetic import generate_attack_lab


def test_attack_lab_is_reproducible() -> None:
    a, b = generate_attack_lab(), generate_attack_lab()
    assert a.sentiment_poisoned.equals(b.sentiment_poisoned)
    assert a.instruct_poisoned.equals(b.instruct_poisoned)
    assert a.ground_truth == b.ground_truth


def test_attack_rows_are_disjoint_and_in_range() -> None:
    lab = generate_attack_lab()
    for name, df in (("sentiment_poisoned", lab.sentiment_poisoned), ("instruct_poisoned", lab.instruct_poisoned)):
        seen: set[int] = set()
        for attack in lab.ground_truth[name].values():
            rows = set(attack.get("rows", []))
            assert not rows & seen
            assert all(0 <= r < len(df) for r in rows)
            seen |= rows


@pytest.fixture(scope="module")
def report():  # type: ignore[no-untyped-def]
    return run_benchmark()


def test_every_attack_type_is_surfaced(report) -> None:  # type: ignore[no-untyped-def]
    for dataset in report["datasets"].values():
        for attack, info in dataset["per_attack"].items():
            if info["detected_by_engine"] is not None:
                assert info["detected_by_engine"] >= 0.7, attack


def test_actionable_precision_recall_floors(report) -> None:  # type: ignore[no-untyped-def]
    for dataset in report["datasets"].values():
        m = dataset["combined_engine_actionable"]
        assert m["recall"] >= 0.8 and m["precision"] >= 0.8 and m["false_positive_rate"] <= 0.03


def test_clean_datasets_stay_low_risk(report) -> None:  # type: ignore[no-untyped-def]
    for dataset in report["datasets"].values():
        assert dataset["clean_dataset_risk_level"] in ("none", "low")
        assert dataset["clean_dataset_actionable_rows"] == 0


def test_distribution_shift_reported(report) -> None:  # type: ignore[no-untyped-def]
    assert report["datasets"]["sentiment"]["distribution_shift_findings"]
