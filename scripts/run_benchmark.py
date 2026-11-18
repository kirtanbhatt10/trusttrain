#!/usr/bin/env python3
"""Run the detection benchmark against the synthetic attack lab and print/save the results.

Usage: python scripts/run_benchmark.py [--output benchmark-results.json]
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.evaluation.benchmark import run_benchmark


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=2024)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = run_benchmark(args.seed)
    report["environment"] = {
        "python": platform.python_version(),
        "machine": platform.machine(),
        "system": platform.system(),
    }
    for name, data in report["datasets"].items():
        print(
            f"\n== {name}: {data['rows']} rows, {data['poisoned_rows']} poisoned, risk={data['risk_level']}, "
            f"clean-set risk={data['clean_dataset_risk_level']}, {data['processing_seconds']}s"
        )
        for label in ("combined_engine_actionable", "combined_engine_all_findings"):
            m = data[label]
            print(
                f"  {label:30} P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} FPR={m['false_positive_rate']:.3f}"
            )
        for method, d in data["per_detector"].items():
            m = d["vs_all_poisoned_rows"]
            print(
                f"  {method:32} {d['status']:7} flagged={m['flagged']:4} P={m['precision']:.3f} targeted-recall={d['recall_on_targeted_attack']} "
                f"clean-flags={d['rows_flagged_on_clean_dataset']} {d['duration_ms']}ms"
            )
        for attack, info in data["per_attack"].items():
            print(
                f"  attack {attack:24} rows={info['rows']:3} detected={info['detected_by_engine']}"
            )
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(f"\nSaved {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
