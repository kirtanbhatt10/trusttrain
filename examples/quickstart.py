"""End-to-end TrustTrain walkthrough using the Python SDK.

Prerequisites
-------------
1. A running backend (see README "Backend setup").
2. ``pip install ./sdk``
3. ``python scripts/generate_attack_lab.py`` to create the synthetic datasets.
4. Credentials in the environment: ``TRUSTTRAIN_EMAIL`` and ``TRUSTTRAIN_PASSWORD``
   (or ``TRUSTTRAIN_TOKEN``), and optionally ``TRUSTTRAIN_API_URL``.

Run::

    python examples/quickstart.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from trusttrain import InspectionReport, TrustTrain, TrustTrainError

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "datasets" / "synthetic" / "sentiment_poisoned.csv"


def main() -> int:
    if not DATASET.exists():
        print(
            f"{DATASET} not found. Run: python scripts/generate_attack_lab.py",
            file=sys.stderr,
        )
        return 2

    api_url = os.environ.get("TRUSTTRAIN_API_URL", "http://localhost:8000")
    try:
        with TrustTrain(api_url=api_url) as security:
            # 1. Upload and inspect a dataset.
            report = security.inspect_dataset(DATASET, source="synthetic attack lab")
            if not isinstance(report, InspectionReport):
                raise TrustTrainError("Expected a single-file inspection report")
            print(
                f"Dataset {report.dataset_id}: risk {report.risk_level} (score {report.risk_score:.2f})"
            )
            for finding in report.findings[:5]:
                print(
                    f"  [{finding.severity}] {finding.title} ({finding.method}, confidence {finding.confidence:.2f})"
                )

            # 2. Verify integrity of the stored copy against its manifest.
            verification = security.verify_dataset(report.dataset_id)
            print(f"Integrity: {verification['status']}")

            # 3. Record what was trained on it.
            run = security.record_training_run(
                "sentiment-demo", dataset_ids=[report.dataset_id]
            )
            model = security.register_model(
                "sentiment-demo-model", training_run_id=run["id"]
            )
            print(f"Recorded training run {run['id']} -> model {model['id']}")

            # 4. Trace downstream impact and open an incident.
            downstream = security.lineage(report.dataset_id)
            affected = downstream["affected"]
            print(
                f"Downstream artifacts: {downstream['total_affected']} "
                f"({len(affected['training_runs'])} training runs, {len(affected['models'])} models)"
            )
            incident = security.create_incident(
                "Suspicious rows in sentiment dataset",
                dataset_ids=[report.dataset_id],
                severity="high",
                description="Raised from examples/quickstart.py",
            )
            print(f"Opened incident {incident['id']}")
            markdown = security.incident_report(incident["id"], format="markdown")
            print(str(markdown).splitlines()[0])
    except TrustTrainError as exc:
        print(f"TrustTrain error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
